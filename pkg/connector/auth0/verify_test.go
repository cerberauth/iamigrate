package auth0_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

func TestConnectorVerifyLooksUpByEmailUsernameOrPhone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var found []map[string]any
		switch r.URL.Path {
		case "/users-by-email":
			if r.URL.Query().Get("email") == "email@example.com" {
				found = []map[string]any{{"user_id": "auth0|email", "blocked": false}}
			}
		case "/users":
			require.Equal(t, "v3", r.URL.Query().Get("search_engine"))
			switch r.URL.Query().Get("q") {
			case `username:"jane.doe"`:
				found = []map[string]any{{"user_id": "auth0|username", "blocked": true}}
			case `phone_number:"+12025550142"`:
				found = []map[string]any{{"user_id": "auth0|phone", "blocked": false}}
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		require.NoError(t, json.NewEncoder(w).Encode(found))
	}))
	defer srv.Close()

	user := func(id string) cmf.User {
		return cmf.User{
			CMFVersion: cmf.Version,
			SourceID:   id,
			Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
		}
	}
	byEmail := user("by-email")
	byEmail.Emails = []cmf.Contact{{Value: "email@example.com"}}
	byUsername := user("by-username")
	byUsername.Username = "jane.doe"
	byPhone := user("by-phone")
	byPhone.Phones = []cmf.Contact{{Value: "+12025550142"}}
	missing := user("missing")
	missing.Username = "nobody"
	none := user("none")

	target := auth0.New(auth0.NewClient(srv.URL, "tok"))
	report, err := target.Verify(context.Background(), writeUsers(t, []cmf.User{byEmail, byUsername, byPhone, missing, none}))
	require.NoError(t, err)
	require.Equal(t, []string{"missing"}, report.MissingInTarget)
	require.Equal(t, []string{"none"}, report.NoIdentifier)
	require.Len(t, report.AttributeDrift, 1)
	require.Equal(t, "by-username", report.AttributeDrift[0].SourceID)
}

// fakeLookupServer answers the Management API's lookups (users-by-email
// and the search behind username/phone) from a fixed tenant.
func fakeLookupServer(t *testing.T) *httptest.Server {
	t.Helper()
	tenant := map[string][]map[string]any{
		"ok@example.com": {{"user_id": "auth0|ok", "email_verified": true, "given_name": "Ok", "name": "Ok User"}},
		"drift@example.com": {{
			"user_id": "auth0|drift", "blocked": true, "email_verified": false,
			"given_name": "Other", "family_name": "Drift", "name": "Drift User",
		}},
		// An email shared by two connections: the user Import created wins.
		"shared@example.com": {
			{"user_id": "google-oauth2|1", "email_verified": true, "blocked": true},
			{"user_id": "auth0|shared", "email_verified": true},
		},
		`username:"phoneless"`: {{"user_id": "auth0|phoneless", "username": "phoneless"}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("email")
		if key == "" {
			key = r.URL.Query().Get("q")
		}
		found := tenant[key]
		if found == nil {
			found = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(found))
	}))
}

// queryMatcher matches a replayed request on method, path and query,
// ignoring the host the cassette was recorded from.
func queryMatcher(r *http.Request, i cassette.Request) bool {
	u, err := url.Parse(i.URL)
	return err == nil && r.Method == i.Method && r.URL.Path == u.Path && r.URL.RawQuery == u.RawQuery
}

// TestConnectorVerifyRecordedCassette records Verify's lookups against a
// fake tenant, then replays that cassette with no server reachable,
// asserting both runs produce the same DiffReport: counts, missing users,
// per-field drift and unlookable users, all keyed by source_id.
func TestConnectorVerifyRecordedCassette(t *testing.T) {
	server := fakeLookupServer(t)
	defer server.Close()

	user := func(id, email string) cmf.User {
		u := cmf.User{
			CMFVersion: cmf.Version,
			SourceID:   id,
			Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
		}
		if email != "" {
			u.Emails = []cmf.Contact{{Value: email, Verified: true}}
		}
		return u
	}
	ok := user("ok", "ok@example.com")
	ok.Profile = cmf.Profile{GivenName: "Ok"}
	drift := user("drift", "drift@example.com")
	drift.Profile = cmf.Profile{GivenName: "Drift", FamilyName: "Drift"}
	shared := user("shared", "shared@example.com")
	byUsername := user("by-username", "")
	byUsername.Username = "phoneless"
	missing := user("missing", "missing@example.com")
	none := user("none", "")
	users := []cmf.User{ok, drift, shared, byUsername, missing, none}

	want := connector.DiffReport{
		SourceCount:     6,
		TargetCount:     4,
		MissingInTarget: []string{"missing"},
		AttributeDrift: []connector.DriftEntry{
			{SourceID: "drift", Fields: []string{"blocked", "email_verified", "given_name"}},
		},
		NoIdentifier: []string{"none"},
	}

	cassettePath := filepath.Join(t.TempDir(), "verify")
	rec, err := recorder.New(cassettePath)
	require.NoError(t, err)
	rec.SetMatcher(queryMatcher)
	client := auth0.NewClient(server.URL, "test-token")
	client.HTTP = rec.GetDefaultClient()

	report, err := auth0.New(client).Verify(context.Background(), writeUsers(t, users))
	require.NoError(t, err)
	require.NoError(t, rec.Stop())
	require.Equal(t, want, report)
	require.True(t, report.CountMismatch())

	// Replay against an unreachable host: only the cassette can answer.
	replayRec, err := recorder.NewWithOptions(&recorder.Options{
		CassetteName: cassettePath,
		Mode:         recorder.ModeReplayOnly,
	})
	require.NoError(t, err)
	replayRec.SetMatcher(queryMatcher)
	defer replayRec.Stop()
	replayClient := auth0.NewClient("http://127.0.0.1:1", "test-token")
	replayClient.HTTP = replayRec.GetDefaultClient()

	replayed, err := auth0.New(replayClient).Verify(context.Background(), writeUsers(t, users))
	require.NoError(t, err)
	require.Equal(t, want, replayed)
}
