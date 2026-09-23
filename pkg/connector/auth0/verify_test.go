package auth0_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
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
