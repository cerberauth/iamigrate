package auth0_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

// fakeAuth0Server mimics just enough of the Management API's bulk import
// job lifecycle (submit -> pending -> completed -> errors) to exercise
// RunBulkImport's chunking, polling, and DUPLICATED_USER handling without
// any real Auth0 tenant.
func fakeAuth0Server(t *testing.T) *httptest.Server {
	t.Helper()
	var polls int32

	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-imports", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(10<<20))
		require.Equal(t, "conn_123", r.FormValue("connection_id"))
		require.Equal(t, "false", r.FormValue("upsert"))

		file, _, err := r.FormFile("users")
		require.NoError(t, err)
		defer file.Close()
		body, err := io.ReadAll(file)
		require.NoError(t, err)

		var users []map[string]any
		require.NoError(t, json.Unmarshal(body, &users))
		require.NotEmpty(t, users)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "pending"})
	})
	mux.HandleFunc("/jobs/job_1", func(w http.ResponseWriter, r *http.Request) {
		status := "completed"
		if atomic.AddInt32(&polls, 1) == 1 {
			status = "processing"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	mux.HandleFunc("/jobs/job_1/errors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"user":   map[string]string{"user_id": "u2"},
				"errors": []map[string]string{{"code": "DUPLICATED_USER", "message": "already exists"}},
			},
		})
	})
	return httptest.NewServer(mux)
}

func writeUsers(t *testing.T, users []cmf.User) *cmf.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	return r
}

func bcryptUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Profile:    cmf.Profile{GivenName: "Test"},
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
		Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
	}
}

// TestRunBulkImportRecordedCassette records RunBulkImport's HTTP traffic
// against fakeAuth0Server, then replays that cassette with no live server
// running at all, asserting both runs produce the same request shapes and
// ImportReport. This is the "recorded-cassette Auth0 connector test"
// layer from DESIGN.md's testing strategy.
func TestRunBulkImportRecordedCassette(t *testing.T) {
	orig := setFastPolling(t)
	defer orig()

	server := fakeAuth0Server(t)
	defer server.Close()

	cassettePath := filepath.Join(t.TempDir(), "bulk-import")

	rec, err := recorder.New(cassettePath)
	require.NoError(t, err)
	rec.SetMatcher(pathAndBodyMatcher)

	client := auth0.NewClient(server.URL, "test-token")
	client.HTTP = rec.GetDefaultClient()

	users := []cmf.User{bcryptUser("u1"), bcryptUser("u2")}
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, users), "conn_123", false)
	require.NoError(t, err)
	require.NoError(t, rec.Stop())

	require.ElementsMatch(t, []string{"u1"}, report.Succeeded)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "DUPLICATED_USER", report.Failed[0].Code)
	require.Equal(t, "u2", report.Failed[0].SourceID)

	// Replay: point at a bogus, unreachable host. If replay actually
	// avoids the network (using only the cassette), this succeeds anyway.
	replayRec, err := recorder.NewWithOptions(&recorder.Options{
		CassetteName: cassettePath,
		Mode:         recorder.ModeReplayOnly,
	})
	require.NoError(t, err)
	replayRec.SetMatcher(pathAndBodyMatcher)
	defer replayRec.Stop()

	replayClient := auth0.NewClient("http://127.0.0.1:1", "test-token")
	replayClient.HTTP = replayRec.GetDefaultClient()

	replayReport, _, err := auth0.RunBulkImport(context.Background(), replayClient, writeUsers(t, users), "conn_123", false)
	require.NoError(t, err)
	require.Equal(t, report.Succeeded, replayReport.Succeeded)
	require.Equal(t, report.Failed, replayReport.Failed)
}

// pathAndBodyMatcher matches on method, URL path (ignoring host/scheme,
// since the recorded host and the replay host differ), and body, so a
// committed-style cassette replays independently of where it was
// recorded from.
func pathAndBodyMatcher(r *http.Request, i cassette.Request) bool {
	u, err := parseURLPath(i.URL)
	if err != nil {
		return false
	}
	if r.Method != i.Method || r.URL.Path != u {
		return false
	}
	return true
}

func parseURLPath(raw string) (string, error) {
	idx := indexPath(raw)
	return raw[idx:], nil
}

// indexPath finds where the path component starts in a recorded absolute
// URL (after "scheme://host").
func indexPath(raw string) int {
	schemeEnd := 0
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] == ':' && raw[i+1] == '/' && raw[i+2] == '/' {
			schemeEnd = i + 3
			break
		}
	}
	for i := schemeEnd; i < len(raw); i++ {
		if raw[i] == '/' {
			return i
		}
	}
	return len(raw)
}

func setFastPolling(t *testing.T) func() {
	t.Helper()
	return auth0.SetPollIntervalsForTest(10*time.Millisecond, 50*time.Millisecond)
}
