package auth0_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

const exportResult = `{"user_id":"auth0|1","email":"a@example.com","email_verified":true,"username":"alice","given_name":"Alice","app_metadata":{"plan":"pro"},"user_metadata":{"theme":"dark"}}
{"user_id":"google-oauth2|2","email":"b@example.com","email_verified":true,"name":"Bob","picture":"https://example.com/b.png","blocked":true}
{"user_id":"sms|3","phone_number":"+33612345678","phone_verified":true}
{"email":"orphan@example.com"}
`

// exportServer is a fake Management API with a user export job that is
// pending on its first poll, and serves result (optionally gzipped) from a
// download URL that rejects requests carrying an Authorization header.
type exportServer struct {
	*httptest.Server
	request   map[string]any
	polls     int
	downloads int
}

func newExportServer(t *testing.T, result string, gz bool, finalStatus string) *exportServer {
	t.Helper()
	s := &exportServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-exports", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&s.request))
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "job_1", "status": "pending", "type": "users_export"})
	})
	mux.HandleFunc("/jobs/job_1", func(w http.ResponseWriter, r *http.Request) {
		s.polls++
		if s.polls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "job_1", "status": "processing"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "job_1", "status": finalStatus, "location": s.URL + "/download"})
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		s.downloads++
		require.Empty(t, r.Header.Get("Authorization"), "the signed download URL must not get the Management API token")
		if !gz {
			_, _ = w.Write([]byte(result))
			return
		}
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(result))
		require.NoError(t, zw.Close())
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func runExport(t *testing.T, s *exportServer, opts auth0.ExportOptions) ([]cmf.User, connector.Manifest, error) {
	t.Helper()
	defer auth0.SetPollIntervalsForTest(time.Millisecond, 5*time.Millisecond)()

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	m, err := auth0.New(auth0.NewClient(s.URL, "tok")).Export(context.Background(), w, opts)
	require.NoError(t, w.Close())
	if err != nil {
		return nil, m, err
	}

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err != nil {
			break
		}
		users = append(users, u)
	}
	return users, m, nil
}

func TestExportMapsEveryUserWithoutPassword(t *testing.T) {
	for _, gz := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%v", gz), func(t *testing.T) {
			s := newExportServer(t, exportResult, gz, "completed")
			users, m, err := runExport(t, s, auth0.ExportOptions{})
			require.NoError(t, err)

			require.Equal(t, 3, m.RecordCount)
			require.Equal(t, []connector.SkippedRecord{{Reason: "no user_id"}}, m.SkippedRecords)
			require.Len(t, users, 3)

			alice := users[0]
			require.Equal(t, "auth0|1", alice.SourceID)
			require.Equal(t, []cmf.Contact{{Value: "a@example.com", Verified: true, Primary: true}}, alice.Emails)
			require.Equal(t, "alice", alice.Username)
			require.Equal(t, "Alice", alice.Profile.GivenName)
			require.Equal(t, map[string]any{"plan": "pro"}, alice.AppMetadata)
			require.Equal(t, map[string]any{"theme": "dark"}, alice.UserMetadata)
			require.Nil(t, alice.Password)

			bob := users[1]
			require.Equal(t, "google-oauth2|2", bob.SourceID)
			require.True(t, bob.Blocked)
			require.Equal(t, "https://example.com/b.png", bob.Profile.Picture)
			require.Nil(t, bob.Password)

			require.Equal(t, []cmf.Contact{{Value: "+33612345678", Verified: true, Primary: true}}, users[2].Phones)
			require.Empty(t, users[2].Emails)

			require.Equal(t, 2, s.polls)
			require.Equal(t, 1, s.downloads)
		})
	}
}

func TestExportRequestSelection(t *testing.T) {
	names := func(req map[string]any) []string {
		var out []string
		for _, f := range req["fields"].([]any) {
			out = append(out, f.(map[string]any)["name"].(string))
		}
		return out
	}

	t.Run("all fields by default", func(t *testing.T) {
		s := newExportServer(t, exportResult, false, "completed")
		_, _, err := runExport(t, s, auth0.ExportOptions{})
		require.NoError(t, err)

		require.Equal(t, "json", s.request["format"])
		require.NotContains(t, s.request, "connection_id")
		require.NotContains(t, s.request, "limit")
		require.Equal(t, append([]string{"user_id"}, auth0.ExportFields...), names(s.request))
	})

	t.Run("selected fields, connection and limit", func(t *testing.T) {
		s := newExportServer(t, exportResult, false, "completed")
		_, _, err := runExport(t, s, auth0.ExportOptions{
			Fields:       []string{"email", "user_id", "app_metadata"},
			ConnectionID: "con_0123456789abcdef",
			Limit:        10,
		})
		require.NoError(t, err)

		require.Equal(t, []string{"user_id", "email", "app_metadata"}, names(s.request))
		require.Equal(t, "con_0123456789abcdef", s.request["connection_id"])
		require.EqualValues(t, 10, s.request["limit"])
	})
}

func TestExportRejectsUnknownField(t *testing.T) {
	s := newExportServer(t, exportResult, false, "completed")
	_, _, err := runExport(t, s, auth0.ExportOptions{Fields: []string{"email", "password_hash"}})
	require.ErrorContains(t, err, `unknown export field "password_hash"`)
	require.Nil(t, s.request, "no job should be created for an invalid selection")
}

func TestExportFailedJob(t *testing.T) {
	s := newExportServer(t, "", false, "failed")
	_, _, err := runExport(t, s, auth0.ExportOptions{})
	require.ErrorContains(t, err, `ended with status "failed"`)
	require.Zero(t, s.downloads)
}
