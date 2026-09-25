package auth0_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

// requireIamigrateHeaders asserts a request carries iamigrate's User-Agent
// and Auth0-Client headers.
func requireIamigrateHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	require.Regexp(t, `^iamigrate/\S+ \(\+https://github\.com/cerberauth/iamigrate\)$`, r.Header.Get("User-Agent"))

	raw, err := base64.StdEncoding.DecodeString(r.Header.Get("Auth0-Client"))
	require.NoError(t, err)
	var client struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal(raw, &client))
	require.Equal(t, "iamigrate", client.Name)
}

func TestClientSetsUserAgentOnAPIRequests(t *testing.T) {
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		_, _ = w.Write([]byte(`[{"id":"con_a","name":"db"}]`))
	}))
	defer srv.Close()

	client := auth0.NewClient(srv.URL, "token")
	_, err := auth0.ResolveConnectionID(context.Background(), client, "")
	require.NoError(t, err)
	requireIamigrateHeaders(t, &http.Request{Header: gotHeaders})
}

func TestClientCredentialsSetsUserAgentOnTokenRequest(t *testing.T) {
	var gotHeaders http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := auth0.NewClientCredentialsClient(srv.URL+"/api/v2", srv.URL+"/oauth/token", "cid", "csecret")
	_, err := client.Credentials.Token(context.Background(), client.HTTP)
	require.NoError(t, err)
	requireIamigrateHeaders(t, &http.Request{Header: gotHeaders})
}

func TestRunBulkImportSetsUserAgentOnMultipartRequest(t *testing.T) {
	var gotHeaders http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-imports", func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "pending"})
	})
	mux.HandleFunc("/jobs/job_1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
	})
	mux.HandleFunc("/jobs/job_1/errors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := auth0.NewClient(srv.URL, "token")
	users := writeUsers(t, []cmf.User{bcryptUser("u1")})
	_, _, err := auth0.RunBulkImport(context.Background(), client, users, "conn_123", false)
	require.NoError(t, err)
	requireIamigrateHeaders(t, &http.Request{Header: gotHeaders})
}
