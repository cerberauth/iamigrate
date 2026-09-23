package auth0_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

func TestClientCredentialsFetchesAndCachesToken(t *testing.T) {
	var tokenRequests int
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		require.Equal(t, "cid", r.PostForm.Get("client_id"))
		require.Equal(t, "csecret", r.PostForm.Get("client_secret"))
		require.Equal(t, srv.URL+"/api/v2/", r.PostForm.Get("audience"))
		_, _ = w.Write([]byte(`{"access_token":"m2m-token","token_type":"Bearer","expires_in":86400}`))
	})
	mux.HandleFunc("/api/v2/connections", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer m2m-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`[{"id":"con_a","name":"db"}]`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := auth0.NewClientCredentialsClient(srv.URL+"/api/v2", srv.URL+"/oauth/token", "cid", "csecret")
	for range 2 {
		id, err := auth0.ResolveConnectionID(context.Background(), client, "")
		require.NoError(t, err)
		require.Equal(t, "con_a", id)
	}
	require.Equal(t, 1, tokenRequests)
}

func TestClientCredentialsRefreshesExpiringToken(t *testing.T) {
	var tokenRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		_, _ = w.Write([]byte(`{"access_token":"short-lived","expires_in":30}`))
	}))
	defer srv.Close()

	cc := &auth0.ClientCredentials{TokenURL: srv.URL, ClientID: "cid", ClientSecret: "csecret"}
	for range 2 {
		tok, err := cc.Token(context.Background(), srv.Client())
		require.NoError(t, err)
		require.Equal(t, "short-lived", tok)
	}
	require.Equal(t, 2, tokenRequests)
}

func TestClientCredentialsGrantError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"Unauthorized"}`))
	}))
	defer srv.Close()

	cc := &auth0.ClientCredentials{TokenURL: srv.URL, ClientID: "cid", ClientSecret: "wrong"}
	_, err := cc.Token(context.Background(), srv.Client())
	require.ErrorContains(t, err, "client_credentials grant")
	require.ErrorContains(t, err, "access_denied")
}
