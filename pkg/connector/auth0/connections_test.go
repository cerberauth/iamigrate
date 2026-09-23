package auth0_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

func connectionsServer(t *testing.T, status int, conns []auth0.Connection) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/connections", r.URL.Path)
		require.Equal(t, "auth0", r.URL.Query().Get("strategy"))
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"statusCode":403,"error":"Forbidden","message":"Insufficient scope, expected any of: read:connections"}`))
			return
		}
		out := conns
		if name := r.URL.Query().Get("name"); name != "" {
			out = nil
			for _, c := range conns {
				if c.Name == name {
					out = append(out, c)
				}
			}
		}
		require.NoError(t, json.NewEncoder(w).Encode(out))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveConnectionID(t *testing.T) {
	two := []auth0.Connection{
		{ID: "con_a", Name: "Username-Password-Authentication"},
		{ID: "con_b", Name: "legacy-db"},
	}

	tests := []struct {
		name    string
		status  int
		conns   []auth0.Connection
		lookup  string
		want    string
		wantErr string
	}{
		{name: "by name", status: http.StatusOK, conns: two, lookup: "legacy-db", want: "con_b"},
		{name: "unknown name", status: http.StatusOK, conns: two, lookup: "nope", wantErr: `no database connection named "nope"`},
		{name: "only connection", status: http.StatusOK, conns: two[:1], want: "con_a"},
		{name: "several connections", status: http.StatusOK, conns: two, wantErr: "2 database connections"},
		{name: "no connection", status: http.StatusOK, wantErr: "no database connection"},
		{name: "missing scope", status: http.StatusForbidden, lookup: "legacy-db", wantErr: "read:connections"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := connectionsServer(t, tt.status, tt.conns)
			id, err := auth0.ResolveConnectionID(context.Background(), auth0.NewClient(srv.URL, "tok"), tt.lookup)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, id)
		})
	}
}
