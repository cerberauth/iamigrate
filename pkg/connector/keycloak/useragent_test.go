package keycloak_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportSetsUserAgentOnTokenAndAdminAPIRequests(t *testing.T) {
	var tokenUA, usersUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenUA = r.Header.Get("User-Agent")
		tokenHandler(t)(w, r)
	})
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		usersUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	target := keycloak.New(newTestClient(server.URL))
	users := []cmf.User{pbkdf2User(t, "u1")}
	_, err := target.Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	require.Regexp(t, `^iamigrate/\S+ \(\+https://github\.com/cerberauth/iamigrate\)$`, tokenUA)
	require.Regexp(t, `^iamigrate/\S+ \(\+https://github\.com/cerberauth/iamigrate\)$`, usersUA)
}
