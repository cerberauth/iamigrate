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

func TestImportRecordsTheGeneratedUserID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", tokenHandler(t))
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://"+r.Host+"/admin/realms/acme/users/f2d85f54-887a-40c7-8161-abd69fc7d832")
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	report, err := keycloak.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{pbkdf2User(t, "u1")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"u1": "f2d85f54-887a-40c7-8161-abd69fc7d832"}, report.TargetIDs)
	require.False(t, (&keycloak.Connector{}).Capabilities().SupportsCustomID)
}
