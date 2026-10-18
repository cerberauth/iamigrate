package keycloak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportAppliesTargetFields(t *testing.T) {
	var created map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", tokenHandler(t))
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&created))
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	u := pbkdf2User(t, "u1")
	u.AppMetadata = map[string]any{"seats": 3.0}
	m := mapping.Mapping{TargetFields: []mapping.TargetField{
		{CMF: "source_id", Target: "attributes.legacy_id"},
		{CMF: "app_metadata.seats", Target: "attributes.seats"},
		{CMF: "emails.0.value", Target: "firstName", Transform: "uppercase"},
	}}
	_, err := keycloak.New(newTestClient(server.URL)).Import(context.Background(), writeUsers(t, []cmf.User{u}), m, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, []any{"u1"}, created["attributes"].(map[string]any)["legacy_id"])
	require.Equal(t, []any{"3"}, created["attributes"].(map[string]any)["seats"])
	require.Equal(t, "U1@EXAMPLE.COM", created["firstName"])
	require.ErrorContains(t, (&keycloak.Connector{}).CheckTargetField("username"), "keycloak can't set")
}
