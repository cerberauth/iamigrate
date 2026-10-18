package kratos_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportAppliesTargetFields(t *testing.T) {
	var created map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&created))
		created["id"] = "id-1"
		_ = json.NewEncoder(w).Encode(created)
	}))
	defer server.Close()

	u := bcryptUser("u1")
	u.Profile.Locale = "FR"
	u.AppMetadata = map[string]any{"plan": "pro"}
	m := mapping.Mapping{TargetFields: []mapping.TargetField{
		{CMF: "profile.locale", Target: "traits.locale", Transform: "lowercase"},
		{CMF: "app_metadata.plan", Target: "metadata_admin.plan"},
		{CMF: "source_id", Target: "metadata_public.legacy_id"},
	}}
	_, err := kratos.New(kratos.NewClient(server.URL), "default").Import(context.Background(), writeUsers(t, []cmf.User{u}), m, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, "fr", created["traits"].(map[string]any)["locale"])
	require.Equal(t, "u1@example.com", created["traits"].(map[string]any)["email"])
	require.Equal(t, map[string]any{"plan": "pro"}, created["metadata_admin"])
	require.Equal(t, map[string]any{"legacy_id": "u1"}, created["metadata_public"])
}

func TestCheckTargetField(t *testing.T) {
	c := &kratos.Connector{}
	require.NoError(t, c.CheckTargetField("traits.locale"))
	require.ErrorContains(t, c.CheckTargetField("traits.email"), "identifier trait")
	require.ErrorContains(t, c.CheckTargetField("state"), "kratos can't set")
	_, err := kratos.New(kratos.NewClient("http://127.0.0.1:1"), "default").Import(context.Background(), writeUsers(t, nil),
		mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "username", Target: "traits.username"}}}, connector.ImportOptions{})
	require.ErrorContains(t, err, "identifier trait", "checked before any user is sent")
}
