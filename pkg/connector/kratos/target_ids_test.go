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

func TestImportRecordsTheGeneratedIdentityID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.NotContains(t, body, "id", "Kratos rejects an id in a new identity")
		body["id"] = "kratos-" + body["traits"].(map[string]any)["email"].(string)
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	report, err := kratos.New(kratos.NewClient(server.URL), "default").Import(context.Background(),
		writeUsers(t, []cmf.User{bcryptUser("u1")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"u1": "kratos-u1@example.com"}, report.TargetIDs)
	require.False(t, (&kratos.Connector{}).Capabilities().SupportsCustomID)
}
