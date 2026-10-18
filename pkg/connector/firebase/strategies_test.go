package firebase_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportPayloadAndConflicts(t *testing.T) {
	rec := &batchRecorder{reject: map[string]string{"dup": "DUPLICATE_LOCAL_ID : exists"}}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		p := item["payload"].(map[string]any)
		p["displayName"] = "from hook " + key
		return map[string]any{"payload": p}
	}, "")
	m := mapping.Mapping{
		Strategies: map[string]mapping.StrategyRef{"import.payload": {Handler: "h"}},
		Conflict:   &mapping.Conflict{OnDuplicate: "skip"},
	}
	c := firebase.New(newTestClient(server.URL))
	report, err := c.Import(hooks.WithDispatcher(context.Background(), d), writeUsers(t, []cmf.User{bcryptUser("u1"), bcryptUser("dup")}), m, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, "from hook u1", rec.requests[0]["users"].([]any)[0].(map[string]any)["displayName"])
	require.True(t, c.IsConflict(report.Failed[0]))
	require.True(t, c.IsConflict(connector.ImportError{Code: "IMPORT_ERROR", Message: "localId belongs to an existing account - can not overwrite."}))
	require.False(t, c.IsConflict(connector.ImportError{Code: "INVALID_EMAIL"}))
}
