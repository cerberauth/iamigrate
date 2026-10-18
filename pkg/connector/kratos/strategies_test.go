package kratos_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/stretchr/testify/require"
)

func TestImportStrategies(t *testing.T) {
	var created []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		created = append(created, body)
		if body["traits"].(map[string]any)["email"] == "dup@example.com" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"message":"conflict"}}`))
			return
		}
		body["id"] = "id-" + body["traits"].(map[string]any)["email"].(string)
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		switch hook {
		case "import.user":
			if key == "skip" {
				return map[string]any{"action": "drop", "reason": "bot"}
			}
			return map[string]any{}
		case "import.payload":
			p := item["payload"].(map[string]any)
			p["external_id"] = key
			return map[string]any{"payload": p}
		}
		return nil
	}, "")
	dup := bcryptUser("dup")
	dup.Emails = []cmf.Contact{{Value: "dup@example.com"}}
	m := mapping.Mapping{
		Strategies: map[string]mapping.StrategyRef{"import.user": {Handler: "h"}, "import.payload": {Handler: "h"}},
		Conflict:   &mapping.Conflict{OnDuplicate: "skip"},
	}
	c := kratos.New(kratos.NewClient(server.URL), "default")
	report, err := c.Import(hooks.WithDispatcher(context.Background(), d),
		writeUsers(t, []cmf.User{bcryptUser("u1"), bcryptUser("skip"), dup}), m, connector.ImportOptions{})
	require.NoError(t, err)

	require.Len(t, created, 2, "the skipped user is never sent")
	require.Equal(t, "u1", created[0]["external_id"], "the import.payload answer is what is sent")
	require.Equal(t, 1, rc.Calls("import.payload"), "one call for the batch")
	require.Equal(t, []string{"u1"}, report.Succeeded)
	require.Len(t, report.Skipped, 1)
	require.Equal(t, "skip", report.Skipped[0].SourceID)
	require.True(t, c.IsConflict(report.Failed[0]), "Kratos' 409 is a conflict")
}

func TestVerifyByTargetID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities/id-1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "id-1", "state": "active", "traits": map[string]any{}})
	})
	mux.HandleFunc("/admin/identities/id-gone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	u2 := bcryptUser("u2")
	u2.Emails = []cmf.Contact{{Value: "u2@example.com"}}
	ctx := reconcile.WithOptions(context.Background(), reconcile.Options{
		Mapping:   mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Strategy: "target_id"}}},
		TargetIDs: map[string]string{"u1": "id-1", "u2": "id-gone"},
	})
	report, err := kratos.New(kratos.NewClient(server.URL), "").Verify(ctx, writeUsers(t, []cmf.User{bcryptUser("u1"), u2}))
	require.NoError(t, err)
	require.Equal(t, 1, report.TargetCount)
	require.Equal(t, []string{"u2"}, report.MissingInTarget)
}
