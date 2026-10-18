package auth0_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportPayloadAndResolveHooks(t *testing.T) {
	defer setFastPolling(t)()
	var mu sync.Mutex
	var payload []map[string]any
	var createdRoles, createdOrgs []string
	var assigned []string
	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-imports", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(10<<20))
		f, _, err := r.FormFile("users")
		require.NoError(t, err)
		b, _ := io.ReadAll(f)
		require.NoError(t, json.Unmarshal(b, &payload))
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "pending"})
	})
	mux.HandleFunc("/jobs/job_1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "completed"})
	})
	mux.HandleFunc("/jobs/job_1/errors", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "rol_existing", "name": "Admins"}})
			return
		}
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		createdRoles = append(createdRoles, body["name"])
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "rol_new"})
	})
	mux.HandleFunc("/organizations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]map[string]string{})
			return
		}
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		createdOrgs = append(createdOrgs, body["name"].(string))
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "org_new"})
	})
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		assigned = append(assigned, r.URL.Path)
		mu.Unlock()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		switch hook {
		case "import.payload":
			p := item["payload"].(map[string]any)
			p["app_metadata"] = map[string]any{"migrated": true}
			return map[string]any{"payload": p}
		case "role.resolve":
			if key == "r-admin" {
				return map[string]any{"id": "rol_chosen"}
			}
			return map[string]any{"name": "Support Team"}
		case "org.resolve":
			return map[string]any{"name": "acme-" + key}
		}
		return nil
	}, "")
	u := bcryptUser("u1")
	u.GlobalRoles = []string{"r-admin"}
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{
		"import.payload": {Handler: "h"}, "role.resolve": {Handler: "h"}, "org.resolve": {Handler: "h"},
	}}
	opts := connector.ImportOptions{
		ConnectionID:  "con_1",
		Roles:         []cmf.Role{{SourceID: "r-admin", Name: "Admins"}, {SourceID: "r-support", Name: "Support"}},
		Organizations: []cmf.Organization{{SourceID: "o1", Name: "acme"}},
	}
	report, err := auth0.New(auth0.NewClient(srv.URL, "t")).Import(hooks.WithDispatcher(context.Background(), d), writeUsers(t, []cmf.User{u}), m, opts)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"migrated": true}, payload[0]["app_metadata"])
	require.Equal(t, map[string]string{"r-admin": "rol_chosen", "r-support": "rol_new"}, report.RoleIDMap)
	require.Equal(t, []string{"Support Team"}, createdRoles, "a resolved name is matched, then created")
	require.Equal(t, []string{"acme-o1"}, createdOrgs)
	require.Equal(t, []string{"/users/auth0|u1/roles"}, assigned)
}

func TestConflicts(t *testing.T) {
	c := &auth0.Connector{}
	require.True(t, c.IsConflict(connector.ImportError{Code: auth0.DuplicatedUserCode}))
	require.False(t, c.IsConflict(connector.ImportError{Code: auth0.JobFailedCode}))
	require.True(t, c.Capabilities().SupportsUpsert)
}
