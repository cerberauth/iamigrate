package kratos_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/stretchr/testify/require"
)

// fakeIdentities serves lookup, get and delete for identities by ID, with
// byIdentifier giving the IDs each credentials_identifier finds.
func fakeIdentities(t *testing.T, byIdentifier map[string][]string, ids ...string) (*httptest.Server, *[]string) {
	t.Helper()
	live := map[string]bool{}
	for _, id := range ids {
		live[id] = true
	}
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		var found []map[string]any
		for _, id := range byIdentifier[r.URL.Query().Get("credentials_identifier")] {
			found = append(found, map[string]any{"id": id, "state": "active"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(found)
	})
	mux.HandleFunc("/admin/identities/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/admin/identities/")
		if !live[id] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404}}`))
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "state": "active"})
		case http.MethodDelete:
			delete(live, id)
			deleted = append(deleted, id)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &deleted
}

func TestDeleteUsers(t *testing.T) {
	server, deleted := fakeIdentities(t, map[string][]string{
		"u2@example.com": {"id-2"},
		"u4@example.com": {"id-4a", "id-4b"},
	}, "id-1", "id-2", "id-4a", "id-4b")

	none := bcryptUser("u5")
	none.Emails = nil
	reqs := []connector.DeleteRequest{
		{User: bcryptUser("u1"), TargetID: "id-1"},
		{User: bcryptUser("u2")},
		{User: bcryptUser("u3")},
		{User: bcryptUser("u4")},
		{User: none},
		{User: bcryptUser("u6"), TargetID: "gone"},
	}
	report, err := kratos.New(kratos.NewClient(server.URL), "").DeleteUsers(context.Background(), reqs, false)
	require.NoError(t, err)

	require.Equal(t, []connector.DeletedUser{{SourceID: "u1", TargetID: "id-1"}, {SourceID: "u2", TargetID: "id-2"}}, report.Deleted)
	require.Equal(t, []string{"u3", "u6"}, report.NotFound)
	require.Equal(t, []string{"u5"}, report.NoIdentifier)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "u4", report.Failed[0].SourceID, "an identifier matching several identities deletes none")
	require.Equal(t, []string{"id-1", "id-2"}, *deleted)
}

func TestDeleteUsersDryRun(t *testing.T) {
	server, deleted := fakeIdentities(t, map[string][]string{"u1@example.com": {"id-1"}}, "id-1")

	report, err := kratos.New(kratos.NewClient(server.URL), "").
		DeleteUsers(context.Background(), []connector.DeleteRequest{{User: bcryptUser("u1")}, {User: cmf.User{SourceID: "u2", Username: "nobody"}}}, true)
	require.NoError(t, err)
	require.True(t, report.DryRun)
	require.Equal(t, []connector.DeletedUser{{SourceID: "u1", TargetID: "id-1"}}, report.Deleted)
	require.Equal(t, []string{"u2"}, report.NotFound)
	require.Empty(t, *deleted)
}
