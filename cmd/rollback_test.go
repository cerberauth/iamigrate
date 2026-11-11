package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func writeCMF(t *testing.T, path string, ids ...string) {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, id := range ids {
		require.NoError(t, w.WriteUser(cmf.User{CMFVersion: cmf.Version, SourceID: id, Emails: []cmf.Contact{{Value: id + "@example.com"}}}))
	}
	require.NoError(t, w.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

func TestRollbackRequestsKeepOnlyTheImportsSucceededUsers(t *testing.T) {
	in := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	writeCMF(t, in, "u1", "u2", "u3")

	all, err := rollbackRequests(in, nil)
	require.NoError(t, err)
	require.Len(t, all, 3)

	reqs, err := rollbackRequests(in, &connector.ImportReport{
		Succeeded: []string{"u1", "u3", "not-in-file"},
		TargetIDs: map[string]string{"u1": "id-1"},
	})
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	require.Equal(t, "u1", reqs[0].User.SourceID)
	require.Equal(t, "id-1", reqs[0].TargetID)
	require.Equal(t, "u3", reqs[1].User.SourceID)
	require.Empty(t, reqs[1].TargetID)
}

func TestAskConfirmationNeedsYes(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, askConfirmation(strings.NewReader("yes\n"), &out, 3, "kratos"))
	require.Contains(t, out.String(), "Delete up to 3 users from kratos?")
	require.ErrorIs(t, askConfirmation(strings.NewReader("y\n"), &out, 3, "kratos"), errNotConfirmed)
	require.ErrorIs(t, askConfirmation(strings.NewReader(""), &out, 3, "kratos"), errNotConfirmed)
}

// TestRollbackKratosCommand runs `rollback kratos` against a fake Admin
// API: it refuses without --yes when not interactive, and with --yes
// deletes the report's users by their target IDs.
func TestRollbackKratosCommand(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/admin/identities/")
		if r.Method == http.MethodDelete {
			deleted = append(deleted, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
	}))
	defer server.Close()

	dir := t.TempDir()
	in := filepath.Join(dir, "users.cmf.jsonl")
	writeCMF(t, in, "u1", "u2")
	report, err := json.Marshal(connector.ImportReport{Succeeded: []string{"u2"}, TargetIDs: map[string]string{"u2": "id-2"}})
	require.NoError(t, err)
	reportPath := filepath.Join(dir, "import-report.json")
	require.NoError(t, os.WriteFile(reportPath, report, 0o600))

	args := []string{"rollback", "kratos", "--sqa-opt-out", "--in", in, "--report", reportPath, "--admin-url", server.URL}
	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(strings.NewReader("yes\n"))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	require.ErrorContains(t, root.Execute(), "pass --yes")
	require.Empty(t, deleted)

	root = newRootCmd()
	root.SetArgs(append(args, "--yes"))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	require.NoError(t, root.Execute())
	require.Equal(t, []string{"id-2"}, deleted)
	require.Contains(t, out.String(), "rollback: deleted 1, not found 0, failed 0")

	b, err := os.ReadFile(filepath.Join(dir, "rollback-report.json"))
	require.NoError(t, err)
	var got connector.RollbackReport
	require.NoError(t, json.Unmarshal(b, &got))
	require.Equal(t, []connector.DeletedUser{{SourceID: "u2", TargetID: "id-2"}}, got.Deleted)
}
