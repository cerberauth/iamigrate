package jobs_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

// customIDTarget is a fakeTarget that accepts chosen user IDs.
type customIDTarget struct{ fakeTarget }

func (*customIDTarget) Capabilities() connector.Capabilities {
	return connector.Capabilities{HashAlgorithms: []cmf.Algorithm{cmf.AlgBcrypt}, SupportsCustomID: true}
}

func writeMapping(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "mapping.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func readTargetIDs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := cmf.NewReader(f)
	require.NoError(t, err)
	out := map[string]string{}
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		out[u.SourceID] = u.TargetIDs["fake"]
	}
}

func TestExportAssignsTargetIDs(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.cmf.jsonl.gz")
	src := &fakeSource{users: fakeUsers(3)}
	tgt := &customIDTarget{fakeTarget{chunkSize: 10}}
	r, _ := newRunner(t, jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) { return src, nil, nil },
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
	}))
	j, err := r.Create(map[string]string{
		jobs.ParamSource: "fake", jobs.ParamUsers: users,
		jobs.ParamMapping: writeMapping(t, dir, "target: fake\nids:\n  target: {strategy: prefix, prefix: 'legacy-'}\n"),
	})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State, j.Error)
	require.Equal(t, 3, j.Manifest.RecordCount)
	require.Equal(t, map[string]string{"u0": "legacy-u0", "u1": "legacy-u1", "u2": "legacy-u2"}, readTargetIDs(t, users))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "no temporary file left behind: %v", entries)
}

func TestValidateRequiresAssignedIDsForAJobWithoutExport(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.cmf.jsonl")
	writeUsersFile(t, users, fakeUsers(2))
	tgt := &customIDTarget{fakeTarget{chunkSize: 10}}
	r, _ := newRunner(t, jobs.NewSteps(jobs.Connectors{
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
	}))
	j, err := r.Create(map[string]string{
		jobs.ParamUsers:   users,
		jobs.ParamMapping: writeMapping(t, dir, "target: fake\nids:\n  target: {strategy: prefix, prefix: p}\n"),
	})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Validating, j.FailedIn)
	require.Len(t, j.Problems, 2)
	require.Equal(t, "target_ids.fake", j.Problems[0].Field)
}

func TestExportFailsOnAnIDHandlerFailureAndRecordsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv("JOBS_TEST_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {ids: {webhook: {url: '" + srv.URL + "', secret_env: JOBS_TEST_SECRET}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)

	dir := t.TempDir()
	users := filepath.Join(dir, "users.cmf.jsonl")
	src := &fakeSource{users: fakeUsers(2)}
	tgt := &customIDTarget{fakeTarget{chunkSize: 10}}
	r, _ := newRunner(t, jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) { return src, nil, nil },
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
	}))
	r.Hooks = d
	j, err := r.Create(map[string]string{
		jobs.ParamSource: "fake", jobs.ParamUsers: users,
		jobs.ParamMapping: writeMapping(t, dir, "target: fake\nids:\n  target: {handler: ids}\n"),
	})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Exporting, j.FailedIn)
	require.Contains(t, j.Error, "webhook answered 400")
	require.Len(t, j.Hooks, 1)
	require.Equal(t, hooks.Result{
		Hook: "id.target", EventID: hooks.EventID(j.ID, "id.target", "exporting", 1),
		State: "exporting", Outcome: hooks.Failed, Reason: "webhook answered 400: nope", At: j.Hooks[0].At,
	}, j.Hooks[0])
	_, err = os.Stat(users)
	require.ErrorIs(t, err, os.ErrNotExist, "no users file for a failed export")
}

func writeUsersFile(t *testing.T, path string, users []cmf.User) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := cmf.NewPlainWriter(f)
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
}
