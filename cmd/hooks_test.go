package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateFiresValidateAfter(t *testing.T) {
	var got []string
	answer := `{"fail": true}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(b, &env))
		got = append(got, env["hook"].(string))
		require.Equal(t, "", env["job_id"], "a standalone command runs no job")
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	t.Setenv("CMD_HOOK_SECRET", "s")

	dir := t.TempDir()
	_, _, err := runRootCmd(t, "testdata", "generate", "--count", "2", "--hash", "bcrypt:cost=4", "--out", dir)
	require.NoError(t, err)
	hooksPath := filepath.Join(dir, "hooks.yaml")
	require.NoError(t, os.WriteFile(hooksPath, []byte("version: 1\nhandlers: {rx: {webhook: {url: '"+srv.URL+"', secret_env: CMD_HOOK_SECRET}}}\nevents: {validate.after: {handler: rx}}\n"), 0o600))
	in := filepath.Join(dir, "users.cmf.jsonl.gz")

	_, _, err = runRootCmd(t, "validate", "--in", in, "--target", "kratos")
	require.NoError(t, err)
	require.Empty(t, got, "no --hooks, no call")

	_, _, err = runRootCmd(t, "validate", "--in", in, "--target", "kratos", "--hooks", hooksPath)
	require.ErrorContains(t, err, "validate failed: the validate.after hook failed it")
	require.Equal(t, []string{"validate.after"}, got)

	answer = `{}`
	_, _, err = runRootCmd(t, "validate", "--in", in, "--target", "kratos", "--hooks", hooksPath)
	require.NoError(t, err)
}

func TestHooksFileErrorsStopTheCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\nhandlers: {rx: {webhook: {url: 'http://x', secret_env: CMD_HOOK_UNSET}}}\n"), 0o600))
	_, _, err := runRootCmd(t, "import", "kratos", "--in", "x", "--hooks", path)
	require.ErrorContains(t, err, "$CMD_HOOK_UNSET is not set")
}

func TestValidateChecksTargetFields(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runRootCmd(t, "testdata", "generate", "--count", "1", "--hash", "bcrypt:cost=4", "--out", dir)
	require.NoError(t, err)
	m := filepath.Join(dir, "mapping.yaml")
	require.NoError(t, os.WriteFile(m, []byte("target: kratos\ntarget_fields:\n  - {cmf: username, target: traits.email}\n"), 0o600))
	_, _, err = runRootCmd(t, "validate", "--in", filepath.Join(dir, "users.cmf.jsonl.gz"), "--target", "kratos", "--mapping", m)
	require.ErrorContains(t, err, "traits.email is an identifier trait")

	require.NoError(t, os.WriteFile(m, []byte("target: kratos\ntarget_fields:\n  - {cmf: profile.locale, target: traits.locale, transform: my_fn}\n"), 0o600))
	_, _, err = runRootCmd(t, "validate", "--in", filepath.Join(dir, "users.cmf.jsonl.gz"), "--target", "kratos", "--mapping", m)
	require.ErrorContains(t, err, `unknown transform "my_fn"`)
}

func TestDiffReadsVerifyOptions(t *testing.T) {
	_, _, err := runRootCmd(t, "diff", "kratos", "--in", "x", "--admin-url", "http://127.0.0.1:1", "--report", filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	m := filepath.Join(t.TempDir(), "mapping.yaml")
	require.NoError(t, os.WriteFile(m, []byte("strategies:\n  verify.lookup: {strategy: by_magic}\n"), 0o600))
	dir := t.TempDir()
	_, _, err = runRootCmd(t, "testdata", "generate", "--count", "1", "--hash", "bcrypt:cost=4", "--out", dir)
	require.NoError(t, err)
	_, _, err = runRootCmd(t, "diff", "kratos", "--in", filepath.Join(dir, "users.cmf.jsonl.gz"), "--admin-url", "http://127.0.0.1:1", "--mapping", m)
	require.ErrorContains(t, err, `verify.lookup: unknown strategy "by_magic"`)
}
