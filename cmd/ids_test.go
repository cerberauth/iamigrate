package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIDsAssignThenValidate(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runRootCmd(t, "testdata", "generate", "--count", "3", "--hash", "bcrypt:cost=4", "--out", dir)
	require.NoError(t, err)
	in := filepath.Join(dir, "users.cmf.jsonl.gz")
	m := filepath.Join(dir, "mapping.yaml")
	require.NoError(t, os.WriteFile(m, []byte("target: firebase\nids:\n  target: {strategy: uuidv5, namespace: 6ba7b811-9dad-11d1-80b4-00c04fd430c8}\n"), 0o600))

	_, _, err = runRootCmd(t, "validate", "--in", in, "--target", "firebase", "--mapping", m)
	require.ErrorContains(t, err, "3 problem(s)", "IDs not assigned yet")

	out := filepath.Join(dir, "assigned.cmf.jsonl.gz")
	stdout, _, err := runRootCmd(t, "ids", "assign", "--in", in, "--out", out, "--mapping", m, "--target", "firebase")
	require.NoError(t, err)
	require.Contains(t, stdout, "assigned firebase IDs to 3 users")
	_, _, err = runRootCmd(t, "validate", "--in", out, "--target", "firebase", "--mapping", m)
	require.NoError(t, err)

	_, _, err = runRootCmd(t, "ids", "assign", "--in", in, "--out", out, "--mapping", m, "--target", "kratos")
	require.ErrorContains(t, err, "kratos generates its own user IDs")
	_, _, err = runRootCmd(t, "ids", "assign", "--in", in, "--out", in, "--mapping", m, "--target", "firebase")
	require.ErrorContains(t, err, "--out must differ from --in")
}

func TestJobHooksCantBeUsedWithAPIURL(t *testing.T) {
	_, _, err := runRootCmd(t, "job", "--api-url", "http://127.0.0.1:1", "--hooks", "hooks.yaml", "status", "x")
	require.ErrorContains(t, err, "--hooks can't be used with --api-url")
}
