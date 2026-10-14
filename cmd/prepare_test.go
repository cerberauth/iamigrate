package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fixtures shared with the flatfile package tests: one directory per source
// layout, each with its own mapping.yaml.
const mappingCases = "../pkg/connector/flatfile/testdata/mappings"

func runRootCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestPrepareThenExportMatchesMappedExport(t *testing.T) {
	for _, c := range []struct{ name, input, format string }{
		{"csv-crm", "input.csv", "csv"},
		{"csv-salted-hex", "input.csv", "csv"},
		{"csv-combined-column", "input.csv", "csv"},
		{"csv-mixed-schemes", "input.csv", "csv"},
		{"json-digest-base64", "input.json", "json"},
		{"json-flat", "input.json", "json"},
		{"json-nested", "input.json", "json"},
		{"json-wrapped", "input.json", "json"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(mappingCases, c.name, c.input)
			mapping := filepath.Join(mappingCases, c.name, "mapping.yaml")
			prepared := filepath.Join(dir, "prepared.csv")

			stdout, _, err := runRootCmd(t, "prepare", "--in", in, "--format", c.format,
				"--mapping", mapping, "--out", prepared, "--out-format", "csv")
			require.NoError(t, err)
			require.Contains(t, stdout, "prepared ")

			_, _, err = runRootCmd(t, "export", "--source", "flatfile", "--in", prepared, "--out", filepath.Join(dir, "plain"), "--no-gzip")
			require.NoError(t, err)
			_, _, err = runRootCmd(t, "export", "--source", "flatfile", "--in", in, "--format", c.format,
				"--mapping", mapping, "--out", filepath.Join(dir, "mapped"), "--no-gzip")
			require.NoError(t, err)

			plain := readUsers(t, filepath.Join(dir, "plain", "users.cmf.jsonl"))
			mapped := readUsers(t, filepath.Join(dir, "mapped", "users.cmf.jsonl"))
			require.NotEmpty(t, mapped)
			require.Len(t, plain, len(mapped))
			for i := range mapped {
				plain[i].Provenance.ExportedAt = mapped[i].Provenance.ExportedAt
				require.Equal(t, mapped[i], plain[i])
			}
		})
	}
}

func TestPrepareWarnsAboutRecordsExportWouldSkip(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, err := runRootCmd(t, "prepare",
		"--in", filepath.Join(mappingCases, "csv-crm", "input.csv"),
		"--mapping", filepath.Join(mappingCases, "csv-crm", "mapping.yaml"),
		"--out", filepath.Join(dir, "users.csv"))
	require.NoError(t, err)
	require.Contains(t, stdout, "prepared 3 records")
	require.Contains(t, stderr, "1 records will be skipped by export")
	require.Contains(t, stderr, "record 3: missing source_id")
}

func TestPrepareRequiresMappingAndOut(t *testing.T) {
	_, _, err := runRootCmd(t, "prepare", "--in", "users.csv", "--out", "out.csv")
	require.ErrorContains(t, err, "mapping")
	_, _, err = runRootCmd(t, "prepare", "--in", "users.csv", "--mapping", "mapping.yaml")
	require.ErrorContains(t, err, "out")
}

func TestExportMappingOnlyForFlatfile(t *testing.T) {
	_, _, err := runRootCmd(t, "export", "--source", "kratos", "--mapping", "mapping.yaml", "--out", t.TempDir())
	require.ErrorContains(t, err, "--mapping only applies to --source flatfile")
}

// --mapping may point at the mapping.yaml an earlier export wrote into the
// output directory; re-exporting must not lose its fields.
func TestExportKeepsMappingFieldsInScaffold(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mapping.yaml")
	b, err := os.ReadFile(filepath.Join(mappingCases, "json-wrapped", "mapping.yaml"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mappingPath, b, 0o600))

	_, _, err = runRootCmd(t, "export", "--source", "flatfile", "--format", "json",
		"--in", filepath.Join(mappingCases, "json-wrapped", "input.json"),
		"--mapping", mappingPath, "--out", dir)
	require.NoError(t, err)

	after, err := os.ReadFile(mappingPath)
	require.NoError(t, err)
	require.Contains(t, string(after), "records_path: data.users")
	require.Contains(t, string(after), "source: login")
}
