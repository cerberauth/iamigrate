package flatfile_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestCSVExportSimpleCaseNoMappingEdits(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "users.csv")
	require.NoError(t, os.WriteFile(csvPath, []byte(
		"source_id,email,given_name,family_name,password,password_algorithm\n"+
			"u1,jane@example.com,Jane,Doe,$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW,bcrypt\n",
	), 0o644))

	opts := flatfile.ExportOptions{Path: csvPath, Format: flatfile.FormatCSV}
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := flatfile.New().Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 1, manifest.RecordCount)

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	u, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "u1", u.SourceID)
	require.Equal(t, "jane@example.com", u.Emails[0].Value)
	require.Equal(t, cmf.AlgBcrypt, u.Password.Algorithm)
}

func TestCSVExportFlagsCustomAppMetadata(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "users.csv")
	require.NoError(t, os.WriteFile(csvPath, []byte(
		"source_id,email,custom_tier,custom_region\n"+
			"u1,jane@example.com,gold,eu\n",
	), 0o644))

	opts := flatfile.ExportOptions{Path: csvPath, Format: flatfile.FormatCSV}
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := flatfile.New().Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	u, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "gold", u.AppMetadata["custom_tier"])
	require.Equal(t, "eu", u.AppMetadata["custom_region"])
}

func TestImportWritesFlatFile(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	require.NoError(t, w.WriteUser(cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   "u1",
		Profile:    cmf.Profile{GivenName: "Jane"},
		Provenance: cmf.Provenance{SourceConnector: "test"},
	}))
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	outPath := filepath.Join(dir, "out.json")
	target := flatfile.NewTarget(outPath, flatfile.FormatJSON)
	report, err := target.Import(context.Background(), r, mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, report.Succeeded)

	b, err := os.ReadFile(outPath)
	require.NoError(t, err)
	require.Contains(t, string(b), "u1")

	_, err = io.ReadAll(bytes.NewReader(b))
	require.NoError(t, err)
}
