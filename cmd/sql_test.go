package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestSQLExportOptionsRequireADriver(t *testing.T) {
	t.Setenv(envSQLDSN, "")
	_, err := sqlExportOptions("", "dsn", "SELECT 1", mapping.Mapping{})
	require.ErrorContains(t, err, "--driver is required")
	require.ErrorContains(t, err, "sqlserver", "the engines there are are listed")

	_, err = sqlExportOptions("oracle", "dsn", "SELECT 1", mapping.Mapping{})
	require.ErrorContains(t, err, `unknown --driver "oracle"`)
}

func TestSQLExportOptionsReadTheDSNFromTheEnvironment(t *testing.T) {
	t.Setenv(envSQLDSN, "from-env")
	o, err := sqlExportOptions("sqlite", "", "SELECT 1", mapping.Mapping{})
	require.NoError(t, err)
	require.Equal(t, "from-env", o.DSN)

	o, err = sqlExportOptions("sqlite", "from-flag", "SELECT 1", mapping.Mapping{})
	require.NoError(t, err)
	require.Equal(t, "from-flag", o.DSN, "the flag wins")

	t.Setenv(envSQLDSN, "")
	_, err = sqlExportOptions("sqlite", "", "SELECT 1", mapping.Mapping{})
	require.ErrorContains(t, err, envSQLDSN)
}

func TestSQLExportOptionsReadTheQueryFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.sql")
	require.NoError(t, os.WriteFile(path, []byte("SELECT id AS source_id FROM users"), 0o600))
	o, err := sqlExportOptions("sqlite", "dsn", "@"+path, mapping.Mapping{})
	require.NoError(t, err)
	require.Equal(t, "SELECT id AS source_id FROM users", o.Query)

	_, err = sqlExportOptions("sqlite", "dsn", "@"+filepath.Join(t.TempDir(), "missing.sql"), mapping.Mapping{})
	require.ErrorContains(t, err, "reading --query file")

	_, err = sqlExportOptions("sqlite", "dsn", "", mapping.Mapping{})
	require.ErrorContains(t, err, "--query is required")
}
