package cmd

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector/sqlsource"
	"github.com/stretchr/testify/require"
)

func sqliteDB(t *testing.T, statements ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close()
	for _, s := range statements {
		_, err := db.Exec(s)
		require.NoError(t, err)
	}
	return path
}

func TestExportSQL(t *testing.T) {
	db := sqliteDB(t,
		"CREATE TABLE u (id TEXT, mail TEXT)", "INSERT INTO u VALUES ('u1', 'a@example.com')",
		"CREATE TABLE m (uid TEXT, org TEXT)", "INSERT INTO m VALUES ('u1', 'o1')",
	)
	dir := t.TempDir()
	queryFile := filepath.Join(dir, "users.sql")
	require.NoError(t, os.WriteFile(queryFile, []byte("SELECT id, mail FROM u"), 0o600))
	mappingFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(mappingFile, []byte("fields:\n  - {source: id, cmf: source_id}\n  - {source: mail, cmf: email}\n"), 0o600))

	t.Setenv(envSQLDSN, db)
	out := filepath.Join(dir, "out")
	stdout, _, err := runRootCmd(t, "export", "--source", "sql", "--driver", "sqlite",
		"--query", "@"+queryFile, "--memberships-query", "SELECT uid AS user_id, org AS organization FROM m",
		"--mapping", mappingFile, "--out", out)
	require.NoError(t, err)
	require.Contains(t, stdout, "exported 1 users")
	for _, f := range []string{"users.cmf.jsonl.gz", "organizations.cmf.jsonl", "roles.cmf.jsonl", "mapping.yaml"} {
		_, err := os.Stat(filepath.Join(out, f))
		require.NoError(t, err, f)
	}
}

func TestExportSQLFlagErrors(t *testing.T) {
	db := sqliteDB(t)
	t.Setenv(envSQLDSN, "")
	for name, c := range map[string]struct {
		args []string
		err  string
	}{
		"no driver":       {[]string{"--source", "sql", "--dsn", db, "--query", "SELECT 1"}, "--driver: sql: a driver is required"},
		"no dsn":          {[]string{"--source", "sql", "--driver", "sqlite", "--query", "SELECT 1"}, "a DSN is required: --dsn, --dsn-file or $SQL_DSN"},
		"both dsn":        {[]string{"--source", "sql", "--driver", "sqlite", "--dsn", db, "--dsn-file", db, "--query", "SELECT 1"}, "mutually exclusive"},
		"no query":        {[]string{"--source", "sql", "--driver", "sqlite", "--dsn", db}, "--query is required"},
		"missing file":    {[]string{"--source", "sql", "--driver", "sqlite", "--dsn", db, "--query", "@nope.sql"}, "--query:"},
		"other source":    {[]string{"--source", "kratos", "--driver", "sqlite"}, "only apply to --source sql"},
		"mapping for sql": {[]string{"--source", "kratos", "--mapping", "m.yaml"}, "--mapping only applies to --source flatfile and sql"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runRootCmd(t, append([]string{"export", "--out", t.TempDir()}, c.args...)...)
			require.ErrorContains(t, err, c.err)
		})
	}
}

func TestDSNFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "dsn")
	require.NoError(t, os.WriteFile(f, []byte("file:app.db\n"), 0o600))
	dsn, err := resolveDSN("", f)
	require.NoError(t, err)
	require.Equal(t, "file:app.db", dsn)
}

func TestJobSourceSQL(t *testing.T) {
	db := sqliteDB(t)
	t.Setenv(envSQLDSN, db)
	src, opts, err := jobSource(&jobs.Job{Params: map[string]string{
		jobs.ParamSource: sqlsource.Name, paramDriver: "sqlite", paramQuery: "SELECT 1 AS source_id",
	}})
	require.NoError(t, err)
	require.Equal(t, sqlsource.Name, src.Name())
	o := opts.(sqlsource.ExportOptions)
	require.Equal(t, db, o.DSN)
	require.Equal(t, "SELECT 1 AS source_id", o.Query)

	_, _, err = jobSource(&jobs.Job{Params: map[string]string{jobs.ParamSource: sqlsource.Name, paramQuery: "SELECT 1"}})
	require.ErrorContains(t, err, "a driver is required")
}
