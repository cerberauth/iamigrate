package sqlsource_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/sqlsource"
	_ "github.com/cerberauth/iamigrate/pkg/connector/sqlsource/sqlite"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// newDB creates a SQLite database file with schema run in it, and returns
// its path.
func newDB(t *testing.T, statements ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close()
	for _, s := range statements {
		_, err := db.Exec(s)
		require.NoError(t, err, s)
	}
	return path
}

func export(t *testing.T, opts sqlsource.ExportOptions) (connector.Manifest, []cmf.User, *sqlsource.Connector) {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	c := sqlsource.New()
	m, err := c.Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return m, users, c
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

const appSchema = `CREATE TABLE accounts (
	id INTEGER PRIMARY KEY, mail TEXT, first_name TEXT, active INTEGER,
	pw_hash BLOB, pw_salt BLOB, created_at TEXT)`

func TestExportMapsRowsAndBinaryColumns(t *testing.T) {
	// sha256(salt || "password"), the salt and the digest stored as bytes.
	path := newDB(t, appSchema,
		`INSERT INTO accounts VALUES (1, 'Jane@Example.com', 'Jane', 1,
			X'c3d1f0e8ea1e9ec8d2ca1d10a4fdb7ee8e7cf88d38b42bc7e3b33e8e1fc2a3d5', X'0011223344', '2024-01-02')`,
		`INSERT INTO accounts VALUES (2, 'john@example.com', NULL, 0, NULL, NULL, NULL)`,
	)
	m, users, _ := export(t, sqlsource.ExportOptions{
		Driver: "sqlite", DSN: path,
		Query: "SELECT id, mail, first_name, active, pw_hash, pw_salt, 'sha256' AS alg FROM accounts ORDER BY id",
		Mapping: mapping.Mapping{Fields: []mapping.FieldMapping{
			{Source: "id", CMF: "source_id"},
			{Source: "mail", CMF: "email", Transform: "lowercase"},
			{Source: "first_name", CMF: "given_name"},
			{Source: "active", CMF: "blocked", Transform: "not"},
			{Source: "pw_hash", CMF: "password"},
			{Source: "alg", CMF: "password_algorithm"},
			{CMF: "password_encoding", Default: "hex"},
			{Source: "pw_salt", CMF: "password_salt"},
			{CMF: "password_salt_encoding", Default: "hex"},
			{CMF: "password_salt_position", Default: "prefix"},
		}},
	})
	require.Equal(t, 2, m.RecordCount, m.SkippedRecords)
	require.Equal(t, "1", users[0].SourceID)
	require.Equal(t, "jane@example.com", users[0].Emails[0].Value)
	require.Equal(t, "Jane", users[0].Profile.GivenName)
	require.False(t, users[0].Blocked)
	require.True(t, users[1].Blocked)
	require.Equal(t, sqlsource.Name, users[0].Provenance.SourceConnector)

	pw := users[0].Password
	require.NotNil(t, pw)
	require.Equal(t, cmf.AlgSHA256, pw.Algorithm)
	require.Equal(t, cmf.EncodingHex, pw.Hash.Encoding)
	require.Equal(t, "c3d1f0e8ea1e9ec8d2ca1d10a4fdb7ee8e7cf88d38b42bc7e3b33e8e1fc2a3d5", pw.Hash.Value)
	require.Equal(t, "ABEiM0Q=", pw.Salt.Value, "the salt's bytes, re-encoded")
	require.Equal(t, cmf.SaltPrefix, pw.Salt.Position)
	require.Nil(t, users[1].Password)
}

func TestExportStreamsPastOneBatch(t *testing.T) {
	n := sqlsource.BatchSize*2 + 7
	path := newDB(t, "CREATE TABLE u (id INTEGER PRIMARY KEY, email TEXT)",
		fmt.Sprintf(`WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < %d)
			INSERT INTO u SELECT i, 'user' || i || '@example.com' FROM s`, n))
	m, users, _ := export(t, sqlsource.ExportOptions{
		Driver: "sqlite", DSN: path,
		Query: "SELECT id AS source_id, email FROM u ORDER BY id",
	})
	require.Equal(t, n, m.RecordCount)
	require.Len(t, users, n)
	require.Equal(t, fmt.Sprint(n), users[n-1].SourceID)
}

func TestExportMemberships(t *testing.T) {
	path := newDB(t,
		"CREATE TABLE u (id TEXT, email TEXT)",
		"INSERT INTO u VALUES ('u1', 'a@example.com'), ('u2', 'b@example.com')",
		"CREATE TABLE teams (id TEXT, slug TEXT)",
		"INSERT INTO teams VALUES ('t1', 'acme')",
		"CREATE TABLE grants (member TEXT, team TEXT, perm TEXT)",
		"INSERT INTO grants VALUES ('u1', 't1', 'admin'), ('u2', 't1', NULL), ('u2', NULL, 'auditor'), ('gone', 't1', 'admin')",
	)
	m, users, c := export(t, sqlsource.ExportOptions{
		Driver: "sqlite", DSN: path,
		Query:              "SELECT id AS source_id, email FROM u ORDER BY id",
		OrganizationsQuery: "SELECT id AS source_id, slug AS name FROM teams",
		RolesQuery:         "SELECT DISTINCT perm AS source_id FROM grants WHERE perm IS NOT NULL",
		MembershipsQuery:   "SELECT member, team, perm FROM grants",
		Mapping: mapping.Mapping{Memberships: &mapping.RecordMapping{Fields: []mapping.FieldMapping{
			{Source: "member", CMF: "user_id"}, {Source: "team", CMF: "organization"}, {Source: "perm", CMF: "role"},
		}}},
	})
	require.Equal(t, []connector.SkippedRecord{{SourceID: "gone", Reason: "memberships name a user that isn't exported"}}, m.SkippedRecords)
	require.Equal(t, []cmf.Membership{{Organization: "t1", Roles: []string{"admin"}}}, users[0].Memberships)
	require.Equal(t, []cmf.Membership{{Organization: "t1"}}, users[1].Memberships)
	require.Equal(t, []string{"auditor"}, users[1].GlobalRoles)

	d := c.Directory()
	require.Equal(t, []cmf.Organization{{SourceID: "t1", Name: "acme"}}, d.Organizations)
	require.ElementsMatch(t, []cmf.Role{{SourceID: "admin", Name: "admin"}, {SourceID: "auditor", Name: "auditor"}}, d.Roles)
}

func TestExportIsReadOnly(t *testing.T) {
	path := newDB(t, "CREATE TABLE u (id TEXT)", "INSERT INTO u VALUES ('u1')")
	_, err := sqlsource.New().Export(context.Background(), cmf.NewPlainWriter(io.Discard), sqlsource.ExportOptions{
		Driver: "sqlite", DSN: path, Query: "DELETE FROM u RETURNING id AS source_id",
	})
	require.Error(t, err)

	_, users, _ := export(t, sqlsource.ExportOptions{Driver: "sqlite", DSN: path, Query: "SELECT id AS source_id FROM u"})
	require.Len(t, users, 1, "the delete didn't happen")
}

func TestExportErrors(t *testing.T) {
	path := newDB(t, "CREATE TABLE u (id TEXT, email TEXT)")
	for name, c := range map[string]struct {
		opts sqlsource.ExportOptions
		err  string
	}{
		"no driver":        {sqlsource.ExportOptions{DSN: path, Query: "SELECT 1"}, "sql: a driver is required (one of sqlite"},
		"unknown driver":   {sqlsource.ExportOptions{Driver: "oracle", DSN: path, Query: "SELECT 1"}, `sql: unknown driver "oracle"`},
		"no query":         {sqlsource.ExportOptions{Driver: "sqlite", DSN: path}, "a query selecting the users is required"},
		"duplicate column": {sqlsource.ExportOptions{Driver: "sqlite", DSN: path, Query: "SELECT id, id FROM u"}, `two columns are named "id"`},
		"bad query":        {sqlsource.ExportOptions{Driver: "sqlite", DSN: path, Query: "SELECT nope FROM u"}, "sql: users query:"},
		"bad memberships":  {sqlsource.ExportOptions{Driver: "sqlite", DSN: path, Query: "SELECT id FROM u", MembershipsQuery: "SELECT x"}, "sql: memberships query:"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sqlsource.New().Export(context.Background(), cmf.NewPlainWriter(io.Discard), c.opts)
			require.ErrorContains(t, err, c.err)
		})
	}
}

func TestRedact(t *testing.T) {
	cause := errors.New("cause")
	for _, c := range []struct{ dsn, msg, want string }{
		{"postgres://app:s3cr%40t@db:5432/app", "dial postgres://app:s3cr%40t@db:5432/app: s3cr@t", "dial ***: ***"},
		{"server=db;user id=app;password=Pw0rd!;database=app", "login failed: Pw0rd!", "login failed: ***"},
		{"app:pw@tcp(db)/app", "nothing secret", "nothing secret"},
	} {
		err := sqlsource.Redact(fmt.Errorf("%s: %w", c.msg, cause), c.dsn)
		require.Equal(t, c.want+": cause", err.Error())
		require.ErrorIs(t, err, cause)
	}
}
