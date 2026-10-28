package sql_test

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	sqlsrc "github.com/cerberauth/iamigrate/pkg/connector/sql"
	_ "github.com/cerberauth/iamigrate/pkg/connector/sql/sqlite"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// seed creates a SQLite database holding the given statements' effects and
// returns its DSN.
func seed(t *testing.T, stmts ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := stdsql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close()
	for _, s := range stmts {
		_, err := db.Exec(s)
		require.NoError(t, err, s)
	}
	return path
}

func export(t *testing.T, opts sqlsrc.ExportOptions) ([]cmf.User, connector.Manifest, error) {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := sqlsrc.New().Export(context.Background(), w, opts)
	if err != nil {
		return nil, manifest, err
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users, manifest, nil
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

const bcryptHash = "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW"

func TestRowsBecomeUsers(t *testing.T) {
	dsn := seed(t,
		`CREATE TABLE users (source_id TEXT, email TEXT, given_name TEXT, password BLOB, password_algorithm TEXT, plan TEXT)`,
		`INSERT INTO users VALUES ('u1', 'jane@example.com', 'Jane', CAST('`+bcryptHash+`' AS BLOB), 'bcrypt', 'gold')`,
		`INSERT INTO users VALUES ('u2', NULL, 'Ann', NULL, NULL, NULL)`,
	)
	users, manifest, err := export(t, sqlsrc.ExportOptions{Driver: "sqlite", DSN: dsn, Query: "SELECT * FROM users ORDER BY source_id"})
	require.NoError(t, err)
	require.Equal(t, 2, manifest.RecordCount)
	require.Equal(t, "jane@example.com", users[0].Emails[0].Value)
	require.Equal(t, cmf.AlgBcrypt, users[0].Password.Algorithm, "a text hash stored as bytes is read as text")
	require.Equal(t, "gold", users[0].AppMetadata["plan"], "other columns pass through, as for a flat file")
	require.Empty(t, users[1].Emails, "NULL is an empty cell")
	require.Nil(t, users[1].Password)
}

// Binary columns arrive as bytes: a raw digest and its salt are told to the
// mapping in hex, exactly as the same file's columns would be.
func TestBinaryDigestAndSaltApplyAsForFlatFiles(t *testing.T) {
	digest := bytes.Repeat([]byte{0xAB}, 32)
	salt := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	dsn := seed(t,
		`CREATE TABLE users (id TEXT, pw BLOB, salt BLOB)`,
		fmt.Sprintf(`INSERT INTO users VALUES ('u1', X'%x', X'%x')`, digest, salt),
	)
	m := mapping.Mapping{Fields: []mapping.FieldMapping{
		{Source: "id", CMF: "source_id"},
		{Source: "pw", CMF: "password"},
		{Source: "salt", CMF: "password_salt"},
		{CMF: "password_algorithm", Default: "sha256"},
		{CMF: "password_encoding", Default: "hex"},
		{CMF: "password_salt_encoding", Default: "hex"},
		{CMF: "password_salt_position", Default: "suffix"},
	}}
	users, _, err := export(t, sqlsrc.ExportOptions{Driver: "sqlite", DSN: dsn, Query: "SELECT id, pw, salt FROM users", Mapping: m})
	require.NoError(t, err)
	require.Len(t, users, 1)
	pw := users[0].Password
	require.Equal(t, cmf.AlgSHA256, pw.Algorithm)
	require.Equal(t, hex.EncodeToString(digest), pw.Hash.Value)
	require.Equal(t, base64.StdEncoding.EncodeToString(salt), pw.Salt.Value)
}

func TestResultIsHandedOnInBatches(t *testing.T) {
	stmts := []string{`CREATE TABLE users (source_id TEXT, email TEXT)`}
	for i := 0; i < 1050; i++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO users VALUES ('u%04d', 'u%04d@example.com')`, i, i))
	}
	dsn := seed(t, stmts...)
	users, manifest, err := export(t, sqlsrc.ExportOptions{
		Driver: "sqlite", DSN: dsn, BatchSize: 100,
		Query: "SELECT * FROM users ORDER BY source_id",
	})
	require.NoError(t, err)
	require.Equal(t, 1050, manifest.RecordCount, "the last, partial batch is written too")
	for i, u := range users {
		require.Equal(t, fmt.Sprintf("u%04d", i), u.SourceID, "rows keep their order across batches")
	}
}

func TestQueryCannotWrite(t *testing.T) {
	dsn := seed(t, `CREATE TABLE users (source_id TEXT)`, `INSERT INTO users VALUES ('u1')`)
	_, _, err := export(t, sqlsrc.ExportOptions{Driver: "sqlite", DSN: dsn, Query: "DELETE FROM users RETURNING source_id"})
	require.Error(t, err)

	users, _, err := export(t, sqlsrc.ExportOptions{Driver: "sqlite", DSN: dsn, Query: "SELECT source_id FROM users"})
	require.NoError(t, err)
	require.Len(t, users, 1, "nothing was deleted")
}

func TestNoEngineIsAssumed(t *testing.T) {
	_, _, err := export(t, sqlsrc.ExportOptions{DSN: "x", Query: "SELECT 1"})
	require.ErrorContains(t, err, "driver is required")
	require.ErrorContains(t, err, "sqlite", "it lists the engines there are")

	_, _, err = export(t, sqlsrc.ExportOptions{Driver: "oracle", DSN: "x", Query: "SELECT 1"})
	require.ErrorContains(t, err, `unknown driver "oracle"`)
}

func TestColumnsMustBeNamedOnce(t *testing.T) {
	dsn := seed(t, `CREATE TABLE users (a TEXT)`)
	_, _, err := export(t, sqlsrc.ExportOptions{Driver: "sqlite", DSN: dsn, Query: "SELECT a, a FROM users"})
	require.ErrorContains(t, err, `named "a" more than once`)
}

func TestDSNNeverAppearsInAnError(t *testing.T) {
	const dsn = "fake://sa:s3cret-passw0rd@host/db"
	sqlsrc.Register("fake-failing", sqlsrc.Driver{
		Open: func(dsn string) (*stdsql.DB, error) {
			return nil, errors.New("cannot reach " + dsn)
		},
	})
	_, _, err := export(t, sqlsrc.ExportOptions{Driver: "fake-failing", DSN: dsn, Query: "SELECT 1"})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "s3cret-passw0rd")
	require.True(t, strings.Contains(err.Error(), "cannot reach"), "the rest of the error is kept")
}
