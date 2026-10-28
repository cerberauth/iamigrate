package sqlserver_test

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	sqlsrc "github.com/cerberauth/iamigrate/pkg/connector/sql"
	_ "github.com/cerberauth/iamigrate/pkg/connector/sql/sqlserver"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// These tests run against a real SQL Server, and are skipped without one:
//
//	docker compose -f .docker/sqlserver/docker-compose.yml up --wait
//	SQLSERVER_DSN='sqlserver://sa:Iamigrate-Passw0rd@127.0.0.1:1433?database=master&encrypt=true&TrustServerCertificate=true' \
//	  go test ./pkg/connector/sql/sqlserver/... -run TestLive
//	docker compose -f .docker/sqlserver/docker-compose.yml down -v
//
// The DSN must be in the URL form, and its login able to create a database.

const testDB = "iamigrate_test"

// liveDB creates (or empties) the test database and returns the DSN of it.
func liveDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SQLSERVER_DSN")
	if dsn == "" {
		t.Skip("SQLSERVER_DSN is not set")
	}
	admin, err := stdsql.Open("sqlserver", dsn)
	require.NoError(t, err)
	defer admin.Close()
	_, err = admin.Exec(`IF DB_ID('` + testDB + `') IS NOT NULL BEGIN ALTER DATABASE ` + testDB + ` SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ` + testDB + ` END`)
	require.NoError(t, err)
	_, err = admin.Exec(`CREATE DATABASE ` + testDB)
	require.NoError(t, err)
	t.Cleanup(func() {
		c, err := stdsql.Open("sqlserver", dsn)
		if err == nil {
			_, _ = c.Exec(`ALTER DATABASE ` + testDB + ` SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ` + testDB)
			c.Close()
		}
	})

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	q := u.Query()
	q.Set("database", testDB)
	u.RawQuery = q.Encode()
	return u.String()
}

func setSnapshot(t *testing.T, dsn string, on bool) {
	t.Helper()
	db, err := stdsql.Open("sqlserver", dsn)
	require.NoError(t, err)
	defer db.Close()
	state := "OFF"
	if on {
		state = "ON"
	}
	_, err = db.Exec(`ALTER DATABASE ` + testDB + ` SET ALLOW_SNAPSHOT_ISOLATION ` + state)
	require.NoError(t, err)
}

func run(t *testing.T, opts sqlsrc.ExportOptions) ([]cmf.User, error) {
	t.Helper()
	opts.Driver = "sqlserver"
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	if _, err := sqlsrc.New().Export(context.Background(), w, opts); err != nil {
		return nil, err
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users, nil
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

func TestLiveVarbinaryColumnsAreRead(t *testing.T) {
	dsn := liveDB(t)
	db, err := stdsql.Open("sqlserver", dsn)
	require.NoError(t, err)
	defer db.Close()
	digest := bytes.Repeat([]byte{0xCD}, 32)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	_, err = db.Exec(`CREATE TABLE users (id uniqueidentifier, email nvarchar(100), pw varbinary(64), salt varbinary(16))`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO users VALUES ('6F9619FF-8B86-D011-B42D-00C04FC964FF', N'jane@example.com', @p1, @p2)`, digest, salt)
	require.NoError(t, err)

	m := mapping.Mapping{Fields: []mapping.FieldMapping{
		{Source: "id", CMF: "source_id"}, {Source: "email", CMF: "email"},
		{Source: "pw", CMF: "password"}, {Source: "salt", CMF: "password_salt"},
		{CMF: "password_algorithm", Default: "sha256"}, {CMF: "password_encoding", Default: "hex"},
		{CMF: "password_salt_encoding", Default: "hex"}, {CMF: "password_salt_position", Default: "prefix"},
	}}
	users, err := run(t, sqlsrc.ExportOptions{DSN: dsn, Query: "SELECT id, email, pw, salt FROM users", Mapping: m})
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "6f9619ff-8b86-d011-b42d-00c04fc964ff", users[0].SourceID, "a GUID is the string SQL Server shows, not its bytes")
	require.Equal(t, hex.EncodeToString(digest), users[0].Password.Hash.Value)
	require.Equal(t, base64.StdEncoding.EncodeToString(salt), users[0].Password.Salt.Value)
}

// What the export ran under is asked of the server itself: 5 is snapshot,
// 2 is read committed.
const isolationQuery = `SELECT 'u1' AS source_id,
	(SELECT transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID) AS [app_metadata.isolation]`

func TestLiveSnapshotIsolationWhenTheDatabaseAllowsIt(t *testing.T) {
	dsn := liveDB(t)

	setSnapshot(t, dsn, true)
	users, err := run(t, sqlsrc.ExportOptions{DSN: dsn, Query: isolationQuery})
	require.NoError(t, err)
	require.Equal(t, "5", users[0].AppMetadata["isolation"], "snapshot")

	setSnapshot(t, dsn, false)
	users, err = run(t, sqlsrc.ExportOptions{DSN: dsn, Query: isolationQuery})
	require.NoError(t, err, "a database without snapshot isolation still exports")
	require.Equal(t, "2", users[0].AppMetadata["isolation"], "read committed")
}

// TLS is whatever the DSN says: a server certificate the client doesn't
// trust is refused, and trusting it is the DSN's to say. A refused
// connection doesn't print the DSN, password included.
func TestLiveTLSSettingsComeFromTheDSN(t *testing.T) {
	dsn := liveDB(t)
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	password, _ := u.User.Password()

	q := u.Query()
	q.Set("encrypt", "true")
	q.Set("TrustServerCertificate", "false")
	u.RawQuery = q.Encode()
	_, err = run(t, sqlsrc.ExportOptions{DSN: u.String(), Query: "SELECT 'u1' AS source_id"})
	require.Error(t, err, "the container's self-signed certificate is not trusted")
	require.NotContains(t, err.Error(), password)

	q.Set("TrustServerCertificate", "true")
	u.RawQuery = q.Encode()
	users, err := run(t, sqlsrc.ExportOptions{DSN: u.String(), Query: "SELECT 'u1' AS source_id"})
	require.NoError(t, err)
	require.Len(t, users, 1)
}
