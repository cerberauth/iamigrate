// Package sqlserver registers Microsoft SQL Server (and Azure SQL) for the
// sql source, through github.com/microsoft/go-mssqldb.
//
// Import it for its side effect:
//
//	import _ "github.com/cerberauth/iamigrate/pkg/connector/sql/sqlserver"
//
// The DSN is the driver's standard one, handed over untouched, so TLS is set
// in it (encrypt, TrustServerCertificate, certificate, hostNameInCertificate)
// and so is the way to sign in. With no fedauth parameter that is a SQL
// login (user id and password); with one, it is Microsoft Entra
// authentication, e.g. fedauth=ActiveDirectoryDefault.
package sqlserver

import (
	"context"
	stdsql "database/sql"
	"net/url"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/connector/sql"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/azuread"
)

// Name is the engine's name, as used for --driver.
const Name = "sqlserver"

func init() {
	sql.Register(Name, sql.Driver{
		Open: func(dsn string) (*stdsql.DB, error) {
			// The azuread driver is the same one plus Entra token
			// acquisition, but it pulls the Azure SDK in on each use, so
			// it only serves a DSN that asks for it.
			if usesEntra(dsn) {
				return stdsql.Open(azuread.DriverName, dsn)
			}
			return stdsql.Open("sqlserver", dsn)
		},
		Begin: begin,
		Value: value,
	})
}

// usesEntra reports whether dsn selects Microsoft Entra authentication, by
// a fedauth parameter, in either of the driver's DSN forms (a URL, or
// ADO-style key=value pairs separated by semicolons).
func usesEntra(dsn string) bool {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return false
		}
		for k, v := range u.Query() {
			if strings.EqualFold(k, "fedauth") && len(v) > 0 && v[0] != "" {
				return true
			}
		}
		return false
	}
	for _, kv := range strings.Split(dsn, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "fedauth") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// begin runs the export under snapshot isolation when the database has it
// turned on, so the export sees the data as it was when it started, whatever
// the application writes meanwhile, without blocking those writes. When it
// is off, the isolation level is left as the database has it (read committed,
// or the row-versioned flavour of it if READ_COMMITTED_SNAPSHOT is on).
//
// SQL Server has no read-only transaction for the driver to ask for, so the
// query is not stopped from writing: use a login that can only read.
func begin(ctx context.Context, db *stdsql.DB, notice func(string, ...any)) (*stdsql.Tx, error) {
	var state int
	// 1 is ON; 2 is turning on, when it can't be relied on yet.
	err := db.QueryRowContext(ctx, "SELECT snapshot_isolation_state FROM sys.databases WHERE name = DB_NAME()").Scan(&state)
	switch {
	case err != nil:
		// Not being allowed to look isn't a reason not to export.
		notice("could not check snapshot isolation (%v): exporting at the database's default isolation", err)
	case state == 1:
		return db.BeginTx(ctx, &stdsql.TxOptions{Isolation: stdsql.LevelSnapshot})
	default:
		notice("snapshot isolation is off on this database: exporting at the database's default isolation")
	}
	return db.BeginTx(ctx, nil)
}

// value renders the SQL Server types the driver doesn't give as text.
func value(typeName string, v any) (string, bool) {
	b, ok := v.([]byte)
	if !ok {
		return "", false
	}
	// uniqueidentifier comes as its 16 bytes in SQL Server's own order,
	// not as the UUID string everything else shows.
	if typeName == "UNIQUEIDENTIFIER" && len(b) == 16 {
		var id mssql.UniqueIdentifier
		if err := id.Scan(b); err != nil {
			return "", false
		}
		return strings.ToLower(id.String()), true
	}
	return "", false
}

