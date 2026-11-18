// Package sqlite registers SQLite as the sql source's "sqlite" driver,
// through a pure-Go driver that needs no cgo. The DSN is a database file
// path, or a file: URI with the driver's query parameters.
package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/connector/sqlsource"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Name is the engine's --driver value.
const Name = "sqlite"

func init() {
	sqlsource.Register(sqlsource.Engine{
		Name: Name,
		Open: func(dsn string) (*sql.DB, error) { return sql.Open("sqlite", dsn) },
		Begin: func(ctx context.Context, conn *sql.Conn) (*sql.Tx, error) {
			// query_only refuses every write on this connection; a deferred
			// transaction then reads one snapshot from its first read on.
			if _, err := conn.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
				return nil, err
			}
			return conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		},
		Binary: func(typeName string) bool { return strings.Contains(typeName, "BLOB") },
	})
}
