// Package sqlite registers the SQLite engine for the sql source, through
// modernc.org/sqlite: pure Go, so it needs no cgo, and doubles as the
// database the connector's tests run against.
//
// Import it for its side effect:
//
//	import _ "github.com/cerberauth/iamigrate/pkg/connector/sql/sqlite"
package sqlite

import (
	"context"
	stdsql "database/sql"

	"github.com/cerberauth/iamigrate/pkg/connector/sql"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Name is the engine's name, as used for --driver.
const Name = "sqlite"

func init() {
	sql.Register(Name, sql.Driver{
		Open: func(dsn string) (*stdsql.DB, error) {
			db, err := stdsql.Open("sqlite", dsn)
			if err != nil {
				return nil, err
			}
			// query_only is a setting of the connection, so there must be
			// only one for it to hold on the connection the query uses.
			db.SetMaxOpenConns(1)
			return db, nil
		},
		// SQLite's driver has no read-only transaction: query_only makes
		// the connection refuse any write instead.
		Begin: func(ctx context.Context, db *stdsql.DB, _ func(string, ...any)) (*stdsql.Tx, error) {
			if _, err := db.ExecContext(ctx, "PRAGMA query_only = 1"); err != nil {
				return nil, err
			}
			return db.BeginTx(ctx, nil)
		},
	})
}
