// Package sql implements a SourceConnector over a query on an application's
// own user database. Each row of the query becomes a record for the same
// mapping a flat file goes through, with the column names as source fields.
//
// No engine is built in: each one registers a Driver (see Register), by
// being imported for its side effect, and is picked with ExportOptions.Driver.
package sql

import (
	"context"
	stdsql "database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// Name is the connector's identifier, as used for --source.
const Name = "sql"

// DefaultBatchSize is how many rows are read before they go through the
// mapping and are written out. It bounds memory, and is the unit a custom
// transform or strategy handler is called on.
const DefaultBatchSize = 1000

// Driver is what the connector needs to know about one engine.
type Driver struct {
	// Open returns the database for dsn. Nil: database/sql's Open with
	// DriverName.
	Open func(dsn string) (*stdsql.DB, error)
	// DriverName is the database/sql driver registered by the engine's
	// package, for the default Open.
	DriverName string
	// Begin starts the transaction the query runs in. Nil: a read-only
	// one, at the engine's default isolation. notice reports a choice the
	// person running the export should know about (e.g. a fallback).
	Begin func(ctx context.Context, db *stdsql.DB, notice func(format string, args ...any)) (*stdsql.Tx, error)
	// Value renders one column's value as text, or reports false to leave
	// it to the generic conversion. typeName is the column's database type
	// name, as the driver reports it.
	Value func(typeName string, v any) (string, bool)
}

var (
	mu      sync.RWMutex
	drivers = map[string]Driver{}
)

// Register makes an engine usable as ExportOptions.Driver. It panics on a
// duplicate name, like database/sql.Register.
func Register(name string, d Driver) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := drivers[name]; dup {
		panic("sql: driver " + name + " registered twice")
	}
	drivers[name] = d
}

// Drivers lists the registered engines, sorted.
func Drivers() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(drivers))
	for n := range drivers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ExportOptions configures reading users out of a database.
type ExportOptions struct {
	connector.BaseExportOptions
	// Driver is the engine, as registered. Required: none is assumed.
	Driver string
	// DSN is the engine's own connection string. It is handed to the
	// driver untouched, and kept out of every error.
	DSN string
	// Query returns one row per user.
	Query string
	// Mapping renames and transforms the query's columns, as for a flat file.
	Mapping mapping.Mapping
	// HashHints is as for flatfile.ExportOptions.
	HashHints map[string]cmf.Algorithm
	// BatchSize is how many rows are held at once (default DefaultBatchSize).
	BatchSize int
}

// Connector is a SourceConnector over a SQL query.
type Connector struct{}

// New returns a sql connector.
func New() *Connector { return &Connector{} }

func (*Connector) Name() string { return Name }

// Export runs opts.Query and writes one CMF user per row to w. Rows are
// read as they arrive and handed on in batches, so memory doesn't grow with
// the size of the result.
func (*Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (manifest connector.Manifest, err error) {
	opts, ok := eo.(ExportOptions)
	if !ok {
		return manifest, fmt.Errorf("sql: Export requires sql.ExportOptions, got %T", eo)
	}
	if opts.Driver == "" {
		return manifest, fmt.Errorf("sql: a driver is required (one of %s)", strings.Join(Drivers(), ", "))
	}
	if strings.TrimSpace(opts.Query) == "" {
		return manifest, errors.New("sql: a query is required")
	}
	if opts.DSN == "" {
		return manifest, errors.New("sql: a DSN is required")
	}
	mu.RLock()
	drv, ok := drivers[opts.Driver]
	mu.RUnlock()
	if !ok {
		return manifest, fmt.Errorf("sql: unknown driver %q (one of %s)", opts.Driver, strings.Join(Drivers(), ", "))
	}
	// Whatever a driver puts in an error, the DSN (it can hold a password)
	// doesn't leave this function.
	defer func() { err = redact(err, opts.DSN) }()

	open := drv.Open
	if open == nil {
		open = func(dsn string) (*stdsql.DB, error) { return stdsql.Open(drv.DriverName, dsn) }
	}
	db, err := open(opts.DSN)
	if err != nil {
		return manifest, fmt.Errorf("sql: opening %s: %w", opts.Driver, err)
	}
	defer db.Close()

	bar := progress.FromContext(ctx)
	notice := func(format string, args ...any) { bar.Status(format, args...) }
	begin := drv.Begin
	if begin == nil {
		begin = func(ctx context.Context, db *stdsql.DB, _ func(string, ...any)) (*stdsql.Tx, error) {
			return db.BeginTx(ctx, &stdsql.TxOptions{ReadOnly: true})
		}
	}
	tx, err := begin(ctx, db, notice)
	if err != nil {
		return manifest, fmt.Errorf("sql: starting the transaction: %w", err)
	}
	// Nothing is written: the transaction only gives the query a stable view.
	defer func() { _ = tx.Rollback() }()

	rs, err := tx.QueryContext(ctx, opts.Query)
	if err != nil {
		return manifest, fmt.Errorf("sql: running the query: %w", err)
	}
	defer rs.Close()

	cols, err := rs.ColumnTypes()
	if err != nil {
		return manifest, fmt.Errorf("sql: reading the query's columns: %w", err)
	}
	names := make([]string, len(cols))
	types := make([]string, len(cols))
	for i, c := range cols {
		if names[i] = c.Name(); names[i] == "" {
			return manifest, fmt.Errorf("sql: column %d of the query has no name; give it one with AS", i+1)
		}
		types[i] = strings.ToUpper(c.DatabaseTypeName())
	}
	if dup := firstDuplicate(names); dup != "" {
		return manifest, fmt.Errorf("sql: the query returns a column named %q more than once; rename one with AS", dup)
	}

	size := opts.BatchSize
	if size <= 0 {
		size = DefaultBatchSize
	}
	fopts := flatfile.ExportOptions{HashHints: opts.HashHints, Mapping: opts.Mapping}
	batch := make([]map[string]string, 0, size)
	offset := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := flatfile.ExportRows(ctx, w, batch, fopts, offset, &manifest); err != nil {
			return err
		}
		offset += len(batch)
		batch = batch[:0]
		return nil
	}

	raw := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	for rs.Next() {
		if err := ctx.Err(); err != nil {
			return manifest, err
		}
		if err := rs.Scan(ptrs...); err != nil {
			return manifest, fmt.Errorf("sql: reading row %d: %w", offset+len(batch)+1, err)
		}
		row := make(map[string]string, len(cols))
		for i, v := range raw {
			if s := text(drv, types[i], v); s != "" {
				row[names[i]] = s
			}
		}
		if batch = append(batch, row); len(batch) >= size {
			if err := flush(); err != nil {
				return manifest, err
			}
		}
	}
	if err := rs.Err(); err != nil {
		return manifest, fmt.Errorf("sql: reading the result: %w", err)
	}
	if err := flush(); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func firstDuplicate(names []string) string {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			return n
		}
		seen[n] = true
	}
	return ""
}

// redact removes dsn from err's message. The error's chain is dropped, as
// it may carry the DSN in its own fields.
func redact(err error, dsn string) error {
	if err == nil || dsn == "" || !strings.Contains(err.Error(), dsn) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), dsn, "[dsn]"))
}
