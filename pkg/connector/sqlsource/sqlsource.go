// Package sqlsource implements a SourceConnector over a SQL database: the
// rows of a query become flat records, mapped into CMF through mapping.yaml
// exactly like a flat file's, so transforms, hash detection and the export
// strategies apply unchanged. Each database engine registers itself (see
// Register) from its own package.
package sqlsource

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Name is the connector's identifier, as used for --source.
const Name = "sql"

// BatchSize is how many rows go through the mapping and its hooks at a
// time.
const BatchSize = 1000

// Engine is one database engine the connector can read from, registered by
// its --driver name.
type Engine struct {
	// Name is the engine's --driver value.
	Name string
	// Open connects to the database dsn names.
	Open func(dsn string) (*sql.DB, error)
	// Begin starts the transaction every query of an export runs in, on
	// conn: read-only and over one snapshot of the database, as far as the
	// engine can.
	Begin func(ctx context.Context, conn *sql.Conn) (*sql.Tx, error)
	// Binary reports whether a column of this database type name (as
	// sql.ColumnType.DatabaseTypeName gives it) holds bytes rather than
	// text.
	Binary func(typeName string) bool
}

var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{}
)

// Register makes e available as --driver e.Name. It panics if the name is
// taken, as two engines can't answer to one name.
func Register(e Engine) {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	if _, ok := engines[e.Name]; ok {
		panic("sqlsource: engine " + e.Name + " registered twice")
	}
	engines[e.Name] = e
}

// Engines lists the registered engine names, sorted.
func Engines() []string {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Lookup returns the engine registered as name.
func Lookup(name string) (Engine, error) {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	if name == "" {
		return Engine{}, fmt.Errorf("sql: a driver is required (one of %s)", strings.Join(namesLocked(), ", "))
	}
	e, ok := engines[name]
	if !ok {
		return Engine{}, fmt.Errorf("sql: unknown driver %q (one of %s)", name, strings.Join(namesLocked(), ", "))
	}
	return e, nil
}

func namesLocked() []string {
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ExportOptions configures an export from a SQL database.
type ExportOptions struct {
	connector.BaseExportOptions
	// Driver names the engine (see Register). Required.
	Driver string
	// DSN is the engine's data source name. It is never logged: errors
	// carrying it have it masked.
	DSN string
	// Query selects the users, one row each, its column names being the
	// source fields of Mapping.
	Query string
	// OrganizationsQuery, RolesQuery and MembershipsQuery, each optional,
	// select the organizations, roles and memberships (user_id,
	// organization, role), mapped by the mapping's sections of the same
	// names as a flat file's are.
	OrganizationsQuery, RolesQuery, MembershipsQuery string
	// Mapping maps the query's columns into CMF, as for a flat file.
	Mapping mapping.Mapping
	// HashHints are as for a flat file (see flatfile.ExportOptions).
	HashHints map[string]cmf.Algorithm
}

// Connector is a SourceConnector over a SQL database.
type Connector struct {
	ff *flatfile.Connector
}

// New returns a SQL source connector.
func New() *Connector { return &Connector{ff: flatfile.New()} }

func (*Connector) Name() string { return Name }

// Directory returns the organizations and roles the last Export read, nil
// when it had none of their queries.
func (c *Connector) Directory() *connector.Directory { return c.ff.Directory() }

// Export runs opts.Query, and the directory queries given, in one read-only
// transaction, and writes the users to w as they stream in.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	opts, ok := eo.(ExportOptions)
	if !ok {
		return connector.Manifest{}, fmt.Errorf("sql: Export requires sqlsource.ExportOptions, got %T", eo)
	}
	if strings.TrimSpace(opts.Query) == "" {
		return connector.Manifest{}, errors.New("sql: a query selecting the users is required")
	}
	e, err := Lookup(opts.Driver)
	if err != nil {
		return connector.Manifest{}, err
	}
	m, err := c.export(ctx, w, e, opts)
	return m, redact(err, opts.DSN)
}

func (c *Connector) export(ctx context.Context, w *cmf.Writer, e Engine, opts ExportOptions) (connector.Manifest, error) {
	db, err := e.Open(opts.DSN)
	if err != nil {
		return connector.Manifest{}, fmt.Errorf("sql: opening the %s database: %w", e.Name, err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return connector.Manifest{}, fmt.Errorf("sql: connecting to the %s database: %w", e.Name, err)
	}
	defer conn.Close()
	tx, err := e.Begin(ctx, conn)
	if err != nil {
		return connector.Manifest{}, fmt.Errorf("sql: starting a read-only transaction: %w", err)
	}
	// Nothing is written: the transaction is only ever rolled back.
	defer func() { _ = tx.Rollback() }()

	dir, err := readDirectory(ctx, tx, e, opts)
	if err != nil {
		return connector.Manifest{}, err
	}
	rows, err := tx.QueryContext(ctx, opts.Query)
	if err != nil {
		return connector.Manifest{}, fmt.Errorf("sql: users query: %w", err)
	}
	defer rows.Close()
	rr, err := newRowReader(rows, e)
	if err != nil {
		return connector.Manifest{}, fmt.Errorf("sql: users query: %w", err)
	}
	return c.ff.ExportRows(ctx, w, rr, dir, flatfile.ExportOptions{
		Mapping: opts.Mapping, HashHints: opts.HashHints, Provenance: Name,
	}, BatchSize)
}

// readDirectory runs the directory queries opts has, nil when it has none.
// Their results are read whole, as memberships are joined into users as
// those stream by.
func readDirectory(ctx context.Context, tx *sql.Tx, e Engine, opts ExportOptions) (*flatfile.DirectoryRows, error) {
	if opts.OrganizationsQuery == "" && opts.RolesQuery == "" && opts.MembershipsQuery == "" {
		return nil, nil
	}
	var d flatfile.DirectoryRows
	for _, q := range []struct {
		name, query string
		into        *[]map[string]string
	}{
		{"organizations", opts.OrganizationsQuery, &d.Organizations},
		{"roles", opts.RolesQuery, &d.Roles},
		{"memberships", opts.MembershipsQuery, &d.Memberships},
	} {
		if q.query == "" {
			continue
		}
		all, err := queryAll(ctx, tx, e, q.query)
		if err != nil {
			return nil, fmt.Errorf("sql: %s query: %w", q.name, err)
		}
		*q.into = all
	}
	return &d, nil
}

func queryAll(ctx context.Context, tx *sql.Tx, e Engine, query string) ([]map[string]string, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rr, err := newRowReader(rows, e)
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for {
		row, err := rr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
}

// rowReader turns the rows of a query into flat records, one at a time.
type rowReader struct {
	rows   *sql.Rows
	names  []string
	binary []bool
	vals   []any
}

func newRowReader(rows *sql.Rows, e Engine) (*rowReader, error) {
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	r := &rowReader{rows: rows, names: make([]string, len(types)), binary: make([]bool, len(types)), vals: make([]any, len(types))}
	seen := map[string]bool{}
	for i, t := range types {
		r.names[i] = t.Name()
		if seen[t.Name()] {
			return nil, fmt.Errorf("two columns are named %q: give them distinct names with AS", t.Name())
		}
		seen[t.Name()] = true
		r.binary[i] = e.Binary != nil && e.Binary(strings.ToUpper(t.DatabaseTypeName()))
	}
	return r, nil
}

func (r *rowReader) Next() (map[string]string, error) {
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	ptrs := make([]any, len(r.vals))
	for i := range r.vals {
		ptrs[i] = &r.vals[i]
	}
	if err := r.rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	row := make(map[string]string, len(r.names))
	for i, v := range r.vals {
		if s, ok := text(v, r.binary[i]); ok {
			row[r.names[i]] = s
		}
	}
	return row, nil
}

// text renders a column value as the string a flat file would hold, false
// for NULL. Bytes from a binary column are hex-encoded, so password_encoding
// and password_salt_encoding read them as hex; bytes from any other column
// are its text.
func text(v any, binary bool) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case []byte:
		if binary {
			return hex.EncodeToString(t), true
		}
		return string(t), true
	case string:
		return t, true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano), true
	default:
		return fmt.Sprint(t), true
	}
}

// redact masks dsn, and the password it may carry, in err's message, as a
// driver error can quote what it was given.
func redact(err error, dsn string) error {
	if err == nil || dsn == "" {
		return err
	}
	msg := err.Error()
	secrets := []string{dsn}
	if u, perr := url.Parse(dsn); perr == nil && u.User != nil {
		if p, ok := u.User.Password(); ok && p != "" {
			secrets = append(secrets, p, url.QueryEscape(p), url.PathEscape(p))
		}
	}
	for _, kv := range strings.FieldsFunc(dsn, func(r rune) bool { return r == ';' || r == ' ' || r == '&' || r == '?' }) {
		k, v, ok := strings.Cut(kv, "=")
		if ok && v != "" && isPasswordKey(k) {
			secrets = append(secrets, strings.Trim(v, `'"{}`))
		}
	}
	changed := false
	for _, s := range secrets {
		if s != "" && strings.Contains(msg, s) {
			msg = strings.ReplaceAll(msg, s, "***")
			changed = true
		}
	}
	if !changed {
		return err
	}
	return redactedError{msg: msg, err: err}
}

func isPasswordKey(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "password", "pwd", "passwd", "pass":
		return true
	}
	return false
}

// redactedError is an error whose message had a secret masked; it still
// unwraps to the original, for errors.Is.
type redactedError struct {
	msg string
	err error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.err }
