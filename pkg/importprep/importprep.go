// Package importprep prepares the CMF users an import reads, for the
// target connector to build its payloads from: the import-side strategies
// (import.user, identity.primary, hash.translate, mfa.translate) decide what is imported of
// each user, metadata.place and the mapping's metadata routes move metadata
// keys away from where the connector puts them, and its target_fields set fields of the
// target's user from CMF fields, through the same transforms as the export
// side (see package transform). import.payload, last, has the final say on
// the payload the connector built.
//
// Users are prepared a batch at a time, so each handler gets one call per
// batch, never one per user. The connectors read users through a Reader,
// which hands each one over with its target fields, and with no strategy,
// route or target field configured reads them as the CMF reader does.
package importprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/cerberauth/iamigrate/pkg/transform"
)

// Field is one resolved target field: the target path to set and its value,
// a string once transformed, else the CMF value as is.
type Field struct {
	Path  string
	Value any
}

// Applier prepares users for one target.
type Applier struct {
	rules  []rule
	routes []mapping.MetadataRoute
	set    *strategy.Set
	batch  int
	// check is the target connector's word on whether it can set a path,
	// for the destinations metadata.place's handler answers.
	check func(path string) error
	// identifiers are the kinds of identifier the target can make a user's
	// primary one, for identity.primary.
	identifiers []cmf.Identifier
}

// Option sets how an Applier is built.
type Option func(*Applier)

// WithPrimaryIdentifiers tells the Applier which kinds of identifier its
// target can make a user's primary one (see
// connector.Capabilities.PrimaryIdentifiers), for identity.primary.
func WithPrimaryIdentifiers(kinds []cmf.Identifier) Option {
	return func(a *Applier) { a.identifiers = kinds }
}

type rule struct {
	cmf      []string
	target   string
	def      string
	pipeline *transform.Pipeline
	// transforms is whether the rule has any transform, which needs a
	// string to work on.
	transforms bool
}

// defaultBatch is how many users a Reader resolves at a time.
const defaultBatch = 100

// New returns the Applier of m's import-side strategies, metadata routes and
// target fields, nil when it has none. check is the target connector's word
// on whether it can set a path; handlers are reached through d.
func New(m mapping.Mapping, check func(path string) error, d *hooks.Dispatcher, opts ...Option) (*Applier, error) {
	set, err := strategy.New(strategy.Only(m, importStrategies...), d)
	if err != nil {
		return nil, err
	}
	delegated := false
	for _, n := range importStrategies {
		delegated = delegated || set.Delegated(n)
	}
	if len(m.TargetFields) == 0 && len(m.Metadata) == 0 && !delegated && !set.Configured(strategy.IdentityPrimary) {
		return nil, nil
	}
	reg, err := transform.New(m, transform.ImportHook, d)
	if err != nil {
		return nil, err
	}
	a := &Applier{set: set, routes: m.Metadata, batch: defaultBatch, check: check}
	for _, o := range opts {
		o(a)
	}
	for _, n := range importStrategies {
		a.batch = max(a.batch, set.BatchSize(n))
	}
	for i, r := range m.Metadata {
		if r.Destination != routeDrop {
			if err := check(r.Destination); err != nil {
				return nil, fmt.Errorf("mapping: metadata[%d] (%s): %w", i, r.Key, err)
			}
		}
	}
	for i, f := range m.TargetFields {
		where := fmt.Sprintf("mapping: target_fields[%d]", i)
		if f.CMF == "" || f.Target == "" {
			return nil, fmt.Errorf("%s: cmf and target are required", where)
		}
		if err := check(f.Target); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		p, err := reg.Compile(f.Transform)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", where, f.Target, err)
		}
		a.rules = append(a.rules, rule{cmf: strings.Split(f.CMF, "."), target: f.Target, def: f.Default, pipeline: p, transforms: f.Transform != ""})
	}
	return a, nil
}

// Check checks m's target fields and transforms for target, offline: what
// New checks, but without the hooks file a custom transform's handler is
// declared in.
func Check(m mapping.Mapping, target connector.TargetConnector) error {
	if err := transform.Check(m); err != nil {
		return err
	}
	if err := strategy.Check(m); err != nil {
		return err
	}
	if err := checkPrimary(m, target); err != nil {
		return err
	}
	if c := m.Conflict; c != nil && c.OnDuplicate == mapping.OnDuplicateUpsert && !target.Capabilities().SupportsUpsert {
		return fmt.Errorf("mapping: conflict: %s can't update an existing user: on_duplicate can't be upsert", target.Name())
	}
	if len(m.TargetFields) == 0 && len(m.Metadata) == 0 && !strategyConfigured(m, strategy.MetadataPlace) {
		return nil
	}
	tc, ok := target.(connector.TargetFieldChecker)
	if !ok {
		return fmt.Errorf("mapping: %s doesn't support target fields or metadata routes", target.Name())
	}
	for i, f := range m.TargetFields {
		if f.CMF == "" || f.Target == "" {
			return fmt.Errorf("mapping: target_fields[%d]: cmf and target are required", i)
		}
		if err := tc.CheckTargetField(f.Target); err != nil {
			return fmt.Errorf("mapping: target_fields[%d]: %w", i, err)
		}
	}
	return checkRoutes(m, tc)
}

func strategyConfigured(m mapping.Mapping, name string) bool {
	_, ok := m.Strategies[name]
	return ok
}

func checkRoutes(m mapping.Mapping, tc connector.TargetFieldChecker) error {
	for i, r := range m.Metadata {
		if r.Destination == routeDrop {
			continue
		}
		if err := tc.CheckTargetField(r.Destination); err != nil {
			return fmt.Errorf("mapping: metadata[%d] (%s): %w", i, r.Key, err)
		}
	}
	return nil
}

// Resolve returns the target fields of each of users, in order.
func (a *Applier) Resolve(ctx context.Context, users []cmf.User) ([][]Field, error) {
	docs := make([]any, len(users))
	keys := make([]string, len(users))
	for i, u := range users {
		b, err := json.Marshal(u)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &docs[i]); err != nil {
			return nil, err
		}
		keys[i] = u.SourceID
	}
	out := make([][]Field, len(users))
	for _, r := range a.rules {
		values := make([]any, len(users))
		strs := make([]string, len(users))
		for i := range users {
			v := lookup(docs[i], r.cmf)
			if empty(v) && r.def != "" {
				v = r.def
			}
			values[i] = v
			if r.transforms && !empty(v) {
				s, err := scalarString(v)
				if err != nil {
					return nil, fmt.Errorf("user %s: target field %s: %w", keys[i], r.target, err)
				}
				strs[i] = s
			}
		}
		if r.transforms {
			if err := r.pipeline.Apply(ctx, r.target, keys, strs); err != nil {
				var ve *transform.ValueError
				if errors.As(err, &ve) {
					return nil, fmt.Errorf("user %s: target field %s: %w", keys[ve.Index], r.target, ve.Err)
				}
				return nil, fmt.Errorf("target field %s: %w", r.target, err)
			}
			for i, s := range strs {
				values[i] = s
			}
		}
		for i, v := range values {
			if !empty(v) {
				out[i] = append(out[i], Field{Path: r.target, Value: v})
			}
		}
	}
	return out, nil
}

// lookup walks path, object keys and array indexes, through doc.
func lookup(doc any, path []string) any {
	for _, seg := range path {
		switch d := doc.(type) {
		case map[string]any:
			doc = d[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(d) {
				return nil
			}
			doc = d[i]
		default:
			return nil
		}
	}
	return doc
}

func empty(v any) bool { return v == nil || v == "" }

func scalarString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool, float64:
		b, _ := json.Marshal(t)
		return string(b), nil
	}
	return "", errors.New("a transform needs a string, number or boolean, not an object or array")
}

// Reader reads users from a CMF reader, prepared.
type Reader struct {
	ctx context.Context
	r   *cmf.Reader
	a   *Applier

	users   []cmf.User
	fields  [][]Field
	pos     int
	err     error
	skipped []connector.ImportError
}

// NewReader returns a Reader over r applying a, which may be nil for no
// preparation: users are then read one at a time, as from r.
func NewReader(ctx context.Context, r *cmf.Reader, a *Applier) *Reader {
	return &Reader{ctx: ctx, r: r, a: a}
}

// ReadUser returns the next user and its target fields, or the error
// reading it, io.EOF at the end. Users import.user skips are left out (see
// Skipped).
func (r *Reader) ReadUser() (cmf.User, []Field, error) {
	if r.a == nil {
		u, err := r.r.ReadUser()
		return u, nil, err
	}
	if err := r.next(); err != nil {
		return cmf.User{}, nil, err
	}
	u, f := r.users[r.pos], r.fields[r.pos]
	r.pos++
	return u, f, nil
}

// Prepared is a user ready for the connector, with its target fields.
type Prepared struct {
	User   cmf.User
	Fields []Field
}

// ReadBatch returns the users left of the current batch, reading the next
// one if there are none, for a connector to build their payloads together
// (see Applier.Payloads). With no preparation a batch is one user.
func (r *Reader) ReadBatch() ([]Prepared, error) {
	if r.a == nil {
		u, err := r.r.ReadUser()
		if err != nil {
			return nil, err
		}
		return []Prepared{{User: u}}, nil
	}
	if err := r.next(); err != nil {
		return nil, err
	}
	out := make([]Prepared, 0, len(r.users)-r.pos)
	for ; r.pos < len(r.users); r.pos++ {
		out = append(out, Prepared{User: r.users[r.pos], Fields: r.fields[r.pos]})
	}
	return out, nil
}

// Skipped returns the users import.user skipped so far, for the import
// report.
func (r *Reader) Skipped() []connector.ImportError { return r.skipped }

// next makes sure a prepared user is waiting, reading batches until one is
// (import.user can skip a whole batch).
func (r *Reader) next() error {
	for r.pos == len(r.users) {
		if r.err != nil {
			return r.err
		}
		if err := r.fill(); err != nil {
			return err
		}
	}
	return nil
}

// fill reads and prepares the next batch. A read error after some users is
// kept for after them, so they are imported as they would be without
// preparation.
func (r *Reader) fill() error {
	var raw []cmf.User
	for len(raw) < r.a.batch {
		u, err := r.r.ReadUser()
		if err != nil {
			r.err = err
			break
		}
		raw = append(raw, u)
	}
	if len(raw) == 0 {
		return r.err
	}
	users, fields, skipped, err := r.a.prepare(r.ctx, raw)
	if err != nil {
		r.users, r.pos, r.err = nil, 0, err
		return err
	}
	r.users, r.fields, r.pos = users, fields, 0
	r.skipped = append(r.skipped, skipped...)
	return nil
}

// Set sets path, a dotted key path, to v in m, creating the maps on the way.
func Set(m map[string]any, path string, v any) {
	keys := strings.Split(path, ".")
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

// Under reports whether path is root followed by a key, returning the key.
func Under(path, root string) (string, bool) {
	k, ok := strings.CutPrefix(path, root+".")
	return k, ok && k != "" && !strings.Contains(k, ".")
}

// ErrNotSettable builds the error of a target path a connector can't set.
func ErrNotSettable(target, path string, settable string) error {
	return fmt.Errorf("%s can't set %q: target fields are %s", target, path, settable)
}
