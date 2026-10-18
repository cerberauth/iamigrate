// Package strategy resolves the strategies a mapping's `strategies` section
// configures: the per-user decisions iamigrate makes itself by default and
// an operator can hand to a handler (export.user, import.payload, ...).
//
// Each strategy point keeps today's behavior unless configured, and only a
// few have named built-in alternatives; the rest are delegated or not.
// id.target (mapping `ids`) and the transforms (mapping `transforms`) have
// their own sections and packages.
package strategy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Strategy hook points configured under `strategies`.
const (
	ExportRecord     = "export.record"
	ExportUser       = "export.user"
	ValidateUser     = "validate.user"
	ValidateDedupKey = "validate.dedup_key"
	ImportUser       = "import.user"
	HashTranslate    = "hash.translate"
	MFATranslate     = "mfa.translate"
	ImportPayload    = "import.payload"
	OrgResolve       = "org.resolve"
	RoleResolve      = "role.resolve"
	VerifyLookup     = "verify.lookup"
	VerifyCompare    = "verify.compare"
)

// Built-in alternatives of verify.lookup: look users up by their
// identifier (the default), or by the ID the import gave them.
const (
	LookupIdentifier = "identifier"
	LookupTargetID   = "target_id"
)

// configurable are the strategy points `strategies` accepts, with their
// built-in alternatives.
var configurable = map[string][]string{
	ExportRecord:     nil,
	ExportUser:       nil,
	ValidateUser:     nil,
	ValidateDedupKey: nil,
	ImportUser:       nil,
	HashTranslate:    nil,
	MFATranslate:     nil,
	ImportPayload:    nil,
	OrgResolve:       nil,
	RoleResolve:      nil,
	VerifyLookup:     {LookupIdentifier, LookupTargetID},
	VerifyCompare:    nil,
}

// planned are strategy points designed but not built yet, so naming one
// says so rather than that it doesn't exist.
var planned = map[string]string{
	"identity.primary": "not supported yet",
	"id.source":        "not supported yet: map source_id with a field, a custom transform or export.record",
	"hash.detect":      "not supported yet: map the password columns with fields, or use export.record",
	"import.conflict":  "per-user conflict decisions aren't supported yet: use the conflict section's on_duplicate",
	"metadata.place":   "a handler isn't supported yet: route keys with the metadata section",
}

// Check checks m's `strategies`, `metadata` and `conflict` sections
// offline, without the hooks file their handlers are declared in.
func Check(m mapping.Mapping) error {
	for _, name := range sortedKeys(m.Strategies) {
		ref := m.Strategies[name]
		builtins, ok := configurable[name]
		if !ok {
			if why, ok := planned[name]; ok {
				return fmt.Errorf("mapping: strategies: %s: %s", name, why)
			}
			if hooks.IsStrategy(name) {
				return fmt.Errorf("mapping: strategies: %s isn't configured here (see the ids and transforms sections)", name)
			}
			return fmt.Errorf("mapping: strategies: unknown strategy %q", name)
		}
		switch {
		case ref.Handler != "" && ref.Strategy != "":
			return fmt.Errorf("mapping: strategies: %s: set either strategy or handler, not both", name)
		case ref.Handler == "" && ref.Strategy == "":
			return fmt.Errorf("mapping: strategies: %s: needs a handler", name)
		case ref.Strategy != "" && !contains(builtins, ref.Strategy):
			return fmt.Errorf("mapping: strategies: %s: unknown strategy %q", name, ref.Strategy)
		case ref.Handler == "" && ref.OnFailure != "":
			return fmt.Errorf("mapping: strategies: %s: on_failure only applies to a handler", name)
		}
	}
	for i, r := range m.Metadata {
		if r.Key == "" || r.Destination == "" {
			return fmt.Errorf("mapping: metadata[%d]: key and destination are required", i)
		}
		if r.From != "app_metadata" && r.From != "user_metadata" {
			return fmt.Errorf("mapping: metadata[%d] (%s): from must be app_metadata or user_metadata", i, r.Key)
		}
	}
	if c := m.Conflict; c != nil {
		switch c.OnDuplicate {
		case mapping.OnDuplicateFail, mapping.OnDuplicateSkip, mapping.OnDuplicateUpsert:
		default:
			return fmt.Errorf("mapping: conflict: on_duplicate must be fail, skip or upsert, got %q", c.OnDuplicate)
		}
	}
	return nil
}

// Only returns m with only the named strategies, for a step to build the
// Set of those it runs: the others' handlers needn't be declared for it.
func Only(m mapping.Mapping, names ...string) mapping.Mapping {
	kept := map[string]mapping.StrategyRef{}
	for _, n := range names {
		if ref, ok := m.Strategies[n]; ok {
			kept[n] = ref
		}
	}
	m.Strategies = kept
	return m
}

// Set is the strategies of one mapping.
type Set struct {
	refs     map[string]mapping.StrategyRef
	batchers map[string]*hooks.Batcher
}

// New returns the Set of m's strategies, their handlers looked up in d's
// hooks file. A nil *Set has no strategy configured.
func New(m mapping.Mapping, d *hooks.Dispatcher) (*Set, error) {
	if err := Check(m); err != nil {
		return nil, err
	}
	if len(m.Strategies) == 0 {
		return nil, nil
	}
	s := &Set{refs: m.Strategies, batchers: map[string]*hooks.Batcher{}}
	for _, name := range sortedKeys(m.Strategies) {
		ref := m.Strategies[name]
		if ref.Handler == "" {
			continue
		}
		hr := hooks.Ref{Handler: ref.Handler, OnFailure: hooks.OnFailure(ref.OnFailure)}
		if err := d.Config().CheckRef(hr); err != nil {
			return nil, fmt.Errorf("mapping: strategies: %s: %w", name, err)
		}
		s.batchers[name] = d.Batcher(name, hr)
	}
	return s, nil
}

// Delegated reports whether name is handed to a handler.
func (s *Set) Delegated(name string) bool {
	return s != nil && s.batchers[name] != nil
}

// Builtin returns the built-in alternative configured for name, "" for the
// default.
func (s *Set) Builtin(name string) string {
	if s == nil {
		return ""
	}
	return s.refs[name].Strategy
}

// BatchSize is how many items to gather before calling Resolve for name.
func (s *Set) BatchSize(name string) int {
	if !s.Delegated(name) {
		return 1
	}
	return s.batchers[name].Size()
}

// Resolve sends items to name's handler, in batches, and returns its
// answers by item key: nil when name isn't delegated, or when its handler
// failed and its on_failure is ignore, for the caller to keep its built-in
// behavior.
func (s *Set) Resolve(ctx context.Context, name string, items []hooks.Item) (map[string]json.RawMessage, error) {
	if !s.Delegated(name) || len(items) == 0 {
		return nil, nil
	}
	return s.batchers[name].Resolve(ctx, items)
}

// Decode decodes the answer for key into v, naming the strategy in the
// error.
func Decode(name, key string, raw json.RawMessage, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: answer for %q: %w", name, key, err)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
