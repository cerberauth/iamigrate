// Package transform runs the value transforms a mapping's `transform` names
// (e.g. "trim|lowercase|my_fn"), on export (source field -> CMF) and on
// import (CMF -> target field) alike: the built-in ones, and the custom
// ones mapping.yaml's `transforms` hands to a handler.
//
// A pipeline runs over a whole column of values, one step at a time, so a
// custom step is one batched handler call for many values rather than one
// call per value.
package transform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Hook points a custom transform is sent to: on export, and on import.
const (
	ExportHook = "map.field"
	ImportHook = "map.target_field"
)

// Func is a built-in transform. Empty stays empty, so a default or a
// missing value is never turned into something else.
type Func func(string) (string, error)

var builtins = map[string]Func{
	"trim":      func(s string) (string, error) { return strings.TrimSpace(s), nil },
	"lowercase": func(s string) (string, error) { return strings.ToLower(s), nil },
	"uppercase": func(s string) (string, error) { return strings.ToUpper(s), nil },
	// bool turns true/false, yes/no, y/n, on/off, t/f and 1/0 (any case)
	// into "true" or "false".
	"bool": func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		b, err := ParseBool(s)
		return strconv.FormatBool(b), err
	},
	// not is bool, inverted: a source's `active` or `enabled` column becomes
	// the CMF `blocked`.
	"not": func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		b, err := ParseBool(s)
		return strconv.FormatBool(!b), err
	},
}

// Builtins lists the built-in transform names.
func Builtins() []string {
	names := make([]string, 0, len(builtins))
	for n := range builtins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ParseBool reads the truthy and falsy spellings the bool transform
// accepts.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "t", "1", "yes", "y", "on":
		return true, nil
	case "false", "f", "0", "no", "n", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean (true/false, yes/no, 1/0)", s)
}

// Registry resolves transform names: the built-ins, plus a mapping's custom
// transforms, each sent to its handler through one hook point.
type Registry struct {
	custom map[string]*hooks.Batcher
}

// Builtin is the Registry of the built-in transforms only.
var Builtin = &Registry{}

// New returns the Registry of m's custom transforms, sent to hook (ExportHook
// or ImportHook) through d. A custom transform can't take a built-in's name,
// and its handler must be declared in d's hooks file, which is only needed
// once a pipeline names it.
func New(m mapping.Mapping, hook string, d *hooks.Dispatcher) (*Registry, error) {
	r := &Registry{custom: map[string]*hooks.Batcher{}}
	for _, name := range sortedNames(m.Transforms) {
		t := m.Transforms[name]
		if _, ok := builtins[name]; ok {
			return nil, fmt.Errorf("mapping: transforms: %q is a built-in transform", name)
		}
		if name == "" || strings.ContainsAny(name, "| ") {
			return nil, fmt.Errorf("mapping: transforms: %q is not a valid name", name)
		}
		ref := hooks.Ref{Handler: t.Handler, OnFailure: hooks.OnFailure(t.OnFailure)}
		if err := d.Config().CheckRef(ref); err != nil {
			return nil, fmt.Errorf("mapping: transforms: %s: %w", name, err)
		}
		r.custom[name] = d.Batcher(hook, ref)
	}
	return r, nil
}

// Check reports whether every transform spec in m (its fields' and its
// target fields') names a built-in or one of m's custom transforms, without
// needing the hooks file.
func Check(m mapping.Mapping) error {
	known := func(name string) bool {
		_, b := builtins[name]
		_, c := m.Transforms[name]
		return b || c
	}
	check := func(where, spec string) error {
		for _, name := range splitSpec(spec) {
			if !known(name) {
				return fmt.Errorf("mapping: %s: unknown transform %q", where, name)
			}
		}
		return nil
	}
	for i, f := range m.Fields {
		if err := check(fmt.Sprintf("fields[%d] (%s)", i, f.CMF), f.Transform); err != nil {
			return err
		}
	}
	for i, f := range m.TargetFields {
		if err := check(fmt.Sprintf("target_fields[%d] (%s)", i, f.Target), f.Transform); err != nil {
			return err
		}
	}
	return nil
}

func splitSpec(spec string) []string {
	if spec == "" {
		return nil
	}
	parts := strings.Split(spec, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// step is one transform of a pipeline: a built-in fn, or a custom one sent
// through batcher.
type step struct {
	name    string
	fn      Func
	batcher *hooks.Batcher
}

// Pipeline is a compiled transform spec.
type Pipeline struct {
	steps []step
}

// Compile compiles spec, transform names joined with "|"; an empty spec is
// a pipeline that changes nothing.
func (r *Registry) Compile(spec string) (*Pipeline, error) {
	p := &Pipeline{}
	for _, name := range splitSpec(spec) {
		if fn, ok := builtins[name]; ok {
			p.steps = append(p.steps, step{name: name, fn: fn})
			continue
		}
		b, ok := r.custom[name]
		if !ok {
			return nil, fmt.Errorf("unknown transform %q", name)
		}
		p.steps = append(p.steps, step{name: name, batcher: b})
	}
	return p, nil
}

// ValueError is a transform failing on one of a column's values.
type ValueError struct {
	Index int
	Err   error
}

func (e *ValueError) Error() string { return e.Err.Error() }
func (e *ValueError) Unwrap() error { return e.Err }

// Apply runs the pipeline over values, in place, a step at a time. keys[i]
// identifies values[i] to a custom transform's handler, field names the
// field being written. Empty values are left alone. A built-in failing on
// a value returns a *ValueError naming it; a custom one failing fails the
// whole column.
func (p *Pipeline) Apply(ctx context.Context, field string, keys, values []string) error {
	for _, s := range p.steps {
		if s.fn != nil {
			for i, v := range values {
				out, err := s.fn(v)
				if err != nil {
					return &ValueError{Index: i, Err: err}
				}
				values[i] = out
			}
			continue
		}
		if err := s.applyCustom(ctx, field, keys, values); err != nil {
			return err
		}
	}
	return nil
}

func (s step) applyCustom(ctx context.Context, field string, keys, values []string) error {
	var items []hooks.Item
	index := map[string]int{}
	for i, v := range values {
		if v == "" {
			continue
		}
		items = append(items, hooks.Item{Key: keys[i], Data: map[string]string{"transform": s.name, "field": field, "value": v}})
		index[keys[i]] = i
	}
	if len(items) == 0 {
		return nil
	}
	res, err := s.batcher.Resolve(ctx, items)
	if err != nil {
		return err
	}
	if res == nil {
		// The handler failed and its on_failure is ignore: the values go
		// on untransformed.
		return nil
	}
	for k, raw := range res {
		var ans struct {
			Value *string `json:"value"`
		}
		if err := json.Unmarshal(raw, &ans); err != nil {
			return fmt.Errorf("transform %s: answer for %q: %w", s.name, k, err)
		}
		if ans.Value == nil {
			return errors.New("transform " + s.name + ": answer for " + strconv.Quote(k) + " has no value")
		}
		values[index[k]] = *ans.Value
	}
	return nil
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
