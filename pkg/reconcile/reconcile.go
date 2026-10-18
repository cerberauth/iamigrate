// Package reconcile drives a target connector's Verify: it reads the CMF
// users, has the connector look each one up and compare it, and builds the
// DiffReport, applying on the way the verify strategies: verify.lookup
// (look users up by the ID the import gave them, built-in target_id, or as
// a handler says) and verify.compare (a handler deciding the drift).
//
// Verify has no mapping argument, so the mapping and the import's target
// IDs travel in the context (see WithOptions), like connector.ChunkStore.
package reconcile

import (
	"context"
	"io"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// Lookup says how to find a user in the target: by TargetID, else by
// Identifier, else (both empty) the connector's own way.
type Lookup struct {
	TargetID   string
	Identifier string
}

// Found is what the connector found of a user: nothing to look it up by,
// no such user, or the target's record and how it differs from the CMF
// user.
type Found struct {
	NoIdentifier bool
	Missing      bool
	Record       any
	Drift        []string
}

// CheckFunc looks u up in the target as l says, and compares it.
type CheckFunc func(ctx context.Context, u cmf.User, l Lookup) (Found, error)

// Options are what Run needs beyond the users: the mapping its strategies
// come from, and the target IDs of the import being verified, by source ID.
type Options struct {
	Mapping   mapping.Mapping
	TargetIDs map[string]string
	// NotImported are the users the import skipped on purpose, by source
	// ID: verify doesn't look for them.
	NotImported map[string]bool
}

// OptionsFor returns the Options of verifying the import report, under
// mapping m.
func OptionsFor(m mapping.Mapping, report *connector.ImportReport) Options {
	o := Options{Mapping: m}
	if report == nil {
		return o
	}
	o.TargetIDs = report.TargetIDs
	for _, e := range report.Skipped {
		if e.Code == SkippedCode {
			if o.NotImported == nil {
				o.NotImported = map[string]bool{}
			}
			o.NotImported[e.SourceID] = true
		}
	}
	return o
}

// SkippedCode is the import report code of a user an import.user hook
// skipped (importprep.SkippedCode, which can't be imported from here).
const SkippedCode = "SKIPPED"

type optionsKey struct{}

// WithOptions returns a context carrying o for Run.
func WithOptions(ctx context.Context, o Options) context.Context {
	return context.WithValue(ctx, optionsKey{}, o)
}

func optionsFrom(ctx context.Context) Options {
	o, _ := ctx.Value(optionsKey{}).(Options)
	return o
}

// Run reconciles the users of r with check, in input order.
func Run(ctx context.Context, r *cmf.Reader, check CheckFunc) (connector.DiffReport, error) {
	var report connector.DiffReport
	opts := optionsFrom(ctx)
	set, err := strategy.New(strategy.Only(opts.Mapping, strategy.VerifyLookup, strategy.VerifyCompare), hooks.FromContext(ctx))
	if err != nil {
		return report, err
	}
	byTargetID := set.Builtin(strategy.VerifyLookup) == strategy.LookupTargetID
	size := max(set.BatchSize(strategy.VerifyLookup), set.BatchSize(strategy.VerifyCompare))
	bar := progress.FromContext(ctx)

	batch := make([]cmf.User, 0, size)
	flush := func() error {
		lookups, err := lookups(ctx, set, batch, opts.TargetIDs, byTargetID)
		if err != nil {
			return err
		}
		founds := make([]Found, len(batch))
		for i, u := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			bar.Add(1)
			if founds[i], err = check(ctx, u, lookups[i]); err != nil {
				return err
			}
		}
		if err := compare(ctx, set, batch, founds); err != nil {
			return err
		}
		for i, u := range batch {
			f := founds[i]
			report.SourceCount++
			switch {
			case f.NoIdentifier:
				report.NoIdentifier = append(report.NoIdentifier, u.SourceID)
			case f.Missing:
				report.MissingInTarget = append(report.MissingInTarget, u.SourceID)
			default:
				report.TargetCount++
				if len(f.Drift) > 0 {
					report.AttributeDrift = append(report.AttributeDrift, connector.DriftEntry{SourceID: u.SourceID, Fields: f.Drift})
				}
			}
		}
		batch = batch[:0]
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		if opts.NotImported[u.SourceID] {
			bar.Add(1)
			report.Skipped = append(report.Skipped, u.SourceID)
			continue
		}
		batch = append(batch, u)
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return report, err
			}
		}
	}
	return report, flush()
}

// lookups decides how to look each user up: by the import's target ID with
// the target_id built-in (for a user the import gave one), or as the
// verify.lookup handler answers.
func lookups(ctx context.Context, set *strategy.Set, users []cmf.User, targetIDs map[string]string, byTargetID bool) ([]Lookup, error) {
	out := make([]Lookup, len(users))
	if byTargetID {
		for i, u := range users {
			out[i].TargetID = targetIDs[u.SourceID]
		}
	}
	if !set.Delegated(strategy.VerifyLookup) {
		return out, nil
	}
	items := make([]hooks.Item, len(users))
	for i, u := range users {
		v := strategy.UserView(u)
		if id := targetIDs[u.SourceID]; id != "" {
			v["target_id"] = id
		}
		items[i] = hooks.Item{Key: u.SourceID, Data: v}
	}
	res, err := set.Resolve(ctx, strategy.VerifyLookup, items)
	if err != nil || res == nil {
		return out, err
	}
	for i, u := range users {
		var a struct {
			TargetID   string `json:"target_id"`
			Identifier string `json:"identifier"`
		}
		if err := strategy.Decode(strategy.VerifyLookup, u.SourceID, res[u.SourceID], &a); err != nil {
			return nil, err
		}
		out[i] = Lookup{TargetID: a.TargetID, Identifier: a.Identifier}
	}
	return out, nil
}

// compare hands the users found, with their target records and the drift
// the connector saw, to verify.compare, which answers the drift instead.
func compare(ctx context.Context, set *strategy.Set, users []cmf.User, founds []Found) error {
	if !set.Delegated(strategy.VerifyCompare) {
		return nil
	}
	var items []hooks.Item
	index := map[string]int{}
	for i, u := range users {
		if f := founds[i]; !f.NoIdentifier && !f.Missing {
			items = append(items, hooks.Item{Key: u.SourceID, Data: map[string]any{
				"user": strategy.UserView(u), "target": f.Record, "drift": f.Drift,
			}})
			index[u.SourceID] = i
		}
	}
	res, err := set.Resolve(ctx, strategy.VerifyCompare, items)
	if err != nil || res == nil {
		return err
	}
	for k, raw := range res {
		var a struct {
			Drift []string `json:"drift"`
		}
		if err := strategy.Decode(strategy.VerifyCompare, k, raw, &a); err != nil {
			return err
		}
		founds[index[k]].Drift = a.Drift
	}
	return nil
}
