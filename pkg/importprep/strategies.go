package importprep

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// importStrategies are the strategies an Applier runs.
var importStrategies = []string{strategy.ImportUser, strategy.IdentityPrimary, strategy.HashTranslate, strategy.MFATranslate, strategy.ImportPayload}

// routeDrop is the metadata route destination that leaves a key out.
const routeDrop = "drop"

// keySourceID is the item data key holding a user's source ID.
const keySourceID = "source_id"

// SkippedCode is the ImportError code of a user import.user skipped.
const SkippedCode = reconcile.SkippedCode

// prepare runs, over users, import.user, identity.primary, hash.translate, mfa.translate, the
// metadata routes and the target fields, in that order, and returns the
// users left with their fields, and those import.user skipped.
func (a *Applier) prepare(ctx context.Context, users []cmf.User) ([]cmf.User, [][]Field, []connector.ImportError, error) {
	users, skipped, err := a.importUser(ctx, users)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := a.identityPrimary(ctx, users); err != nil {
		return nil, nil, nil, err
	}
	if err := a.hashTranslate(ctx, users); err != nil {
		return nil, nil, nil, err
	}
	if err := a.mfaTranslate(ctx, users); err != nil {
		return nil, nil, nil, err
	}
	routed := a.route(users)
	fields, err := a.Resolve(ctx, users)
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range fields {
		// Target fields come after the routes, so they win on a shared path.
		fields[i] = append(routed[i], fields[i]...)
	}
	return users, fields, skipped, nil
}

func (a *Applier) importUser(ctx context.Context, users []cmf.User) ([]cmf.User, []connector.ImportError, error) {
	items := make([]hooks.Item, len(users))
	for i, u := range users {
		items[i] = hooks.Item{Key: u.SourceID, Data: strategy.UserView(u)}
	}
	res, err := a.set.Resolve(ctx, strategy.ImportUser, items)
	if err != nil || res == nil {
		return users, nil, err
	}
	var kept []cmf.User
	var skipped []connector.ImportError
	for _, u := range users {
		var ans strategy.UserAnswer
		if err := strategy.Decode(strategy.ImportUser, u.SourceID, res[u.SourceID], &ans); err != nil {
			return nil, nil, err
		}
		nu, keep, err := ans.Apply(u)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: user %s: %w", strategy.ImportUser, u.SourceID, err)
		}
		if !keep {
			reason := ans.Reason
			if reason == "" {
				reason = "skipped by the " + strategy.ImportUser + " hook"
			}
			skipped = append(skipped, connector.ImportError{SourceID: u.SourceID, Code: SkippedCode, Message: reason})
			continue
		}
		kept = append(kept, nu)
	}
	return kept, skipped, nil
}

// hashTranslate hands each password to hash.translate, which answers a
// replacement CMF password, or {"reset": true} to import none and have the
// user reset it: the password is then marked non-portable, which every
// connector already treats that way.
func (a *Applier) hashTranslate(ctx context.Context, users []cmf.User) error {
	var items []hooks.Item
	for _, u := range users {
		if u.Password != nil {
			items = append(items, hooks.Item{Key: u.SourceID, Data: map[string]any{keySourceID: u.SourceID, "password": u.Password}})
		}
	}
	res, err := a.set.Resolve(ctx, strategy.HashTranslate, items)
	if err != nil || res == nil {
		return err
	}
	for i, u := range users {
		raw, ok := res[u.SourceID]
		if !ok {
			continue
		}
		var ans struct {
			Password *cmf.Password `json:"password"`
			Reset    bool          `json:"reset"`
		}
		if err := strategy.Decode(strategy.HashTranslate, u.SourceID, raw, &ans); err != nil {
			return err
		}
		switch {
		case ans.Reset:
			p := *u.Password
			p.Portable = false
			users[i].Password = &p
		case ans.Password != nil:
			users[i].Password = ans.Password
		}
	}
	return nil
}

// mfaTranslate hands each user's MFA factors to mfa.translate, which
// answers the factors to import instead.
func (a *Applier) mfaTranslate(ctx context.Context, users []cmf.User) error {
	var items []hooks.Item
	for _, u := range users {
		if len(u.MFAFactors) > 0 {
			items = append(items, hooks.Item{Key: u.SourceID, Data: map[string]any{keySourceID: u.SourceID, "mfa_factors": u.MFAFactors}})
		}
	}
	res, err := a.set.Resolve(ctx, strategy.MFATranslate, items)
	if err != nil || res == nil {
		return err
	}
	for i, u := range users {
		raw, ok := res[u.SourceID]
		if !ok {
			continue
		}
		var ans struct {
			MFAFactors *[]cmf.MFAFactor `json:"mfa_factors"`
		}
		if err := strategy.Decode(strategy.MFATranslate, u.SourceID, raw, &ans); err != nil {
			return err
		}
		if ans.MFAFactors != nil {
			users[i].MFAFactors = *ans.MFAFactors
		}
	}
	return nil
}

// route takes the routed metadata keys out of each user, where the
// connector would place them by default, and returns them as fields at
// their destination (none for a dropped key).
func (a *Applier) route(users []cmf.User) [][]Field {
	out := make([][]Field, len(users))
	if len(a.routes) == 0 {
		return out
	}
	for i := range users {
		u := &users[i]
		u.AppMetadata, u.UserMetadata = maps.Clone(u.AppMetadata), maps.Clone(u.UserMetadata)
		for _, r := range a.routes {
			from := u.UserMetadata
			if r.From == "app_metadata" {
				from = u.AppMetadata
			}
			v, ok := from[r.Key]
			if !ok {
				continue
			}
			delete(from, r.Key)
			if r.Destination != routeDrop && !empty(v) {
				out[i] = append(out[i], Field{Path: r.Destination, Value: v})
			}
		}
	}
	return out
}

// Payloads is the Applier's Payloads, for a connector holding the Reader.
func (r *Reader) Payloads(ctx context.Context, sourceIDs []string, payloads []any) ([]any, error) {
	return r.a.Payloads(ctx, sourceIDs, payloads)
}

// Payloads hands the payloads the connector built for a batch of users,
// sourceIDs[i]'s being payloads[i], to import.payload, and returns those to
// send: the handler's {"payload": ...} as raw JSON where it answers one,
// else the connector's. With no import.payload it returns payloads as is.
func (a *Applier) Payloads(ctx context.Context, sourceIDs []string, payloads []any) ([]any, error) {
	if a == nil || !a.set.Delegated(strategy.ImportPayload) {
		return payloads, nil
	}
	items := make([]hooks.Item, len(payloads))
	for i, p := range payloads {
		items[i] = hooks.Item{Key: sourceIDs[i], Data: map[string]any{keySourceID: sourceIDs[i], "payload": p}}
	}
	res, err := a.set.Resolve(ctx, strategy.ImportPayload, items)
	if err != nil || res == nil {
		return payloads, err
	}
	out := make([]any, len(payloads))
	for i, p := range payloads {
		var ans struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := strategy.Decode(strategy.ImportPayload, sourceIDs[i], res[sourceIDs[i]], &ans); err != nil {
			return nil, err
		}
		out[i] = p
		if len(ans.Payload) > 0 && string(ans.Payload) != "null" {
			out[i] = ans.Payload
		}
	}
	return out, nil
}

// Conflicts applies m's conflict.on_duplicate to a finished import's
// report: with skip, the users target says it already had move from Failed
// to Skipped. (fail is the report as is; upsert is applied before, as the
// import's Upsert option, see Upsert.)
func Conflicts(m mapping.Mapping, target connector.TargetConnector, report *connector.ImportReport) {
	cd, ok := target.(connector.ConflictDetector)
	if m.Conflict == nil || m.Conflict.OnDuplicate != mapping.OnDuplicateSkip || !ok {
		return
	}
	failed := report.Failed[:0:0]
	for _, e := range report.Failed {
		if cd.IsConflict(e) {
			report.Skipped = append(report.Skipped, e)
		} else {
			failed = append(failed, e)
		}
	}
	report.Failed = failed
}

// Upsert returns the import's Upsert option under m's conflict section:
// upsert turns it on, otherwise flag (--upsert) decides.
func Upsert(m mapping.Mapping, flag bool) bool {
	return flag || (m.Conflict != nil && m.Conflict.OnDuplicate == mapping.OnDuplicateUpsert)
}
