package strategy

import (
	"context"
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
)

// Validator runs validate.user (more problems per user) and
// validate.dedup_key (more keys two users can't share, on top of the
// emails, usernames and phones validate already compares) over the users
// validate reads, a batch at a time.
type Validator struct {
	set   *Set
	batch []cmf.User
	seen  map[string]string // dedup key -> source ID of its first user
}

// NewValidator returns the Validator of set, nil when neither strategy is
// delegated. A nil *Validator finds nothing.
func NewValidator(set *Set) *Validator {
	if !set.Delegated(ValidateUser) && !set.Delegated(ValidateDedupKey) {
		return nil
	}
	return &Validator{set: set, seen: map[string]string{}}
}

// Add queues u, and returns the problems of the batch it completes, if it
// does.
func (v *Validator) Add(ctx context.Context, u cmf.User) ([]connector.Problem, error) {
	if v == nil {
		return nil, nil
	}
	v.batch = append(v.batch, u)
	if len(v.batch) < max(v.set.BatchSize(ValidateUser), v.set.BatchSize(ValidateDedupKey)) {
		return nil, nil
	}
	return v.Flush(ctx)
}

// Flush returns the problems of the users queued since the last batch.
func (v *Validator) Flush(ctx context.Context) ([]connector.Problem, error) {
	if v == nil || len(v.batch) == 0 {
		return nil, nil
	}
	users := v.batch
	v.batch = nil
	items := make([]hooks.Item, len(users))
	for i, u := range users {
		items[i] = hooks.Item{Key: u.SourceID, Data: UserView(u)}
	}
	userRes, err := v.set.Resolve(ctx, ValidateUser, items)
	if err != nil {
		return nil, err
	}
	keyRes, err := v.set.Resolve(ctx, ValidateDedupKey, items)
	if err != nil {
		return nil, err
	}
	var problems []connector.Problem
	for _, u := range users {
		if raw, ok := userRes[u.SourceID]; ok {
			var a struct {
				Problems []struct {
					Field string `json:"field"`
					Rule  string `json:"rule"`
					Value string `json:"value"`
				} `json:"problems"`
			}
			if err := Decode(ValidateUser, u.SourceID, raw, &a); err != nil {
				return nil, err
			}
			for _, p := range a.Problems {
				problems = append(problems, connector.Problem{SourceID: u.SourceID, Field: p.Field, Rule: p.Rule, Value: p.Value})
			}
		}
		if raw, ok := keyRes[u.SourceID]; ok {
			var a struct {
				Keys []string `json:"keys"`
			}
			if err := Decode(ValidateDedupKey, u.SourceID, raw, &a); err != nil {
				return nil, err
			}
			for _, k := range a.Keys {
				if first, dup := v.seen[k]; dup && first != u.SourceID {
					problems = append(problems, connector.Problem{SourceID: u.SourceID, Field: "dedup_key",
						Rule: fmt.Sprintf("duplicate of %s within file", first), Value: k})
				} else if !dup {
					v.seen[k] = u.SourceID
				}
			}
		}
	}
	return problems, nil
}
