package importprep

import (
	"context"
	"fmt"
	"slices"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// checkPrimary checks m's identity.primary built-in against what target can
// make a user's primary identifier: the kind it prefers must be one, or the
// strategy would quietly prefer another. (A handler's answers are checked as
// they come.)
func checkPrimary(m mapping.Mapping, target connector.TargetConnector) error {
	ref, ok := m.Strategies[strategy.IdentityPrimary]
	if !ok {
		return nil
	}
	kinds := target.Capabilities().PrimaryIdentifiers
	if len(kinds) == 0 {
		return fmt.Errorf("mapping: strategies: %s: %s has no primary identifier to choose", strategy.IdentityPrimary, target.Name())
	}
	if ref.Strategy != "" {
		if lead := strategy.PrimaryLead(ref.Strategy); !slices.Contains(kinds, lead) {
			return fmt.Errorf("mapping: strategies: %s: %s: %s can't make the %s its primary identifier (it takes %v)",
				strategy.IdentityPrimary, ref.Strategy, target.Name(), lead, kinds)
		}
	}
	return nil
}

// identityPrimary decides each user's primary identifier, and makes it the
// one the connector reads: the user's Login is set to its kind, and the
// contact it is (the one the handler named, else the one flagged primary)
// moved first in its list, where connectors take it from. A user the
// strategy picks no kind for (no answer, or none of the target's kinds)
// keeps the connector's own pick of kind, with its flagged contacts first.
func (a *Applier) identityPrimary(ctx context.Context, users []cmf.User) error {
	if !a.set.Configured(strategy.IdentityPrimary) {
		return nil
	}
	var items []hooks.Item
	if a.set.Delegated(strategy.IdentityPrimary) {
		items = make([]hooks.Item, len(users))
		for i, u := range users {
			items[i] = hooks.Item{Key: u.SourceID, Data: strategy.UserView(u)}
		}
	}
	res, err := a.set.Resolve(ctx, strategy.IdentityPrimary, items)
	if err != nil {
		return err
	}
	for i := range users {
		u := &users[i]
		kind, value := strategy.BuiltinPrimary(a.set.Builtin(strategy.IdentityPrimary), *u, a.identifiers)
		if raw, ok := res[u.SourceID]; ok {
			var ans struct {
				Identifier cmf.Identifier `json:"identifier"`
				Value      string         `json:"value"`
			}
			if err := strategy.Decode(strategy.IdentityPrimary, u.SourceID, raw, &ans); err != nil {
				return err
			}
			if kind, value, err = answeredPrimary(*u, ans.Identifier, ans.Value, a.identifiers); err != nil {
				return fmt.Errorf("%s: user %s: %w", strategy.IdentityPrimary, u.SourceID, err)
			}
		}
		*u = strategy.ApplyPrimary(*u, kind, value)
	}
	return nil
}

// answeredPrimary resolves a handler's answer: the kind of identifier u
// should be primary on, or the value of one of its identifiers, which names
// the kind too. An empty answer leaves the built-in's choice (none).
func answeredPrimary(u cmf.User, kind cmf.Identifier, value string, allowed []cmf.Identifier) (cmf.Identifier, string, error) {
	switch {
	case kind != "" && value != "":
		return "", "", fmt.Errorf("answer either identifier or value, not both")
	case value != "":
		switch {
		case anyValue(u.Emails, value):
			kind = cmf.IdentifierEmail
		case u.Username == value:
			kind = cmf.IdentifierUsername
		case anyValue(u.Phones, value):
			kind = cmf.IdentifierPhone
		default:
			return "", "", fmt.Errorf("value %q is none of the user's identifiers", value)
		}
	case kind == "":
		return "", "", nil
	case !slices.Contains([]cmf.Identifier{cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone}, kind):
		return "", "", fmt.Errorf("unknown identifier %q (email, username or phone)", kind)
	case !strategy.HasIdentifier(u, kind):
		return "", "", fmt.Errorf("the user has no %s", kind)
	}
	if len(allowed) > 0 && !slices.Contains(allowed, kind) {
		return "", "", fmt.Errorf("the target can't make the %s the primary identifier (it takes %v)", kind, allowed)
	}
	return kind, value, nil
}

func anyValue(cs []cmf.Contact, v string) bool {
	return slices.ContainsFunc(cs, func(c cmf.Contact) bool { return c.Value == v })
}
