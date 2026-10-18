package auth0

import (
	"context"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
)

// resolution is an org.resolve or role.resolve answer: the Auth0 ID of an
// existing role or organization to use, or the name to match or create it
// by, instead of its CMF name.
type resolution struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// resolveRoles hands roles to the mapping's role.resolve handler, if any,
// and returns them with the names it chose, and the IDs it chose by source
// ID.
func resolveRoles(ctx context.Context, m mapping.Mapping, roles []cmf.Role) ([]cmf.Role, map[string]string, error) {
	items := make([]hooks.Item, len(roles))
	for i, r := range roles {
		items[i] = hooks.Item{Key: r.SourceID, Data: r}
	}
	res, err := resolve(ctx, m, strategy.RoleResolve, items)
	if err != nil || res == nil {
		return roles, nil, err
	}
	ids := map[string]string{}
	out := make([]cmf.Role, len(roles))
	for i, r := range roles {
		a := res[r.SourceID]
		if a.ID != "" {
			ids[r.SourceID] = a.ID
		} else if a.Name != "" {
			r.Name = a.Name
		}
		out[i] = r
	}
	return out, ids, nil
}

// resolveOrgs is resolveRoles for organizations and org.resolve.
func resolveOrgs(ctx context.Context, m mapping.Mapping, orgs []cmf.Organization) ([]cmf.Organization, map[string]string, error) {
	items := make([]hooks.Item, len(orgs))
	for i, o := range orgs {
		items[i] = hooks.Item{Key: o.SourceID, Data: o}
	}
	res, err := resolve(ctx, m, strategy.OrgResolve, items)
	if err != nil || res == nil {
		return orgs, nil, err
	}
	ids := map[string]string{}
	out := make([]cmf.Organization, len(orgs))
	for i, o := range orgs {
		a := res[o.SourceID]
		if a.ID != "" {
			ids[o.SourceID] = a.ID
		} else if a.Name != "" {
			o.Name = a.Name
		}
		out[i] = o
	}
	return out, ids, nil
}

func resolve(ctx context.Context, m mapping.Mapping, name string, items []hooks.Item) (map[string]resolution, error) {
	set, err := strategy.New(strategy.Only(m, name), hooks.FromContext(ctx))
	if err != nil {
		return nil, err
	}
	raw, err := set.Resolve(ctx, name, items)
	if err != nil || raw == nil {
		return nil, err
	}
	out := make(map[string]resolution, len(raw))
	for k, v := range raw {
		var a resolution
		if err := strategy.Decode(name, k, v, &a); err != nil {
			return nil, err
		}
		out[k] = a
	}
	return out, nil
}
