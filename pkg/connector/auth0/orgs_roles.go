package auth0

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// RunOrgsRolesPhase implements DESIGN.md's post-import organizations/
// roles/memberships steps 1-5. It assumes every source_id in roleInfos
// that also appears in userIDs was successfully imported and that
// userIDs[source_id] is that user's Auth0 user_id.
//
// Auth0 has no bulk endpoint for any of this, so each step is its own
// Management API call, run through a bounded, rate-limit-aware worker
// pool (see pool.go) since steps 3-5 are O(users x memberships).
func RunOrgsRolesPhase(
	ctx context.Context,
	client *Client,
	roles []cmf.Role,
	orgs []cmf.Organization,
	roleInfos []userRoleInfo,
	userIDs map[string]string,
	concurrency int,
) (connector.ImportReport, error) {
	report := connector.ImportReport{
		OrgIDMap:  map[string]string{},
		RoleIDMap: map[string]string{},
	}

	// Step 1: roles, matched by name (no source_id round-trip on Auth0's
	// side, per the design doc).
	existingRoles, err := listRolesByName(ctx, client)
	if err != nil {
		return report, err
	}
	for _, role := range roles {
		if id, ok := existingRoles[role.Name]; ok {
			report.RoleIDMap[role.SourceID] = id
			continue
		}
		id, err := createRole(ctx, client, role)
		if err != nil {
			return report, fmt.Errorf("auth0: creating role %q: %w", role.Name, err)
		}
		report.RoleIDMap[role.SourceID] = id
	}

	// Step 2: organizations, matched by name.
	existingOrgs, err := listOrgsByName(ctx, client)
	if err != nil {
		return report, err
	}
	for _, org := range orgs {
		if id, ok := existingOrgs[org.Name]; ok {
			report.OrgIDMap[org.SourceID] = id
			continue
		}
		id, err := createOrg(ctx, client, org)
		if err != nil {
			return report, fmt.Errorf("auth0: creating organization %q: %w", org.Name, err)
		}
		report.OrgIDMap[org.SourceID] = id
	}

	// Steps 3-5: memberships and role assignments, one call per
	// user-per-organization (and one per user for global roles).
	var tasks []poolTask
	for _, info := range roleInfos {
		info := info
		userID, ok := userIDs[info.SourceID]
		if !ok {
			continue // user wasn't successfully imported; skip role/org assignment
		}

		for _, m := range info.Memberships {
			m := m
			orgID, ok := report.OrgIDMap[m.Organization]
			if !ok {
				continue
			}
			tasks = append(tasks, func(ctx context.Context) (RateLimit, error) {
				return addOrgMember(ctx, client, orgID, userID)
			})
			if len(m.Roles) > 0 {
				roleIDs := resolveRoleIDs(report.RoleIDMap, m.Roles)
				tasks = append(tasks, func(ctx context.Context) (RateLimit, error) {
					return assignOrgMemberRoles(ctx, client, orgID, userID, roleIDs)
				})
			}
		}

		if len(info.GlobalRoles) > 0 {
			roleIDs := resolveRoleIDs(report.RoleIDMap, info.GlobalRoles)
			tasks = append(tasks, func(ctx context.Context) (RateLimit, error) {
				return assignUserRoles(ctx, client, userID, roleIDs)
			})
		}
	}

	errs := runPool(ctx, concurrency, tasks)
	for _, err := range errs {
		if err != nil {
			report.Failed = append(report.Failed, connector.ImportError{Code: "ROLE_ORG_PHASE_ERROR", Message: err.Error()})
		}
	}
	return report, nil
}

func resolveRoleIDs(roleIDMap map[string]string, sourceIDs []string) []string {
	ids := make([]string, 0, len(sourceIDs))
	for _, sid := range sourceIDs {
		if id, ok := roleIDMap[sid]; ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func listRolesByName(ctx context.Context, client *Client) (map[string]string, error) {
	var raw []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := client.doJSON(ctx, http.MethodGet, "/roles?per_page=100", nil, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for _, r := range raw {
		out[r.Name] = r.ID
	}
	return out, nil
}

func createRole(ctx context.Context, client *Client, role cmf.Role) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": role.Name, "description": role.Description}
	if _, err := client.doJSON(ctx, http.MethodPost, "/roles", body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func listOrgsByName(ctx context.Context, client *Client) (map[string]string, error) {
	var raw []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := client.doJSON(ctx, http.MethodGet, "/organizations?per_page=100", nil, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for _, o := range raw {
		out[o.Name] = o.ID
	}
	return out, nil
}

func createOrg(ctx context.Context, client *Client, org cmf.Organization) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": org.Name, "display_name": org.DisplayName}
	if len(org.Metadata) > 0 {
		body["metadata"] = org.Metadata
	}
	if _, err := client.doJSON(ctx, http.MethodPost, "/organizations", body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func addOrgMember(ctx context.Context, client *Client, orgID, userID string) (RateLimit, error) {
	body := map[string]any{"members": []string{userID}}
	return client.doJSON(ctx, http.MethodPost, "/organizations/"+orgID+"/members", body, nil)
}

func assignOrgMemberRoles(ctx context.Context, client *Client, orgID, userID string, roleIDs []string) (RateLimit, error) {
	if len(roleIDs) == 0 {
		return RateLimit{}, nil
	}
	body := map[string]any{"roles": roleIDs}
	return client.doJSON(ctx, http.MethodPost, "/organizations/"+orgID+"/members/"+userID+"/roles", body, nil)
}

func assignUserRoles(ctx context.Context, client *Client, userID string, roleIDs []string) (RateLimit, error) {
	if len(roleIDs) == 0 {
		return RateLimit{}, nil
	}
	body := map[string]any{"roles": roleIDs}
	return client.doJSON(ctx, http.MethodPost, "/users/"+userID+"/roles", body, nil)
}
