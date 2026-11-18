package flatfile

import (
	"context"
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// File is one more source file of an export besides the users'.
type File struct {
	Path   string
	Format Format
}

// The cmf fields of the organizations, roles and memberships files.
const (
	colName        = "name"
	colDisplayName = "display_name"
	colDescription = "description"
	colUserID      = "user_id"
	colOrg         = "organization"
	colRole        = "role"

	orgMetadataPrefix = "metadata."
)

var (
	orgFields = fieldSchema{
		section: "organizations.fields",
		valid: func(f string) bool {
			return f == colSourceID || f == colName || f == colDisplayName ||
				(strings.HasPrefix(f, orgMetadataPrefix) && len(f) > len(orgMetadataPrefix))
		},
		known: "one of source_id, name, display_name, or metadata.<key>",
	}
	roleFields = fieldSchema{
		section: "roles.fields",
		valid:   func(f string) bool { return f == colSourceID || f == colName || f == colDescription },
		known:   "one of source_id, name, description",
	}
	membershipFields = fieldSchema{
		section: "memberships.fields",
		valid:   func(f string) bool { return f == colUserID || f == colOrg || f == colRole },
		known:   "one of user_id, organization, role",
	}
)

// records reads f and maps its rows through rm per schema. It returns no
// rows when f names no file.
func records(ctx context.Context, f File, rm *mapping.RecordMapping, schema fieldSchema, m mapping.Mapping) ([]map[string]string, error) {
	if f.Path == "" {
		return nil, nil
	}
	if rm == nil {
		rm = &mapping.RecordMapping{}
	}
	rows, err := readRows(f.Path, f.Format, rm.RecordsPath)
	if err != nil {
		return nil, err
	}
	return applyFields(ctx, rows, rm.Fields, schema, m, hooks.FromContext(ctx))
}

// readOrganizations reads the organizations file: a source_id each, a name
// (the source ID when it has none), a display name, and the rest of its
// columns as metadata.
func readOrganizations(ctx context.Context, f File, m mapping.Mapping) ([]cmf.Organization, []connector.SkippedRecord, error) {
	rows, err := records(ctx, f, m.Organizations, orgFields, m)
	if err != nil {
		return nil, nil, err
	}
	var orgs []cmf.Organization
	var skipped []connector.SkippedRecord
	seen := map[string]bool{}
	for i, row := range rows {
		id := row[colSourceID]
		if id == "" {
			skipped = append(skipped, connector.SkippedRecord{SourceID: fmt.Sprintf("organization record %d", i+1), Reason: reasonMissingSourceID})
			continue
		}
		if seen[id] {
			return nil, nil, fmt.Errorf("flatfile: %s: more than one organization has source_id %q", f.Path, id)
		}
		seen[id] = true
		o := cmf.Organization{SourceID: id, Name: row[colName], DisplayName: row[colDisplayName]}
		if o.Name == "" {
			o.Name = id
		}
		for k, v := range row {
			if v == "" || k == colSourceID || k == colName || k == colDisplayName {
				continue
			}
			if o.Metadata == nil {
				o.Metadata = map[string]any{}
			}
			o.Metadata[strings.TrimPrefix(k, orgMetadataPrefix)] = v
		}
		orgs = append(orgs, o)
	}
	return orgs, skipped, nil
}

// readRoles reads the roles file: a source_id each, a name (the source ID
// when it has none) and a description. Other columns are left out, as CMF
// roles have nowhere to keep them.
func readRoles(ctx context.Context, f File, m mapping.Mapping) ([]cmf.Role, []connector.SkippedRecord, error) {
	rows, err := records(ctx, f, m.Roles, roleFields, m)
	if err != nil {
		return nil, nil, err
	}
	var roles []cmf.Role
	var skipped []connector.SkippedRecord
	seen := map[string]bool{}
	for i, row := range rows {
		id := row[colSourceID]
		if id == "" {
			skipped = append(skipped, connector.SkippedRecord{SourceID: fmt.Sprintf("role record %d", i+1), Reason: reasonMissingSourceID})
			continue
		}
		if seen[id] {
			return nil, nil, fmt.Errorf("flatfile: %s: more than one role has source_id %q", f.Path, id)
		}
		seen[id] = true
		r := cmf.Role{SourceID: id, Name: row[colName], Description: row[colDescription]}
		if r.Name == "" {
			r.Name = id
		}
		roles = append(roles, r)
	}
	return roles, skipped, nil
}

// Grants is what memberships give users: by user source ID, the
// organizations they belong to, with their roles in each, and the roles they
// hold outside any organization. Rows are joined in the order they come.
type Grants struct {
	byUser map[string]*grant
	order  []string
	used   map[string]bool
}

type grant struct {
	memberships []cmf.Membership
	globalRoles []string
}

// NewGrants returns an empty Grants.
func NewGrants() *Grants {
	return &Grants{byUser: map[string]*grant{}, used: map[string]bool{}}
}

// Add records that user belongs to organization with role: either may be
// empty, but not both. Without an organization, role is a global role;
// without a role, the user is a member with no role in organization.
func (g *Grants) Add(user, organization, role string) {
	gr := g.byUser[user]
	if gr == nil {
		gr = &grant{}
		g.byUser[user] = gr
		g.order = append(g.order, user)
	}
	if organization == "" {
		gr.globalRoles = appendUnique(gr.globalRoles, role)
		return
	}
	for i := range gr.memberships {
		if gr.memberships[i].Organization == organization {
			if role != "" {
				gr.memberships[i].Roles = appendUnique(gr.memberships[i].Roles, role)
			}
			return
		}
	}
	m := cmf.Membership{Organization: organization}
	if role != "" {
		m.Roles = []string{role}
	}
	gr.memberships = append(gr.memberships, m)
}

// Apply gives u the memberships and global roles recorded for its source
// ID, and notes it was found.
func (g *Grants) Apply(u *cmf.User) {
	gr := g.byUser[u.SourceID]
	if gr == nil {
		return
	}
	g.used[u.SourceID] = true
	u.Memberships = append(u.Memberships, gr.memberships...)
	for _, r := range gr.globalRoles {
		u.GlobalRoles = appendUnique(u.GlobalRoles, r)
	}
}

// Unused reports, as skipped records, the users memberships were recorded
// for that no exported user had: unknown to the source, or skipped.
func (g *Grants) Unused() []connector.SkippedRecord {
	var out []connector.SkippedRecord
	for _, id := range g.order {
		if !g.used[id] {
			out = append(out, connector.SkippedRecord{SourceID: id, Reason: "memberships name a user that isn't exported"})
		}
	}
	return out
}

// readMemberships reads the memberships file, a user_id and an organization,
// a role or both on each row, into Grants.
func readMemberships(ctx context.Context, f File, m mapping.Mapping) (*Grants, []connector.SkippedRecord, error) {
	rows, err := records(ctx, f, m.Memberships, membershipFields, m)
	if err != nil {
		return nil, nil, err
	}
	g := NewGrants()
	var skipped []connector.SkippedRecord
	for i, row := range rows {
		key := fmt.Sprintf("membership record %d", i+1)
		switch {
		case row[colUserID] == "":
			skipped = append(skipped, connector.SkippedRecord{SourceID: key, Reason: "missing user_id"})
		case row[colOrg] == "" && row[colRole] == "":
			skipped = append(skipped, connector.SkippedRecord{SourceID: key, Reason: "neither an organization nor a role"})
		default:
			g.Add(row[colUserID], row[colOrg], row[colRole])
		}
	}
	return g, skipped, nil
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// readDirectory reads the organizations, roles and memberships files opts
// names. dir is nil when it names none of them.
func readDirectory(ctx context.Context, opts ExportOptions) (dir *connector.Directory, grants *Grants, skipped []connector.SkippedRecord, err error) {
	if opts.Organizations.Path == "" && opts.Roles.Path == "" && opts.Memberships.Path == "" {
		return nil, nil, nil, nil
	}
	dir = &connector.Directory{}
	var s []connector.SkippedRecord
	if dir.Organizations, s, err = readOrganizations(ctx, opts.Organizations, opts.Mapping); err != nil {
		return nil, nil, nil, err
	}
	skipped = append(skipped, s...)
	if dir.Roles, s, err = readRoles(ctx, opts.Roles, opts.Mapping); err != nil {
		return nil, nil, nil, err
	}
	skipped = append(skipped, s...)
	if grants, s, err = readMemberships(ctx, opts.Memberships, opts.Mapping); err != nil {
		return nil, nil, nil, err
	}
	return dir, grants, append(skipped, s...), nil
}
