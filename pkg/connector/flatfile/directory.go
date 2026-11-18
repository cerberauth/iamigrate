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

// mapRecords maps rows through rm per schema.
func mapRecords(ctx context.Context, rows []map[string]string, rm *mapping.RecordMapping, schema fieldSchema, m mapping.Mapping) ([]map[string]string, error) {
	if rm == nil || len(rows) == 0 {
		return rows, nil
	}
	return applyFields(ctx, rows, 0, rm.Fields, schema, m, hooks.FromContext(ctx))
}

// readFile reads f's records, found at rm's records path in JSON; none when
// f names no file.
func readFile(f File, rm *mapping.RecordMapping) ([]map[string]string, error) {
	if f.Path == "" {
		return nil, nil
	}
	var recordsPath string
	if rm != nil {
		recordsPath = rm.RecordsPath
	}
	return readRows(f.Path, f.Format, recordsPath)
}

// mapOrganizations maps organization records: a source_id each, a name
// (the source ID when it has none), a display name, and the rest of their
// columns as metadata.
func mapOrganizations(ctx context.Context, rows []map[string]string, m mapping.Mapping) ([]cmf.Organization, []connector.SkippedRecord, error) {
	rows, err := mapRecords(ctx, rows, m.Organizations, orgFields, m)
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
			return nil, nil, fmt.Errorf("flatfile: more than one organization has source_id %q", id)
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

// mapRoles maps role records: a source_id each, a name (the source ID when
// it has none) and a description. Other columns are left out, as CMF roles
// have nowhere to keep them.
func mapRoles(ctx context.Context, rows []map[string]string, m mapping.Mapping) ([]cmf.Role, []connector.SkippedRecord, error) {
	rows, err := mapRecords(ctx, rows, m.Roles, roleFields, m)
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
			return nil, nil, fmt.Errorf("flatfile: more than one role has source_id %q", id)
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

// mapMemberships maps membership records, a user_id and an organization, a
// role or both on each, into Grants.
func mapMemberships(ctx context.Context, rows []map[string]string, m mapping.Mapping) (*Grants, []connector.SkippedRecord, error) {
	rows, err := mapRecords(ctx, rows, m.Memberships, membershipFields, m)
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

// readDirectoryFiles reads the organizations, roles and memberships files
// opts names; nil when it names none of them.
func readDirectoryFiles(opts ExportOptions) (*DirectoryRows, error) {
	if opts.Organizations.Path == "" && opts.Roles.Path == "" && opts.Memberships.Path == "" {
		return nil, nil
	}
	m := opts.Mapping
	var d DirectoryRows
	var err error
	if d.Organizations, err = readFile(opts.Organizations, m.Organizations); err != nil {
		return nil, err
	}
	if d.Roles, err = readFile(opts.Roles, m.Roles); err != nil {
		return nil, err
	}
	if d.Memberships, err = readFile(opts.Memberships, m.Memberships); err != nil {
		return nil, err
	}
	return &d, nil
}

// mapDirectory maps the records of d through m.
func mapDirectory(ctx context.Context, d DirectoryRows, m mapping.Mapping) (dir *connector.Directory, grants *Grants, skipped []connector.SkippedRecord, err error) {
	dir = &connector.Directory{}
	var s []connector.SkippedRecord
	if dir.Organizations, s, err = mapOrganizations(ctx, d.Organizations, m); err != nil {
		return nil, nil, nil, err
	}
	skipped = append(skipped, s...)
	if dir.Roles, s, err = mapRoles(ctx, d.Roles, m); err != nil {
		return nil, nil, nil, err
	}
	skipped = append(skipped, s...)
	if grants, s, err = mapMemberships(ctx, d.Memberships, m); err != nil {
		return nil, nil, nil, err
	}
	return dir, grants, append(skipped, s...), nil
}
