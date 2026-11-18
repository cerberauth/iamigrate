package flatfile_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func readUsers(t *testing.T, buf *bytes.Buffer) map[string]cmf.User {
	t.Helper()
	r, err := cmf.NewReader(buf)
	require.NoError(t, err)
	defer r.Close()
	out := map[string]cmf.User{}
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		out[u.SourceID] = u
	}
}

func TestExportOrganizationsRolesAndMemberships(t *testing.T) {
	dir := t.TempDir()
	opts := flatfile.ExportOptions{
		Path:   writeFile(t, dir, "users.csv", "id,mail\nu1,a@example.com\nu2,b@example.com\n"),
		Format: flatfile.FormatCSV,
		Organizations: flatfile.File{Format: flatfile.FormatJSON, Path: writeFile(t, dir, "orgs.json",
			`{"data":[{"id":"o1","slug":"acme","title":"Acme Inc","plan":"gold"},{"id":"o2"}]}`)},
		Roles: flatfile.File{Format: flatfile.FormatCSV, Path: writeFile(t, dir, "roles.csv",
			"key,label,about\nadmin,Admin,Does everything\nviewer,,\n")},
		Memberships: flatfile.File{Format: flatfile.FormatCSV, Path: writeFile(t, dir, "members.csv",
			"user,org,role\nu1,o1,admin\nu1,o1,viewer\nu1,o2,\nu1,,admin\nu2,o1,viewer\nghost,o1,admin\n,o1,admin\nu2,,\n")},
		Mapping: mapping.Mapping{
			Fields: []mapping.FieldMapping{{Source: "id", CMF: "source_id"}, {Source: "mail", CMF: "email"}},
			Organizations: &mapping.RecordMapping{RecordsPath: "data", Fields: []mapping.FieldMapping{
				{Source: "id", CMF: "source_id"}, {Source: "slug", CMF: "name"}, {Source: "title", CMF: "display_name", Transform: "uppercase"},
			}},
			Roles: &mapping.RecordMapping{Fields: []mapping.FieldMapping{
				{Source: "key", CMF: "source_id"}, {Source: "label", CMF: "name"}, {Source: "about", CMF: "description"},
			}},
			Memberships: &mapping.RecordMapping{Fields: []mapping.FieldMapping{
				{Source: "user", CMF: "user_id"}, {Source: "org", CMF: "organization"}, {Source: "role", CMF: "role"},
			}},
		},
	}

	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	c := flatfile.New()
	manifest, err := c.Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 2, manifest.RecordCount)
	require.ElementsMatch(t, []connector.SkippedRecord{
		{SourceID: "membership record 7", Reason: "missing user_id"},
		{SourceID: "membership record 8", Reason: "neither an organization nor a role"},
		{SourceID: "ghost", Reason: "memberships name a user that isn't exported"},
	}, manifest.SkippedRecords)

	users := readUsers(t, &buf)
	require.Equal(t, []cmf.Membership{
		{Organization: "o1", Roles: []string{"admin", "viewer"}},
		{Organization: "o2"},
	}, users["u1"].Memberships)
	require.Equal(t, []string{"admin"}, users["u1"].GlobalRoles)
	require.Equal(t, []cmf.Membership{{Organization: "o1", Roles: []string{"viewer"}}}, users["u2"].Memberships)

	d := c.Directory()
	require.NotNil(t, d)
	require.Equal(t, []cmf.Organization{
		{SourceID: "o1", Name: "acme", DisplayName: "ACME INC", Metadata: map[string]any{"plan": "gold"}},
		{SourceID: "o2", Name: "o2"},
	}, d.Organizations)
	require.Equal(t, []cmf.Role{
		{SourceID: "admin", Name: "Admin", Description: "Does everything"},
		{SourceID: "viewer", Name: "viewer"},
	}, d.Roles)
}

func TestExportWithoutDirectoryFilesHasNoDirectory(t *testing.T) {
	dir := t.TempDir()
	c := flatfile.New()
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	_, err := c.Export(context.Background(), w, flatfile.ExportOptions{
		Path: writeFile(t, dir, "users.csv", "source_id\nu1\n"), Format: flatfile.FormatCSV,
	})
	require.NoError(t, err)
	require.Nil(t, c.Directory())
}

func TestExportDirectoryMappingErrors(t *testing.T) {
	dir := t.TempDir()
	users := writeFile(t, dir, "users.csv", "source_id\nu1\n")
	orgs := writeFile(t, dir, "orgs.csv", "source_id\no1\no1\n")
	for name, c := range map[string]struct {
		opts flatfile.ExportOptions
		err  string
	}{
		"unknown field": {
			opts: flatfile.ExportOptions{Memberships: flatfile.File{Path: orgs, Format: flatfile.FormatCSV}, Mapping: mapping.Mapping{
				Memberships: &mapping.RecordMapping{Fields: []mapping.FieldMapping{{Source: "source_id", CMF: "email"}}},
			}},
			err: `mapping: memberships.fields[0]: unknown cmf field "email" (one of user_id, organization, role)`,
		},
		"duplicate organization": {
			opts: flatfile.ExportOptions{Organizations: flatfile.File{Path: orgs, Format: flatfile.FormatCSV}},
			err:  `more than one organization has source_id "o1"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c.opts.Path, c.opts.Format = users, flatfile.FormatCSV
			_, err := flatfile.New().Export(context.Background(), cmf.NewPlainWriter(io.Discard), c.opts)
			require.ErrorContains(t, err, c.err)
		})
	}
}

func TestWriteDirectory(t *testing.T) {
	dir := t.TempDir()
	c := flatfile.New()
	_, err := c.Export(context.Background(), cmf.NewPlainWriter(io.Discard), flatfile.ExportOptions{
		Path: writeFile(t, dir, "users.csv", "source_id\nu1\n"), Format: flatfile.FormatCSV,
		Roles: flatfile.File{Path: writeFile(t, dir, "roles.csv", "source_id,name\nr1,Reader\n"), Format: flatfile.FormatCSV},
	})
	require.NoError(t, err)

	out := t.TempDir()
	require.NoError(t, connector.WriteDirectory(out, c))
	d, err := connector.ReadDirectory(out)
	require.NoError(t, err)
	require.Empty(t, d.Organizations)
	require.Equal(t, []cmf.Role{{SourceID: "r1", Name: "Reader"}}, d.Roles)
	_, err = os.Stat(filepath.Join(out, cmf.OrganizationsFile))
	require.NoError(t, err, "an export with a directory writes both files")

	empty := t.TempDir()
	require.NoError(t, connector.WriteDirectory(empty, flatfile.New()))
	_, err = os.Stat(filepath.Join(empty, cmf.RolesFile))
	require.ErrorIs(t, err, os.ErrNotExist)
}
