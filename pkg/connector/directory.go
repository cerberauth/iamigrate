package connector

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/x/fsx"
)

// Directory is the organizations and roles a source exported besides its
// users, whom memberships and global roles tie to them by source ID.
type Directory struct {
	Organizations []cmf.Organization
	Roles         []cmf.Role
}

// DirectorySource is a SourceConnector that can export organizations and
// roles too. Directory returns what its last Export found, nil when that
// export wasn't asked for them.
type DirectorySource interface {
	Directory() *Directory
}

// WriteDirectory writes the organizations and roles src's last export found
// to cmf.OrganizationsFile and cmf.RolesFile in dir, where import reads them
// next to the users file. It writes nothing when src exported none, so an
// export that wasn't asked for them leaves those files alone.
func WriteDirectory(dir string, src SourceConnector) error {
	ds, ok := src.(DirectorySource)
	if !ok {
		return nil
	}
	d := ds.Directory()
	if d == nil {
		return nil
	}
	var orgs, roles bytes.Buffer
	if err := cmf.WriteOrganizations(&orgs, d.Organizations); err != nil {
		return err
	}
	if err := cmf.WriteRoles(&roles, d.Roles); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, cmf.OrganizationsFile), orgs.Bytes()); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, cmf.RolesFile), roles.Bytes())
}

// writeFile writes b to path through a temporary file renamed over it, so a
// crash never leaves a truncated file behind.
func writeFile(path string, b []byte) error {
	part := path + ".part"
	if err := fsx.WriteFile(part, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(part, path); err != nil {
		os.Remove(part)
		return err
	}
	return nil
}

// ReadDirectory reads cmf.OrganizationsFile and cmf.RolesFile from dir,
// each left empty when the file isn't there.
func ReadDirectory(dir string) (Directory, error) {
	var d Directory
	var err error
	if d.Organizations, err = readOptional(filepath.Join(dir, cmf.OrganizationsFile), cmf.ReadOrganizations); err != nil {
		return d, err
	}
	d.Roles, err = readOptional(filepath.Join(dir, cmf.RolesFile), cmf.ReadRoles)
	return d, err
}

func readOptional[T any](path string, read func(io.Reader) ([]T, error)) ([]T, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return read(f)
}
