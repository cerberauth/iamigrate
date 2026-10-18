package auth0

import (
	"github.com/cerberauth/iamigrate/pkg/connector"

	"maps"

	"github.com/cerberauth/iamigrate/pkg/importprep"
)

// settableFields are the top-level bulk import fields a target field can
// set.
var settableFields = map[string]bool{keyGivenName: true, keyFamilyName: true, keyName: true, keyNickname: true, keyPicture: true}

// CheckTargetField accepts the target_fields paths Import can set: a
// profile field, or a user_metadata or app_metadata key.
func (*Connector) CheckTargetField(path string) error {
	if settableFields[path] {
		return nil
	}
	for _, root := range []string{keyUserMetadata, keyAppMetadata} {
		if _, ok := importprep.Under(path, root); ok {
			return nil
		}
	}
	return importprep.ErrNotSettable(Name, path, "given_name, family_name, name, nickname, picture, user_metadata.<key> and app_metadata.<key>")
}

// applyFields writes resolved target fields into rec, a bulk import record,
// over what buildImportUser put there. Metadata maps are copied before
// they're written to, as rec shares them with the CMF user.
func applyFields(rec map[string]any, fields []importprep.Field) {
	copied := map[string]bool{}
	for _, f := range fields {
		for _, root := range []string{keyUserMetadata, keyAppMetadata} {
			if _, ok := importprep.Under(f.Path, root); ok && !copied[root] {
				if m, ok := rec[root].(map[string]any); ok {
					rec[root] = maps.Clone(m)
				}
				copied[root] = true
			}
		}
		importprep.Set(rec, f.Path, f.Value)
	}
}

// IsConflict reports a user the connection already has.
func (*Connector) IsConflict(e connector.ImportError) bool { return e.Code == DuplicatedUserCode }
