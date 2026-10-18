package kratos

import (
	"github.com/cerberauth/iamigrate/pkg/connector"

	"strings"

	"fmt"

	"github.com/cerberauth/iamigrate/pkg/importprep"
)

// CheckTargetField accepts the target_fields paths Import can set: a trait,
// or a key of the public or admin metadata. The identifier traits are
// iamigrate's own, set from the user's email, username and phone, so a
// target field can't overwrite them.
func (*Connector) CheckTargetField(path string) error {
	if k, ok := importprep.Under(path, "traits"); ok {
		if k == traitEmail || k == traitUsername || k == traitPhone {
			return fmt.Errorf("kratos: %s is an identifier trait, set from the user's %s", path, k)
		}
		return nil
	}
	for _, root := range []string{"metadata_public", "metadata_admin"} {
		if _, ok := importprep.Under(path, root); ok {
			return nil
		}
	}
	return importprep.ErrNotSettable(Name, path, "traits.<key>, metadata_public.<key> and metadata_admin.<key>")
}

// applyFields writes resolved target fields into id, over what buildIdentity
// put there.
func applyFields(id *identity, fields []importprep.Field) {
	for _, f := range fields {
		if k, ok := importprep.Under(f.Path, "traits"); ok {
			id.Traits[k] = f.Value
		} else if k, ok := importprep.Under(f.Path, "metadata_public"); ok {
			if id.MetadataPublic == nil {
				id.MetadataPublic = map[string]any{}
			}
			id.MetadataPublic[k] = f.Value
		} else if k, ok := importprep.Under(f.Path, "metadata_admin"); ok {
			if id.MetadataAdmin == nil {
				id.MetadataAdmin = map[string]any{}
			}
			id.MetadataAdmin[k] = f.Value
		}
	}
}

// IsConflict reports an identity Kratos already has: it answers its
// creation with a 409.
func (*Connector) IsConflict(e connector.ImportError) bool {
	return e.Code == "REQUEST_ERROR" && strings.Contains(e.Message, "status 409")
}
