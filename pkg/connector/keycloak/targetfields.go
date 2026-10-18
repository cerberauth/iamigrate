package keycloak

import (
	"github.com/cerberauth/iamigrate/pkg/connector"

	"encoding/json"

	"github.com/cerberauth/iamigrate/pkg/importprep"
)

// CheckTargetField accepts the target_fields paths Import can set: the first
// and last name, or a user attribute.
func (*Connector) CheckTargetField(path string) error {
	if path == attrFirstName || path == attrLastName {
		return nil
	}
	if _, ok := importprep.Under(path, "attributes"); ok {
		return nil
	}
	return importprep.ErrNotSettable(Name, path, "firstName, lastName and attributes.<key>")
}

// applyFields writes resolved target fields into rep, over what buildUser
// put there. Keycloak attributes are lists of strings: a value is the one
// element of its list, a non-string one in JSON.
func applyFields(rep *userRepresentation, fields []importprep.Field) {
	for _, f := range fields {
		v, ok := f.Value.(string)
		if !ok {
			b, _ := json.Marshal(f.Value)
			v = string(b)
		}
		switch f.Path {
		case attrFirstName:
			rep.FirstName = v
		case "lastName":
			rep.LastName = v
		default:
			k, _ := importprep.Under(f.Path, "attributes")
			if rep.Attributes == nil {
				rep.Attributes = map[string][]string{}
			}
			rep.Attributes[k] = []string{v}
		}
	}
}

// IsConflict reports a user the realm already has.
func (*Connector) IsConflict(e connector.ImportError) bool { return e.Code == UserExistsCode }
