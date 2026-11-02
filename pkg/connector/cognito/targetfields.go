package cognito

import (
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/importprep"
)

// customPrefix starts the name of a custom attribute. Cognito prefixes the
// ones a pool declares with it when it stores them; the schema itself
// decides which exist.
const customPrefix = "custom:"

// settableAttributes are the standard attributes target_fields can set.
// email and phone_number are the user's own, and sub is Cognito's.
var settableAttributes = map[string]bool{
	"address": true, "birthdate": true, "gender": true, "locale": true,
	"middle_name": true, "name": true, "nickname": true, "picture": true,
	"preferred_username": true, "profile": true, "updated_at": true,
	"website": true, "zoneinfo": true, "given_name": true, "family_name": true,
}

// CheckTargetField accepts the target_fields paths Import can set: a
// standard attribute by its name, or a custom attribute as custom:<name>.
// A custom attribute has to be in the pool's schema, which only the pool
// can say.
func (*Connector) CheckTargetField(path string) error {
	if settableAttributes[path] {
		return nil
	}
	if name, ok := strings.CutPrefix(path, customPrefix); ok && name != "" {
		return nil
	}
	return importprep.ErrNotSettable(Name, path, "standard attributes such as name, birthdate or locale, and custom:<name>")
}

// applyFields writes resolved target fields into req, over what buildUser
// put there.
func applyFields(req *createUserRequest, fields []importprep.Field) error {
	for _, f := range fields {
		v, err := attributeValue(f.Value)
		if err != nil {
			return fmt.Errorf("target field %s %w", f.Path, err)
		}
		req.setAttribute(f.Path, v)
	}
	return nil
}

// UsernameExistsCode is the error code of a user the pool already has.
const UsernameExistsCode = "UsernameExistsException"

// IsConflict reports a user the pool already has.
func (*Connector) IsConflict(e connector.ImportError) bool {
	return e.Code == UsernameExistsCode
}
