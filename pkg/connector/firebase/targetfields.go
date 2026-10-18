package firebase

import (
	"github.com/cerberauth/iamigrate/pkg/connector"

	"strings"

	"encoding/json"
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/importprep"
)

// fieldDisplayName is the Firebase display name attribute.
const fieldDisplayName = "displayName"

// CheckTargetField accepts the target_fields paths Import can set: the
// display name, the photo URL, or a custom claim whose name Firebase
// doesn't reserve.
func (*Connector) CheckTargetField(path string) error {
	if path == fieldDisplayName || path == "photoUrl" {
		return nil
	}
	if k, ok := importprep.Under(path, "custom_claims"); ok {
		if reservedClaims[k] {
			return fmt.Errorf("firebase: %s: %q is a reserved custom claim name", path, k)
		}
		return nil
	}
	return importprep.ErrNotSettable(Name, path, "displayName, photoUrl and custom_claims.<key>")
}

// applyFields writes resolved target fields into a, over what buildAccount
// put there. Custom claims are merged into the ones from app_metadata, and
// must still fit Firebase's size limit.
func applyFields(a *account, fields []importprep.Field) error {
	claims := map[string]any{}
	setClaims := false
	for _, f := range fields {
		switch f.Path {
		case fieldDisplayName, "photoUrl":
			s, ok := f.Value.(string)
			if !ok {
				return fmt.Errorf("target field %s must be a string", f.Path)
			}
			if f.Path == fieldDisplayName {
				a.DisplayName = s
			} else {
				a.PhotoURL = s
			}
		default:
			if !setClaims && a.CustomAttributes != "" {
				if err := json.Unmarshal([]byte(a.CustomAttributes), &claims); err != nil {
					return err
				}
			}
			k, _ := importprep.Under(f.Path, "custom_claims")
			claims[k], setClaims = f.Value, true
		}
	}
	if setClaims {
		b, err := json.Marshal(claims)
		if err != nil {
			return err
		}
		if len(b) > maxClaimsLen {
			return fmt.Errorf("custom claims are %d bytes with the target fields, over Firebase's %d", len(b), maxClaimsLen)
		}
		a.CustomAttributes = string(b)
	}
	return nil
}

// IsConflict reports an account the project already has: batchCreate
// answers DUPLICATE_LOCAL_ID or DUPLICATE_EMAIL (the emulator, in prose,
// that the localId "belongs to an existing account").
func (*Connector) IsConflict(e connector.ImportError) bool {
	return strings.HasPrefix(e.Code, "DUPLICATE_") || strings.Contains(e.Message, "existing account")
}
