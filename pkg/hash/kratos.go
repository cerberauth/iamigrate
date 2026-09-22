package hash

import (
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// ToKratosHashedPassword translates a CMF password into the string Ory
// Kratos' Admin API accepts under credentials.password.config.hashed_password
// when importing an identity. Kratos' importer only recognizes bcrypt
// hashes and argon2id PHC strings (see Kratos' hash comparator), so every
// other CMF algorithm is rejected here rather than silently mistranslated.
func ToKratosHashedPassword(p cmf.Password) (string, error) {
	if !p.Portable {
		return "", fmt.Errorf("hash: password marked non-portable, cannot translate to Kratos")
	}

	switch p.Algorithm {
	case cmf.AlgBcrypt:
		if !strings.HasPrefix(p.Hash.Value, "$2a$") && !strings.HasPrefix(p.Hash.Value, "$2b$") && !strings.HasPrefix(p.Hash.Value, "$2y$") {
			return "", fmt.Errorf("hash: bcrypt value %q does not have a $2a$/$2b$/$2y$ prefix accepted by Kratos", p.Hash.Value)
		}
		return p.Hash.Value, nil
	case cmf.AlgArgon2:
		if p.PHCString == "" {
			return "", fmt.Errorf("hash: argon2 requires a full PHC string for Kratos (phc_string is empty)")
		}
		if !strings.HasPrefix(p.PHCString, "$argon2id$") {
			return "", fmt.Errorf("hash: Kratos only imports argon2id, got PHC string %q", p.PHCString)
		}
		return p.PHCString, nil
	default:
		return "", fmt.Errorf("hash: algorithm %q is not one of Kratos' supported import hashers (bcrypt, argon2id)", p.Algorithm)
	}
}

// NormalizeKratosHashedPassword is the export-side inverse of
// ToKratosHashedPassword: it turns the hashed_password string Kratos'
// Admin API returns back into a CMF password object, using pkg/hash's
// existing format detection (bcrypt/argon2 both have self-describing
// prefixes, so no Hint is needed).
func NormalizeKratosHashedPassword(hashed string) (cmf.Password, error) {
	return Normalize(hashed, Hint{})
}
