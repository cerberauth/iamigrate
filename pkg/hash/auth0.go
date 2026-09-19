package hash

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// Auth0Field names which field of an Auth0 bulk-import user record a
// translated hash belongs under.
type Auth0Field string

const (
	// FieldPasswordHash is Auth0's simple password_hash field: settable
	// only on a user's first import, never on a later upsert.
	FieldPasswordHash Auth0Field = "password_hash"
	// FieldCustomPasswordHash is Auth0's structured custom_password_hash
	// field: updatable on later upserts, required for every algorithm
	// except a plain bcrypt string at the default cost.
	FieldCustomPasswordHash Auth0Field = "custom_password_hash"
)

// Auth0Hash is a translated CMF password ready to attach to an Auth0 bulk
// import user record under Field.
type Auth0Hash struct {
	Field   Auth0Field
	Payload map[string]any
}

var bcryptPrefixRE = regexp.MustCompile(`^\$2[ab]\$10\$`)

const (
	payloadKeyValue     = "value"
	payloadKeyAlgorithm = "algorithm"
	payloadKeyEncoding  = "encoding"
	payloadKeyHash      = "hash"
	encodingUTF8        = "utf8"
)

// ToAuth0 translates a CMF password into the field/payload Auth0's bulk
// user import job expects, per DESIGN.md's hash algorithm mapping
// table. allowPasswordHash should be false whenever the importer might
// need to upsert this user again later, since password_hash can only be
// set once (see DESIGN.md, "Idempotent re-runs").
func ToAuth0(p cmf.Password, allowPasswordHash bool) (Auth0Hash, error) {
	if !p.Portable {
		return Auth0Hash{}, fmt.Errorf("hash: password marked non-portable, cannot translate to Auth0")
	}

	switch p.Algorithm {
	case cmf.AlgBcrypt:
		return translateBcrypt(p, allowPasswordHash)
	case cmf.AlgScrypt:
		return translateScrypt(p)
	case cmf.AlgPBKDF2:
		return translatePBKDF2(p)
	case cmf.AlgArgon2:
		return translateArgon2(p)
	case cmf.AlgMD4, cmf.AlgMD5, cmf.AlgSHA1, cmf.AlgSHA256, cmf.AlgSHA512:
		return translateDigest(p)
	case cmf.AlgHMAC:
		return translateHMAC(p)
	case cmf.AlgLDAP:
		return translateLDAP(p)
	default:
		return Auth0Hash{}, fmt.Errorf("hash: algorithm %q is not one of Auth0's eleven supported custom_password_hash algorithms", p.Algorithm)
	}
}

func translateBcrypt(p cmf.Password, allowPasswordHash bool) (Auth0Hash, error) {
	if allowPasswordHash && bcryptPrefixRE.MatchString(p.Hash.Value) {
		return Auth0Hash{Field: FieldPasswordHash, Payload: map[string]any{payloadKeyValue: p.Hash.Value}}, nil
	}
	if !strings.HasPrefix(p.Hash.Value, "$2a$") && !strings.HasPrefix(p.Hash.Value, "$2b$") && !strings.HasPrefix(p.Hash.Value, "$2y$") {
		return Auth0Hash{}, fmt.Errorf("hash: bcrypt value %q does not have a $2a$/$2b$/$2y$ prefix accepted by Auth0", p.Hash.Value)
	}
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "bcrypt",
			payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: encodingUTF8},
		},
	}, nil
}

func translateScrypt(p cmf.Password) (Auth0Hash, error) {
	keylen, _ := p.Params["keylen"].(int)
	if keylen == 0 {
		return Auth0Hash{}, fmt.Errorf("hash: scrypt requires params.keylen for Auth0")
	}
	cost, _ := p.Params["cost"].(int)
	if cost == 0 || cost&(cost-1) != 0 {
		return Auth0Hash{}, fmt.Errorf("hash: scrypt params.cost must be a power of two, got %v", p.Params["cost"])
	}
	payload := map[string]any{
		payloadKeyAlgorithm: "scrypt",
		payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: string(p.Hash.Encoding)},
	}
	if p.Salt != nil {
		payload["salt"] = map[string]any{payloadKeyValue: p.Salt.Value, payloadKeyEncoding: string(p.Salt.Encoding)}
	}
	return Auth0Hash{Field: FieldCustomPasswordHash, Payload: payload}, nil
}

func translatePBKDF2(p cmf.Password) (Auth0Hash, error) {
	iterations, ok := p.Params["iterations"].(int)
	if !ok || iterations == 0 {
		iterations = 100000
	}
	keylen, ok := p.Params["keylen"].(int)
	if !ok || keylen == 0 {
		keylen = 64
	}
	if p.Salt == nil {
		return Auth0Hash{}, fmt.Errorf("hash: pbkdf2 requires a salt for Auth0")
	}
	digest, _ := p.Params["digest"].(string)
	phc := fmt.Sprintf("$pbkdf2-%s$i=%d,l=%d$%s$%s", digest, iterations, keylen, p.Salt.Value, p.Hash.Value)
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "pbkdf2",
			payloadKeyHash:      map[string]any{payloadKeyValue: phc, payloadKeyEncoding: encodingUTF8},
		},
	}, nil
}

func translateArgon2(p cmf.Password) (Auth0Hash, error) {
	if p.PHCString == "" {
		return Auth0Hash{}, fmt.Errorf("hash: argon2 requires a full PHC string for Auth0 (phc_string is empty)")
	}
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "argon2",
			payloadKeyHash:      map[string]any{payloadKeyValue: p.PHCString, payloadKeyEncoding: encodingUTF8},
		},
	}, nil
}

func translateDigest(p cmf.Password) (Auth0Hash, error) {
	if p.Hash.Encoding != cmf.EncodingHex && p.Hash.Encoding != cmf.EncodingBase64 {
		return Auth0Hash{}, fmt.Errorf("hash: %s requires hash.encoding of hex or base64 for Auth0, got %q", p.Algorithm, p.Hash.Encoding)
	}
	payload := map[string]any{
		payloadKeyAlgorithm: string(p.Algorithm),
		payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: string(p.Hash.Encoding)},
	}
	if p.Salt != nil {
		payload["salt"] = map[string]any{
			payloadKeyValue:    p.Salt.Value,
			payloadKeyEncoding: string(p.Salt.Encoding),
			"position":         string(p.Salt.Position),
		}
	}
	return Auth0Hash{Field: FieldCustomPasswordHash, Payload: payload}, nil
}

func translateHMAC(p cmf.Password) (Auth0Hash, error) {
	if p.Hash.Digest == "" || p.Key == nil || p.Key.Value == "" {
		return Auth0Hash{}, fmt.Errorf("hash: hmac requires hash.digest and key.value for Auth0")
	}
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "hmac",
			payloadKeyHash: map[string]any{
				payloadKeyValue:    p.Hash.Value,
				payloadKeyEncoding: string(p.Hash.Encoding),
				"digest":           p.Hash.Digest,
			},
			"key": map[string]any{payloadKeyValue: p.Key.Value, payloadKeyEncoding: string(p.Key.Encoding)},
		},
	}, nil
}

var ldapCryptRE = regexp.MustCompile(`^\{CRYPT\}`)

func translateLDAP(p cmf.Password) (Auth0Hash, error) {
	if ldapCryptRE.MatchString(p.Hash.Value) {
		return Auth0Hash{}, fmt.Errorf("hash: LDAP {CRYPT} scheme is not supported by Auth0")
	}
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "ldap",
			payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: encodingUTF8},
		},
	}, nil
}
