package hash

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"slices"
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

// intParam reads an integer CMF param. Params built in-process hold int,
// but params decoded from a CMF file hold float64 (encoding/json's
// default for numbers), so both must be accepted.
func intParam(params map[string]any, key string) (int, bool) {
	switch v := params[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != math.Trunc(v) {
			return 0, false
		}
		return int(v), true
	default:
		return 0, false
	}
}

func translateScrypt(p cmf.Password) (Auth0Hash, error) {
	if p.Params["variant"] == firebaseVariant {
		return Auth0Hash{}, fmt.Errorf("hash: Firebase's modified scrypt is not one of Auth0's custom_password_hash algorithms")
	}
	if p.Hash.Encoding != cmf.EncodingHex && p.Hash.Encoding != cmf.EncodingBase64 {
		return Auth0Hash{}, fmt.Errorf("hash: scrypt requires hash.encoding of hex or base64 for Auth0, got %q", p.Hash.Encoding)
	}
	keylen, _ := intParam(p.Params, "keylen")
	if keylen <= 0 {
		return Auth0Hash{}, fmt.Errorf("hash: scrypt requires a positive params.keylen for Auth0")
	}
	cost, _ := intParam(p.Params, "cost")
	if cost <= 1 || cost&(cost-1) != 0 {
		return Auth0Hash{}, fmt.Errorf("hash: scrypt params.cost must be a power of two greater than 1, got %v", p.Params["cost"])
	}
	payload := map[string]any{
		payloadKeyAlgorithm: "scrypt",
		payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: string(p.Hash.Encoding)},
		"keylen":            keylen,
		"cost":              cost,
	}
	// blockSize and parallelization are optional in Auth0 (defaults 8 and 1).
	for _, key := range []string{"blockSize", "parallelization"} {
		if v, ok := intParam(p.Params, key); ok && v != 0 {
			payload[key] = v
		}
	}
	if p.Salt != nil {
		payload["salt"] = saltPayload(p.Salt)
	}
	return Auth0Hash{Field: FieldCustomPasswordHash, Payload: payload}, nil
}

// saltPayload is a CMF salt as Auth0's salt object. position is left out
// when CMF doesn't record one, so Auth0 applies its prefix default instead of
// getting an empty string.
func saltPayload(s *cmf.SaltValue) map[string]any {
	out := map[string]any{payloadKeyValue: s.Value, payloadKeyEncoding: string(s.Encoding)}
	if s.Position != "" {
		out["position"] = string(s.Position)
	}
	return out
}

// auth0PBKDF2Digests are the digests Auth0 accepts in a PBKDF2 PHC string's
// pbkdf2-<digest> identifier, spelled as Auth0 documents them.
var auth0PBKDF2Digests = []string{
	"RSA-MD4", "RSA-MD5", "RSA-MDC2", "RSA-RIPEMD160", "RSA-SHA1", "RSA-SHA1-2",
	"RSA-SHA224", "RSA-SHA256", "RSA-SHA384", "RSA-SHA512",
	"md4", "md4WithRSAEncryption", "md5", "md5WithRSAEncryption",
	"mdc2", "mdc2WithRSA", "ripemd", "ripemd160", "ripemd160WithRSA", "rmd160",
	digestSHA1, "sha1WithRSAEncryption", "sha224", "sha224WithRSAEncryption",
	"sha256", "sha256WithRSAEncryption", "sha384", "sha384WithRSAEncryption",
	"sha512", "sha512WithRSAEncryption", "ssl3-md5", "ssl3-sha1", "whirlpool",
}

// phcBase64 re-encodes a CMF value as the unpadded base64 a PHC string
// carries, which Auth0 requires for the salt.
func phcBase64(v string, enc cmf.Encoding) (string, error) {
	b, err := DecodeBytes(v, enc)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func translatePBKDF2(p cmf.Password) (Auth0Hash, error) {
	iterations, ok := intParam(p.Params, "iterations")
	if !ok || iterations == 0 {
		iterations = 100000
	}
	keylen, ok := intParam(p.Params, "keylen")
	if !ok || keylen == 0 {
		keylen = 64
	}
	if p.Salt == nil {
		return Auth0Hash{}, fmt.Errorf("hash: pbkdf2 requires a salt for Auth0")
	}
	digest, _ := p.Params["digest"].(string)
	if !slices.Contains(auth0PBKDF2Digests, digest) {
		return Auth0Hash{}, fmt.Errorf("hash: pbkdf2 params.digest %q is not one of Auth0's supported digests", digest)
	}
	salt, err := phcBase64(p.Salt.Value, p.Salt.Encoding)
	if err != nil {
		return Auth0Hash{}, fmt.Errorf("hash: pbkdf2 salt isn't valid %s: %w", p.Salt.Encoding, err)
	}
	key, err := phcBase64(p.Hash.Value, p.Hash.Encoding)
	if err != nil {
		return Auth0Hash{}, fmt.Errorf("hash: pbkdf2 hash isn't valid %s: %w", p.Hash.Encoding, err)
	}
	phc := fmt.Sprintf("$pbkdf2-%s$i=%d,l=%d$%s$%s", digest, iterations, keylen, salt, key)
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
		payload["salt"] = saltPayload(p.Salt)
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
				// Auth0 nests the HMAC key under hash; a top-level key is rejected.
				"key": map[string]any{payloadKeyValue: p.Key.Value, payloadKeyEncoding: string(p.Key.Encoding)},
			},
		},
	}, nil
}

// ldapSchemeRE captures the {scheme} prefix of an RFC 2307 userPassword.
var ldapSchemeRE = regexp.MustCompile(`^\{([^}]*)\}`)

// auth0LDAPScheme matches the schemes Auth0 accepts: md5, smd5, sha* and ssha*.
var auth0LDAPScheme = regexp.MustCompile(`(?i)^(md5|smd5|s?sha[0-9]*)$`)

func translateLDAP(p cmf.Password) (Auth0Hash, error) {
	m := ldapSchemeRE.FindStringSubmatch(p.Hash.Value)
	if m == nil {
		return Auth0Hash{}, fmt.Errorf("hash: LDAP value has no {scheme} prefix")
	}
	if !auth0LDAPScheme.MatchString(m[1]) {
		return Auth0Hash{}, fmt.Errorf("hash: LDAP {%s} scheme is not supported by Auth0 (md5, smd5, sha* and ssha* only)", m[1])
	}
	return Auth0Hash{
		Field: FieldCustomPasswordHash,
		Payload: map[string]any{
			payloadKeyAlgorithm: "ldap",
			payloadKeyHash:      map[string]any{payloadKeyValue: p.Hash.Value, payloadKeyEncoding: encodingUTF8},
		},
	}, nil
}
