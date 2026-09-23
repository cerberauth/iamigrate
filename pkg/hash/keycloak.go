package hash

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// KeycloakCredential is a password hash in the shape Keycloak stores it and
// accepts on user creation: a CredentialRepresentation's secretData and
// credentialData, each a JSON document serialized to a string.
type KeycloakCredential struct {
	SecretData     string
	CredentialData string
}

// keycloakSecretData is PasswordSecretData: the derived key and salt, both
// standard padded base64 (Java's Base64 of a byte[]).
type keycloakSecretData struct {
	Value                string              `json:"value"`
	Salt                 string              `json:"salt,omitempty"`
	AdditionalParameters map[string][]string `json:"additionalParameters"`
}

// keycloakCredentialData is PasswordCredentialData: the hash provider ID
// plus its parameters.
type keycloakCredentialData struct {
	HashIterations       int                 `json:"hashIterations"`
	Algorithm            string              `json:"algorithm"`
	AdditionalParameters map[string][]string `json:"additionalParameters"`
}

// Keycloak's built-in PasswordHashProvider IDs.
const (
	keycloakPBKDF2       = "pbkdf2"
	keycloakPBKDF2SHA256 = "pbkdf2-sha256"
	keycloakPBKDF2SHA512 = "pbkdf2-sha512"
	keycloakArgon2       = "argon2"
)

// Argon2 version labels Keycloak uses in credentialData, keyed by the PHC
// v= value.
var keycloakArgon2Versions = map[string]string{"19": "1.3", "16": "1.0"}

// ToKeycloakCredential translates a CMF password into the secretData and
// credentialData Keycloak's Admin API accepts on a password credential when
// creating a user. Keycloak ships only PBKDF2 (sha1/sha256/sha512) and
// Argon2 hash providers; every other algorithm would need a custom
// PasswordHashProvider on the Keycloak side, so it's rejected here.
func ToKeycloakCredential(p cmf.Password) (KeycloakCredential, error) {
	if !p.Portable {
		return KeycloakCredential{}, fmt.Errorf("hash: password marked non-portable, cannot translate to Keycloak")
	}

	var (
		secret keycloakSecretData
		data   keycloakCredentialData
	)
	switch p.Algorithm {
	case cmf.AlgPBKDF2:
		provider, err := keycloakPBKDF2Provider(p)
		if err != nil {
			return KeycloakCredential{}, err
		}
		iterations, ok := intParam(p.Params, "iterations")
		if !ok || iterations == 0 {
			return KeycloakCredential{}, fmt.Errorf("hash: pbkdf2 requires params.iterations for Keycloak")
		}
		if p.Salt == nil {
			return KeycloakCredential{}, fmt.Errorf("hash: pbkdf2 requires a salt for Keycloak")
		}
		key, err := decodeBinary(p.Hash.Value, p.Hash.Encoding)
		if err != nil {
			return KeycloakCredential{}, err
		}
		salt, err := decodeBinary(p.Salt.Value, p.Salt.Encoding)
		if err != nil {
			return KeycloakCredential{}, err
		}
		// Keycloak derives a key as long as the stored one, so any keylen
		// verifies as-is.
		secret = keycloakSecretData{Value: b64std(key), Salt: b64std(salt)}
		data = keycloakCredentialData{HashIterations: iterations, Algorithm: provider}

	case cmf.AlgArgon2:
		if p.PHCString == "" {
			return KeycloakCredential{}, fmt.Errorf("hash: argon2 requires a full PHC string for Keycloak (phc_string is empty)")
		}
		m := argon2RE.FindStringSubmatch(p.PHCString)
		if m == nil {
			return KeycloakCredential{}, fmt.Errorf("hash: argon2 PHC string %q is malformed", p.PHCString)
		}
		version, ok := keycloakArgon2Versions[m[2]]
		if !ok {
			return KeycloakCredential{}, fmt.Errorf("hash: argon2 version v=%s is not supported by Keycloak", m[2])
		}
		iterations, _ := strconv.Atoi(m[4])
		salt, err := decodeBinary(m[6], cmf.EncodingBase64)
		if err != nil {
			return KeycloakCredential{}, err
		}
		key, err := decodeBinary(m[7], cmf.EncodingBase64)
		if err != nil {
			return KeycloakCredential{}, err
		}
		secret = keycloakSecretData{Value: b64std(key), Salt: b64std(salt)}
		data = keycloakCredentialData{
			HashIterations: iterations,
			Algorithm:      keycloakArgon2,
			AdditionalParameters: map[string][]string{
				"type":        {strings.TrimPrefix(m[1], "argon2")},
				"version":     {version},
				"hashLength":  {strconv.Itoa(len(key))},
				"memory":      {m[3]},
				"parallelism": {m[5]},
			},
		}

	default:
		return KeycloakCredential{}, fmt.Errorf("hash: algorithm %q is not one of Keycloak's built-in hash providers (pbkdf2, argon2)", p.Algorithm)
	}

	if secret.AdditionalParameters == nil {
		secret.AdditionalParameters = map[string][]string{}
	}
	if data.AdditionalParameters == nil {
		data.AdditionalParameters = map[string][]string{}
	}
	secretJSON, err := json.Marshal(secret)
	if err != nil {
		return KeycloakCredential{}, err
	}
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return KeycloakCredential{}, err
	}
	return KeycloakCredential{SecretData: string(secretJSON), CredentialData: string(dataJSON)}, nil
}

func keycloakPBKDF2Provider(p cmf.Password) (string, error) {
	digest, _ := p.Params["digest"].(string)
	if digest == "" {
		digest = p.Hash.Digest
	}
	switch digest {
	case "sha1":
		return keycloakPBKDF2, nil
	case "sha256":
		return keycloakPBKDF2SHA256, nil
	case "sha512":
		return keycloakPBKDF2SHA512, nil
	default:
		return "", fmt.Errorf("hash: pbkdf2 digest %q is not supported by Keycloak (sha1, sha256, sha512)", digest)
	}
}

// NormalizeKeycloakCredential is the export-side inverse of
// ToKeycloakCredential: it turns a password credential's secretData and
// credentialData, as found in a `kc.sh export` realm file, back into a CMF
// password object.
func NormalizeKeycloakCredential(secretData, credentialData string) (cmf.Password, error) {
	var secret keycloakSecretData
	if err := json.Unmarshal([]byte(secretData), &secret); err != nil {
		return cmf.Password{}, fmt.Errorf("hash: decoding Keycloak secretData: %w", err)
	}
	var data keycloakCredentialData
	if err := json.Unmarshal([]byte(credentialData), &data); err != nil {
		return cmf.Password{}, fmt.Errorf("hash: decoding Keycloak credentialData: %w", err)
	}

	key, err := decodeBinary(secret.Value, cmf.EncodingBase64)
	if err != nil {
		return cmf.Password{}, err
	}
	salt, err := decodeBinary(secret.Salt, cmf.EncodingBase64)
	if err != nil {
		return cmf.Password{}, err
	}

	switch data.Algorithm {
	case keycloakPBKDF2, keycloakPBKDF2SHA256, keycloakPBKDF2SHA512:
		digest := "sha1"
		if d, ok := strings.CutPrefix(data.Algorithm, keycloakPBKDF2+"-"); ok {
			digest = d
		}
		raw := fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", digest, data.HashIterations, b64raw(salt), b64raw(key))
		p, err := Normalize(raw, Hint{})
		if err != nil {
			return cmf.Password{}, err
		}
		p.Params["keylen"] = len(key)
		return p, nil

	case keycloakArgon2:
		param := func(k string) string {
			if v := data.AdditionalParameters[k]; len(v) > 0 {
				return v[0]
			}
			return ""
		}
		var v string
		for phc, label := range keycloakArgon2Versions {
			if label == param("version") {
				v = phc
			}
		}
		if v == "" {
			return cmf.Password{}, fmt.Errorf("hash: unknown Keycloak argon2 version %q", param("version"))
		}
		raw := fmt.Sprintf("$argon2%s$v=%s$m=%s,t=%d,p=%s$%s$%s",
			param("type"), v, param("memory"), data.HashIterations, param("parallelism"), b64raw(salt), b64raw(key))
		return Normalize(raw, Hint{})

	default:
		return cmf.Password{}, fmt.Errorf("hash: Keycloak hash provider %q has no CMF equivalent", data.Algorithm)
	}
}

// decodeBinary decodes a hex, or padded or unpadded standard base64, value.
func decodeBinary(value string, encoding cmf.Encoding) ([]byte, error) {
	switch encoding {
	case cmf.EncodingHex:
		b, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("hash: %q is not valid hex: %w", value, err)
		}
		return b, nil
	case cmf.EncodingBase64:
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
		if err != nil {
			return nil, fmt.Errorf("hash: %q is not valid base64: %w", value, err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("hash: encoding %q can't carry binary hash or salt bytes", encoding)
	}
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
