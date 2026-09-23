package hash_test

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// keycloakArgon2Secret/Data are a password credential exactly as Keycloak
// 26 wrote it for the password "secret" in a `kc.sh export` realm file.
const (
	keycloakArgon2Secret = `{"value":"xKjWvB9+0sSP6wTqI1JoEI7w+iA0x9VDhPgmrOHRG80=","salt":"LRScGShC7shkdoU5B1UgUQ==","additionalParameters":{}}`
	keycloakArgon2Data   = `{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}`
)

func TestNormalizeKeycloakArgon2KAT(t *testing.T) {
	p, err := iamhash.NormalizeKeycloakCredential(keycloakArgon2Secret, keycloakArgon2Data)
	require.NoError(t, err)
	require.Equal(t, cmf.AlgArgon2, p.Algorithm)
	require.Equal(t, "$argon2id$v=19$m=7168,t=5,p=1$LRScGShC7shkdoU5B1UgUQ$xKjWvB9+0sSP6wTqI1JoEI7w+iA0x9VDhPgmrOHRG80", p.PHCString)

	salt, err := base64.StdEncoding.DecodeString("LRScGShC7shkdoU5B1UgUQ==")
	require.NoError(t, err)
	key := argon2.IDKey([]byte("secret"), salt, 5, 7168, 1, 32)
	require.Equal(t, "xKjWvB9+0sSP6wTqI1JoEI7w+iA0x9VDhPgmrOHRG80=", base64.StdEncoding.EncodeToString(key))

	// Translating back yields the same credential Keycloak stored.
	kc, err := iamhash.ToKeycloakCredential(p)
	require.NoError(t, err)
	require.JSONEq(t, keycloakArgon2Secret, kc.SecretData)
	require.JSONEq(t, keycloakArgon2Data, kc.CredentialData)
}

func TestKeycloakPBKDF2RoundTrip(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := pbkdf2.Key([]byte("secret"), salt, 1000, 64, sha512.New)
	raw := "$pbkdf2-sha512$i=1000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
	p, err := iamhash.Normalize(raw, iamhash.Hint{})
	require.NoError(t, err)

	kc, err := iamhash.ToKeycloakCredential(p)
	require.NoError(t, err)

	var secret map[string]any
	require.NoError(t, json.Unmarshal([]byte(kc.SecretData), &secret))
	require.Equal(t, base64.StdEncoding.EncodeToString(key), secret["value"])
	require.Equal(t, base64.StdEncoding.EncodeToString(salt), secret["salt"])
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(kc.CredentialData), &data))
	require.Equal(t, "pbkdf2-sha512", data["algorithm"])
	require.EqualValues(t, 1000, data["hashIterations"])

	back, err := iamhash.NormalizeKeycloakCredential(kc.SecretData, kc.CredentialData)
	require.NoError(t, err)
	require.Equal(t, cmf.AlgPBKDF2, back.Algorithm)
	require.Equal(t, "sha512", back.Params["digest"])
	require.Equal(t, 1000, back.Params["iterations"])
	require.Equal(t, 64, back.Params["keylen"])
}

func TestKeycloakPBKDF2SHA1ProviderID(t *testing.T) {
	p, err := iamhash.NormalizeKeycloakCredential(
		`{"value":"AAAA","salt":"AAAA"}`, `{"hashIterations":27500,"algorithm":"pbkdf2"}`)
	require.NoError(t, err)
	require.Equal(t, "sha1", p.Params["digest"])

	kc, err := iamhash.ToKeycloakCredential(p)
	require.NoError(t, err)
	require.Contains(t, kc.CredentialData, `"algorithm":"pbkdf2"`)
}

func TestToKeycloakCredentialRejectsUnsupported(t *testing.T) {
	_, err := iamhash.ToKeycloakCredential(cmf.Password{
		Algorithm: cmf.AlgBcrypt, Portable: true,
		Hash: cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
	})
	require.ErrorContains(t, err, "not one of Keycloak's built-in hash providers")

	_, err = iamhash.ToKeycloakCredential(cmf.Password{Algorithm: cmf.AlgPBKDF2, Portable: false})
	require.ErrorContains(t, err, "non-portable")
}

func TestNormalizeKeycloakCredentialUnknownProvider(t *testing.T) {
	_, err := iamhash.NormalizeKeycloakCredential(`{"value":"AAAA","salt":"AAAA"}`, `{"hashIterations":10,"algorithm":"bcrypt"}`)
	require.ErrorContains(t, err, `"bcrypt" has no CMF equivalent`)
}
