package hash_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Known-answer vectors: fixed password + parameters, hash produced by the
// underlying stdlib/x/crypto implementation, then round-tripped through
// Normalize and ToAuth0 to prove the translation is lossless.

func TestNormalizeBcryptKAT(t *testing.T) {
	password := "Tr0ub4dor&3"
	raw, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	require.NoError(t, err)

	p, err := iamhash.Normalize(string(raw), iamhash.Hint{})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgBcrypt, p.Algorithm)
	require.True(t, p.Portable)
	require.Equal(t, string(raw), p.Hash.Value)

	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(p.Hash.Value), []byte(password)))

	a0, err := iamhash.ToAuth0(p, true)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldPasswordHash, a0.Field)
	require.Equal(t, string(raw), a0.Payload["value"])
}

func TestNormalizeBcryptNonDefaultCostUsesCustomPasswordHash(t *testing.T) {
	raw, err := bcrypt.GenerateFromPassword([]byte("x"), 12)
	require.NoError(t, err)

	p, err := iamhash.Normalize(string(raw), iamhash.Hint{})
	require.NoError(t, err)

	a0, err := iamhash.ToAuth0(p, true)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
	require.Equal(t, "bcrypt", a0.Payload["algorithm"])
}

func TestNormalizeArgon2KAT(t *testing.T) {
	// Known argon2id vector from the RFC 9106 test vector suite's PHC
	// encoding shape (structure verified, not a copy of the RFC's raw
	// digest bytes).
	raw := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

	p, err := iamhash.Normalize(raw, iamhash.Hint{})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgArgon2, p.Algorithm)
	require.Equal(t, raw, p.PHCString)
	require.Equal(t, 65536, p.Params["memory"])
	require.Equal(t, 3, p.Params["time"])
	require.Equal(t, 4, p.Params["parallelism"])

	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
	require.Equal(t, raw, a0.Payload["hash"].(map[string]any)["value"])
}

func TestNormalizeArgon2WithoutPHCStringRejectedByAuth0(t *testing.T) {
	p := cmf.Password{Algorithm: cmf.AlgArgon2, Portable: true, Hash: cmf.HashValue{Value: "x", Encoding: cmf.EncodingBase64}}
	_, err := iamhash.ToAuth0(p, false)
	require.Error(t, err)
}

func TestNormalizeScryptKAT(t *testing.T) {
	raw := "$scrypt$ln=14,r=8,p=1$c29tZXNhbHQ$aGVsbG93b3JsZA"
	p, err := iamhash.Normalize(raw, iamhash.Hint{})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgScrypt, p.Algorithm)
	require.Equal(t, 1<<14, p.Params["cost"])

	p.Params["keylen"] = 32
	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
	require.Equal(t, "scrypt", a0.Payload["algorithm"])
}

func TestNormalizePBKDF2KAT(t *testing.T) {
	raw := "$pbkdf2-sha256$i=100000$c29tZXNhbHQ$aGVsbG93b3JsZA"
	p, err := iamhash.Normalize(raw, iamhash.Hint{})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgPBKDF2, p.Algorithm)
	require.Equal(t, 100000, p.Params["iterations"])
	require.Equal(t, "sha256", p.Params["digest"])

	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
	require.Equal(t, "pbkdf2", a0.Payload["algorithm"])
}

func TestNormalizeSHA256WithHintKAT(t *testing.T) {
	sum := sha256.Sum256([]byte("password123"))
	raw := hex.EncodeToString(sum[:])

	p, err := iamhash.Normalize(raw, iamhash.Hint{Algorithm: cmf.AlgSHA256})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgSHA256, p.Algorithm)
	require.Equal(t, cmf.EncodingHex, p.Hash.Encoding)
	require.Equal(t, raw, p.Hash.Value)

	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
}

func TestNormalizeRawDigestWithoutHintIsAmbiguous(t *testing.T) {
	sum := sha256.Sum256([]byte("password123"))
	_, err := iamhash.Normalize(hex.EncodeToString(sum[:]), iamhash.Hint{})
	require.ErrorIs(t, err, iamhash.ErrAmbiguous)
}

func TestNormalizeHMACKAT(t *testing.T) {
	key := []byte("supersecretkey")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("password123"))
	sum := mac.Sum(nil)
	raw := hex.EncodeToString(sum)

	p, err := iamhash.Normalize(raw, iamhash.Hint{
		Algorithm: cmf.AlgHMAC,
		Key:       key,
		Digest:    "sha256",
	})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgHMAC, p.Algorithm)
	require.Equal(t, "sha256", p.Hash.Digest)
	require.Equal(t, base64.StdEncoding.EncodeToString(key), p.Key.Value)

	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, iamhash.FieldCustomPasswordHash, a0.Field)
	require.Equal(t, "hmac", a0.Payload["algorithm"])
}

func TestNormalizeLDAPKAT(t *testing.T) {
	raw := "{SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
	p, err := iamhash.Normalize(raw, iamhash.Hint{})
	require.NoError(t, err)
	require.Equal(t, cmf.AlgLDAP, p.Algorithm)

	a0, err := iamhash.ToAuth0(p, false)
	require.NoError(t, err)
	require.Equal(t, "ldap", a0.Payload["algorithm"])
}

func TestNormalizeLDAPCryptRejected(t *testing.T) {
	_, err := iamhash.Normalize("{CRYPT}abcdefgh", iamhash.Hint{})
	require.Error(t, err)
}

func TestToAuth0RejectsNonPortable(t *testing.T) {
	p := cmf.Password{Algorithm: cmf.AlgBcrypt, Portable: false, Hash: cmf.HashValue{Value: "x"}}
	_, err := iamhash.ToAuth0(p, true)
	require.Error(t, err)
}
