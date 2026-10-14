package hash_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/stretchr/testify/require"
)

func TestParseAlgorithm(t *testing.T) {
	for in, want := range map[string]cmf.Algorithm{
		"sha256": cmf.AlgSHA256, "SHA-256": cmf.AlgSHA256, "sha_256": cmf.AlgSHA256, "SHA2-256": cmf.AlgSHA256,
		"SHA-512": cmf.AlgSHA512, "SHA": cmf.AlgSHA1, "Sha1": cmf.AlgSHA1, "MD5": cmf.AlgMD5,
		"BCrypt": cmf.AlgBcrypt, "PBKDF2": cmf.AlgPBKDF2, "argon2id": cmf.AlgArgon2, "LDAP": cmf.AlgLDAP,
	} {
		got, err := iamhash.ParseAlgorithm(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "rot13", "sha3-256", "pbkdf2_sha256"} {
		_, err := iamhash.ParseAlgorithm(in)
		require.ErrorContains(t, err, "unknown algorithm", in)
	}
}

func TestDecodeBytes(t *testing.T) {
	want := []byte{0xfb, 0xff, 0xfe, 0x01}
	for name, c := range map[string]struct {
		in  string
		enc cmf.Encoding
	}{
		"hex":               {"fbfffe01", cmf.EncodingHex},
		"upper hex":         {"FBFFFE01", cmf.EncodingHex},
		"base64":            {"+//+AQ==", cmf.EncodingBase64},
		"unpadded base64":   {"+//+AQ", cmf.EncodingBase64},
		"URL-safe base64":   {"-__-AQ==", cmf.EncodingBase64},
		"unpadded URL-safe": {"-__-AQ", cmf.EncodingBase64},
	} {
		got, err := iamhash.DecodeBytes(c.in, c.enc)
		require.NoError(t, err, name)
		require.Equal(t, want, got, name)
	}

	got, err := iamhash.DecodeBytes("plain salt", cmf.EncodingUTF8)
	require.NoError(t, err)
	require.Equal(t, []byte("plain salt"), got)

	_, err = iamhash.DecodeBytes("not hex", cmf.EncodingHex)
	require.Error(t, err)
}

func TestNormalizeRawDigestWithExplicitEncoding(t *testing.T) {
	sum := sha256.Sum256([]byte("password123"))
	std := base64.StdEncoding.EncodeToString(sum[:])
	unpaddedURL := base64.RawURLEncoding.EncodeToString(sum[:])

	// Left to guess, only padded standard base64 is recognized.
	_, err := iamhash.Normalize(unpaddedURL, iamhash.Hint{Algorithm: cmf.AlgSHA256})
	require.Error(t, err)

	for _, raw := range []string{std, unpaddedURL, std[:len(std)-1]} {
		p, err := iamhash.Normalize(raw, iamhash.Hint{Algorithm: cmf.AlgSHA256, Encoding: cmf.EncodingBase64})
		require.NoError(t, err, raw)
		require.Equal(t, cmf.EncodingBase64, p.Hash.Encoding)
		require.Equal(t, std, p.Hash.Value, "stored as standard padded base64")
	}

	p, err := iamhash.Normalize(hex.EncodeToString(sum[:]), iamhash.Hint{Algorithm: cmf.AlgSHA256, Encoding: cmf.EncodingHex})
	require.NoError(t, err)
	require.Equal(t, cmf.EncodingHex, p.Hash.Encoding)

	_, err = iamhash.Normalize(std, iamhash.Hint{Algorithm: cmf.AlgSHA256, Encoding: cmf.EncodingHex})
	require.Error(t, err, "base64 isn't hex")
	_, err = iamhash.Normalize(std, iamhash.Hint{Algorithm: cmf.AlgSHA256, Encoding: cmf.EncodingUTF8})
	require.ErrorContains(t, err, "hex or base64")
}

func TestNormalizeRawDigestCatchesTheWrongAlgorithm(t *testing.T) {
	sha := sha256.Sum256([]byte("password123"))
	sum := md5.Sum([]byte("password123"))

	_, err := iamhash.Normalize(hex.EncodeToString(sha[:]), iamhash.Hint{Algorithm: cmf.AlgMD5})
	require.ErrorContains(t, err, "is not a md5 digest")
	require.ErrorContains(t, err, "16 bytes expected, got 32")

	_, err = iamhash.Normalize(hex.EncodeToString(sum[:]), iamhash.Hint{Algorithm: cmf.AlgSHA512})
	require.ErrorContains(t, err, "is not a sha512 digest")

	// A bcrypt or argon2 hash carries its parameters; a bare digest labeled as one is wrong.
	_, err = iamhash.Normalize(hex.EncodeToString(sum[:]), iamhash.Hint{Algorithm: cmf.AlgBcrypt})
	require.ErrorContains(t, err, "not a valid bcrypt hash")
}

func TestNormalizeRawDigestWithSalt(t *testing.T) {
	salt := []byte("pepper")
	sum := sha256.Sum256(append(salt, []byte("password123")...))

	p, err := iamhash.Normalize(hex.EncodeToString(sum[:]), iamhash.Hint{
		Algorithm: cmf.AlgSHA256, Encoding: cmf.EncodingHex, Salt: salt, SaltPosition: cmf.SaltPrefix,
	})
	require.NoError(t, err)
	require.Equal(t, cmf.SaltPrefix, p.Salt.Position)
	require.Equal(t, base64.StdEncoding.EncodeToString(salt), p.Salt.Value)
	require.Equal(t, cmf.EncodingBase64, p.Salt.Encoding)
}
