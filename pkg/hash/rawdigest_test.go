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

func TestValidate(t *testing.T) {
	md5hex := "5f4dcc3b5aa765d61d8327deb882cf99"
	bcrypt := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	for name, p := range map[string]cmf.Password{
		"hex digest":     {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}},
		"salted digest":  {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}, Salt: &cmf.SaltValue{Value: "pepper", Encoding: cmf.EncodingUTF8, Position: cmf.SaltPrefix}},
		"bcrypt":         {Algorithm: cmf.AlgBcrypt, Hash: cmf.HashValue{Value: bcrypt, Encoding: cmf.EncodingUTF8}},
		"hmac":           {Algorithm: cmf.AlgHMAC, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex, Digest: "sha256"}, Key: &cmf.KeyValue{Value: "a2V5", Encoding: cmf.EncodingBase64}},
		"phc string":     {Algorithm: cmf.AlgPBKDF2, PHCString: "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA", Hash: cmf.HashValue{Value: "aGFzaA", Encoding: cmf.EncodingBase64}},
		"base64 digest":  {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: "X03MO1qnZdYdgyfeuILPmQ==", Encoding: cmf.EncodingBase64}},
		"unpadded b64":   {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: "X03MO1qnZdYdgyfeuILPmQ", Encoding: cmf.EncodingBase64}},
		"suffixed (def)": {Algorithm: cmf.AlgSHA1, Hash: cmf.HashValue{Value: "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", Encoding: cmf.EncodingHex}, Salt: &cmf.SaltValue{Value: "73616c74", Encoding: cmf.EncodingHex}},
	} {
		require.NoError(t, iamhash.Validate(p), name)
	}

	for want, p := range map[string]cmf.Password{
		"unknown algorithm":     {Algorithm: "rot13", Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}},
		`algorithm "SHA-256"`:   {Algorithm: "SHA-256", Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}},
		"no hash value":         {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Encoding: cmf.EncodingHex}},
		"is not valid hex":      {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: "zz", Encoding: cmf.EncodingHex}},
		"hash encoding must be": {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex}},
		"not a sha256 digest":   {Algorithm: cmf.AlgSHA256, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}},
		"hex or base64, not":    {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingUTF8}},
		"not a bcrypt hash":     {Algorithm: cmf.AlgBcrypt, Hash: cmf.HashValue{Value: "nope", Encoding: cmf.EncodingUTF8}},
		"hmac requires":         {Algorithm: cmf.AlgHMAC, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}},
		"hmac key isn't valid":  {Algorithm: cmf.AlgHMAC, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex, Digest: "sha256"}, Key: &cmf.KeyValue{Value: "zz", Encoding: cmf.EncodingHex}},
		"salt isn't valid":      {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}, Salt: &cmf.SaltValue{Value: "zz", Encoding: cmf.EncodingHex}},
		"salt position":         {Algorithm: cmf.AlgMD5, Hash: cmf.HashValue{Value: md5hex, Encoding: cmf.EncodingHex}, Salt: &cmf.SaltValue{Value: "00", Encoding: cmf.EncodingHex, Position: "middle"}},
		"phc_string is":         {Algorithm: cmf.AlgScrypt, PHCString: "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA", Hash: cmf.HashValue{Value: "aGFzaA", Encoding: cmf.EncodingBase64}},
		"phc_string: ":          {Algorithm: cmf.AlgPBKDF2, PHCString: "nonsense", Hash: cmf.HashValue{Value: "aGFzaA", Encoding: cmf.EncodingBase64}},
	} {
		require.ErrorContains(t, iamhash.Validate(p), want, want)
	}
}
