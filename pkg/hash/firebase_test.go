package hash_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/scrypt"
)

// Reference vector from Firebase's own scrypt implementation
// (github.com/firebase/scrypt).
var firebaseVector = struct {
	cfg      hash.FirebaseScryptConfig
	password string
	salt     string
	hash     string
}{
	cfg: hash.FirebaseScryptConfig{
		SignerKey:     "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
		SaltSeparator: "Bw==",
		Rounds:        8,
		MemCost:       14,
	},
	password: "user1password",
	salt:     "42xEC+ixf3L2lw==",
	hash:     "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==",
}

// firebaseScryptHash is Firebase's modified scrypt: scrypt(password,
// salt||separator) derives an AES-256 key that encrypts the signer key in
// CTR mode with a zero IV.
func firebaseScryptHash(t *testing.T, password string, salt []byte, cfg hash.FirebaseScryptConfig) []byte {
	t.Helper()
	signer, err := base64.StdEncoding.DecodeString(cfg.SignerKey)
	require.NoError(t, err)
	separator, err := base64.StdEncoding.DecodeString(cfg.SaltSeparator)
	require.NoError(t, err)

	key, err := scrypt.Key([]byte(password), append(append([]byte{}, salt...), separator...), 1<<cfg.MemCost, cfg.Rounds, 1, 32)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	out := make([]byte, len(signer))
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(out, signer)
	return out
}

func TestFirebaseScryptReferenceVector(t *testing.T) {
	v := firebaseVector
	salt, err := base64.StdEncoding.DecodeString(v.salt)
	require.NoError(t, err)

	got := firebaseScryptHash(t, v.password, salt, v.cfg)
	require.Equal(t, v.hash, base64.StdEncoding.EncodeToString(got))
}

func TestNormalizeFirebaseScryptAcceptsURLSafeBase64(t *testing.T) {
	v := firebaseVector
	urlSafe := func(s string) string {
		b, err := base64.StdEncoding.DecodeString(s)
		require.NoError(t, err)
		return base64.URLEncoding.EncodeToString(b)
	}

	p, err := hash.NormalizeFirebaseScrypt(urlSafe(v.hash), urlSafe(v.salt), v.cfg)
	require.NoError(t, err)

	require.Equal(t, cmf.AlgScrypt, p.Algorithm)
	require.True(t, p.Portable)
	require.Equal(t, "firebase", p.Params["variant"])
	require.Equal(t, 8, p.Params["rounds"])
	require.Equal(t, 14, p.Params["mem_cost"])
	require.Equal(t, "Bw==", p.Params["salt_separator"])
	require.Equal(t, v.cfg.SignerKey, p.Key.Value)
	require.Equal(t, cmf.EncodingBase64, p.Hash.Encoding)

	// The CMF values decode back to the same bytes Firebase sent.
	gotHash, err := base64.RawStdEncoding.DecodeString(p.Hash.Value)
	require.NoError(t, err)
	wantHash, _ := base64.StdEncoding.DecodeString(v.hash)
	require.Equal(t, wantHash, gotHash)
}

func TestNormalizeFirebaseScryptRejectsBadInput(t *testing.T) {
	v := firebaseVector
	tests := []struct {
		name string
		hash string
		salt string
		cfg  hash.FirebaseScryptConfig
		want string
	}{
		{name: "no signer key", hash: v.hash, salt: v.salt, cfg: hash.FirebaseScryptConfig{Rounds: 8, MemCost: 14}, want: "signer key is empty"},
		{name: "rounds out of range", hash: v.hash, salt: v.salt, cfg: hash.FirebaseScryptConfig{SignerKey: v.cfg.SignerKey, Rounds: 9, MemCost: 14}, want: "rounds must be 1-8"},
		{name: "mem cost out of range", hash: v.hash, salt: v.salt, cfg: hash.FirebaseScryptConfig{SignerKey: v.cfg.SignerKey, Rounds: 8, MemCost: 15}, want: "memory cost must be 1-14"},
		{name: "no salt", hash: v.hash, cfg: v.cfg, want: "salt is missing"},
		{name: "bad hash", hash: "!!!", salt: v.salt, cfg: v.cfg, want: "passwordHash is not valid base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hash.NormalizeFirebaseScrypt(tt.hash, tt.salt, tt.cfg)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestToFirebaseHashScryptRoundTrip(t *testing.T) {
	v := firebaseVector
	p, err := hash.NormalizeFirebaseScrypt(v.hash, v.salt, v.cfg)
	require.NoError(t, err)

	// Through a CMF file, params come back as float64.
	b, err := json.Marshal(p)
	require.NoError(t, err)
	var decoded cmf.Password
	require.NoError(t, json.Unmarshal(b, &decoded))

	got, err := hash.ToFirebaseHash(decoded)
	require.NoError(t, err)

	require.Equal(t, hash.FirebaseHashParams{
		HashAlgorithm: "SCRYPT",
		SignerKey:     v.cfg.SignerKey,
		SaltSeparator: "Bw==",
		Rounds:        8,
		MemoryCost:    14,
	}, got.Params)

	wantHash, _ := base64.StdEncoding.DecodeString(v.hash)
	gotHash, err := base64.URLEncoding.DecodeString(got.PasswordHash)
	require.NoError(t, err)
	require.Equal(t, wantHash, gotHash)
	wantSalt, _ := base64.StdEncoding.DecodeString(v.salt)
	gotSalt, err := base64.URLEncoding.DecodeString(got.Salt)
	require.NoError(t, err)
	require.Equal(t, wantSalt, gotSalt)
}

func TestToFirebaseHashStandardScrypt(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key, err := scrypt.Key([]byte("secret"), salt, 1024, 8, 1, 32)
	require.NoError(t, err)
	raw := "$scrypt$ln=10,r=8,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
	p, err := hash.Normalize(raw, hash.Hint{})
	require.NoError(t, err)

	got, err := hash.ToFirebaseHash(p)
	require.NoError(t, err)

	require.Equal(t, hash.FirebaseHashParams{
		HashAlgorithm:   "STANDARD_SCRYPT",
		CPUMemCost:      1024,
		Parallelization: 1,
		BlockSize:       8,
		DKLen:           32,
	}, got.Params)
	gotHash, err := base64.URLEncoding.DecodeString(got.PasswordHash)
	require.NoError(t, err)
	require.Equal(t, key, gotHash)
	gotSalt, err := base64.URLEncoding.DecodeString(got.Salt)
	require.NoError(t, err)
	require.Equal(t, salt, gotSalt)
}

func TestToFirebaseHashBcrypt(t *testing.T) {
	const raw = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	p, err := hash.Normalize(raw, hash.Hint{})
	require.NoError(t, err)

	got, err := hash.ToFirebaseHash(p)
	require.NoError(t, err)

	require.Equal(t, hash.FirebaseHashParams{HashAlgorithm: "BCRYPT"}, got.Params)
	require.Empty(t, got.Salt)
	decoded, err := base64.URLEncoding.DecodeString(got.PasswordHash)
	require.NoError(t, err)
	require.Equal(t, raw, string(decoded))
}

func TestToFirebaseHashRejects(t *testing.T) {
	pbkdf2, err := hash.Normalize("$pbkdf2-sha256$i=1000$c2FsdHNhbHQ$aGFzaGhhc2g", hash.Hint{})
	require.NoError(t, err)
	nonPortable := pbkdf2
	nonPortable.Portable = false

	_, err = hash.ToFirebaseHash(pbkdf2)
	require.ErrorContains(t, err, "not one of the Firebase import hashes")
	_, err = hash.ToFirebaseHash(nonPortable)
	require.ErrorContains(t, err, "non-portable")

	// A Firebase-variant scrypt missing its project parameters can't verify.
	v := firebaseVector
	p, err := hash.NormalizeFirebaseScrypt(v.hash, v.salt, v.cfg)
	require.NoError(t, err)
	p.Key = nil
	_, err = hash.ToFirebaseHash(p)
	require.ErrorContains(t, err, "signer key")

	// Auth0 has no Firebase scrypt either.
	p, err = hash.NormalizeFirebaseScrypt(v.hash, v.salt, v.cfg)
	require.NoError(t, err)
	_, err = hash.ToAuth0(p, false)
	require.ErrorContains(t, err, "Firebase's modified scrypt")
}
