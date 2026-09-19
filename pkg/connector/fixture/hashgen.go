package fixture

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // fixture generator supports md5 for legacy-hash migration rehearsal only
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // fixture generator supports sha1 for legacy-hash migration rehearsal only
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4" //nolint:staticcheck,gosec // fixture generator supports md4 for legacy-hash migration rehearsal only
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// hmacFixtureKey is the fixed HMAC key used for every generated hmac
// fixture; answer-key.json doesn't need to carry it since it's a build
// constant the Auth0 connector test suite already knows.
var hmacFixtureKey = []byte("iamigrate-fixture-hmac-key")

func randomSalt(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return b
}

// generatePassword derives a CMF password object for spec from a cleartext
// password, returning the CMF object to embed on the user record.
func generatePassword(spec HashSpec, password string) (cmf.Password, error) {
	switch spec.Algorithm {
	case cmf.AlgBcrypt:
		cost := spec.intParam("cost", 10)
		raw, err := bcrypt.GenerateFromPassword([]byte(password), cost)
		if err != nil {
			return cmf.Password{}, err
		}
		return iamhash.Normalize(string(raw), iamhash.Hint{})

	case cmf.AlgScrypt:
		cost := spec.intParam("cost", 16384)
		blockSize := spec.intParam("blockSize", 8)
		parallelization := spec.intParam("parallelization", 1)
		keylen := spec.intParam("keylen", 32)
		salt := randomSalt(16)
		key, err := scrypt.Key([]byte(password), salt, cost, blockSize, parallelization, keylen)
		if err != nil {
			return cmf.Password{}, err
		}
		ln := 0
		for c := cost; c > 1; c >>= 1 {
			ln++
		}
		raw := fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s", ln, blockSize, parallelization, b64(salt), b64(key))
		p, err := iamhash.Normalize(raw, iamhash.Hint{})
		if err != nil {
			return cmf.Password{}, err
		}
		p.Params["keylen"] = keylen
		return p, nil

	case cmf.AlgPBKDF2:
		digest := spec.Params["digest"]
		if digest == "" {
			digest = "sha256"
		}
		iterations := spec.intParam("iterations", 100000)
		keylen := spec.intParam("keylen", 32)
		salt := randomSalt(16)
		key := pbkdf2.Key([]byte(password), salt, iterations, keylen, pbkdf2HashFunc(digest))
		raw := fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", digest, iterations, b64(salt), b64(key))
		p, err := iamhash.Normalize(raw, iamhash.Hint{})
		if err != nil {
			return cmf.Password{}, err
		}
		p.Params["keylen"] = keylen
		return p, nil

	case cmf.AlgArgon2:
		memory := uint32(spec.intParam("memory", 65536))      //nolint:gosec // fixture-only, spec-controlled test parameter
		timeCost := uint32(spec.intParam("time", 2))          //nolint:gosec // fixture-only, spec-controlled test parameter
		parallelism := uint8(spec.intParam("parallelism", 1)) //nolint:gosec // fixture-only, spec-controlled test parameter
		salt := randomSalt(16)
		key := argon2.IDKey([]byte(password), salt, timeCost, memory, parallelism, 32)
		raw := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version, memory, timeCost, parallelism, b64(salt), b64(key))
		return iamhash.Normalize(raw, iamhash.Hint{})

	case cmf.AlgMD5, cmf.AlgSHA1, cmf.AlgSHA256, cmf.AlgSHA512, cmf.AlgMD4:
		digest := digestSum(spec.Algorithm, password)
		return iamhash.Normalize(hex.EncodeToString(digest), iamhash.Hint{Algorithm: spec.Algorithm})

	case cmf.AlgHMAC:
		mac := hmac.New(sha256.New, hmacFixtureKey)
		mac.Write([]byte(password))
		sum := mac.Sum(nil)
		return iamhash.Normalize(hex.EncodeToString(sum), iamhash.Hint{
			Algorithm: cmf.AlgHMAC,
			Key:       hmacFixtureKey,
			Digest:    "sha256",
		})

	case cmf.AlgLDAP:
		salt := randomSalt(4)
		h := sha1.New() //nolint:gosec // fixture-only, not a real credential store
		h.Write([]byte(password))
		h.Write(salt)
		sum := h.Sum(nil)
		raw := "{SSHA}" + base64.StdEncoding.EncodeToString(append(sum, salt...))
		return iamhash.Normalize(raw, iamhash.Hint{})

	default:
		return cmf.Password{}, fmt.Errorf("fixture: unsupported --hash algorithm %q", spec.Algorithm)
	}
}

func digestSum(alg cmf.Algorithm, password string) []byte {
	switch alg {
	case cmf.AlgMD5:
		s := md5.Sum([]byte(password)) //nolint:gosec // fixture-only, not a real credential store
		return s[:]
	case cmf.AlgSHA1:
		s := sha1.Sum([]byte(password)) //nolint:gosec // fixture-only
		return s[:]
	case cmf.AlgSHA256:
		s := sha256.Sum256([]byte(password))
		return s[:]
	case cmf.AlgSHA512:
		s := sha512.Sum512([]byte(password))
		return s[:]
	case cmf.AlgMD4:
		h := md4.New() //nolint:gosec // fixture-only, not a real credential store
		h.Write([]byte(password))
		return h.Sum(nil)
	default:
		panic("fixture: digestSum called with non-digest algorithm " + string(alg))
	}
}

func pbkdf2HashFunc(name string) func() hash.Hash {
	switch name {
	case "sha1":
		return sha1.New
	case "sha512":
		return sha512.New
	default:
		return sha256.New
	}
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
