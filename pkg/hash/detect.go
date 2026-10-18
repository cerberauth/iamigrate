// Package hash detects and normalizes inbound password hash formats into
// CMF's password object, then translates CMF into Auth0's
// custom_password_hash / password_hash payloads.
//
// Detection conventions (PHC-style prefixes, registry-of-algorithms
// pattern, regex-based Detect) follow github.com/cerberauth/pashly's
// internal/hash package; the code here is independent since pashly's
// package is internal to that module and not importable, and CMF's
// Password type carries more structure (portable flag, separate HMAC key,
// explicit salt position) than pashly's Result needs for its own CLI.
package hash

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

var (
	bcryptRE = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)
	argon2RE = regexp.MustCompile(`^\$(argon2id|argon2i)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`)
	scryptRE = regexp.MustCompile(`^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`)
	pbkdf2RE = regexp.MustCompile(`^\$pbkdf2-(sha1|sha256|sha512)\$i=(\d+)\$([^$]+)\$([^$]+)$`)
	ldapRE   = regexp.MustCompile(`^\{(SSHA|SHA|SMD5|MD5|CRYPT)\}(.+)$`)
	hexRE    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// Hint carries out-of-band information a caller has about an inbound hash
// that can't be recovered from the encoded string alone -- typically a
// column-name heuristic ("password_sha256", "password_hmac_sha256") from a
// flat-file source, or an explicit --hash flag from the fixture generator.
type Hint struct {
	Algorithm cmf.Algorithm
	// Encoding, when set, is how a raw digest is encoded (hex or base64,
	// the latter standard or URL-safe, padded or not) instead of guessing
	// it from the characters.
	Encoding cmf.Encoding
	// Salt, if the source stores it in a separate column rather than
	// embedded in the hash string.
	Salt []byte
	// SaltPosition describes where Salt was concatenated during hashing,
	// when known.
	SaltPosition cmf.SaltPosition
	// Key is HMAC key material, required when Algorithm is cmf.AlgHMAC.
	Key []byte
	// Digest names the underlying digest for an HMAC hash (e.g. "sha256").
	Digest string
}

// ErrAmbiguous is returned when raw digest bytes were given without a
// Hint.Algorithm to disambiguate them.
var ErrAmbiguous = fmt.Errorf("hash: raw digest format requires a Hint.Algorithm (md4/md5/sha1/sha256/sha512/hmac cannot be told apart from bytes alone)")

// Normalize detects the format of an inbound password hash and returns it
// as a CMF Password object. Structured formats (bcrypt, PHC-style
// scrypt/pbkdf2/argon2, RFC 2307 LDAP userPassword) are detected from the
// string itself. Raw digests require hint.Algorithm.
func Normalize(raw string, hint Hint) (cmf.Password, error) {
	switch {
	case bcryptRE.MatchString(raw):
		return normalizeBcrypt(raw), nil
	case argon2RE.MatchString(raw):
		return normalizeArgon2(raw)
	case scryptRE.MatchString(raw):
		return normalizeScrypt(raw)
	case pbkdf2RE.MatchString(raw):
		return normalizePBKDF2(raw)
	case ldapRE.MatchString(raw):
		return normalizeLDAP(raw)
	}

	if hint.Algorithm == "" {
		return cmf.Password{}, ErrAmbiguous
	}
	return normalizeRawDigest(raw, hint)
}

func normalizeBcrypt(raw string) cmf.Password {
	return cmf.Password{
		Algorithm: cmf.AlgBcrypt,
		Hash:      cmf.HashValue{Value: raw, Encoding: cmf.EncodingUTF8},
		Portable:  true,
	}
}

func normalizeArgon2(raw string) (cmf.Password, error) {
	m := argon2RE.FindStringSubmatch(raw)
	memory, _ := strconv.Atoi(m[3])
	timeCost, _ := strconv.Atoi(m[4])
	parallelism, _ := strconv.Atoi(m[5])
	return cmf.Password{
		Algorithm: cmf.AlgArgon2,
		PHCString: raw,
		Hash:      cmf.HashValue{Value: m[7], Encoding: cmf.EncodingBase64},
		Salt:      &cmf.SaltValue{Value: m[6], Encoding: cmf.EncodingBase64, Position: cmf.SaltPrefix},
		Params: map[string]any{
			"variant":     m[1],
			"version":     m[2],
			"memory":      memory,
			"time":        timeCost,
			"parallelism": parallelism,
		},
		Portable: true,
	}, nil
}

func normalizeScrypt(raw string) (cmf.Password, error) {
	m := scryptRE.FindStringSubmatch(raw)
	ln, _ := strconv.Atoi(m[1])
	r, _ := strconv.Atoi(m[2])
	p, _ := strconv.Atoi(m[3])
	return cmf.Password{
		Algorithm: cmf.AlgScrypt,
		Hash:      cmf.HashValue{Value: m[5], Encoding: cmf.EncodingBase64},
		Salt:      &cmf.SaltValue{Value: m[4], Encoding: cmf.EncodingBase64, Position: cmf.SaltPrefix},
		Params: map[string]any{
			"cost":            1 << ln,
			"blockSize":       r,
			"parallelization": p,
		},
		Portable: true,
	}, nil
}

func normalizePBKDF2(raw string) (cmf.Password, error) {
	m := pbkdf2RE.FindStringSubmatch(raw)
	iterations, _ := strconv.Atoi(m[2])
	return cmf.Password{
		Algorithm: cmf.AlgPBKDF2,
		Hash:      cmf.HashValue{Value: m[4], Encoding: cmf.EncodingBase64, Digest: m[1]},
		Salt:      &cmf.SaltValue{Value: m[3], Encoding: cmf.EncodingBase64, Position: cmf.SaltPrefix},
		Params: map[string]any{
			"digest":     m[1],
			"iterations": iterations,
		},
		Portable: true,
	}, nil
}

func normalizeLDAP(raw string) (cmf.Password, error) {
	m := ldapRE.FindStringSubmatch(raw)
	scheme := m[1]
	if scheme == "CRYPT" {
		return cmf.Password{}, fmt.Errorf("hash: LDAP {CRYPT} scheme is not portable to Auth0 (unsupported by custom_password_hash)")
	}
	return cmf.Password{
		Algorithm: cmf.AlgLDAP,
		Hash:      cmf.HashValue{Value: raw, Encoding: cmf.EncodingUTF8},
		Params:    map[string]any{"scheme": scheme},
		Portable:  true,
	}, nil
}

// digestSizes is the length in bytes of each raw digest algorithm's output,
// to catch a hash labeled with the wrong algorithm. hmac isn't listed: its
// size depends on the underlying digest.
var digestSizes = map[cmf.Algorithm]int{
	cmf.AlgMD4: 16, cmf.AlgMD5: 16, cmf.AlgSHA1: 20, cmf.AlgSHA256: 32, cmf.AlgSHA512: 64,
}

// aliases are the spellings ParseAlgorithm accepts besides the CMF names,
// compared lowercase with "-", "_" and spaces removed.
var aliases = map[string]cmf.Algorithm{
	"argon2id": cmf.AlgArgon2, "argon2i": cmf.AlgArgon2,
	"sha": cmf.AlgSHA1, "sha2256": cmf.AlgSHA256, "sha2512": cmf.AlgSHA512,
}

// ParseAlgorithm returns the CMF algorithm named by s, ignoring case and
// the separators in spellings like "SHA-256" or "sha_256".
func ParseAlgorithm(s string) (cmf.Algorithm, error) {
	key := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	if a, ok := aliases[key]; ok {
		return a, nil
	}
	for _, a := range []cmf.Algorithm{
		cmf.AlgBcrypt, cmf.AlgScrypt, cmf.AlgPBKDF2, cmf.AlgArgon2, cmf.AlgMD5, cmf.AlgSHA1,
		cmf.AlgSHA256, cmf.AlgSHA512, cmf.AlgMD4, cmf.AlgHMAC, cmf.AlgLDAP,
	} {
		if key == string(a) {
			return a, nil
		}
	}
	return "", fmt.Errorf("hash: unknown algorithm %q", s)
}

// DecodeBytes decodes s as enc: hex, base64 (standard or URL-safe alphabet,
// padded or not) or utf8 (the bytes of the string itself, for a salt kept
// as plain text).
func DecodeBytes(s string, enc cmf.Encoding) ([]byte, error) {
	if enc == cmf.EncodingUTF8 {
		return []byte(s), nil
	}
	return decodeBinary(s, enc)
}

func normalizeRawDigest(raw string, hint Hint) (cmf.Password, error) {
	if _, ok := digestSizes[hint.Algorithm]; !ok && hint.Algorithm != cmf.AlgHMAC {
		return cmf.Password{}, fmt.Errorf("hash: %q is not a valid %s hash (a %s hash carries its own parameters; a raw digest must be md4, md5, sha1, sha256, sha512 or hmac)", raw, hint.Algorithm, hint.Algorithm)
	}
	value, encoding, err := detectDigestEncoding(raw, hint.Encoding)
	if err != nil {
		return cmf.Password{}, err
	}
	if want, ok := digestSizes[hint.Algorithm]; ok {
		if b, err := decodeBinary(value, encoding); err != nil || len(b) != want {
			return cmf.Password{}, fmt.Errorf("hash: %q is not a %s digest (%d bytes expected, got %d): is the algorithm or the encoding wrong?", raw, hint.Algorithm, want, len(b))
		}
	}

	p := cmf.Password{
		Algorithm: hint.Algorithm,
		Hash:      cmf.HashValue{Value: value, Encoding: encoding},
		Portable:  true,
	}
	if hint.Algorithm == cmf.AlgHMAC {
		if len(hint.Key) == 0 || hint.Digest == "" {
			return cmf.Password{}, fmt.Errorf("hash: hmac requires Hint.Key and Hint.Digest")
		}
		p.Hash.Digest = hint.Digest
		p.Key = &cmf.KeyValue{Value: base64.StdEncoding.EncodeToString(hint.Key), Encoding: cmf.EncodingBase64}
	}
	if len(hint.Salt) > 0 {
		pos := hint.SaltPosition
		if pos == "" {
			pos = cmf.SaltSuffix
		}
		p.Salt = &cmf.SaltValue{
			Value:    base64.StdEncoding.EncodeToString(hint.Salt),
			Encoding: cmf.EncodingBase64,
			Position: pos,
		}
	}
	return p, nil
}

// detectDigestEncoding returns raw in a canonical form (lowercase hex, or
// standard padded base64) and its encoding: the one given, or else the one
// it looks like, with hex preferred when both fit.
func detectDigestEncoding(raw string, given cmf.Encoding) (value string, encoding cmf.Encoding, err error) {
	switch given {
	case "":
	case cmf.EncodingHex, cmf.EncodingBase64:
		b, err := decodeBinary(raw, given)
		if err != nil {
			return "", "", err
		}
		if given == cmf.EncodingHex {
			return hex.EncodeToString(b), given, nil
		}
		return base64.StdEncoding.EncodeToString(b), given, nil
	default:
		return "", "", fmt.Errorf("hash: a digest is encoded as hex or base64, not %q", given)
	}
	if hexRE.MatchString(raw) {
		if _, err := hex.DecodeString(raw); err == nil {
			return raw, cmf.EncodingHex, nil
		}
	}
	if _, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return raw, cmf.EncodingBase64, nil
	}
	return "", "", fmt.Errorf("hash: %q is neither valid hex nor base64", raw)
}

// Validate checks a password that didn't come from Normalize (one an
// operator's handler answered with, say) is one the translators can work
// with: a known algorithm, a hash, salt and key that decode as the encoding
// they name, a raw digest of the right size, a bcrypt hash of the right
// shape, an hmac with its key and digest, and a PHC string that says the
// same algorithm.
func Validate(p cmf.Password) error {
	alg, err := ParseAlgorithm(string(p.Algorithm))
	if err != nil || alg != p.Algorithm {
		return fmt.Errorf("hash: unknown algorithm %q", p.Algorithm)
	}
	if p.Hash.Value == "" {
		return fmt.Errorf("hash: %s password has no hash value", alg)
	}
	want, raw := digestSizes[alg]
	switch p.Hash.Encoding {
	case cmf.EncodingHex, cmf.EncodingBase64:
		b, err := decodeBinary(p.Hash.Value, p.Hash.Encoding)
		if err != nil {
			return err
		}
		if raw && len(b) != want {
			return fmt.Errorf("hash: not a %s digest (%d bytes expected, got %d): is the algorithm or the encoding wrong?", alg, want, len(b))
		}
	case cmf.EncodingUTF8:
		if raw || alg == cmf.AlgHMAC {
			return fmt.Errorf("hash: a %s digest is encoded as hex or base64, not %q", alg, p.Hash.Encoding)
		}
	default:
		return fmt.Errorf("hash: hash encoding must be hex, base64 or utf8, got %q", p.Hash.Encoding)
	}
	if alg == cmf.AlgBcrypt && !bcryptRE.MatchString(p.Hash.Value) {
		return fmt.Errorf("hash: %q is not a bcrypt hash", p.Hash.Value)
	}
	if alg == cmf.AlgHMAC {
		if p.Key == nil || p.Hash.Digest == "" {
			return fmt.Errorf("hash: hmac requires a key and a hash digest")
		}
		if _, err := DecodeBytes(p.Key.Value, p.Key.Encoding); err != nil || p.Key.Value == "" {
			return fmt.Errorf("hash: hmac key isn't valid %s", p.Key.Encoding)
		}
	}
	if s := p.Salt; s != nil {
		if _, err := DecodeBytes(s.Value, s.Encoding); err != nil {
			return fmt.Errorf("hash: salt isn't valid %s", s.Encoding)
		}
		if s.Position != "" && s.Position != cmf.SaltPrefix && s.Position != cmf.SaltSuffix {
			return fmt.Errorf("hash: salt position must be prefix or suffix, got %q", s.Position)
		}
	}
	if p.PHCString != "" {
		got, err := Normalize(p.PHCString, Hint{})
		if err != nil {
			return fmt.Errorf("hash: phc_string: %w", err)
		}
		if got.Algorithm != alg {
			return fmt.Errorf("hash: phc_string is %s, not %s", got.Algorithm, alg)
		}
	}
	return nil
}
