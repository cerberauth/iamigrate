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

func normalizeRawDigest(raw string, hint Hint) (cmf.Password, error) {
	value, encoding, err := detectDigestEncoding(raw)
	if err != nil {
		return cmf.Password{}, err
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

func detectDigestEncoding(raw string) (value string, encoding cmf.Encoding, err error) {
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
