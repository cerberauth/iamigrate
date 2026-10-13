package hash

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// firebaseVariant is the params.variant value marking a CMF scrypt password
// as Firebase's modified scrypt rather than plain scrypt.
const firebaseVariant = "firebase"

// Bounds Firebase enforces on its modified scrypt's project parameters.
const (
	firebaseMaxRounds  = 8
	firebaseMaxMemCost = 14
)

// FirebaseScryptConfig holds the project-wide parameters of Firebase's
// modified scrypt. They're shown once per project in the console (Users >
// menu > Password hash parameters) and aren't returned by any API, yet a
// hash can't be verified anywhere else without them.
type FirebaseScryptConfig struct {
	// SignerKey is the project's base64 signer key.
	SignerKey string
	// SaltSeparator is the base64 salt separator appended to each salt.
	SaltSeparator string
	// Rounds is scrypt's block size r (1-8).
	Rounds int
	// MemCost is log2 of scrypt's CPU/memory cost N (1-14).
	MemCost int
}

// Validate reports whether c is a usable configuration.
func (c FirebaseScryptConfig) Validate() error {
	if c.SignerKey == "" {
		return fmt.Errorf("hash: Firebase scrypt signer key is empty")
	}
	if _, err := decodeFirebaseBytes(c.SignerKey); err != nil {
		return fmt.Errorf("hash: Firebase scrypt signer key: %w", err)
	}
	if _, err := decodeFirebaseBytes(c.SaltSeparator); err != nil {
		return fmt.Errorf("hash: Firebase scrypt salt separator: %w", err)
	}
	if c.Rounds < 1 || c.Rounds > firebaseMaxRounds {
		return fmt.Errorf("hash: Firebase scrypt rounds must be 1-%d, got %d", firebaseMaxRounds, c.Rounds)
	}
	if c.MemCost < 1 || c.MemCost > firebaseMaxMemCost {
		return fmt.Errorf("hash: Firebase scrypt memory cost must be 1-%d, got %d", firebaseMaxMemCost, c.MemCost)
	}
	return nil
}

// NormalizeFirebaseScrypt turns the passwordHash and salt of a Firebase
// user, as returned by accounts:batchGet, plus the project's scrypt
// configuration, into a CMF password. Firebase writes both values as
// URL-safe base64; CMF keeps them as standard base64.
func NormalizeFirebaseScrypt(passwordHash, salt string, cfg FirebaseScryptConfig) (cmf.Password, error) {
	if err := cfg.Validate(); err != nil {
		return cmf.Password{}, err
	}
	hashed, err := decodeFirebaseBytes(passwordHash)
	if err != nil || len(hashed) == 0 {
		return cmf.Password{}, fmt.Errorf("hash: Firebase passwordHash is not valid base64")
	}
	saltBytes, err := decodeFirebaseBytes(salt)
	if err != nil || len(saltBytes) == 0 {
		return cmf.Password{}, fmt.Errorf("hash: Firebase salt is missing or not valid base64")
	}
	signer, _ := decodeFirebaseBytes(cfg.SignerKey)
	separator, _ := decodeFirebaseBytes(cfg.SaltSeparator)

	return cmf.Password{
		Algorithm: cmf.AlgScrypt,
		Hash:      cmf.HashValue{Value: b64raw(hashed), Encoding: cmf.EncodingBase64},
		Salt:      &cmf.SaltValue{Value: b64raw(saltBytes), Encoding: cmf.EncodingBase64},
		Key:       &cmf.KeyValue{Value: b64std(signer), Encoding: cmf.EncodingBase64},
		Params: map[string]any{
			"variant":        firebaseVariant,
			"salt_separator": b64std(separator),
			"rounds":         cfg.Rounds,
			"mem_cost":       cfg.MemCost,
		},
		Portable: true,
	}, nil
}

// FirebaseHashParams are the request-wide hash parameters of Firebase's
// accounts:batchCreate: one request can only carry users hashed with the
// same algorithm and parameters. It's comparable, so it can key a map of
// per-configuration batches.
type FirebaseHashParams struct {
	HashAlgorithm   string `json:"hashAlgorithm,omitempty"`
	SignerKey       string `json:"signerKey,omitempty"`
	SaltSeparator   string `json:"saltSeparator,omitempty"`
	Rounds          int    `json:"rounds,omitempty"`
	MemoryCost      int    `json:"memoryCost,omitempty"`
	CPUMemCost      int    `json:"cpuMemCost,omitempty"`
	Parallelization int    `json:"parallelization,omitempty"`
	BlockSize       int    `json:"blockSize,omitempty"`
	DKLen           int    `json:"dkLen,omitempty"`
}

// FirebaseHash is a password hash in the shape accounts:batchCreate
// accepts: the per-user passwordHash and salt, plus the Params that must
// be sent once for the whole request.
type FirebaseHash struct {
	Params       FirebaseHashParams
	PasswordHash string
	Salt         string
}

// ToFirebaseHash translates a CMF password into what Firebase's
// accounts:batchCreate accepts. Firebase takes bcrypt, its own modified
// scrypt, and standard scrypt among others; only these are translated, as
// the others (HMAC and plain digests, PBKDF2) leave the salt and key
// handling unspecified, and a wrong guess would lock users out silently.
func ToFirebaseHash(p cmf.Password) (FirebaseHash, error) {
	if !p.Portable {
		return FirebaseHash{}, fmt.Errorf("hash: password marked non-portable, cannot translate to Firebase")
	}

	switch p.Algorithm {
	case cmf.AlgBcrypt:
		if !strings.HasPrefix(p.Hash.Value, "$2a$") && !strings.HasPrefix(p.Hash.Value, "$2b$") && !strings.HasPrefix(p.Hash.Value, "$2y$") {
			return FirebaseHash{}, fmt.Errorf("hash: bcrypt value %q does not have a $2a$/$2b$/$2y$ prefix", p.Hash.Value)
		}
		// Firebase takes the whole bcrypt string, salt included, as bytes.
		return FirebaseHash{
			Params:       FirebaseHashParams{HashAlgorithm: "BCRYPT"},
			PasswordHash: base64.URLEncoding.EncodeToString([]byte(p.Hash.Value)),
		}, nil

	case cmf.AlgScrypt:
		hashed, err := decodeBinary(p.Hash.Value, p.Hash.Encoding)
		if err != nil {
			return FirebaseHash{}, err
		}
		if p.Salt == nil {
			return FirebaseHash{}, fmt.Errorf("hash: scrypt requires a salt for Firebase")
		}
		salt, err := decodeBinary(p.Salt.Value, p.Salt.Encoding)
		if err != nil {
			return FirebaseHash{}, err
		}
		out := FirebaseHash{
			PasswordHash: base64.URLEncoding.EncodeToString(hashed),
			Salt:         base64.URLEncoding.EncodeToString(salt),
		}
		if p.Params["variant"] == firebaseVariant {
			params, err := firebaseScryptParams(p)
			if err != nil {
				return FirebaseHash{}, err
			}
			out.Params = params
			return out, nil
		}

		cost, _ := intParam(p.Params, "cost")
		if cost < 2 || cost&(cost-1) != 0 {
			return FirebaseHash{}, fmt.Errorf("hash: scrypt params.cost must be a power of two, got %v", p.Params["cost"])
		}
		blockSize, ok := intParam(p.Params, "blockSize")
		if !ok || blockSize == 0 {
			return FirebaseHash{}, fmt.Errorf("hash: scrypt requires params.blockSize for Firebase")
		}
		parallelization, ok := intParam(p.Params, "parallelization")
		if !ok || parallelization == 0 {
			return FirebaseHash{}, fmt.Errorf("hash: scrypt requires params.parallelization for Firebase")
		}
		out.Params = FirebaseHashParams{
			HashAlgorithm:   "STANDARD_SCRYPT",
			CPUMemCost:      cost,
			Parallelization: parallelization,
			BlockSize:       blockSize,
			DKLen:           len(hashed),
		}
		return out, nil

	default:
		return FirebaseHash{}, fmt.Errorf("hash: algorithm %q is not one of the Firebase import hashes iamigrate translates (bcrypt, scrypt)", p.Algorithm)
	}
}

// firebaseScryptParams reads a Firebase-variant scrypt password's project
// parameters back out of its CMF key and params.
func firebaseScryptParams(p cmf.Password) (FirebaseHashParams, error) {
	if p.Key == nil {
		return FirebaseHashParams{}, fmt.Errorf("hash: Firebase scrypt requires the project's signer key (key)")
	}
	signer, err := decodeBinary(p.Key.Value, p.Key.Encoding)
	if err != nil {
		return FirebaseHashParams{}, err
	}
	separator, _ := p.Params["salt_separator"].(string)
	sepBytes, err := decodeFirebaseBytes(separator)
	if err != nil {
		return FirebaseHashParams{}, fmt.Errorf("hash: Firebase scrypt params.salt_separator: %w", err)
	}
	rounds, _ := intParam(p.Params, "rounds")
	memCost, _ := intParam(p.Params, "mem_cost")
	cfg := FirebaseScryptConfig{
		SignerKey:     b64std(signer),
		SaltSeparator: b64std(sepBytes),
		Rounds:        rounds,
		MemCost:       memCost,
	}
	if err := cfg.Validate(); err != nil {
		return FirebaseHashParams{}, err
	}
	return FirebaseHashParams{
		HashAlgorithm: "SCRYPT",
		SignerKey:     cfg.SignerKey,
		SaltSeparator: cfg.SaltSeparator,
		Rounds:        rounds,
		MemoryCost:    memCost,
	}, nil
}

// decodeFirebaseBytes decodes standard or URL-safe base64, padded or not;
// Firebase emits the URL-safe alphabet, while its console shows the
// project's signer key and salt separator in the standard one. An empty
// string decodes to no bytes.
func decodeFirebaseBytes(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	return b, nil
}
