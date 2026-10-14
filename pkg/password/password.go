// Package password generates strong random cleartext passwords, e.g. to
// give users a credential when a CMF file carries none.
package password

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	// MinLength and MaxLength bound Generate's length. The upper bound is
	// bcrypt's 72-byte input limit: a longer password would be silently
	// truncated, weakening it without anyone noticing.
	MinLength = 12
	MaxLength = 72

	// DefaultLength is the length callers should use unless told otherwise.
	DefaultLength = 24
)

// Character classes. Look-alike characters (0/O, 1/l/I) are kept out so a
// password can be read out or retyped, and the symbols are the ones that
// need no escaping in CSV, JSON, shell, or URL contexts.
const (
	lower   = "abcdefghijkmnopqrstuvwxyz"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "!@#%^*-_=+?"
)

var classes = []string{lower, upper, digits, symbols}

// Generate returns a random password of the given length drawn from
// crypto/rand, with at least one lowercase letter, uppercase letter, digit,
// and symbol so it satisfies common target password policies.
func Generate(length int) (string, error) {
	if length < MinLength || length > MaxLength {
		return "", fmt.Errorf("password: length must be between %d and %d, got %d", MinLength, MaxLength, length)
	}

	all := ""
	for _, c := range classes {
		all += c
	}

	out := make([]byte, 0, length)
	for _, c := range classes {
		b, err := pick(c)
		if err != nil {
			return "", err
		}
		out = append(out, b)
	}
	for len(out) < length {
		b, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, b)
	}

	// The guaranteed characters sit at the front; shuffle so their
	// positions are not predictable.
	for i := len(out) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	i, err := randInt(len(set))
	if err != nil {
		return 0, err
	}
	return set[i], nil
}

// randInt returns a uniform random int in [0, n).
func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("password: reading random bytes: %w", err)
	}
	return int(v.Int64()), nil
}
