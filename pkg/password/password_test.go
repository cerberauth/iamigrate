package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateLengthBounds(t *testing.T) {
	for _, n := range []int{MinLength - 1, MaxLength + 1, 0, -1} {
		_, err := Generate(n)
		require.Error(t, err, "length %d", n)
	}
	for _, n := range []int{MinLength, DefaultLength, MaxLength} {
		pw, err := Generate(n)
		require.NoError(t, err)
		require.Len(t, pw, n)
	}
}

func TestGenerateCoversEveryClassAndOnlyUsesThem(t *testing.T) {
	for range 200 {
		pw, err := Generate(MinLength)
		require.NoError(t, err)
		for _, c := range classes {
			require.True(t, strings.ContainsAny(pw, c), "%q misses a character from %q", pw, c)
		}
		for _, r := range pw {
			require.True(t, strings.ContainsRune(lower+upper+digits+symbols, r), "%q has unexpected %q", pw, r)
		}
	}
}

func TestGenerateIsRandom(t *testing.T) {
	seen := map[string]struct{}{}
	for range 1000 {
		pw, err := Generate(DefaultLength)
		require.NoError(t, err)
		_, dup := seen[pw]
		require.False(t, dup, "repeated password %q", pw)
		seen[pw] = struct{}{}
	}
}
