package cmf_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

const goldenPath = "testdata/golden/users.golden.jsonl"

// goldenUsers covers the edge cases DESIGN.md calls out for this
// layer: password: null, ten MFA factors on one user, and non-ASCII
// names.
func goldenUsers() []cmf.User {
	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	tenFactors := make([]cmf.MFAFactor, 0, 10)
	types := []cmf.MFAType{
		cmf.MFATOTP, cmf.MFASMS, cmf.MFAEmail, cmf.MFAWebAuthn, cmf.MFARecoveryCodes, cmf.MFAPush,
	}
	for i := 0; i < 10; i++ {
		t := types[i%len(types)]
		tenFactors = append(tenFactors, cmf.MFAFactor{
			Type:     t,
			Value:    "factor-value",
			Portable: t != cmf.MFAWebAuthn && t != cmf.MFARecoveryCodes,
		})
	}

	return []cmf.User{
		{
			CMFVersion: cmf.Version,
			SourceID:   "golden-1",
			Emails:     []cmf.Contact{{Value: "no-password@example.com", Verified: true, Primary: true}},
			Profile:    cmf.Profile{GivenName: "SSO", FamilyName: "Only"},
			Password:   nil,
			Provenance: cmf.Provenance{SourceConnector: "golden", ExportedAt: fixedTime},
		},
		{
			CMFVersion: cmf.Version,
			SourceID:   "golden-2",
			Emails:     []cmf.Contact{{Value: "many-factors@example.com", Verified: true, Primary: true}},
			Profile:    cmf.Profile{GivenName: "Many", FamilyName: "Factors"},
			Password: &cmf.Password{
				Algorithm: cmf.AlgBcrypt,
				Hash:      cmf.HashValue{Value: "$2b$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", Encoding: cmf.EncodingUTF8},
				Portable:  true,
			},
			MFAFactors: tenFactors,
			Provenance: cmf.Provenance{SourceConnector: "golden", ExportedAt: fixedTime},
		},
		{
			CMFVersion: cmf.Version,
			SourceID:   "golden-3",
			Emails:     []cmf.Contact{{Value: "unicode@example.com", Verified: true, Primary: true}},
			Profile: cmf.Profile{
				GivenName:  "Zoé",
				FamilyName: "Müller-Świątek",
				Name:       "Zoé Müller-Świątek 田中",
				Locale:     "ja_JP",
			},
			Password: &cmf.Password{
				Algorithm: cmf.AlgArgon2,
				PHCString: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
				Hash:      cmf.HashValue{Value: "RdescudvJCsgt3ub+b+dWRWJTmaaJObG", Encoding: cmf.EncodingBase64},
				Portable:  true,
			},
			Provenance: cmf.Provenance{SourceConnector: "golden", ExportedAt: fixedTime},
		},
	}
}

func TestCMFGoldenFileRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, u := range goldenUsers() {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())

	gz, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	actual, err := io.ReadAll(gz)
	require.NoError(t, err)

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(goldenPath, actual, 0o644))
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden file missing; run with UPDATE_GOLDEN=1 to create it")
	require.Equal(t, string(expected), string(actual), "CMF encoding regressed vs golden file (bump cmf_version or UPDATE_GOLDEN=1 if intentional)")

	// Semantic round-trip: decode the golden bytes back and check they
	// still parse into the same structs, independent of exact byte
	// layout.
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, err = gzw.Write(expected)
	require.NoError(t, err)
	require.NoError(t, gzw.Close())

	r, err := cmf.NewReader(&gzBuf)
	require.NoError(t, err)
	defer r.Close()

	want := goldenUsers()
	var got []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		got = append(got, u)
	}
	require.Equal(t, want, got)
}
