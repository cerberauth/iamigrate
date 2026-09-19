package auth0

import (
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func TestBuildImportUserFlagsWebAuthnAndRecoveryCodes(t *testing.T) {
	now := time.Now().UTC()
	u := cmf.User{
		SourceID: "u1",
		MFAFactors: []cmf.MFAFactor{
			{Type: cmf.MFAWebAuthn, Value: "cred", Portable: false, EnrolledAt: &now},
			{Type: cmf.MFARecoveryCodes, Value: "codes", Portable: false, EnrolledAt: &now},
			{Type: cmf.MFATOTP, Value: "SECRET", Portable: true, EnrolledAt: &now},
		},
	}
	rec, flags, err := buildImportUser(u, false)
	require.NoError(t, err)
	require.True(t, flags.requiresReenrollment)
	require.True(t, flags.requiresRecoveryCodeRegen)

	mfa, ok := rec["mfa_factors"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, mfa, 1) // only totp made it in
}

func TestBuildImportUserNonPortablePasswordRequiresReset(t *testing.T) {
	u := cmf.User{
		SourceID: "u1",
		Password: &cmf.Password{Algorithm: cmf.AlgBcrypt, Portable: false, Hash: cmf.HashValue{Value: "x"}},
	}
	rec, flags, err := buildImportUser(u, false)
	require.NoError(t, err)
	require.True(t, flags.requiresPasswordReset)
	_, hasHash := rec["password_hash"]
	require.False(t, hasHash)
	_, hasCustom := rec["custom_password_hash"]
	require.False(t, hasCustom)
}

func TestBuildImportUserPasswordHashVsCustomPasswordHash(t *testing.T) {
	u := cmf.User{
		SourceID: "u1",
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Portable:  true,
			Hash:      cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
		},
	}

	rec, _, err := buildImportUser(u, false) // allowUpsert=false -> may use password_hash
	require.NoError(t, err)
	require.Contains(t, rec, "password_hash")
	require.NotContains(t, rec, "custom_password_hash")

	rec2, _, err := buildImportUser(u, true) // allowUpsert=true -> must use custom_password_hash
	require.NoError(t, err)
	require.Contains(t, rec2, "custom_password_hash")
	require.NotContains(t, rec2, "password_hash")
}
