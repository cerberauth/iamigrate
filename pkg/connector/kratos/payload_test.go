package kratos

import (
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func TestBuildIdentityPassword(t *testing.T) {
	u := cmf.User{
		SourceID: "u1",
		Emails:   []cmf.Contact{{Value: "u1@example.com", Verified: true, Primary: true}},
		Username: "u1",
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
	}

	id, flags, err := buildIdentity(u, "default")
	require.NoError(t, err)
	require.False(t, flags.requiresPasswordReset)
	require.Equal(t, "default", id.SchemaID)
	require.Equal(t, "u1@example.com", id.Traits["email"])
	require.Equal(t, "u1", id.Traits["username"])
	require.Equal(t, "active", id.State)
	require.Equal(t, u.Password.Hash.Value, id.Credentials["password"].Config["hashed_password"])
	require.Len(t, id.VerifiableAddresses, 1)
	require.True(t, id.VerifiableAddresses[0].Verified)
}

func TestBuildIdentityBlockedAndNonPortablePassword(t *testing.T) {
	u := cmf.User{
		SourceID: "u2",
		Blocked:  true,
		Password: &cmf.Password{Algorithm: cmf.AlgSHA256, Portable: false},
	}

	id, flags, err := buildIdentity(u, "default")
	require.NoError(t, err)
	require.True(t, flags.requiresPasswordReset)
	require.Equal(t, "inactive", id.State)
	require.Nil(t, id.Credentials)
}

func TestBuildIdentityUnsupportedAlgorithm(t *testing.T) {
	u := cmf.User{
		SourceID: "u3",
		Password: &cmf.Password{Algorithm: cmf.AlgSHA256, Portable: true, Hash: cmf.HashValue{Value: "deadbeef", Encoding: cmf.EncodingHex}},
	}

	_, _, err := buildIdentity(u, "default")
	require.Error(t, err)
}

func TestBuildIdentityMFA(t *testing.T) {
	u := cmf.User{
		SourceID: "u4",
		MFAFactors: []cmf.MFAFactor{
			{Type: cmf.MFATOTP, Value: "otpauth://totp/test?secret=ABC", Portable: true},
			{Type: cmf.MFARecoveryCodes, Value: "abc123", Portable: true},
			{Type: cmf.MFAWebAuthn, Portable: false},
		},
	}

	id, flags, err := buildIdentity(u, "default")
	require.NoError(t, err)
	require.True(t, flags.requiresReenrollment)
	require.Equal(t, "otpauth://totp/test?secret=ABC", id.Credentials["totp"].Config["totp_url"])
	require.NotNil(t, id.Credentials["lookup_secret"])
}

func TestUserFromIdentityRoundTrip(t *testing.T) {
	id := identity{
		ID:     "id-1",
		Traits: map[string]any{"email": "u1@example.com", "username": "u1"},
		State:  "active",
		VerifiableAddresses: []verifiableAddress{
			{Value: "u1@example.com", Verified: true, Via: "email"},
		},
		Credentials: map[string]identityCred{
			"password": {Config: map[string]any{"hashed_password": "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW"}},
			"totp":     {Config: map[string]any{"totp_url": "otpauth://totp/test?secret=ABC"}},
		},
	}

	u, skipReason, err := userFromIdentity(id, "kratos")
	require.NoError(t, err)
	require.Empty(t, skipReason)
	require.Equal(t, "id-1", u.SourceID)
	require.Equal(t, "u1@example.com", u.Emails[0].Value)
	require.True(t, u.Emails[0].Verified)
	require.Equal(t, "u1", u.Username)
	require.Equal(t, cmf.AlgBcrypt, u.Password.Algorithm)
	require.Len(t, u.MFAFactors, 1)
	require.Equal(t, cmf.MFATOTP, u.MFAFactors[0].Type)
}

func TestUserFromIdentityUnrecognizedHash(t *testing.T) {
	id := identity{
		ID:     "id-2",
		Traits: map[string]any{"email": "u2@example.com"},
		Credentials: map[string]identityCred{
			"password": {Config: map[string]any{"hashed_password": "not-a-real-hash"}},
		},
	}

	_, skipReason, err := userFromIdentity(id, "kratos")
	require.NoError(t, err)
	require.NotEmpty(t, skipReason)
}
