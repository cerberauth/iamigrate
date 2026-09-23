package keycloak

import (
	"encoding/json"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/stretchr/testify/require"
)

func TestBuildUserProfileAndAttributes(t *testing.T) {
	u := cmf.User{
		SourceID: "u1",
		Emails:   []cmf.Contact{{Value: "jane@example.com", Verified: true, Primary: true}},
		Phones:   []cmf.Contact{{Value: "+12025550142", Verified: false, Primary: true}},
		Username: "jane.doe",
		Blocked:  true,
		Profile:  cmf.Profile{GivenName: "Jane", FamilyName: "Doe", Locale: "fr"},
		UserMetadata: map[string]any{
			"plan": "free", "tags": []any{"a", "b"}, "score": float64(3),
		},
		AppMetadata: map[string]any{"plan": "gold"},
	}

	rep, _, err := buildUser(u)
	require.NoError(t, err)
	require.Equal(t, "jane.doe", rep.Username)
	require.Equal(t, "jane@example.com", rep.Email)
	require.True(t, rep.EmailVerified)
	require.Equal(t, "Jane", rep.FirstName)
	require.Equal(t, "Doe", rep.LastName)
	require.False(t, rep.Enabled)
	require.Equal(t, map[string][]string{
		"plan":                {"gold"},
		"tags":                {"a", "b"},
		"score":               {"3"},
		"phoneNumber":         {"+12025550142"},
		"phoneNumberVerified": {"false"},
		"locale":              {"fr"},
	}, rep.Attributes)
	require.Empty(t, rep.Credentials)
}

func TestBuildUserUsernameFallsBackToEmailThenPhone(t *testing.T) {
	rep, _, err := buildUser(cmf.User{Emails: []cmf.Contact{{Value: "a@example.com"}}, Phones: []cmf.Contact{{Value: "+12025550142"}}})
	require.NoError(t, err)
	require.Equal(t, "a@example.com", rep.Username)

	rep, _, err = buildUser(cmf.User{Phones: []cmf.Contact{{Value: "+12025550142"}}})
	require.NoError(t, err)
	require.Equal(t, "+12025550142", rep.Username)
	require.Empty(t, rep.Email)

	_, _, err = buildUser(cmf.User{SourceID: "none"})
	require.ErrorContains(t, err, "no username, email, or phone")
}

func TestBuildUserMFA(t *testing.T) {
	u := cmf.User{
		Username: "u",
		Password: &cmf.Password{Algorithm: cmf.AlgSHA256, Portable: false},
		MFAFactors: []cmf.MFAFactor{
			{Type: cmf.MFATOTP, Value: "otpauth://totp/acme:u?secret=jbswy3dpehpk3pxp&digits=8&algorithm=SHA256", Portable: true},
			{Type: cmf.MFARecoveryCodes, Portable: false},
			{Type: cmf.MFAWebAuthn, Portable: false},
		},
	}

	rep, flags, err := buildUser(u)
	require.NoError(t, err)
	require.True(t, flags.requiresPasswordReset)
	require.True(t, flags.requiresRecoveryCodeRegen)
	require.True(t, flags.requiresReenrollment)
	require.Len(t, rep.Credentials, 1)
	require.Equal(t, "otp", rep.Credentials[0].Type)
	require.JSONEq(t, `{"value":"JBSWY3DPEHPK3PXP"}`, rep.Credentials[0].SecretData)
	require.JSONEq(t, `{"subType":"totp","digits":8,"period":30,"algorithm":"HmacSHA256","counter":0,"secretEncoding":"BASE32"}`, rep.Credentials[0].CredentialData)
}

func TestBuildUserRejectsInvalidTOTPSecret(t *testing.T) {
	_, _, err := buildUser(cmf.User{Username: "u", MFAFactors: []cmf.MFAFactor{{Type: cmf.MFATOTP, Value: "not base32!", Portable: true}}})
	require.ErrorContains(t, err, "not valid base32")
}

func TestUserFromRepresentationEmailAsUsername(t *testing.T) {
	u, skip, err := userFromRepresentation(userRepresentation{
		ID: "1", Username: "jane@example.com", Email: "jane@example.com", Enabled: true,
	}, Name)
	require.NoError(t, err)
	require.Empty(t, skip)
	require.Empty(t, u.Username)
	require.False(t, u.Blocked)
	require.Nil(t, u.Password)
}

func TestUserFromRepresentationPhoneAsUsername(t *testing.T) {
	u, _, err := userFromRepresentation(userRepresentation{
		ID: "1", Username: "+12025550142", Enabled: true,
		Attributes: map[string][]string{"phoneNumber": {"+12025550142"}},
	}, Name)
	require.NoError(t, err)
	require.Empty(t, u.Username)
	require.Equal(t, []cmf.Contact{{Value: "+12025550142", Primary: true}}, u.Phones)
}

func TestUserFromRepresentationRawOTPSecretAndParams(t *testing.T) {
	u, _, err := userFromRepresentation(userRepresentation{
		ID: "1", Username: "u", Enabled: true,
		Credentials: []credentialRepresentation{
			{Type: "otp", SecretData: `{"value":"12345678901234567890"}`, CredentialData: `{"subType":"totp","digits":8,"period":60,"algorithm":"HmacSHA512"}`},
			{Type: "otp", SecretData: `{"value":"x"}`, CredentialData: `{"subType":"hotp","digits":6}`},
		},
	}, Name)
	require.NoError(t, err)
	require.Equal(t, []cmf.MFAFactor{{
		Type:       cmf.MFATOTP,
		Value:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		TOTPParams: &cmf.TOTPParams{Digits: 8, Period: 60, Algorithm: "SHA512"},
		Portable:   true,
	}}, u.MFAFactors)

	// Translating it back keeps the parameters.
	cred, err := otpCredential(u.MFAFactors[0])
	require.NoError(t, err)
	var data otpCredentialData
	require.NoError(t, json.Unmarshal([]byte(cred.CredentialData), &data))
	require.Equal(t, otpCredentialData{SubType: "totp", Digits: 8, Period: 60, Algorithm: "HmacSHA512", SecretEncoding: "BASE32"}, data)
}

func TestUserFromRepresentationMissingSecretData(t *testing.T) {
	_, skip, err := userFromRepresentation(userRepresentation{
		ID: "1", Username: "u", Credentials: []credentialRepresentation{{Type: "password", CredentialData: `{"algorithm":"argon2"}`}},
	}, Name)
	require.NoError(t, err)
	require.Contains(t, skip, "no secretData")
}
