package firebase

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
)

// account is the subset of an Identity Toolkit UserInfo this connector
// reads and writes: the shape of an accounts:batchGet and accounts:lookup
// result, and of an accounts:batchCreate request entry.
type account struct {
	LocalID          string          `json:"localId,omitempty"`
	Email            string          `json:"email,omitempty"`
	EmailVerified    bool            `json:"emailVerified,omitempty"`
	DisplayName      string          `json:"displayName,omitempty"`
	PhotoURL         string          `json:"photoUrl,omitempty"`
	PhoneNumber      string          `json:"phoneNumber,omitempty"`
	Disabled         bool            `json:"disabled,omitempty"`
	PasswordHash     string          `json:"passwordHash,omitempty"`
	Salt             string          `json:"salt,omitempty"`
	CustomAttributes string          `json:"customAttributes,omitempty"`
	ProviderUserInfo []providerInfo  `json:"providerUserInfo,omitempty"`
	MFAInfo          []mfaEnrollment `json:"mfaInfo,omitempty"`
}

type providerInfo struct {
	ProviderID string `json:"providerId"`
}

// mfaEnrollment is one second factor. Phone factors carry their number in
// PhoneInfo, which exports may mask (+1******1234), with the real one in
// UnobfuscatedPhoneInfo; a TOTP factor carries no secret at all.
type mfaEnrollment struct {
	MFAEnrollmentID       string    `json:"mfaEnrollmentId,omitempty"`
	DisplayName           string    `json:"displayName,omitempty"`
	EnrolledAt            string    `json:"enrolledAt,omitempty"`
	PhoneInfo             string    `json:"phoneInfo,omitempty"`
	UnobfuscatedPhoneInfo string    `json:"unobfuscatedPhoneInfo,omitempty"`
	TOTPInfo              *struct{} `json:"totpInfo,omitempty"`
}

// userFlags records which post-import follow-ups a translated user needs.
type userFlags struct {
	requiresPasswordReset bool
	requiresReenrollment  bool
}

// buildAccount translates one CMF user into an accounts:batchCreate entry,
// plus the hash parameters the request carrying it must declare (the zero
// value for a user without an importable password).
//
// The CMF source_id becomes the Firebase uid. A username is dropped, as
// Firebase has no such sign-in method, and so are user_metadata, extra
// emails/phones, and organizations/roles; app_metadata becomes the custom
// claims.
func buildAccount(u cmf.User) (account, iamhash.FirebaseHashParams, userFlags, error) {
	var (
		flags  userFlags
		params iamhash.FirebaseHashParams
	)
	if len(u.Emails) == 0 && len(u.Phones) == 0 {
		return account{}, params, flags, fmt.Errorf("user has neither an email nor a phone number, which Firebase needs to sign in")
	}

	a := account{
		LocalID:     u.TargetID(Name),
		DisplayName: displayName(u.Profile),
		PhotoURL:    u.Profile.Picture,
		Disabled:    u.Blocked,
	}
	if len(u.Emails) > 0 {
		a.Email = u.Emails[0].Value
		a.EmailVerified = u.Emails[0].Verified
	}
	if len(u.Phones) > 0 {
		a.PhoneNumber = u.Phones[0].Value
	}
	if len(u.AppMetadata) > 0 {
		claims, err := json.Marshal(u.AppMetadata)
		if err != nil {
			return account{}, params, flags, fmt.Errorf("encoding app_metadata as custom claims: %w", err)
		}
		a.CustomAttributes = string(claims)
	}

	if u.Password != nil {
		if !u.Password.Portable {
			flags.requiresPasswordReset = true
		} else {
			h, err := iamhash.ToFirebaseHash(*u.Password)
			if err != nil {
				return account{}, params, flags, err
			}
			a.PasswordHash, a.Salt, params = h.PasswordHash, h.Salt, h.Params
		}
	}

	for _, f := range u.MFAFactors {
		if f.Type != cmf.MFASMS || !f.Portable {
			// Firebase can't import a TOTP secret, and has no other second
			// factor an existing credential could be mapped onto.
			flags.requiresReenrollment = true
			continue
		}
		e := mfaEnrollment{PhoneInfo: f.Value}
		if f.EnrolledAt != nil {
			e.EnrolledAt = f.EnrolledAt.UTC().Format(time.RFC3339)
		}
		a.MFAInfo = append(a.MFAInfo, e)
	}

	return a, params, flags, nil
}

// displayName returns the profile's full name, else its given and family
// names joined.
func displayName(p cmf.Profile) string {
	if p.Name != "" {
		return p.Name
	}
	return strings.TrimSpace(p.GivenName + " " + p.FamilyName)
}

// userFromAccount translates a Firebase account into a CMF user. cfg is the
// project's scrypt configuration; without it a password hash is kept but
// marked non-portable, as nothing could verify it. A non-empty second
// return value is the reason the account was skipped instead.
func userFromAccount(a account, cfg *iamhash.FirebaseScryptConfig, sourceConnector string) (cmf.User, string) {
	if a.Email == "" && a.PhoneNumber == "" && len(a.ProviderUserInfo) == 0 {
		return cmf.User{}, "no email, phone number, or sign-in provider (anonymous or custom-token user)"
	}

	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   a.LocalID,
		Blocked:    a.Disabled,
		Profile:    cmf.Profile{Name: a.DisplayName, Picture: a.PhotoURL},
		Provenance: cmf.Provenance{SourceConnector: sourceConnector, ExportedAt: time.Now().UTC()},
	}
	if a.Email != "" {
		u.Emails = []cmf.Contact{{Value: a.Email, Verified: a.EmailVerified, Primary: true}}
	}
	if a.PhoneNumber != "" {
		// Firebase only stores a phone number once it was verified by SMS.
		u.Phones = []cmf.Contact{{Value: a.PhoneNumber, Verified: true, Primary: true}}
	}

	if a.CustomAttributes != "" {
		var claims map[string]any
		if err := json.Unmarshal([]byte(a.CustomAttributes), &claims); err != nil {
			return cmf.User{}, fmt.Sprintf("invalid customAttributes: %v", err)
		}
		if len(claims) > 0 {
			u.AppMetadata = claims
		}
	}

	if a.PasswordHash != "" {
		p, reason := passwordFromAccount(a, cfg)
		if reason != "" {
			return cmf.User{}, reason
		}
		u.Password = &p
	}

	for _, e := range a.MFAInfo {
		switch {
		case e.TOTPInfo != nil:
			// A TOTP enrollment's secret is never returned.
			u.MFAFactors = append(u.MFAFactors, cmf.MFAFactor{Type: cmf.MFATOTP, Portable: false, EnrolledAt: parseTime(e.EnrolledAt)})
		case e.PhoneInfo != "" || e.UnobfuscatedPhoneInfo != "":
			number := e.UnobfuscatedPhoneInfo
			if number == "" {
				number = e.PhoneInfo
			}
			u.MFAFactors = append(u.MFAFactors, cmf.MFAFactor{
				Type:       cmf.MFASMS,
				Value:      number,
				Portable:   !strings.Contains(number, "*"),
				EnrolledAt: parseTime(e.EnrolledAt),
			})
		}
	}

	return u, ""
}

// passwordFromAccount builds the CMF password for an account with a
// passwordHash. The hash is Firebase's modified scrypt, so it can only be
// verified with the project's configuration.
func passwordFromAccount(a account, cfg *iamhash.FirebaseScryptConfig) (cmf.Password, string) {
	if cfg == nil {
		// The hash is still recorded, but nothing can verify it elsewhere.
		return cmf.Password{
			Algorithm: cmf.AlgScrypt,
			Hash:      cmf.HashValue{Value: standardBase64(a.PasswordHash), Encoding: cmf.EncodingBase64},
			Params:    map[string]any{"variant": "firebase"},
			Portable:  false,
		}, ""
	}
	p, err := iamhash.NormalizeFirebaseScrypt(a.PasswordHash, a.Salt, *cfg)
	if err != nil {
		return cmf.Password{}, fmt.Sprintf("unrecognized password hash format: %v", err)
	}
	return p, ""
}

// standardBase64 rewrites Firebase's URL-safe base64 as unpadded standard
// base64, the form CMF carries.
func standardBase64(s string) string {
	return strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(s, "="))
}

// parseTime parses an RFC 3339 timestamp, or returns nil if it's absent or
// malformed.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// loginIdentifier returns the account field to look u up by: the first
// email, else the first phone number.
func loginIdentifier(u cmf.User) (field, value string) {
	switch {
	case len(u.Emails) > 0:
		return fieldEmail, u.Emails[0].Value
	case len(u.Phones) > 0:
		return "phoneNumber", u.Phones[0].Value
	}
	return "", ""
}
