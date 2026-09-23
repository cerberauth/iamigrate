package auth0

import (
	"errors"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
)

// userFlags records which post-import follow-ups a translated user needs,
// per DESIGN.md's MFA import and idempotent re-run sections.
type userFlags struct {
	requiresPasswordReset     bool
	requiresReenrollment      bool
	requiresRecoveryCodeRegen bool
}

// errEmailRequired rejects a user Auth0's bulk import can't take: its user
// schema requires email, so a username- or phone-only user has no import
// path and must be created another way.
var errEmailRequired = errors.New("auth0: bulk import requires an email; user has only a username and/or phone")

// buildImportUser translates one CMF user into an Auth0 bulk-import user
// record. allowUpsert controls whether custom_password_hash (updatable) is
// preferred over the simpler, write-once password_hash field.
func buildImportUser(u cmf.User, allowUpsert bool) (map[string]any, userFlags, error) {
	var flags userFlags
	rec := map[string]any{
		"user_id": u.SourceID,
	}
	if len(u.Emails) == 0 {
		return nil, flags, errEmailRequired
	}
	rec["email"] = u.Emails[0].Value
	rec["email_verified"] = u.Emails[0].Verified
	if u.Username != "" {
		rec["username"] = u.Username
	}
	if len(u.Phones) > 0 {
		rec["phone_number"] = u.Phones[0].Value
		rec["phone_verified"] = u.Phones[0].Verified
	}
	if u.Profile.GivenName != "" {
		rec["given_name"] = u.Profile.GivenName
	}
	if u.Profile.FamilyName != "" {
		rec["family_name"] = u.Profile.FamilyName
	}
	if u.Profile.Name != "" {
		rec["name"] = u.Profile.Name
	}
	if u.Profile.Nickname != "" {
		rec["nickname"] = u.Profile.Nickname
	}
	if u.Profile.Picture != "" {
		rec["picture"] = u.Profile.Picture
	}
	rec["blocked"] = u.Blocked
	if len(u.AppMetadata) > 0 {
		rec["app_metadata"] = u.AppMetadata
	}
	if len(u.UserMetadata) > 0 {
		rec["user_metadata"] = u.UserMetadata
	}

	if u.Password != nil {
		if !u.Password.Portable {
			flags.requiresPasswordReset = true
		} else {
			a0, err := iamhash.ToAuth0(*u.Password, !allowUpsert)
			if err != nil {
				return nil, flags, err
			}
			switch a0.Field {
			case iamhash.FieldPasswordHash:
				rec["password_hash"] = a0.Payload["value"]
			case iamhash.FieldCustomPasswordHash:
				rec["custom_password_hash"] = a0.Payload
			}
		}
	}

	var mfaFactors []map[string]any
	for _, f := range u.MFAFactors {
		switch f.Type {
		case cmf.MFATOTP:
			mfaFactors = append(mfaFactors, map[string]any{
				"totp": map[string]any{"secret": f.Value},
			})
		case cmf.MFASMS:
			mfaFactors = append(mfaFactors, map[string]any{
				"phone": map[string]any{"value": f.Value, "verified": true},
			})
		case cmf.MFAEmail:
			mfaFactors = append(mfaFactors, map[string]any{
				"email": map[string]any{"value": f.Value, "verified": true},
			})
		case cmf.MFAWebAuthn:
			flags.requiresReenrollment = true
		case cmf.MFARecoveryCodes:
			flags.requiresRecoveryCodeRegen = true
		case cmf.MFAPush:
			// Auth0's bulk import job doesn't accept push factors either;
			// treat as a re-enrollment case like WebAuthn.
			flags.requiresReenrollment = true
		}
	}
	if len(mfaFactors) > 0 {
		rec["mfa_factors"] = mfaFactors
	}

	return rec, flags, nil
}
