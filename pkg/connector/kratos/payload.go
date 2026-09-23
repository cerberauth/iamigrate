package kratos

import (
	"fmt"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
)

// Trait names the identifiers are written to and read from. The target
// identity schema must declare the ones a user has.
const (
	traitEmail    = "email"
	traitUsername = "username"
	traitPhone    = "phone"
)

// Kratos identity states.
const (
	stateActive   = "active"
	stateInactive = "inactive"
)

// identity is the subset of Kratos' Admin API identity JSON this connector
// reads and writes -- both the POST /admin/identities request body and the
// shape returned by GET /admin/identities?include_credential=password.
type identity struct {
	ID                  string                  `json:"id,omitempty"`
	SchemaID            string                  `json:"schema_id,omitempty"`
	Traits              map[string]any          `json:"traits"`
	State               string                  `json:"state,omitempty"`
	MetadataPublic      map[string]any          `json:"metadata_public,omitempty"`
	MetadataAdmin       map[string]any          `json:"metadata_admin,omitempty"`
	VerifiableAddresses []verifiableAddress     `json:"verifiable_addresses,omitempty"`
	Credentials         map[string]identityCred `json:"credentials,omitempty"`
}

type verifiableAddress struct {
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
	Via      string `json:"via"`
}

type identityCred struct {
	Type        string         `json:"type,omitempty"`
	Identifiers []string       `json:"identifiers,omitempty"`
	Config      map[string]any `json:"config,omitempty"`
}

// userFlags records which post-import follow-ups a translated user needs.
type userFlags struct {
	requiresPasswordReset     bool
	requiresReenrollment      bool
	requiresRecoveryCodeRegen bool
}

// buildIdentity translates one CMF user into a Kratos Admin API identity
// creation payload for schemaID.
func buildIdentity(u cmf.User, schemaID string) (identity, userFlags, error) {
	var flags userFlags

	traits := map[string]any{}
	if len(u.Emails) > 0 {
		traits[traitEmail] = u.Emails[0].Value
	}
	if u.Username != "" {
		traits[traitUsername] = u.Username
	}
	if len(u.Phones) > 0 {
		traits[traitPhone] = u.Phones[0].Value
	}
	for k, v := range u.UserMetadata {
		traits[k] = v
	}

	id := identity{
		SchemaID:       schemaID,
		Traits:         traits,
		State:          stateActive,
		MetadataAdmin:  u.AppMetadata,
		MetadataPublic: u.UserMetadata,
	}
	if u.Blocked {
		id.State = stateInactive
	}

	creds := map[string]identityCred{}
	if u.Password != nil {
		if !u.Password.Portable {
			flags.requiresPasswordReset = true
		} else {
			hashed, err := iamhash.ToKratosHashedPassword(*u.Password)
			if err != nil {
				return identity{}, flags, err
			}
			creds["password"] = identityCred{
				Config: map[string]any{"hashed_password": hashed},
			}
		}
	}

	for _, f := range u.MFAFactors {
		switch f.Type {
		case cmf.MFATOTP:
			creds["totp"] = identityCred{
				Config: map[string]any{"totp_url": f.Value},
			}
		case cmf.MFARecoveryCodes:
			creds["lookup_secret"] = identityCred{
				Config: map[string]any{"recovery_codes": []map[string]string{{"code": f.Value}}},
			}
		case cmf.MFASMS, cmf.MFAEmail, cmf.MFAWebAuthn, cmf.MFAPush:
			// Kratos' Admin API has no import path for these factor
			// types (only totp/lookup_secret accept pre-existing
			// secrets), so the user must re-enroll after migration.
			flags.requiresReenrollment = true
		}
	}
	if len(creds) > 0 {
		id.Credentials = creds
	}

	if len(u.Emails) > 0 && u.Emails[0].Verified {
		id.VerifiableAddresses = append(id.VerifiableAddresses,
			verifiableAddress{Value: u.Emails[0].Value, Verified: true, Via: "email"})
	}
	if len(u.Phones) > 0 && u.Phones[0].Verified {
		id.VerifiableAddresses = append(id.VerifiableAddresses,
			verifiableAddress{Value: u.Phones[0].Value, Verified: true, Via: "sms"})
	}

	return id, flags, nil
}

// userFromIdentity translates a Kratos identity (as returned by
// GET /admin/identities?include_credential=password) into a CMF user.
func userFromIdentity(id identity, sourceConnector string) (cmf.User, string, error) {
	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id.ID,
		Blocked:    id.State == stateInactive,
		Provenance: cmf.Provenance{SourceConnector: sourceConnector, ExportedAt: time.Now().UTC()},
	}

	if email, ok := id.Traits[traitEmail].(string); ok && email != "" {
		u.Emails = []cmf.Contact{{Value: email, Verified: id.addressVerified(email), Primary: true}}
	}
	if username, ok := id.Traits[traitUsername].(string); ok {
		u.Username = username
	}
	if phone, ok := id.Traits[traitPhone].(string); ok && phone != "" {
		u.Phones = []cmf.Contact{{Value: phone, Verified: id.addressVerified(phone), Primary: true}}
	}

	u.AppMetadata = id.MetadataAdmin
	u.UserMetadata = id.MetadataPublic

	if cred, ok := id.Credentials["password"]; ok {
		hashed, _ := cred.Config["hashed_password"].(string)
		if hashed == "" {
			return cmf.User{}, "missing hashed_password on identity's password credential", nil
		}
		p, err := iamhash.NormalizeKratosHashedPassword(hashed)
		if err != nil {
			return cmf.User{}, fmt.Sprintf("unrecognized password hash format: %v", err), nil
		}
		u.Password = &p
	}

	if cred, ok := id.Credentials["totp"]; ok {
		if url, ok := cred.Config["totp_url"].(string); ok && url != "" {
			u.MFAFactors = append(u.MFAFactors, cmf.MFAFactor{
				Type: cmf.MFATOTP, Value: url, Portable: true,
			})
		}
	}

	return u, "", nil
}

// addressVerified reports whether value is one of id's verified addresses.
func (id identity) addressVerified(value string) bool {
	for _, va := range id.VerifiableAddresses {
		if va.Value == value && va.Verified {
			return true
		}
	}
	return false
}

// loginIdentifier returns the identifier to look u up by: the email, else
// the username, else the phone, or "" when u has none of them.
func loginIdentifier(u cmf.User) string {
	switch {
	case len(u.Emails) > 0:
		return u.Emails[0].Value
	case u.Username != "":
		return u.Username
	case len(u.Phones) > 0:
		return u.Phones[0].Value
	}
	return ""
}
