// Package cmf defines the Canonical Migration Format: versioned types for
// users, organizations, and roles, plus a streaming JSONL encoder/decoder.
package cmf

import "time"

// Version is the CMF format version this package encodes and validates.
const Version = "1.0"

// Algorithm identifies a password hashing algorithm as captured by a source
// connector and normalized into the CMF password object.
type Algorithm string

const (
	AlgBcrypt Algorithm = "bcrypt"
	AlgScrypt Algorithm = "scrypt"
	AlgPBKDF2 Algorithm = "pbkdf2"
	AlgArgon2 Algorithm = "argon2"
	AlgMD5    Algorithm = "md5"
	AlgSHA1   Algorithm = "sha1"
	AlgSHA256 Algorithm = "sha256"
	AlgSHA512 Algorithm = "sha512"
	AlgMD4    Algorithm = "md4"
	AlgHMAC   Algorithm = "hmac"
	AlgLDAP   Algorithm = "ldap"
)

// Encoding names the byte-to-text encoding used for a hash, salt, or key
// value carried in the password object.
type Encoding string

const (
	EncodingHex    Encoding = "hex"
	EncodingBase64 Encoding = "base64"
	EncodingUTF8   Encoding = "utf8"
)

// SaltPosition records where the salt sits relative to the password in the
// source system's hashing scheme, since targets like Auth0 need this to
// replicate the digest during verification.
type SaltPosition string

const (
	SaltPrefix SaltPosition = "prefix"
	SaltSuffix SaltPosition = "suffix"
)

// MFAType identifies a category of multi-factor authentication credential.
type MFAType string

const (
	MFATOTP          MFAType = "totp"
	MFASMS           MFAType = "sms"
	MFAEmail         MFAType = "email"
	MFAWebAuthn      MFAType = "webauthn"
	MFARecoveryCodes MFAType = "recovery_codes"
	MFAPush          MFAType = "push"
)

// Contact is an email or phone entry on a user record.
type Contact struct {
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

// Profile carries the display fields for a user.
type Profile struct {
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Name       string `json:"name,omitempty"`
	Nickname   string `json:"nickname,omitempty"`
	Picture    string `json:"picture,omitempty"`
	Locale     string `json:"locale,omitempty"`
}

// HashValue is the digest itself plus how it's encoded as text.
type HashValue struct {
	Value    string   `json:"value"`
	Encoding Encoding `json:"encoding"`
	Digest   string   `json:"digest,omitempty"`
}

// SaltValue is a hash's salt, if the algorithm uses a separately stored one.
type SaltValue struct {
	Value    string       `json:"value"`
	Encoding Encoding     `json:"encoding"`
	Position SaltPosition `json:"position,omitempty"`
}

// KeyValue is HMAC key material associated with a password hash.
type KeyValue struct {
	Value    string   `json:"value"`
	Encoding Encoding `json:"encoding"`
}

// Password is CMF's password credential object, modeled on Auth0's
// custom_password_hash schema per DESIGN.md.
type Password struct {
	Algorithm Algorithm      `json:"algorithm"`
	PHCString string         `json:"phc_string,omitempty"`
	Hash      HashValue      `json:"hash"`
	Salt      *SaltValue     `json:"salt,omitempty"`
	Key       *KeyValue      `json:"key,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
	Portable  bool           `json:"portable"`
}

// TOTPParams overrides TOTP defaults (30s period, 6 digits, SHA1) when the
// source system used non-default values.
type TOTPParams struct {
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

// MFAFactor is one enrolled multi-factor credential.
type MFAFactor struct {
	Type       MFAType     `json:"type"`
	Value      string      `json:"value"`
	TOTPParams *TOTPParams `json:"totp_params,omitempty"`
	Portable   bool        `json:"portable"`
	EnrolledAt *time.Time  `json:"enrolled_at,omitempty"`
}

// Membership scopes a user's roles to a single organization.
type Membership struct {
	Organization string   `json:"organization"`
	Roles        []string `json:"roles,omitempty"`
}

// Provenance records where a CMF record came from, for traceability and
// diffing across re-runs.
type Provenance struct {
	SourceConnector  string    `json:"source_connector"`
	ExportedAt       time.Time `json:"exported_at"`
	SourceRecordHash string    `json:"source_record_hash,omitempty"`
}

// User is the top-level CMF record, one per line of users.cmf.jsonl.gz.
type User struct {
	CMFVersion   string         `json:"cmf_version"`
	SourceID     string         `json:"source_id"`
	Emails       []Contact      `json:"emails,omitempty"`
	Phones       []Contact      `json:"phones,omitempty"`
	Username     string         `json:"username,omitempty"`
	Profile      Profile        `json:"profile"`
	Blocked      bool           `json:"blocked"`
	Password     *Password      `json:"password"`
	MFAFactors   []MFAFactor    `json:"mfa_factors,omitempty"`
	AppMetadata  map[string]any `json:"app_metadata,omitempty"`
	UserMetadata map[string]any `json:"user_metadata,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	GlobalRoles  []string       `json:"global_roles,omitempty"`
	Memberships  []Membership   `json:"memberships,omitempty"`
	Provenance   Provenance     `json:"provenance"`
}

// Organization is one row of organizations.cmf.jsonl.
type Organization struct {
	SourceID    string         `json:"source_id"`
	Name        string         `json:"name"`
	DisplayName string         `json:"display_name,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Role is one row of roles.cmf.jsonl.
type Role struct {
	SourceID    string `json:"source_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}
