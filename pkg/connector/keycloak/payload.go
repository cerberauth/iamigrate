package keycloak

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
)

// User attributes the connector reads and writes besides the built-in
// username/email/firstName/lastName fields. Keycloak has no phone field,
// so the phone goes where Keycloak's own "phone number" protocol mapper
// reads it from.
const (
	attrPhoneNumber         = "phoneNumber"
	attrPhoneNumberVerified = "phoneNumberVerified"
	attrLocale              = "locale"
	attrPicture             = "picture"
)

// jsonTrue is the string a boolean attribute or query parameter is set to.
const jsonTrue = "true"

// reservedAttributes are the attributes mapped to CMF fields, so they're
// never copied into user_metadata on export.
var reservedAttributes = map[string]bool{
	attrPhoneNumber: true, attrPhoneNumberVerified: true, attrLocale: true, attrPicture: true,
}

// Keycloak credential types.
const (
	credPassword             = "password"
	credOTP                  = "otp"
	credWebAuthn             = "webauthn"
	credWebAuthnPasswordless = "webauthn-passwordless"
	credRecoveryAuthnCodes   = "recovery-authn-codes"
)

// Keycloak's OTP credential defaults, matching the otpauth:// ones.
const (
	otpSubTypeTOTP          = "totp"
	otpSecretEncodingBase32 = "BASE32"
	defaultTOTPAlgorithm    = "HmacSHA1"
	defaultTOTPDigits       = 6
	defaultTOTPPeriod       = 30
)

// userRepresentation is the subset of Keycloak's UserRepresentation this
// connector reads and writes -- both the Admin API user creation body and
// a user entry of a `kc.sh export` realm file.
type userRepresentation struct {
	ID                       string                     `json:"id,omitempty"`
	Username                 string                     `json:"username"`
	Email                    string                     `json:"email,omitempty"`
	EmailVerified            bool                       `json:"emailVerified"`
	FirstName                string                     `json:"firstName,omitempty"`
	LastName                 string                     `json:"lastName,omitempty"`
	Enabled                  bool                       `json:"enabled"`
	Attributes               map[string][]string        `json:"attributes,omitempty"`
	Credentials              []credentialRepresentation `json:"credentials,omitempty"`
	ServiceAccountClientLink string                     `json:"serviceAccountClientLink,omitempty"`
}

type credentialRepresentation struct {
	Type           string `json:"type"`
	UserLabel      string `json:"userLabel,omitempty"`
	SecretData     string `json:"secretData,omitempty"`
	CredentialData string `json:"credentialData,omitempty"`
}

// otpCredentialData is OTPCredentialData.
type otpCredentialData struct {
	SubType        string `json:"subType"`
	Digits         int    `json:"digits"`
	Period         int    `json:"period"`
	Algorithm      string `json:"algorithm"`
	Counter        int    `json:"counter"`
	SecretEncoding string `json:"secretEncoding,omitempty"`
}

type otpSecretData struct {
	Value string `json:"value"`
}

// userFlags records which post-import follow-ups a translated user needs.
type userFlags struct {
	requiresPasswordReset     bool
	requiresReenrollment      bool
	requiresRecoveryCodeRegen bool
}

// buildUser translates one CMF user into a Keycloak Admin API user
// creation payload.
func buildUser(u cmf.User) (userRepresentation, userFlags, error) {
	var flags userFlags

	username := loginUsername(u)
	if username == "" {
		return userRepresentation{}, flags, fmt.Errorf("keycloak: user has no username, email, or phone to use as a Keycloak username")
	}

	rep := userRepresentation{
		Username:   username,
		FirstName:  u.Profile.GivenName,
		LastName:   u.Profile.FamilyName,
		Enabled:    !u.Blocked,
		Attributes: map[string][]string{},
	}
	if len(u.Emails) > 0 {
		rep.Email = u.Emails[0].Value
		rep.EmailVerified = u.Emails[0].Verified
	}

	// Keycloak has a single attribute bag, with no admin-only/user-editable
	// split: app_metadata wins over user_metadata on a key collision.
	for _, md := range []map[string]any{u.UserMetadata, u.AppMetadata} {
		for k, v := range md {
			rep.Attributes[k] = attributeValues(v)
		}
	}
	if len(u.Phones) > 0 {
		rep.Attributes[attrPhoneNumber] = []string{u.Phones[0].Value}
		rep.Attributes[attrPhoneNumberVerified] = []string{strconv.FormatBool(u.Phones[0].Verified)}
	}
	if u.Profile.Locale != "" {
		rep.Attributes[attrLocale] = []string{u.Profile.Locale}
	}
	if u.Profile.Picture != "" {
		rep.Attributes[attrPicture] = []string{u.Profile.Picture}
	}
	if len(rep.Attributes) == 0 {
		rep.Attributes = nil
	}

	if u.Password != nil {
		if !u.Password.Portable {
			flags.requiresPasswordReset = true
		} else {
			kc, err := iamhash.ToKeycloakCredential(*u.Password)
			if err != nil {
				return userRepresentation{}, flags, err
			}
			rep.Credentials = append(rep.Credentials, credentialRepresentation{
				Type: credPassword, SecretData: kc.SecretData, CredentialData: kc.CredentialData,
			})
		}
	}

	for _, f := range u.MFAFactors {
		switch f.Type {
		case cmf.MFATOTP:
			cred, err := otpCredential(f)
			if err != nil {
				return userRepresentation{}, flags, err
			}
			rep.Credentials = append(rep.Credentials, cred)
		case cmf.MFARecoveryCodes:
			// Keycloak stores recovery codes hashed with its own scheme,
			// so existing codes can't be carried over.
			flags.requiresRecoveryCodeRegen = true
		case cmf.MFASMS, cmf.MFAEmail, cmf.MFAWebAuthn, cmf.MFAPush:
			// Keycloak has no import path for these factor types, so the
			// user must re-enroll after migration.
			flags.requiresReenrollment = true
		}
	}

	return rep, flags, nil
}

// attributeValues flattens a metadata value into Keycloak's multi-valued
// string attributes: strings and string lists as-is, anything else
// JSON-encoded.
func attributeValues(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return []string{jsonString(v)}
			}
			out = append(out, s)
		}
		return out
	default:
		return []string{jsonString(v)}
	}
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// otpCredential translates a CMF TOTP factor, whose value is either a
// base32 secret or an otpauth:// URI, into a Keycloak OTP credential.
func otpCredential(f cmf.MFAFactor) (credentialRepresentation, error) {
	data := otpCredentialData{
		SubType:        otpSubTypeTOTP,
		Digits:         defaultTOTPDigits,
		Period:         defaultTOTPPeriod,
		Algorithm:      defaultTOTPAlgorithm,
		SecretEncoding: otpSecretEncodingBase32,
	}
	secret := f.Value
	params := f.TOTPParams
	if strings.HasPrefix(secret, "otpauth://") {
		parsed, err := parseOTPAuthURI(secret)
		if err != nil {
			return credentialRepresentation{}, err
		}
		secret = parsed.secret
		if params == nil {
			params = &parsed.params
		}
	}
	if params != nil {
		if params.Digits != 0 {
			data.Digits = params.Digits
		}
		if params.Period != 0 {
			data.Period = params.Period
		}
		if params.Algorithm != "" {
			data.Algorithm = "Hmac" + strings.TrimPrefix(strings.ToUpper(params.Algorithm), "HMAC")
		}
	}

	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "=")); err != nil {
		return credentialRepresentation{}, fmt.Errorf("keycloak: TOTP secret is not valid base32: %w", err)
	}

	secretJSON, err := json.Marshal(otpSecretData{Value: secret})
	if err != nil {
		return credentialRepresentation{}, err
	}
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return credentialRepresentation{}, err
	}
	return credentialRepresentation{
		Type: credOTP, SecretData: string(secretJSON), CredentialData: string(dataJSON),
	}, nil
}

type otpAuthURI struct {
	secret string
	params cmf.TOTPParams
}

func parseOTPAuthURI(raw string) (otpAuthURI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return otpAuthURI{}, fmt.Errorf("keycloak: parsing TOTP URI: %w", err)
	}
	if u.Host != otpSubTypeTOTP {
		return otpAuthURI{}, fmt.Errorf("keycloak: OTP URI type %q is not totp", u.Host)
	}
	q := u.Query()
	out := otpAuthURI{secret: q.Get("secret"), params: cmf.TOTPParams{Algorithm: q.Get("algorithm")}}
	if out.secret == "" {
		return otpAuthURI{}, fmt.Errorf("keycloak: TOTP URI has no secret")
	}
	out.params.Digits, _ = strconv.Atoi(q.Get("digits"))
	out.params.Period, _ = strconv.Atoi(q.Get("period"))
	return out, nil
}

// userFromRepresentation translates a user of a `kc.sh export` realm file
// into a CMF user, or returns a reason to skip it.
func userFromRepresentation(rep userRepresentation, sourceConnector string) (cmf.User, string, error) {
	if rep.ServiceAccountClientLink != "" {
		return cmf.User{}, fmt.Sprintf("service account user of client %q", rep.ServiceAccountClientLink), nil
	}

	u := cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   rep.ID,
		Username:   rep.Username,
		Blocked:    !rep.Enabled,
		Profile: cmf.Profile{
			GivenName:  rep.FirstName,
			FamilyName: rep.LastName,
			Name:       strings.TrimSpace(rep.FirstName + " " + rep.LastName),
			Locale:     firstAttribute(rep.Attributes, attrLocale),
			Picture:    firstAttribute(rep.Attributes, attrPicture),
		},
		Provenance: cmf.Provenance{SourceConnector: sourceConnector, ExportedAt: time.Now().UTC()},
	}
	if rep.Email != "" {
		u.Emails = []cmf.Contact{{Value: rep.Email, Verified: rep.EmailVerified, Primary: true}}
		// A realm with "email as username" stores the email as the
		// username too; that's not a separate identifier.
		if strings.EqualFold(rep.Username, rep.Email) {
			u.Username = ""
		}
	}
	if phone := firstAttribute(rep.Attributes, attrPhoneNumber); phone != "" {
		verified := firstAttribute(rep.Attributes, attrPhoneNumberVerified) == jsonTrue
		u.Phones = []cmf.Contact{{Value: phone, Verified: verified, Primary: true}}
		if rep.Username == phone {
			u.Username = ""
		}
	}

	keys := make([]string, 0, len(rep.Attributes))
	for k := range rep.Attributes {
		if !reservedAttributes[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if u.UserMetadata == nil {
			u.UserMetadata = map[string]any{}
		}
		if vs := rep.Attributes[k]; len(vs) == 1 {
			u.UserMetadata[k] = vs[0]
		} else {
			u.UserMetadata[k] = vs
		}
	}

	for _, cred := range rep.Credentials {
		switch cred.Type {
		case credPassword:
			if cred.SecretData == "" {
				return cmf.User{}, "password credential has no secretData (export with `kc.sh export`, not the Admin API)", nil
			}
			p, err := iamhash.NormalizeKeycloakCredential(cred.SecretData, cred.CredentialData)
			if err != nil {
				return cmf.User{}, fmt.Sprintf("unrecognized password hash format: %v", err), nil
			}
			u.Password = &p
		case credOTP:
			f, ok, err := totpFactor(cred)
			if err != nil {
				return cmf.User{}, fmt.Sprintf("unreadable OTP credential: %v", err), nil
			}
			if ok {
				u.MFAFactors = append(u.MFAFactors, f)
			}
		case credWebAuthn, credWebAuthnPasswordless:
			u.MFAFactors = append(u.MFAFactors, cmf.MFAFactor{Type: cmf.MFAWebAuthn, Value: cred.UserLabel, Portable: false})
		case credRecoveryAuthnCodes:
			u.MFAFactors = append(u.MFAFactors, cmf.MFAFactor{Type: cmf.MFARecoveryCodes, Portable: false})
		}
	}

	return u, "", nil
}

// totpFactor translates a Keycloak OTP credential into a CMF TOTP factor,
// with a base32 secret. HOTP credentials have no CMF equivalent and are
// reported as not ok.
func totpFactor(cred credentialRepresentation) (cmf.MFAFactor, bool, error) {
	var data otpCredentialData
	if err := json.Unmarshal([]byte(cred.CredentialData), &data); err != nil {
		return cmf.MFAFactor{}, false, err
	}
	if data.SubType != otpSubTypeTOTP {
		return cmf.MFAFactor{}, false, nil
	}
	var secret otpSecretData
	if err := json.Unmarshal([]byte(cred.SecretData), &secret); err != nil {
		return cmf.MFAFactor{}, false, err
	}
	value := secret.Value
	if data.SecretEncoding != otpSecretEncodingBase32 {
		// Without an explicit encoding, Keycloak uses the secret's raw
		// UTF-8 bytes as the HMAC key.
		value = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(value))
	}

	f := cmf.MFAFactor{Type: cmf.MFATOTP, Value: value, Portable: true}
	if data.Digits != defaultTOTPDigits || data.Period != defaultTOTPPeriod || data.Algorithm != defaultTOTPAlgorithm {
		f.TOTPParams = &cmf.TOTPParams{
			Digits:    data.Digits,
			Period:    data.Period,
			Algorithm: strings.TrimPrefix(data.Algorithm, "Hmac"),
		}
	}
	return f, true, nil
}

func firstAttribute(attrs map[string][]string, key string) string {
	if vs := attrs[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// loginUsername returns the Keycloak username for u: the CMF username,
// else the email, else the phone, or "" when u has none of them. Keycloak
// requires a username on every user and logs in by username or email, so
// a phone-only user logs in with the phone as username.
func loginUsername(u cmf.User) string {
	switch {
	case u.Username != "":
		return u.Username
	case len(u.Emails) > 0:
		return u.Emails[0].Value
	case len(u.Phones) > 0:
		return u.Phones[0].Value
	}
	return ""
}
