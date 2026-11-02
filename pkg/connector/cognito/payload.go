package cognito

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// Names of the Cognito standard attributes this connector sets.
const (
	attrEmail         = "email"
	attrEmailVerified = "email_verified"
	attrPhone         = "phone_number"
	attrPhoneVerified = "phone_number_verified"
	attrGivenName     = "given_name"
	attrFamilyName    = "family_name"
	attrName          = "name"
	attrNickname      = "nickname"
	attrPicture       = "picture"
	attrLocale        = "locale"
	attrPreferred     = "preferred_username"
	attrSub           = "sub"
)

// statusForceChangePassword is the status of a user AdminCreateUser made
// and nobody set a password for.
const statusForceChangePassword = "FORCE_CHANGE_PASSWORD"

// attribute is one user attribute, as the API names its fields.
type attribute struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

// createUserRequest is an AdminCreateUser body, which is also what an
// import.payload hook sees. MessageAction SUPPRESS keeps Cognito from
// sending its invitation message to every imported user.
type createUserRequest struct {
	UserPoolID     string      `json:"UserPoolId"`
	Username       string      `json:"Username"`
	UserAttributes []attribute `json:"UserAttributes,omitempty"`
	MessageAction  string      `json:"MessageAction,omitempty"`
}

// userInfo is a user as AdminCreateUser (User, with Attributes) and
// AdminGetUser (with UserAttributes) return it.
type userInfo struct {
	Username       string      `json:"Username"`
	Attributes     []attribute `json:"Attributes"`
	UserAttributes []attribute `json:"UserAttributes"`
	Enabled        bool        `json:"Enabled"`
	UserStatus     string      `json:"UserStatus"`
}

// attr returns the value of the attribute name, if the user has it.
func (u userInfo) attr(name string) (string, bool) {
	for _, list := range [][]attribute{u.Attributes, u.UserAttributes} {
		for _, a := range list {
			if a.Name == name {
				return a.Value, true
			}
		}
	}
	return "", false
}

// sub is the user's immutable ID in the pool.
func (u userInfo) sub() string {
	s, _ := u.attr(attrSub)
	return s
}

// userFlags records which post-import follow-ups a translated user needs.
type userFlags struct {
	requiresPasswordReset bool
	requiresReenrollment  bool
}

// login returns the identifier the user is created under, and which kind it
// is: the one the mapping's identity.primary strategy picked (the user's
// Login), else the email, the username, or the phone number, in that order.
//
// A user pool signs users in by email or phone number (it is then created
// with the email or the phone number as its Username), or by a username it
// may let them use their email with as an alias. This picks for the former,
// the common modern setup; pick the username with identity.primary for a
// pool of the latter.
func login(u cmf.User) (string, cmf.Identifier) {
	value := func(kind cmf.Identifier) string {
		switch kind {
		case cmf.IdentifierEmail:
			if len(u.Emails) > 0 {
				return u.Emails[0].Value
			}
		case cmf.IdentifierUsername:
			return u.Username
		case cmf.IdentifierPhone:
			if len(u.Phones) > 0 {
				return u.Phones[0].Value
			}
		}
		return ""
	}
	if v := value(u.Login); v != "" {
		return v, u.Login
	}
	for _, kind := range []cmf.Identifier{cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone} {
		if v := value(kind); v != "" {
			return v, kind
		}
	}
	return "", ""
}

// buildUser translates one CMF user into an AdminCreateUser request.
//
// Every other email or phone number, user_metadata and app_metadata are
// dropped: Cognito has one of each, and custom attributes must be declared
// in the pool's schema, so they are set with the mapping's target_fields
// (custom:<name>). A username that isn't the one the user is created under
// becomes preferred_username. Organizations and roles have no equivalent.
func buildUser(u cmf.User, poolID string) (createUserRequest, userFlags, error) {
	var flags userFlags
	username, kind := login(u)
	if username == "" {
		return createUserRequest{}, flags, fmt.Errorf("user has no email, username or phone number to create it under")
	}

	req := createUserRequest{UserPoolID: poolID, Username: username, MessageAction: "SUPPRESS"}
	set := func(name, value string) {
		if value != "" {
			req.UserAttributes = append(req.UserAttributes, attribute{Name: name, Value: value})
		}
	}
	if len(u.Emails) > 0 {
		set(attrEmail, u.Emails[0].Value)
		set(attrEmailVerified, strconv.FormatBool(u.Emails[0].Verified))
	}
	if len(u.Phones) > 0 {
		set(attrPhone, u.Phones[0].Value)
		set(attrPhoneVerified, strconv.FormatBool(u.Phones[0].Verified))
	}
	if kind != cmf.IdentifierUsername {
		set(attrPreferred, u.Username)
	}
	set(attrGivenName, u.Profile.GivenName)
	set(attrFamilyName, u.Profile.FamilyName)
	set(attrName, u.Profile.Name)
	set(attrNickname, u.Profile.Nickname)
	set(attrPicture, u.Profile.Picture)
	set(attrLocale, u.Profile.Locale)

	// Cognito takes no password hash, whatever its algorithm.
	flags.requiresPasswordReset = u.Password != nil
	flags.requiresReenrollment = len(u.MFAFactors) > 0
	return req, flags, nil
}

// setAttribute sets the attribute name, replacing the value it has.
func (r *createUserRequest) setAttribute(name, value string) {
	for i, a := range r.UserAttributes {
		if a.Name == name {
			r.UserAttributes[i].Value = value
			return
		}
	}
	r.UserAttributes = append(r.UserAttributes, attribute{Name: name, Value: value})
}

// attributeValue renders a target field's value as the string Cognito
// stores every attribute as.
func attributeValue(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case json.Number:
		return v.String(), nil
	}
	return "", fmt.Errorf("must be a string, number or boolean, not %T", v)
}

// Character classes of a generated password; with one of each, it meets any
// password policy a user pool can set short of a longer minimum than the
// length below.
const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	symbols = "^$*.[]{}()?-!@#%&/,><:;|_~+="

	passwordLength = 40
)

// randomPassword returns a password nobody knows, to take a user out of
// FORCE_CHANGE_PASSWORD: only a user in a final state can use "forgot
// password".
func randomPassword() (string, error) {
	all := upper + lower + digits + symbols
	pick := func(set string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[n.Int64()], nil
	}
	pw := make([]byte, 0, passwordLength)
	for _, set := range []string{upper, lower, digits, symbols} {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	for len(pw) < passwordLength {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	// Shuffle, so the first four aren't always one of each class.
	for i := len(pw) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(n.Int64())
		pw[i], pw[j] = pw[j], pw[i]
	}
	return string(pw), nil
}
