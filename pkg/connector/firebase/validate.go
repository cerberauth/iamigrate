package firebase

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
)

const (
	// maxUIDLen is the longest uid (localId) Firebase accepts.
	maxUIDLen = 128

	// maxClaimsLen is the longest serialized custom claims payload
	// Firebase accepts.
	maxClaimsLen = 1000
)

// e164RE matches an E.164 phone number, the only format Firebase accepts.
var e164RE = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// reservedClaims are the OIDC and Firebase names custom claims can't use.
var reservedClaims = map[string]bool{
	"acr": true, "amr": true, "at_hash": true, "aud": true, "auth_time": true,
	"azp": true, "cnf": true, "c_hash": true, "exp": true, "firebase": true,
	"iat": true, "iss": true, "jti": true, "nbf": true, "nonce": true, "sub": true,
}

// ValidateUser applies Firebase's account rules to u, offline, beyond the
// hash algorithm/MFA type checks Capabilities already covers: the uid
// length, an email or phone number to sign in with, their formats, the
// custom claims' reserved names and size, and whether the password hash
// can be translated at all.
func (*Connector) ValidateUser(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	add := func(field, rule, value string) {
		problems = append(problems, connector.Problem{SourceID: u.SourceID, Field: field, Rule: rule, Value: value})
	}

	if n := utf8.RuneCountInString(u.TargetID(Name)); n > maxUIDLen {
		add(targetIDField(u), fmt.Sprintf("must be at most %d characters to be a Firebase uid", maxUIDLen), fmt.Sprintf("%d characters", n))
	}

	if len(u.Emails) == 0 && len(u.Phones) == 0 {
		add("emails", "needs an email or a phone number, which Firebase signs users in with", "")
	}
	if len(u.Emails) > 0 {
		if addr, err := mail.ParseAddress(u.Emails[0].Value); err != nil || addr.Address != u.Emails[0].Value {
			add("emails", "must be a valid email address", u.Emails[0].Value)
		}
	}
	if len(u.Phones) > 0 && !e164RE.MatchString(u.Phones[0].Value) {
		add("phones", "must be an E.164 number such as +14155550123", u.Phones[0].Value)
	}

	if len(u.AppMetadata) > 0 {
		keys := make([]string, 0, len(u.AppMetadata))
		for k := range u.AppMetadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if reservedClaims[k] {
				add("app_metadata", "key is a reserved Firebase custom claim name", k)
			}
		}
		if b, err := json.Marshal(u.AppMetadata); err == nil && len(b) > maxClaimsLen {
			add("app_metadata", fmt.Sprintf("must serialize to at most %d characters to be custom claims", maxClaimsLen), fmt.Sprintf("%d characters", len(b)))
		}
	}

	if u.Password != nil && u.Password.Portable {
		if _, err := iamhash.ToFirebaseHash(*u.Password); err != nil {
			add("password", err.Error(), string(u.Password.Algorithm))
		}
	}

	for _, f := range u.MFAFactors {
		if f.Type == cmf.MFASMS && f.Portable && !e164RE.MatchString(f.Value) {
			add("mfa_factors.value", "SMS factor must be an E.164 number such as +14155550123", f.Value)
		}
	}

	return problems
}

// targetIDField names the CMF field the user's Firebase uid comes from.
func targetIDField(u cmf.User) string {
	if u.TargetIDs[Name] != "" {
		return "target_ids." + Name
	}
	return "source_id"
}
