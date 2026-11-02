package cognito

import (
	"net/mail"
	"regexp"
	"unicode/utf8"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// maxUsernameLen is the longest username Cognito accepts.
const maxUsernameLen = 128

// usernameRE matches a Cognito username: letters, marks, symbols, numbers
// and punctuation, so no whitespace.
var usernameRE = regexp.MustCompile(`^[\p{L}\p{M}\p{S}\p{N}\p{P}]+$`)

// e164RE matches an E.164 phone number, the only format Cognito accepts for
// phone_number.
var e164RE = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// ValidateUser applies Cognito's user rules to u, offline: that it has
// something to be created under, the format of that username, of its email
// and of its phone number. Whether the pool takes an email as a username, or
// has the attributes the mapping sets, depends on its configuration, which
// no offline check can see.
func (*Connector) ValidateUser(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	add := func(field, rule, value string) {
		problems = append(problems, connector.Problem{SourceID: u.SourceID, Field: field, Rule: rule, Value: value})
	}

	username, kind := login(u)
	switch {
	case username == "":
		add("emails", "needs an email, a username or a phone number for Cognito to create the user under", "")
	case utf8.RuneCountInString(username) > maxUsernameLen:
		add(string(kind), "must be at most 128 characters to be a Cognito username", username)
	case !usernameRE.MatchString(username):
		add(string(kind), "must not contain whitespace or control characters to be a Cognito username", username)
	}

	if len(u.Emails) > 0 {
		if addr, err := mail.ParseAddress(u.Emails[0].Value); err != nil || addr.Address != u.Emails[0].Value {
			add("emails", "must be a valid email address", u.Emails[0].Value)
		}
	}
	if len(u.Phones) > 0 && !e164RE.MatchString(u.Phones[0].Value) {
		add("phones", "must be an E.164 number such as +14155550123", u.Phones[0].Value)
	}
	return problems
}
