package strategy

import (
	"slices"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// identityOrder is the order each identity.primary built-in prefers kinds of
// identifier in.
var identityOrder = map[string][]cmf.Identifier{
	PrimaryEmailFirst:    {cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone},
	PrimaryUsernameFirst: {cmf.IdentifierUsername, cmf.IdentifierEmail, cmf.IdentifierPhone},
	PrimaryPhoneFirst:    {cmf.IdentifierPhone, cmf.IdentifierEmail, cmf.IdentifierUsername},
}

// PrimaryLead returns the kind of identifier the identity.primary built-in
// prefers first.
func PrimaryLead(builtin string) cmf.Identifier { return identityOrder[builtin][0] }

// BuiltinPrimary returns the kind of identifier an identity.primary built-in
// prefers for u among the allowed ones (all of them when none are given):
// "" when u has none of them, or no built-in is given.
func BuiltinPrimary(builtin string, u cmf.User, allowed []cmf.Identifier) (kind cmf.Identifier, value string) {
	for _, k := range identityOrder[builtin] {
		if (len(allowed) == 0 || slices.Contains(allowed, k)) && HasIdentifier(u, k) {
			return k, ""
		}
	}
	return "", ""
}

// HasIdentifier reports whether u has an identifier of kind k.
func HasIdentifier(u cmf.User, k cmf.Identifier) bool {
	switch k {
	case cmf.IdentifierEmail:
		return len(u.Emails) > 0
	case cmf.IdentifierUsername:
		return u.Username != ""
	case cmf.IdentifierPhone:
		return len(u.Phones) > 0
	}
	return false
}

// ApplyPrimary returns u with identity.primary's decision applied: its
// Login set to kind, and the primary contact of each list first, where
// connectors read it: the one with value when kind is that list's, else the
// first one flagged primary. u itself is not changed.
func ApplyPrimary(u cmf.User, kind cmf.Identifier, value string) cmf.User {
	u.Emails = primaryFirst(u.Emails, kind == cmf.IdentifierEmail, value)
	u.Phones = primaryFirst(u.Phones, kind == cmf.IdentifierPhone, value)
	u.Login = kind
	return u
}

func primaryFirst(cs []cmf.Contact, chosen bool, value string) []cmf.Contact {
	at := slices.IndexFunc(cs, func(c cmf.Contact) bool { return c.Primary })
	if chosen && value != "" {
		at = slices.IndexFunc(cs, func(c cmf.Contact) bool { return c.Value == value })
	}
	if at <= 0 {
		return cs
	}
	out := make([]cmf.Contact, 0, len(cs))
	out = append(out, cs[at])
	out = append(out, cs[:at]...)
	return append(out, cs[at+1:]...)
}
