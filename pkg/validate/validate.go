// Package validate holds the offline checks on a CMF user that don't depend
// on which target it's headed for, shared by the validate command and the
// job runner.
package validate

import (
	"fmt"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// CheckUser reports the problems with u that a target's Capabilities alone
// reveal: a password hash algorithm or a portable MFA factor type it can't
// import.
func CheckUser(u cmf.User, caps connector.Capabilities) []connector.Problem {
	var problems []connector.Problem
	if u.Password != nil && !caps.SupportsAlgorithm(u.Password.Algorithm) {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: "password.algorithm",
			Rule: "unsupported by target", Value: string(u.Password.Algorithm),
		})
	}
	for _, f := range u.MFAFactors {
		if f.Portable && !caps.SupportsMFAType(f.Type) {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "mfa_factors.type",
				Rule: "unsupported by target", Value: string(f.Type),
			})
		}
	}
	return problems
}

// DupTracker flags emails, usernames, and phones reused across more than
// one user within the same CMF file -- a target-agnostic check, since a
// duplicate breaks uniqueness in any target, per issue #57's "Both"
// checks.
type DupTracker struct {
	emails    map[string]string
	usernames map[string]string
	phones    map[string]string
}

// NewDupTracker returns an empty DupTracker.
func NewDupTracker() *DupTracker {
	return &DupTracker{
		emails:    map[string]string{},
		usernames: map[string]string{},
		phones:    map[string]string{},
	}
}

// Check records u's identifiers, and reports those already seen on an
// earlier user.
func (d *DupTracker) Check(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	for _, e := range u.Emails {
		key := strings.ToLower(e.Value)
		if first, ok := d.emails[key]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "emails",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: e.Value,
			})
		} else {
			d.emails[key] = u.SourceID
		}
	}
	if u.Username != "" {
		if first, ok := d.usernames[u.Username]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "username",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: u.Username,
			})
		} else {
			d.usernames[u.Username] = u.SourceID
		}
	}
	for _, p := range u.Phones {
		if first, ok := d.phones[p.Value]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "phones",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: p.Value,
			})
		} else {
			d.phones[p.Value] = u.SourceID
		}
	}
	return problems
}
