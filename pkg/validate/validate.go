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
	if u.Password != nil && !caps.NoPasswords && !caps.SupportsAlgorithm(u.Password.Algorithm) {
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

// DirectoryChecker checks users' memberships and global roles against the
// organizations and roles exported with them, and against a target that
// must take them.
type DirectoryChecker struct {
	caps  connector.Capabilities
	orgs  map[string]bool
	roles map[string]bool
}

// NewDirectoryChecker returns a DirectoryChecker over orgs and roles (those
// of organizations.cmf.jsonl and roles.cmf.jsonl, nil when absent) for a
// target with caps, and the problems with orgs themselves: names used by
// more than one organization, which a target matching them by name merges.
func NewDirectoryChecker(orgs []cmf.Organization, roles []cmf.Role, caps connector.Capabilities) (*DirectoryChecker, []connector.Problem) {
	d := &DirectoryChecker{caps: caps, orgs: map[string]bool{}, roles: map[string]bool{}}
	var problems []connector.Problem
	names := map[string]string{}
	for _, o := range orgs {
		d.orgs[o.SourceID] = true
		key := strings.ToLower(o.Name)
		if first, ok := names[key]; ok {
			problems = append(problems, connector.Problem{
				SourceID: o.SourceID, Field: "organizations.name",
				Rule: fmt.Sprintf("duplicate of organization %s", first), Value: o.Name,
			})
			continue
		}
		names[key] = o.SourceID
	}
	for _, r := range roles {
		d.roles[r.SourceID] = true
	}
	return d, problems
}

// Check reports the memberships and roles of u naming an organization or a
// role that isn't exported, and those the target can't take.
func (d *DirectoryChecker) Check(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	add := func(field, rule, value string) {
		problems = append(problems, connector.Problem{SourceID: u.SourceID, Field: field, Rule: rule, Value: value})
	}
	checkRoles := func(field string, roles []string) {
		for _, r := range roles {
			if !d.roles[r] {
				add(field, "unknown role", r)
			}
		}
		if len(roles) > 0 && !d.caps.SupportsRoles {
			add(field, "roles unsupported by target", strings.Join(roles, ","))
		}
	}
	for _, m := range u.Memberships {
		if !d.orgs[m.Organization] {
			add("memberships.organization", "unknown organization", m.Organization)
		}
		if !d.caps.SupportsOrgs {
			add("memberships.organization", "organizations unsupported by target", m.Organization)
		}
		checkRoles("memberships.roles", m.Roles)
	}
	checkRoles("global_roles", u.GlobalRoles)
	return problems
}
