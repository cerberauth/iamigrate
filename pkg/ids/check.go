package ids

import (
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Checker is validate's check of the users' target IDs, across users since
// two users can't share one.
type Checker struct {
	target   string
	custom   bool
	required bool
	seen     map[string]string // target ID -> source ID of its first user
}

// NewChecker returns the Checker for target, whose capabilities are caps,
// under the id.target strategy s (nil for none).
func NewChecker(s *mapping.IDStrategy, target string, caps connector.Capabilities) *Checker {
	return &Checker{target: target, custom: caps.SupportsCustomID, required: s.Assigns(), seen: map[string]string{}}
}

// Check returns the problems with u's target ID: one the target can't
// accept, one missing although the mapping assigns them, or one another
// user already has.
func (c *Checker) Check(u cmf.User) []connector.Problem {
	field := "target_ids." + c.target
	id := u.TargetIDs[c.target]
	switch {
	case id != "" && !c.custom:
		return []connector.Problem{{SourceID: u.SourceID, Field: field,
			Rule: c.target + " generates its own user IDs and can't import a chosen one", Value: id}}
	case id == "" && c.required:
		return []connector.Problem{{SourceID: u.SourceID, Field: field,
			Rule: "is required by the mapping's ids.target: assign it with `iamigrate ids assign` (a job's export does it)"}}
	case id == "":
		return nil
	}
	if first, dup := c.seen[id]; dup {
		return []connector.Problem{{SourceID: u.SourceID, Field: field,
			Rule: "is the same as user " + first + "'s", Value: id}}
	}
	c.seen[id] = u.SourceID
	return nil
}
