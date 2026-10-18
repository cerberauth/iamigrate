package strategy

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/cmf"
)

// UserView is what a handler deciding about a user is told of them: who
// they are, never their credentials, which only hash.translate and
// mfa.translate get.
func UserView(u cmf.User) map[string]any {
	v := map[string]any{
		"source_id":     u.SourceID,
		"emails":        u.Emails,
		"phones":        u.Phones,
		"username":      u.Username,
		"profile":       u.Profile,
		"blocked":       u.Blocked,
		"app_metadata":  u.AppMetadata,
		"user_metadata": u.UserMetadata,
		"roles":         u.Roles,
		"global_roles":  u.GlobalRoles,
		"memberships":   u.Memberships,
		"provenance":    u.Provenance,
	}
	if len(u.TargetIDs) > 0 {
		v["target_ids"] = u.TargetIDs
	}
	return v
}

// Actions a keep/drop/replace answer can name.
const (
	ActionKeep    = "keep"
	ActionDrop    = "drop"
	ActionReplace = "replace"
)

// UserAnswer is the answer to export.user or import.user: keep the user,
// drop it (with a reason), or replace it. A replacement is the user minus
// its credentials, which are kept as they were: only hash.translate and
// mfa.translate change them.
type UserAnswer struct {
	Action string          `json:"action"`
	Reason string          `json:"reason,omitempty"`
	User   json.RawMessage `json:"user,omitempty"`
}

// Apply returns what a says becomes of u, and whether u is kept at all.
func (a UserAnswer) Apply(u cmf.User) (cmf.User, bool, error) {
	switch a.Action {
	case "", ActionKeep:
		return u, true, nil
	case ActionDrop:
		return u, false, nil
	case ActionReplace:
		if len(a.User) == 0 {
			return u, false, errors.New("replace needs a user")
		}
		var r cmf.User
		if err := json.Unmarshal(a.User, &r); err != nil {
			return u, false, fmt.Errorf("replacement user: %w", err)
		}
		if r.SourceID != u.SourceID {
			return u, false, fmt.Errorf("replacement user has source_id %q, not %q", r.SourceID, u.SourceID)
		}
		r.CMFVersion, r.Password, r.MFAFactors = u.CMFVersion, u.Password, u.MFAFactors
		if r.Provenance.SourceConnector == "" {
			r.Provenance = u.Provenance
		}
		return r, true, nil
	}
	return u, false, fmt.Errorf("unknown action %q (keep, drop or replace)", a.Action)
}
