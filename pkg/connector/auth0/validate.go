package auth0

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"regexp"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// defaultUsernameMin and defaultUsernameMax are Auth0's documented
// database connection defaults for username length, used unless
// --connection-config overrides them via a connection's
// options.validation.username.
const (
	defaultUsernameMin = 1
	defaultUsernameMax = 15
)

// usernameCharPattern matches Auth0's documented allowed username
// characters: alphanumeric plus _ + - . ! # $ ' ^ ` ~ and @.
var usernameCharPattern = regexp.MustCompile("^[a-zA-Z0-9_+\\-.!#$'^`~@]+$")

// phonePattern matches E.164: a leading +, then 2-15 digits, the first
// non-zero.
var phonePattern = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// maxUserIDLen is Auth0's limit on the user_id field, which bulk import
// sets directly from a CMF user's source_id (see buildImportUser).
const maxUserIDLen = 128

// fieldUsername is the Problem.Field value for username-related rules.
const fieldUsername = "username"

// maxMetadataBytes is a conservative default limit for the marshaled size
// of app_metadata/user_metadata. Auth0 doesn't publish one single hard
// number for the bulk import job, so this needs confirming against the
// target tenant's plan before relying on it for anything but a first
// pass (see issue #57).
const maxMetadataBytes = 16 * 1024

// UsernameValidation is a connection's username length bounds, as found
// at options.validation.username in a live connection's configuration.
type UsernameValidation struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// ConnectionConfig is the subset of an Auth0 database connection's
// configuration ValidateUser needs to tighten its default username rules
// and required-identifier check, loaded from --connection-config: either
// a full `GET /connections/{id}` response, or just its "options" object.
type ConnectionConfig struct {
	Options struct {
		RequiresUsername bool `json:"requires_username"`
		Validation       struct {
			Username *UsernameValidation `json:"username,omitempty"`
		} `json:"validation"`
	} `json:"options"`
}

// LoadConnectionConfig reads and parses a --connection-config JSON file.
func LoadConnectionConfig(path string) (*ConnectionConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth0: reading connection config %s: %w", path, err)
	}
	var c ConnectionConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("auth0: parsing connection config %s: %w", path, err)
	}
	return &c, nil
}

// usernameLimits returns the connection's username length bounds, falling
// back to Auth0's documented defaults when c has no ConnectionConfig or
// the config doesn't override them.
func (c *Connector) usernameLimits() (min, max int) {
	if c.ConnectionConfig != nil && c.ConnectionConfig.Options.Validation.Username != nil {
		v := c.ConnectionConfig.Options.Validation.Username
		return v.Min, v.Max
	}
	return defaultUsernameMin, defaultUsernameMax
}

// ValidateUser applies Auth0's bulk-import field rules to u, offline: the
// email requirement and user_id length come from what buildImportUser
// sends the Bulk Import API; the username, phone, and metadata rules are
// Auth0's documented defaults, tightened by c.ConnectionConfig when set
// (see --connection-config).
func (c *Connector) ValidateUser(u cmf.User) []connector.Problem {
	var problems []connector.Problem

	if len(u.Emails) == 0 {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: "emails",
			Rule: "required (Auth0 bulk import requires an email)",
		})
	}
	for _, e := range u.Emails {
		if _, err := mail.ParseAddress(e.Value); err != nil {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "emails", Rule: "invalid email format", Value: e.Value,
			})
		}
	}

	for _, p := range u.Phones {
		if !phonePattern.MatchString(p.Value) {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "phones", Rule: "not E.164 format", Value: p.Value,
			})
		}
	}

	if c.ConnectionConfig != nil && c.ConnectionConfig.Options.RequiresUsername && u.Username == "" {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: fieldUsername,
			Rule: "required (connection has requires_username)",
		})
	}
	if u.Username != "" {
		min, max := c.usernameLimits()
		if l := len(u.Username); l < min || l > max {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: fieldUsername,
				Rule: fmt.Sprintf("length must be %d-%d characters", min, max), Value: u.Username,
			})
		}
		if !usernameCharPattern.MatchString(u.Username) {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: fieldUsername,
				Rule: "contains characters Auth0 usernames don't allow", Value: u.Username,
			})
		}
	}

	if l := len(u.SourceID); l == 0 || l > maxUserIDLen {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: "source_id",
			Rule: fmt.Sprintf("user_id must be 1-%d characters", maxUserIDLen), Value: u.SourceID,
		})
	}

	if p := metadataSizeProblem(u.SourceID, "app_metadata", u.AppMetadata); p != nil {
		problems = append(problems, *p)
	}
	if p := metadataSizeProblem(u.SourceID, "user_metadata", u.UserMetadata); p != nil {
		problems = append(problems, *p)
	}

	return problems
}

// metadataSizeProblem reports a Problem when m marshals to more than
// maxMetadataBytes, or nil when m is empty or within the limit.
func metadataSizeProblem(sourceID, field string, m map[string]any) *connector.Problem {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) <= maxMetadataBytes {
		return nil
	}
	return &connector.Problem{
		SourceID: sourceID, Field: field,
		Rule: fmt.Sprintf("exceeds %d bytes", maxMetadataBytes), Value: fmt.Sprintf("%d bytes", len(b)),
	}
}
