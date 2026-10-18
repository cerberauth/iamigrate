package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
)

// Connector is the Auth0 TargetConnector.
type Connector struct {
	Client      *Client
	Concurrency int // worker pool size for the orgs/roles/memberships phase
	// ConnectionConfig optionally tightens ValidateUser's default
	// username/identifier rules to a specific database connection's
	// configuration; see LoadConnectionConfig and --connection-config.
	ConnectionConfig *ConnectionConfig
}

// New returns an Auth0 target connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client, Concurrency: defaultConcurrency}
}

// Name is the connector's identifier, as used for --source/--target.
const Name = "auth0"

func (*Connector) Name() string { return Name }

// Capabilities declares Auth0's bulk-import support: all 11
// custom_password_hash algorithms, but only totp/sms/email MFA factors
// (webauthn and recovery_codes have no import API at all, per
// DESIGN.md's MFA import section).
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{
			cmf.AlgBcrypt, cmf.AlgScrypt, cmf.AlgPBKDF2, cmf.AlgArgon2,
			cmf.AlgMD5, cmf.AlgSHA1, cmf.AlgSHA256, cmf.AlgSHA512, cmf.AlgMD4,
			cmf.AlgHMAC, cmf.AlgLDAP,
		},
		MFATypes:      []cmf.MFAType{cmf.MFATOTP, cmf.MFASMS, cmf.MFAEmail},
		SupportsOrgs:  true,
		SupportsRoles: true,
		// The bulk import's user_id, which Auth0 puts behind its auth0|
		// prefix.
		SupportsCustomID: true,
		SupportsUpsert:   true,
		// The bulk import requires an email.
		PrimaryIdentifiers: []cmf.Identifier{cmf.IdentifierEmail},
	}
}

// Import runs the bulk user import job (chunked, submitted, and polled
// per DESIGN.md), then, if opts.Organizations and/or opts.Roles are
// set, the per-call organizations/roles/memberships phase -- all in one
// call, per the CLI reference's note that `import auth0` sequences both
// phases automatically.
//
// The orgs/roles phase addresses each user in report.Succeeded by the
// user_id Auth0 gave them, recorded in report.TargetIDs: their target ID,
// without any auth0| prefix it carried, behind the auth0| prefix Auth0
// adds (see targetUserID).
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	applier, err := importprep.New(m, c.CheckTargetField, hooks.FromContext(ctx), importprep.WithPrimaryIdentifiers(c.Capabilities().PrimaryIdentifiers))
	if err != nil {
		return connector.ImportReport{}, err
	}
	report, roleInfos, err := runBulkImport(ctx, c.Client, importprep.NewReader(ctx, r, applier), opts.ConnectionID, opts.Upsert)
	if err != nil {
		return report, err
	}

	if len(opts.Organizations) == 0 && len(opts.Roles) == 0 {
		return report, nil
	}

	userIDs := make(map[string]string, len(report.Succeeded))
	for _, id := range report.Succeeded {
		userIDs[id] = report.TargetIDs[id]
	}

	roles, roleIDs, err := resolveRoles(ctx, m, opts.Roles)
	if err != nil {
		return report, err
	}
	orgs, orgIDs, err := resolveOrgs(ctx, m, opts.Organizations)
	if err != nil {
		return report, err
	}
	phaseReport, err := runOrgsRolesPhase(ctx, c.Client, roles, orgs, roleInfos, userIDs, c.Concurrency, roleIDs, orgIDs)
	if err != nil {
		return report, err
	}
	report.OrgIDMap = phaseReport.OrgIDMap
	report.RoleIDMap = phaseReport.RoleIDMap
	report.Failed = append(report.Failed, phaseReport.Failed...)
	return report, nil
}

// Verify reconciles every CMF user against the live tenant, looking each
// one up by email via the Get Users by Email endpoint, else by username or
// phone via user search, and reports anyone missing, any drift in the
// fields Import sets (see userDrift), and anyone with no identifier to
// look up. Everything is keyed by the CMF source_id.
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return reconcile.Run(ctx, r, c.check)
}

// check looks u up by l's target ID (its user_id), or by l's identifier (an
// email when it has an @, else a username), or else as Verify says, and
// compares the fields Import sets.
func (c *Connector) check(ctx context.Context, u cmf.User, l reconcile.Lookup) (reconcile.Found, error) {
	if l.TargetID != "" {
		var t tenantUser
		if _, err := c.Client.doJSON(ctx, http.MethodGet, "/users/"+url.PathEscape(l.TargetID), nil, &t); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
				return reconcile.Found{Missing: true}, nil
			}
			return reconcile.Found{}, fmt.Errorf("auth0: looking up %s: %w", l.TargetID, err)
		}
		return reconcile.Found{Record: t, Drift: userDrift(u, t)}, nil
	}
	path, identifier := lookupPath(u)
	switch {
	case strings.Contains(l.Identifier, "@"):
		path, identifier = "/users-by-email?email="+url.QueryEscape(l.Identifier), l.Identifier
	case l.Identifier != "":
		path, identifier = searchPath("username", l.Identifier), l.Identifier
	}
	if path == "" {
		return reconcile.Found{NoIdentifier: true}, nil
	}
	var found []tenantUser
	if _, err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &found); err != nil {
		return reconcile.Found{}, fmt.Errorf("auth0: looking up %s: %w", identifier, err)
	}
	if len(found) == 0 {
		return reconcile.Found{Missing: true}, nil
	}
	t := pickUser(found, u.TargetID(Name))
	return reconcile.Found{Record: t, Drift: userDrift(u, t)}, nil
}

// tenantUser is the part of a Management API user record Verify compares.
type tenantUser struct {
	UserID        string `json:"user_id"`
	Blocked       bool   `json:"blocked"`
	EmailVerified bool   `json:"email_verified"`
	Username      string `json:"username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
	Picture       string `json:"picture"`
}

// pickUser returns the lookup result Import would have created for a user
// with target ID id, else the first one: an email can match users in
// several connections.
func pickUser(found []tenantUser, id string) tenantUser {
	for _, f := range found {
		if f.UserID == targetUserID(id) {
			return f
		}
	}
	return found[0]
}

// userDrift names the fields on which the tenant's user differs from u.
// Only fields Import sets are compared, and a profile field only when u
// has a value for it, since Auth0 fills in the others itself (name and
// nickname default from the email, picture from Gravatar).
func userDrift(u cmf.User, t tenantUser) []string {
	var drift []string
	if t.Blocked != u.Blocked {
		drift = append(drift, "blocked")
	}
	if len(u.Emails) > 0 && t.EmailVerified != u.Emails[0].Verified {
		drift = append(drift, "email_verified")
	}
	for _, f := range []struct {
		name      string
		want, got string
	}{
		{"username", u.Username, t.Username},
		{keyGivenName, u.Profile.GivenName, t.GivenName},
		{keyFamilyName, u.Profile.FamilyName, t.FamilyName},
		{"name", u.Profile.Name, t.Name},
		{keyNickname, u.Profile.Nickname, t.Nickname},
		{keyPicture, u.Profile.Picture, t.Picture},
	} {
		if f.want != "" && f.want != f.got {
			drift = append(drift, f.name)
		}
	}
	return drift
}

// lookupPath returns the Management API path finding u in the tenant, and
// the identifier it searches by: the email, else the username, else the
// phone. It returns "" when u has none of them.
func lookupPath(u cmf.User) (path, identifier string) {
	switch {
	case len(u.Emails) > 0:
		return "/users-by-email?email=" + url.QueryEscape(u.Emails[0].Value), u.Emails[0].Value
	case u.Username != "":
		return searchPath("username", u.Username), u.Username
	case len(u.Phones) > 0:
		return searchPath("phone_number", u.Phones[0].Value), u.Phones[0].Value
	}
	return "", ""
}

// searchPath builds a Get Users search for an exact field match.
func searchPath(field, value string) string {
	quoted := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	q := url.Values{"q": {field + ":" + quoted}, "search_engine": {"v3"}}
	return "/users?" + q.Encode()
}
