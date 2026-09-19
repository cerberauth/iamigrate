package auth0

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Connector is the Auth0 TargetConnector.
type Connector struct {
	Client      *Client
	Concurrency int // worker pool size for the orgs/roles/memberships phase
}

// New returns an Auth0 target connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client, Concurrency: defaultConcurrency}
}

func (*Connector) Name() string { return "auth0" }

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
	}
}

// Import runs the bulk user import job (chunked, submitted, and polled
// per DESIGN.md), then, if opts.Organizations and/or opts.Roles are
// set, the per-call organizations/roles/memberships phase -- all in one
// call, per the CLI reference's note that `import auth0` sequences both
// phases automatically.
//
// The orgs/roles phase resolves each user's Auth0 user_id from
// report.Succeeded, assuming Auth0 preserved the source_id passed as
// user_id in the bulk import payload (true for custom database
// connections; the gated live-tenant test in DESIGN.md's testing
// strategy is what actually proves this for a given tenant).
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	report, roleInfos, err := RunBulkImport(ctx, c.Client, r, opts.ConnectionID, opts.Upsert)
	if err != nil {
		return report, err
	}

	if len(opts.Organizations) == 0 && len(opts.Roles) == 0 {
		return report, nil
	}

	userIDs := make(map[string]string, len(report.Succeeded))
	for _, id := range report.Succeeded {
		userIDs[id] = id
	}

	phaseReport, err := RunOrgsRolesPhase(ctx, c.Client, opts.Roles, opts.Organizations, roleInfos, userIDs, c.Concurrency)
	if err != nil {
		return report, err
	}
	report.OrgIDMap = phaseReport.OrgIDMap
	report.RoleIDMap = phaseReport.RoleIDMap
	report.Failed = append(report.Failed, phaseReport.Failed...)
	return report, nil
}

// Verify reconciles every CMF user against the live tenant via Auth0's
// Get Users by Email endpoint, reporting anyone missing and any drift in
// blocked status.
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	var report connector.DiffReport

	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		if len(u.Emails) == 0 {
			continue
		}

		var found []struct {
			UserID  string `json:"user_id"`
			Blocked bool   `json:"blocked"`
		}
		path := "/users-by-email?email=" + url.QueryEscape(u.Emails[0].Value)
		if _, err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &found); err != nil {
			return report, fmt.Errorf("auth0: looking up %s: %w", u.Emails[0].Value, err)
		}

		if len(found) == 0 {
			report.MissingInTarget = append(report.MissingInTarget, u.SourceID)
			continue
		}
		if found[0].Blocked != u.Blocked {
			report.AttributeDrift = append(report.AttributeDrift, connector.DriftEntry{
				SourceID: u.SourceID, Fields: []string{"blocked"},
			})
		}
	}
	return report, nil
}
