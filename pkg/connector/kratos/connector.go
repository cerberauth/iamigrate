package kratos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
)

// defaultPageSize is the number of identities requested per page during
// Export; Kratos caps this at 1000.
const defaultPageSize = 250

// ExportOptions configures reading identities out of a Kratos Admin API as
// a source.
type ExportOptions struct {
	connector.BaseExportOptions
}

// Connector is the Ory Kratos SourceConnector and TargetConnector.
type Connector struct {
	Client *Client
	// SchemaID is the identity schema new identities are created against
	// on Import, e.g. "default".
	SchemaID string
	// IdentitySchema optionally tightens ValidateUser's checks to a
	// specific identity schema's required traits, formats, and
	// identifier traits; see LoadIdentitySchema and --schema-file.
	IdentitySchema *IdentitySchema
}

// New returns a Kratos connector using client, importing identities
// against schemaID.
func New(client *Client, schemaID string) *Connector {
	return &Connector{Client: client, SchemaID: schemaID}
}

// Name is the connector's identifier, as used for --source/--target.
const Name = "kratos"

func (*Connector) Name() string { return Name }

// Capabilities declares Kratos' import support: bcrypt and argon2id
// password hashes (Kratos' only two importable hashers), plus totp and
// lookup_secret (recovery codes) MFA, since those are the only credential
// types Kratos' Admin API accepts pre-existing secrets for. Kratos has no
// built-in organizations/roles concept.
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{cmf.AlgBcrypt, cmf.AlgArgon2},
		MFATypes:       []cmf.MFAType{cmf.MFATOTP, cmf.MFARecoveryCodes},
		SupportsOrgs:   false,
		SupportsRoles:  false,
		// Kratos (v1.3) rejects an "id" in the identity it creates.
		SupportsCustomID: false,
		// All three traits are set; the identity schema decides which logs in.
		PrimaryIdentifiers: []cmf.Identifier{cmf.IdentifierEmail, cmf.IdentifierUsername, cmf.IdentifierPhone},
	}
}

// Export streams every identity from the Kratos Admin API into w as CMF
// users, paginating via the Link response header.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	bar := progress.FromContext(ctx)

	path := "/admin/identities?per_page=" + strconv.Itoa(defaultPageSize) + "&include_credential=password"
	for path != "" {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		var identities []identity
		resp, err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &identities)
		if err != nil {
			return manifest, fmt.Errorf("kratos: listing identities: %w", err)
		}

		for _, id := range identities {
			bar.Add(1)
			u, skipReason, err := userFromIdentity(id, Name)
			if err != nil {
				return manifest, err
			}
			if skipReason != "" {
				manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
					SourceID: id.ID, Reason: skipReason,
				})
				continue
			}
			if err := w.WriteUser(u); err != nil {
				return manifest, fmt.Errorf("kratos: writing user %s: %w", u.SourceID, err)
			}
			manifest.RecordCount++
			if u.Password != nil {
				manifest.HashAlgorithmCounts[u.Password.Algorithm]++
			}
			for _, f := range u.MFAFactors {
				if !f.Portable {
					manifest.NonPortableMFACounts[f.Type]++
				}
			}
		}

		path = nextPage(resp)
	}

	return manifest, nil
}

// nextPage extracts the "next" page path from a Kratos list response's
// Link header (RFC 5988), or "" once there's no further page.
func nextPage(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	for _, link := range resp.Header.Values("Link") {
		for _, part := range splitComma(link) {
			u, rel, ok := parseLinkPart(part)
			if ok && rel == "next" {
				return u
			}
		}
	}
	return ""
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// parseLinkPart parses one `<url>; rel="next"` segment of a Link header.
func parseLinkPart(part string) (link string, rel string, ok bool) {
	start := indexByte(part, '<')
	end := indexByte(part, '>')
	if start < 0 || end < 0 || end < start {
		return "", "", false
	}
	raw := part[start+1 : end]
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}

	relIdx := indexOf(part, `rel="`)
	if relIdx < 0 {
		return "", "", false
	}
	rest := part[relIdx+len(`rel="`):]
	if q := indexByte(rest, '"'); q >= 0 {
		rel = rest[:q]
	}
	return u.RequestURI(), rel, true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Import creates one Kratos identity per CMF user via the Admin API.
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	applier, err := importprep.New(m, c.CheckTargetField, hooks.FromContext(ctx), importprep.WithPrimaryIdentifiers(c.Capabilities().PrimaryIdentifiers))
	if err != nil {
		return connector.ImportReport{}, err
	}
	tr := importprep.NewReader(ctx, r, applier)
	var report connector.ImportReport
	bar := progress.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		batch, err := tr.ReadBatch()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}

		// The batch's identities are all built before any is sent, for
		// import.payload to see them together.
		var sources []string
		var bodies []any
		var allFlags []userFlags
		for _, p := range batch {
			bar.Add(1)
			id, flags, err := buildIdentity(p.User, c.SchemaID)
			if err != nil {
				report.Failed = append(report.Failed, connector.ImportError{
					SourceID: p.User.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
				})
				continue
			}
			applyFields(&id, p.Fields)
			sources, bodies, allFlags = append(sources, p.User.SourceID), append(bodies, id), append(allFlags, flags)
		}
		if bodies, err = applier.Payloads(ctx, sources, bodies); err != nil {
			return report, err
		}

		for i, source := range sources {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			var created identity
			if _, err := c.Client.doJSON(ctx, http.MethodPost, "/admin/identities", bodies[i], &created); err != nil {
				report.Failed = append(report.Failed, connector.ImportError{
					SourceID: source, Code: "REQUEST_ERROR", Message: err.Error(),
				})
				continue
			}

			report.Succeeded = append(report.Succeeded, source)
			if created.ID != "" {
				report.SetTargetID(source, created.ID)
			}
			flags := allFlags[i]
			if flags.requiresPasswordReset {
				report.RequiresPasswordReset = append(report.RequiresPasswordReset, source)
			}
			if flags.requiresReenrollment {
				report.RequiresReenrollment = append(report.RequiresReenrollment, source)
			}
			if flags.requiresRecoveryCodeRegen {
				report.RequiresRecoveryCodeRegen = append(report.RequiresRecoveryCodeRegen, source)
			}
		}
	}

	report.Skipped = append(report.Skipped, tr.Skipped()...)
	return report, nil
}

// Verify reconciles every CMF user against the live Kratos instance by
// looking up their email, else username, else phone via the Admin API's
// credentials_identifier filter, which matches any trait the identity
// schema marks as a password identifier.
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return reconcile.Run(ctx, r, c.check)
}

// check looks u up by l's target ID, or by its identifier, and compares
// whether the identity is inactive.
func (c *Connector) check(ctx context.Context, u cmf.User, l reconcile.Lookup) (reconcile.Found, error) {
	var found []identity
	if l.TargetID != "" {
		var id identity
		if _, err := c.Client.doJSON(ctx, http.MethodGet, "/admin/identities/"+url.PathEscape(l.TargetID), nil, &id); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
				return reconcile.Found{Missing: true}, nil
			}
			return reconcile.Found{}, fmt.Errorf("kratos: looking up identity %s: %w", l.TargetID, err)
		}
		found = []identity{id}
	} else {
		identifier := l.Identifier
		if identifier == "" {
			identifier = loginIdentifier(u)
		}
		if identifier == "" {
			return reconcile.Found{NoIdentifier: true}, nil
		}
		path := "/admin/identities?credentials_identifier=" + url.QueryEscape(identifier)
		if _, err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &found); err != nil {
			return reconcile.Found{}, fmt.Errorf("kratos: looking up %s: %w", identifier, err)
		}
	}
	if len(found) == 0 {
		return reconcile.Found{Missing: true}, nil
	}
	f := reconcile.Found{Record: found[0]}
	if blocked := found[0].State == stateInactive; blocked != u.Blocked {
		f.Drift = []string{"blocked"}
	}
	return f, nil
}
