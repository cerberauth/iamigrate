package keycloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
)

// UserExistsCode is the ImportError code for a user whose username or
// email is already taken in the realm.
const UserExistsCode = "USER_EXISTS"

// ExportOptions configures reading users out of a Keycloak realm export as
// a source.
type ExportOptions struct {
	connector.BaseExportOptions
	// Path is a `kc.sh export --realm <name>` output: the --file JSON file,
	// or the --dir directory.
	Path string
}

// Connector is the Keycloak SourceConnector and TargetConnector.
type Connector struct {
	// Client is the Admin API client Import and Verify use. Export reads a
	// realm export file and doesn't need one.
	Client *Client
}

// New returns a Keycloak connector using client.
func New(client *Client) *Connector {
	return &Connector{Client: client}
}

// Name is the connector's identifier, as used for --source/--target.
const Name = "keycloak"

func (*Connector) Name() string { return Name }

// Capabilities declares Keycloak's import support: the algorithms of its
// built-in password hash providers (PBKDF2 with sha1/sha256/sha512, and
// Argon2), and TOTP, the only MFA credential Keycloak verifies from an
// imported secret. Organizations and roles aren't imported yet.
func (*Connector) Capabilities() connector.Capabilities {
	return connector.Capabilities{
		HashAlgorithms: []cmf.Algorithm{cmf.AlgPBKDF2, cmf.AlgArgon2},
		MFATypes:       []cmf.MFAType{cmf.MFATOTP},
		SupportsOrgs:   false,
		SupportsRoles:  false,
		// POST /users ignores the "id" it's given and generates one.
		SupportsCustomID: false,
	}
}

// maxAttributeNameLen is the longest user attribute name Keycloak
// accepts; a longer one makes it fail the request with an HTTP 500.
const maxAttributeNameLen = 255

// attrFirstName and attrLastName are the Keycloak name fields.
const (
	attrFirstName = "firstName"
	attrLastName  = "lastName"
)

// profileAttributes are the user fields Keycloak keeps in its own
// columns: an attribute with one of these names is dropped silently
// instead of being stored.
var profileAttributes = []string{"username", "email", attrFirstName, attrLastName}

// ValidateUser applies Keycloak's user attribute rules to u, offline,
// beyond the hash algorithm/MFA type checks Capabilities already covers:
// every user_metadata and app_metadata key becomes an attribute, so its
// name must fit maxAttributeNameLen and mustn't shadow a profile field.
func (*Connector) ValidateUser(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	for _, md := range []struct {
		field string
		m     map[string]any
	}{{"user_metadata", u.UserMetadata}, {"app_metadata", u.AppMetadata}} {
		keys := make([]string, 0, len(md.m))
		for k := range md.m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if utf8.RuneCountInString(k) > maxAttributeNameLen {
				problems = append(problems, connector.Problem{
					SourceID: u.SourceID, Field: md.field,
					Rule:  fmt.Sprintf("attribute name must be at most %d characters", maxAttributeNameLen),
					Value: fmt.Sprintf("%d characters", utf8.RuneCountInString(k)),
				})
			}
			if slices.Contains(profileAttributes, k) {
				problems = append(problems, connector.Problem{
					SourceID: u.SourceID, Field: md.field,
					Rule: "attribute name is reserved by Keycloak and would be dropped silently", Value: k,
				})
			}
		}
	}
	return problems
}

// Export streams every user of a `kc.sh export` realm export into w as
// CMF users. Service account users are skipped.
func (c *Connector) Export(ctx context.Context, w *cmf.Writer, eo connector.ExportOptions) (connector.Manifest, error) {
	manifest := connector.Manifest{
		HashAlgorithmCounts:  map[cmf.Algorithm]int{},
		NonPortableMFACounts: map[cmf.MFAType]int{},
	}
	opts, ok := eo.(ExportOptions)
	if !ok {
		return manifest, fmt.Errorf("keycloak: Export requires keycloak.ExportOptions, got %T", eo)
	}
	files, err := exportFiles(opts.Path)
	if err != nil {
		return manifest, err
	}
	bar := progress.FromContext(ctx)

	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return manifest, err
		}
		err = readExportUsers(f, func(rep userRepresentation) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			bar.Add(1)
			u, skipReason, err := userFromRepresentation(rep, Name)
			if err != nil {
				return err
			}
			if skipReason != "" {
				manifest.SkippedRecords = append(manifest.SkippedRecords, connector.SkippedRecord{
					SourceID: rep.ID, Reason: skipReason,
				})
				return nil
			}
			if err := w.WriteUser(u); err != nil {
				return fmt.Errorf("keycloak: writing user %s: %w", u.SourceID, err)
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
			return nil
		})
		f.Close()
		if err != nil {
			return manifest, fmt.Errorf("%s: %w", path, err)
		}
	}

	return manifest, nil
}

// Import creates one Keycloak user per CMF user via the Admin API.
func (c *Connector) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	applier, err := importprep.New(m, c.CheckTargetField, hooks.FromContext(ctx))
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

		// The batch's users are all built before any is sent, for
		// import.payload to see them together.
		var sources []string
		var bodies []any
		var allFlags []userFlags
		for _, p := range batch {
			bar.Add(1)
			rep, flags, err := buildUser(p.User)
			if err != nil {
				report.Failed = append(report.Failed, connector.ImportError{
					SourceID: p.User.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
				})
				continue
			}
			applyFields(&rep, p.Fields)
			sources, bodies, allFlags = append(sources, p.User.SourceID), append(bodies, rep), append(allFlags, flags)
		}
		if bodies, err = applier.Payloads(ctx, sources, bodies); err != nil {
			return report, err
		}

		for i, source := range sources {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			h, err := c.Client.do(ctx, http.MethodPost, c.Client.adminPath("/users"), bodies[i], nil)
			if err != nil {
				code := "REQUEST_ERROR"
				var apiErr *APIError
				if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
					code = UserExistsCode
				}
				report.Failed = append(report.Failed, connector.ImportError{
					SourceID: source, Code: code, Message: err.Error(),
				})
				continue
			}

			report.Succeeded = append(report.Succeeded, source)
			// Keycloak generates the user's ID, and names it only in the
			// Location of the new user.
			if loc := h.Get("Location"); loc != "" {
				report.SetTargetID(source, path.Base(loc))
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

// Verify reconciles every CMF user against the live realm, looking each
// one up by email when they have one, else by the username Import gave
// them (their username, else their phone).
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return reconcile.Run(ctx, r, c.check)
}

// check looks u up by l's target ID, or by l's identifier (an email when it
// has an @, else a username), or else as Verify says, and compares whether
// the user is enabled.
func (c *Connector) check(ctx context.Context, u cmf.User, l reconcile.Lookup) (reconcile.Found, error) {
	var found []userRepresentation
	if l.TargetID != "" {
		var rep userRepresentation
		if err := c.Client.doJSON(ctx, http.MethodGet, c.Client.adminPath("/users/"+url.PathEscape(l.TargetID)), nil, &rep); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
				return reconcile.Found{Missing: true}, nil
			}
			return reconcile.Found{}, fmt.Errorf("keycloak: looking up %s: %w", u.SourceID, err)
		}
		found = []userRepresentation{rep}
	} else {
		query := url.Values{"exact": {jsonTrue}, "briefRepresentation": {jsonTrue}}
		switch {
		case l.Identifier != "" && strings.Contains(l.Identifier, "@"):
			query.Set("email", l.Identifier)
		case l.Identifier != "":
			query.Set("username", l.Identifier)
		case len(u.Emails) > 0:
			query.Set("email", u.Emails[0].Value)
		case loginUsername(u) != "":
			query.Set("username", loginUsername(u))
		default:
			return reconcile.Found{NoIdentifier: true}, nil
		}
		if err := c.Client.doJSON(ctx, http.MethodGet, c.Client.adminPath("/users?"+query.Encode()), nil, &found); err != nil {
			return reconcile.Found{}, fmt.Errorf("keycloak: looking up %s: %w", u.SourceID, err)
		}
	}
	if len(found) == 0 {
		return reconcile.Found{Missing: true}, nil
	}
	f := reconcile.Found{Record: found[0]}
	if found[0].Enabled == u.Blocked {
		f.Drift = []string{"blocked"}
	}
	return f, nil
}
