package keycloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/progress"
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
	}
}

// ValidateUser has no Keycloak-specific field rules yet, beyond the hash
// algorithm/MFA type checks Capabilities already covers; it always
// returns no problems.
func (*Connector) ValidateUser(u cmf.User) []connector.Problem { return nil }

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
	var report connector.ImportReport
	bar := progress.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		bar.Add(1)

		rep, flags, err := buildUser(u)
		if err != nil {
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: u.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
			})
			continue
		}

		if err := c.Client.doJSON(ctx, http.MethodPost, c.Client.adminPath("/users"), rep, nil); err != nil {
			code := "REQUEST_ERROR"
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
				code = UserExistsCode
			}
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: u.SourceID, Code: code, Message: err.Error(),
			})
			continue
		}

		report.Succeeded = append(report.Succeeded, u.SourceID)
		if flags.requiresPasswordReset {
			report.RequiresPasswordReset = append(report.RequiresPasswordReset, u.SourceID)
		}
		if flags.requiresReenrollment {
			report.RequiresReenrollment = append(report.RequiresReenrollment, u.SourceID)
		}
		if flags.requiresRecoveryCodeRegen {
			report.RequiresRecoveryCodeRegen = append(report.RequiresRecoveryCodeRegen, u.SourceID)
		}
	}

	return report, nil
}

// Verify reconciles every CMF user against the live realm, looking each
// one up by email when they have one, else by the username Import gave
// them (their username, else their phone).
func (c *Connector) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	var report connector.DiffReport
	bar := progress.FromContext(ctx)

	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		bar.Add(1)

		query := url.Values{"exact": {jsonTrue}, "briefRepresentation": {jsonTrue}}
		switch {
		case len(u.Emails) > 0:
			query.Set("email", u.Emails[0].Value)
		case loginUsername(u) != "":
			query.Set("username", loginUsername(u))
		default:
			report.NoIdentifier = append(report.NoIdentifier, u.SourceID)
			continue
		}

		var found []userRepresentation
		if err := c.Client.doJSON(ctx, http.MethodGet, c.Client.adminPath("/users?"+query.Encode()), nil, &found); err != nil {
			return report, fmt.Errorf("keycloak: looking up %s: %w", u.SourceID, err)
		}

		if len(found) == 0 {
			report.MissingInTarget = append(report.MissingInTarget, u.SourceID)
			continue
		}
		if found[0].Enabled == u.Blocked {
			report.AttributeDrift = append(report.AttributeDrift, connector.DriftEntry{
				SourceID: u.SourceID, Fields: []string{"blocked"},
			})
		}
	}
	return report, nil
}
