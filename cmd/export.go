package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/azureb2c"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/connector/sqlsource"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/lifecycle"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
)

func newExportCmd() *cobra.Command {
	var (
		source   string
		in       string
		format   string
		mapPath  string
		outDir   string
		adminURL string
		noGzip   bool
		fbAuth   firebaseFlags
		fbHash   firebaseHashFlags
		a0Auth   auth0Flags
		a0Export auth0.ExportOptions
		azAuth   azureB2CFlags
		azExport azureb2c.ExportOptions

		ffDirectory flatfileDirectoryFlags
		sqlOpts     sqlFlags
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export identities from a source into CMF",
		RunE: func(cmd *cobra.Command, args []string) error {
			if source != flatfile.Name && source != sqlsource.Name && source != kratos.Name && source != keycloak.Name && source != firebase.Name && source != auth0.Name && source != azureb2c.Name {
				return fmt.Errorf("unsupported --source %q (supports \"flatfile\", \"sql\", \"kratos\", \"keycloak\", \"firebase\", \"auth0\", and \"azure-ad-b2c\"; use `iamigrate testdata generate` for the fixture source)", source)
			}
			if (source == flatfile.Name || source == keycloak.Name) && in == "" {
				return fmt.Errorf("--in is required for --source %s", source)
			}
			if source != flatfile.Name && ffDirectory.given() {
				return fmt.Errorf("--organizations, --roles and --memberships only apply to --source %s", flatfile.Name)
			}

			if source != sqlsource.Name && sqlOpts.given() {
				return fmt.Errorf("--driver, --dsn, --dsn-file and the --*query flags only apply to --source %s", sqlsource.Name)
			}
			var sqlExport sqlsource.ExportOptions
			if source == sqlsource.Name {
				var err error
				if sqlExport, err = sqlOpts.options(); err != nil {
					return err
				}
			}

			var fileMapping mapping.Mapping
			if mapPath != "" {
				if source != flatfile.Name && source != sqlsource.Name {
					return fmt.Errorf("--mapping only applies to --source %s and %s", flatfile.Name, sqlsource.Name)
				}
				var err error
				if fileMapping, err = mapping.Load(mapPath); err != nil {
					return err
				}
			}
			pass, err := exportPass(cmd.Context(), fileMapping)
			if err != nil {
				return err
			}

			// Everything a Firebase export needs is checked before the output
			// file is created, so a mistake doesn't leave an empty export.
			var fbClient *firebase.Client
			var fbScrypt *iamhash.FirebaseScryptConfig
			if source == firebase.Name {
				var err error
				if fbClient, err = fbAuth.client(); err != nil {
					return err
				}
				if fbScrypt, err = fbHash.config(); err != nil {
					return err
				}
				if fbScrypt == nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "iamigrate: no --hash-signer-key given: password hashes are exported as non-portable, so users will have to reset their passwords")
				}
			}

			// Likewise for Auth0: credentials and the field selection are
			// checked before anything is written.
			var a0Client *auth0.Client
			if source == auth0.Name {
				var err error
				if a0Client, err = a0Auth.client(); err != nil {
					return err
				}
				if err := auth0.ValidateExportFields(a0Export.Fields); err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "iamigrate: Auth0 doesn't return password hashes through its API: users are exported without a password, so they will have to reset it (see the Auth0 export guide to get the hashes from Auth0 support)")
			}

			// And for Azure AD B2C.
			var azClient *azureb2c.Client
			if source == azureb2c.Name {
				var err error
				if azClient, err = azAuth.withCredentials(fbAuth.accessToken, a0Auth.clientID, a0Auth.clientSecret).client(); err != nil {
					return err
				}
				if err := azureb2c.ValidateExtensionAttributes(azExport.ExtensionAttributes); err != nil {
					return err
				}
				azExport.Limit = a0Export.Limit
				fmt.Fprintln(cmd.ErrOrStderr(), "iamigrate: Azure AD B2C doesn't return password hashes through Microsoft Graph: users are exported without a password, so they will have to reset it")
			}

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			usersPath, newWriter := usersOutput(outDir, noGzip)
			// With export strategies, the export is written aside and
			// rewritten through them into usersPath.
			exportPath := usersPath
			if pass != nil {
				exportPath = usersPath + ".raw"
				defer os.Remove(exportPath)
			}
			f, err := os.Create(exportPath)
			if err != nil {
				return err
			}
			defer f.Close()

			w := newWriter(f)
			var manifest connector.Manifest
			ctx, bar := startProgress(cmd)
			defer bar.Done()
			exportStart := time.Now()
			var src connector.SourceConnector
			var opts connector.ExportOptions
			switch source {
			case kratos.Name:
				if adminURL == "" {
					adminURL = os.Getenv("KRATOS_ADMIN_URL")
				}
				if adminURL == "" {
					return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required for --source kratos")
				}
				src, opts = kratos.New(kratos.NewClient(adminURL), ""), kratos.ExportOptions{}
			case keycloak.Name:
				src, opts = keycloak.New(nil), keycloak.ExportOptions{Path: in}
			case firebase.Name:
				src, opts = firebase.New(fbClient), firebase.ExportOptions{Scrypt: fbScrypt}
			case auth0.Name:
				src, opts = auth0.New(a0Client), a0Export
			case azureb2c.Name:
				src, opts = azureb2c.New(azClient), azExport
			case sqlsource.Name:
				sqlExport.Mapping = fileMapping
				src, opts = sqlsource.New(), sqlExport
			default:
				src, opts = flatfile.New(), flatfile.ExportOptions{
					Path: in, Format: flatfile.Format(format), Mapping: fileMapping,
					Organizations: ffDirectory.organizations.file(format),
					Roles:         ffDirectory.roles.file(format),
					Memberships:   ffDirectory.memberships.file(format),
				}
			}
			bar.Stage("exporting users", 0)
			manifest, err = src.Export(ctx, w, opts)
			bar.Done()
			if err != nil {
				return err
			}
			recordExport(ctx, source, time.Since(exportStart), manifest)
			if err := w.Close(); err != nil {
				return err
			}
			if pass != nil {
				f.Close()
				if err := rewriteExport(ctx, pass, exportPath, usersPath, newWriter, &manifest); err != nil {
					os.Remove(usersPath)
					return err
				}
			}
			if err := lifecycle.ExportAfter(ctx, manifest); err != nil {
				// A vetoed export is not to be used: don't leave it around.
				f.Close()
				os.Remove(usersPath)
				return err
			}
			if err := writeManifest(outDir, manifest); err != nil {
				return err
			}
			if err := connector.WriteDirectory(outDir, src); err != nil {
				return err
			}

			// A scaffolded mapping.yaml covering the recognized-column
			// simple case needs no manual edits; any custom column that
			// landed in app_metadata is flagged as a manual step instead
			// of guessed at, per DESIGN.md.
			appKeys, userKeys, err := collectMetadataKeys(usersPath)
			if err != nil {
				return err
			}
			m := mapping.Scaffold("", "", appKeys, userKeys)
			// Keep how the file's columns were read next to the export, and
			// don't lose it when --mapping is the file written here.
			m.RecordsPath, m.Fields = fileMapping.RecordsPath, fileMapping.Fields
			m.Organizations, m.Roles, m.Memberships = fileMapping.Organizations, fileMapping.Roles, fileMapping.Memberships
			if err := mapping.Save(filepath.Join(outDir, "mapping.yaml"), m); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "exported %d users -> %s (%d skipped)\n",
				manifest.RecordCount, usersPath, len(manifest.SkippedRecords))
			return nil
		},
	}

	cmd.Flags().StringVar(&source, "source", "", "source connector name: flatfile|sql|kratos|keycloak|firebase|auth0|azure-ad-b2c")
	_ = cmd.MarkFlagRequired("source")
	cmd.Flags().StringVar(&in, "in", "", "input file path (flatfile source), or a kc.sh export realm file or directory (keycloak source)")
	cmd.Flags().StringVar(&format, "format", "csv", "input format: csv|json (flatfile source)")
	cmd.Flags().StringVar(&mapPath, "mapping", "", "mapping.yaml path renaming the file's or query's own columns into CMF fields, and its export strategies (export.user, ids.target) (flatfile and sql sources)")
	ffDirectory.register(cmd)
	sqlOpts.register(cmd)
	cmd.Flags().StringVar(&outDir, "out", "./export/", "output directory")
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL, kratos source)")
	fbAuth.register(cmd)
	fbHash.register(cmd)
	a0Auth.register(cmd)
	azAuth.register(cmd)
	cmd.Flags().StringSliceVar(&azExport.ExtensionAttributes, "extension-attributes", nil, "B2C custom attributes to export into user_metadata, by Graph name, comma-separated: extension_<app ID>_<name> (azure-ad-b2c source)")
	cmd.Flags().StringVar(&azExport.Filter, "filter", "", "OData $filter limiting the exported users, e.g. \"creationType eq 'LocalAccount'\" (default: every user; azure-ad-b2c source)")
	cmd.Flags().StringVar(&a0Export.ConnectionID, "connection-id", "", "export only the users of this connection, e.g. con_xxx (default: every connection; auth0 source)")
	cmd.Flags().StringSliceVar(&a0Export.Fields, "fields", nil, "export only these user attributes, comma-separated; user_id is always exported (default: all of "+strings.Join(auth0.ExportFields, ",")+"; auth0 source)")
	cmd.Flags().IntVar(&a0Export.Limit, "limit", 0, "export at most this many users, to try an export on a sample (default: no limit; auth0 and azure-ad-b2c sources)")
	addHooksFlag(cmd)
	cmd.Flags().BoolVar(&noGzip, "no-gzip", false, "write users.cmf.jsonl uncompressed instead of users.cmf.jsonl.gz")
	return cmd
}

// collectMetadataKeys scans an already-written CMF file for distinct
// app_metadata/user_metadata keys, so `export` can flag them as manual
// mapping steps instead of silently passing them through.
func collectMetadataKeys(usersPath string) (appKeys, userKeys []string, err error) {
	f, err := os.Open(usersPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	r, err := cmf.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()

	appSeen := map[string]bool{}
	userSeen := map[string]bool{}
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		for k := range u.AppMetadata {
			appSeen[k] = true
		}
		for k := range u.UserMetadata {
			userSeen[k] = true
		}
	}
	return sortedKeys(appSeen), sortedKeys(userSeen), nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Export metrics, declared in the Argvio catalog. Hash algorithms are the
// CMF's own identifiers; anything else is "other".
var (
	exportDuration      = argvio.NewDuration("export.run", argvio.Dims("source"))
	exportUsers         = argvio.NewValue("export.users", argvio.WithUnit(argvio.UnitCount), argvio.Dims("source"))
	exportSkipped       = argvio.NewValue("export.skipped", argvio.WithUnit(argvio.UnitCount), argvio.Dims("source"))
	exportHashAlgorithm = argvio.NewCounter("export.hash-algorithm", argvio.Dims("source", "algorithm"))

	exportSources  = []string{flatfile.Name, sqlsource.Name, kratos.Name, keycloak.Name, firebase.Name, auth0.Name, azureb2c.Name}
	hashAlgorithms = []string{
		string(cmf.AlgBcrypt), string(cmf.AlgScrypt), string(cmf.AlgPBKDF2), string(cmf.AlgArgon2),
		string(cmf.AlgMD5), string(cmf.AlgSHA1), string(cmf.AlgSHA256), string(cmf.AlgSHA512),
		string(cmf.AlgMD4), string(cmf.AlgHMAC), string(cmf.AlgLDAP),
	}
)

func recordExport(ctx context.Context, source string, d time.Duration, m connector.Manifest) {
	source = telemetryx.Vocab(source, exportSources...)
	exportDuration.Record(ctx, d, source)
	exportUsers.Record(ctx, float64(m.RecordCount), source)
	exportSkipped.Record(ctx, float64(len(m.SkippedRecords)), source)
	for alg, n := range m.HashAlgorithmCounts {
		exportHashAlgorithm.Add(ctx, int64(n), source, telemetryx.Vocab(string(alg), hashAlgorithms...))
	}
}

// flatfileDirectoryFlags names the flat-file source's files of
// organizations, roles and memberships.
type flatfileDirectoryFlags struct {
	organizations, roles, memberships flatfileInput
}

func (f *flatfileDirectoryFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar((*string)(&f.organizations), "organizations", "", "organizations file, mapped by the organizations section of --mapping; written to organizations.cmf.jsonl (flatfile source)")
	cmd.Flags().StringVar((*string)(&f.roles), "roles", "", "roles file, mapped by the roles section of --mapping; written to roles.cmf.jsonl (flatfile source)")
	cmd.Flags().StringVar((*string)(&f.memberships), "memberships", "", "memberships file (user_id, organization, role), mapped by the memberships section of --mapping and joined into the users (flatfile source)")
}

func (f flatfileDirectoryFlags) given() bool {
	return f.organizations != "" || f.roles != "" || f.memberships != ""
}

// flatfileInput is the path of a flat file whose format is told by its
// .csv or .json extension, else is the users file's.
type flatfileInput string

func (p flatfileInput) file(format string) flatfile.File {
	switch strings.ToLower(filepath.Ext(string(p))) {
	case ".csv":
		format = string(flatfile.FormatCSV)
	case ".json":
		format = string(flatfile.FormatJSON)
	}
	return flatfile.File{Path: string(p), Format: flatfile.Format(format)}
}
