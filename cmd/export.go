package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newExportCmd() *cobra.Command {
	var (
		source   string
		in       string
		format   string
		outDir   string
		adminURL string
		noGzip   bool
		fbAuth   firebaseFlags
		fbHash   firebaseHashFlags
		a0Auth   auth0Flags
		a0Export auth0.ExportOptions
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export identities from a source into CMF",
		RunE: func(cmd *cobra.Command, args []string) error {
			if source != flatfile.Name && source != kratos.Name && source != keycloak.Name && source != firebase.Name && source != auth0.Name {
				return fmt.Errorf("unsupported --source %q (supports \"flatfile\", \"kratos\", \"keycloak\", \"firebase\", and \"auth0\"; use `iamigrate testdata generate` for the fixture source)", source)
			}
			if (source == flatfile.Name || source == keycloak.Name) && in == "" {
				return fmt.Errorf("--in is required for --source %s", source)
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

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			usersPath, newWriter := usersOutput(outDir, noGzip)
			f, err := os.Create(usersPath)
			if err != nil {
				return err
			}
			defer f.Close()

			w := newWriter(f)
			var manifest connector.Manifest
			ctx, bar := startProgress(cmd)
			defer bar.Done()
			switch source {
			case kratos.Name:
				if adminURL == "" {
					adminURL = os.Getenv("KRATOS_ADMIN_URL")
				}
				if adminURL == "" {
					return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required for --source kratos")
				}
				client := kratos.NewClient(adminURL)
				bar.Stage("exporting users", 0)
				manifest, err = kratos.New(client, "").Export(ctx, w, kratos.ExportOptions{})
			case keycloak.Name:
				bar.Stage("exporting users", 0)
				manifest, err = keycloak.New(nil).Export(ctx, w, keycloak.ExportOptions{Path: in})
			case firebase.Name:
				bar.Stage("exporting users", 0)
				manifest, err = firebase.New(fbClient).Export(ctx, w, firebase.ExportOptions{Scrypt: fbScrypt})
			case auth0.Name:
				bar.Stage("exporting users", 0)
				manifest, err = auth0.New(a0Client).Export(ctx, w, a0Export)
			default:
				opts := flatfile.ExportOptions{Path: in, Format: flatfile.Format(format)}
				bar.Stage("exporting users", 0)
				manifest, err = flatfile.New().Export(ctx, w, opts)
			}
			bar.Done()
			if err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
			if err := writeManifest(outDir, manifest); err != nil {
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
			if err := mapping.Save(filepath.Join(outDir, "mapping.yaml"), m); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "exported %d users -> %s (%d skipped)\n",
				manifest.RecordCount, usersPath, len(manifest.SkippedRecords))
			return nil
		},
	}

	cmd.Flags().StringVar(&source, "source", "", "source connector name: flatfile|kratos|keycloak|firebase|auth0")
	_ = cmd.MarkFlagRequired("source")
	cmd.Flags().StringVar(&in, "in", "", "input file path (flatfile source), or a kc.sh export realm file or directory (keycloak source)")
	cmd.Flags().StringVar(&format, "format", "csv", "input format: csv|json (flatfile source)")
	cmd.Flags().StringVar(&outDir, "out", "./export/", "output directory")
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL, kratos source)")
	fbAuth.register(cmd)
	fbHash.register(cmd)
	a0Auth.register(cmd)
	cmd.Flags().StringVar(&a0Export.ConnectionID, "connection-id", "", "export only the users of this connection, e.g. con_xxx (default: every connection; auth0 source)")
	cmd.Flags().StringSliceVar(&a0Export.Fields, "fields", nil, "export only these user attributes, comma-separated; user_id is always exported (default: all of "+strings.Join(auth0.ExportFields, ",")+"; auth0 source)")
	cmd.Flags().IntVar(&a0Export.Limit, "limit", 0, "export at most this many users, to try an export on a sample (default: no limit; auth0 source)")
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
