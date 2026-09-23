package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
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
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export identities from a source into CMF",
		RunE: func(cmd *cobra.Command, args []string) error {
			if source != flatfile.Name && source != kratos.Name {
				return fmt.Errorf("unsupported --source %q (supports \"flatfile\" and \"kratos\"; use `iamigrate testdata generate` for the fixture source)", source)
			}
			if source == flatfile.Name && in == "" {
				return fmt.Errorf("--in is required for --source flatfile")
			}

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}

			usersPath := filepath.Join(outDir, "users.cmf.jsonl.gz")
			f, err := os.Create(usersPath)
			if err != nil {
				return err
			}
			defer f.Close()

			w := cmf.NewWriter(f)
			var manifest connector.Manifest
			ctx, bar := startProgress(cmd)
			defer bar.Done()
			if source == kratos.Name {
				if adminURL == "" {
					adminURL = os.Getenv("KRATOS_ADMIN_URL")
				}
				if adminURL == "" {
					return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required for --source kratos")
				}
				client := kratos.NewClient(adminURL)
				bar.Stage("exporting users", 0)
				manifest, err = kratos.New(client, "").Export(ctx, w, kratos.ExportOptions{})
			} else {
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

	cmd.Flags().StringVar(&source, "source", "", "source connector name: flatfile|kratos")
	_ = cmd.MarkFlagRequired("source")
	cmd.Flags().StringVar(&in, "in", "", "input file path (flatfile source)")
	cmd.Flags().StringVar(&format, "format", "csv", "input format: csv|json (flatfile source)")
	cmd.Flags().StringVar(&outDir, "out", "./export/", "output directory")
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL, kratos source)")
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
