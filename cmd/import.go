package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "import", Short: "Import CMF identities into a target"}
	cmd.AddCommand(newImportAuth0Cmd())
	cmd.AddCommand(newImportKratosCmd())
	return cmd
}

func newImportAuth0Cmd() *cobra.Command {
	var (
		in           string
		mappingPath  string
		connectionID string
		connection   string
		upsert       bool
		reportPath   string
		auth         auth0Flags
	)

	cmd := &cobra.Command{
		Use:   auth0.Name,
		Short: "Chunk, submit, poll, and import a CMF file into an Auth0 tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := auth.client()
			if err != nil {
				return err
			}

			m := mapping.Mapping{ConnectionID: connectionID}
			if mappingPath != "" {
				var err error
				m, err = mapping.Load(mappingPath)
				if err != nil {
					return err
				}
				if connectionID != "" {
					m.ConnectionID = connectionID
				}
			}

			// An explicit --connection-id (or mapping.yaml's connection_id)
			// needs no extra scope; resolving by name, or picking the only
			// database connection, needs read:connections.
			if connection != "" || m.ConnectionID == "" {
				id, err := auth0.ResolveConnectionID(cmd.Context(), client, connection)
				if err != nil {
					return fmt.Errorf("%w; pass --connection-id (or set connection_id in mapping.yaml), or --connection to pick one by name", err)
				}
				m.ConnectionID = id
			}

			f, err := os.Open(in)
			if err != nil {
				return err
			}
			defer f.Close()
			r, err := cmf.NewReader(f)
			if err != nil {
				return err
			}
			defer r.Close()

			opts := connector.ImportOptions{ConnectionID: m.ConnectionID, Upsert: upsert}

			dir := filepath.Dir(in)
			if orgs, err := loadOrganizations(dir); err == nil {
				opts.Organizations = orgs
			}
			if roles, err := loadRoles(dir); err == nil {
				opts.Roles = roles
			}

			target := auth0.New(client)

			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("importing users", countUsers(bar, in))
			report, err := target.Import(ctx, r, m, opts)
			bar.Done()
			if err != nil {
				return err
			}

			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if reportPath == "" {
				reportPath = filepath.Join(dir, "import-report.json")
			}
			if err := os.WriteFile(reportPath, b, 0o600); err != nil {
				return err
			}

			printImportSummary(cmd.OutOrStdout(), report, reportPath, upsert)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	cmd.Flags().StringVar(&connectionID, "connection-id", "", "Auth0 database connection ID")
	cmd.Flags().StringVar(&connection, "connection", "", "Auth0 database connection name (needs read:connections; default: the tenant's only database connection)")
	cmd.Flags().BoolVar(&upsert, "upsert", false, "allow re-running this import against existing users")
	auth.register(cmd)
	cmd.Flags().StringVar(&reportPath, "report", "", "import-report.json output path (default: alongside --in)")
	_ = cmd.MarkFlagRequired("in")
	cmd.MarkFlagsMutuallyExclusive("connection-id", "connection")
	return cmd
}

func newImportKratosCmd() *cobra.Command {
	var (
		in         string
		schemaID   string
		adminURL   string
		reportPath string
	)

	cmd := &cobra.Command{
		Use:   kratos.Name,
		Short: "Create Ory Kratos identities from a CMF file via the Admin API",
		RunE: func(cmd *cobra.Command, args []string) error {
			if adminURL == "" {
				adminURL = os.Getenv("KRATOS_ADMIN_URL")
			}
			if adminURL == "" {
				return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required")
			}

			f, err := os.Open(in)
			if err != nil {
				return err
			}
			defer f.Close()
			r, err := cmf.NewReader(f)
			if err != nil {
				return err
			}
			defer r.Close()

			client := kratos.NewClient(adminURL)
			target := kratos.New(client, schemaID)

			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("importing users", countUsers(bar, in))
			report, err := target.Import(ctx, r, mapping.Mapping{}, connector.ImportOptions{})
			bar.Done()
			if err != nil {
				return err
			}

			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if reportPath == "" {
				reportPath = filepath.Join(filepath.Dir(in), "import-report.json")
			}
			if err := os.WriteFile(reportPath, b, 0o600); err != nil {
				return err
			}

			printImportSummary(cmd.OutOrStdout(), report, reportPath, false)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&schemaID, "schema-id", "default", "Kratos identity schema ID to create identities against")
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL)")
	cmd.Flags().StringVar(&reportPath, "report", "", "import-report.json output path (default: alongside --in)")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

// printImportSummary prints the import totals, then one line per failure
// code. Users that already exist in the target are counted apart from real
// failures, with a hint on how to update them.
func printImportSummary(w io.Writer, report connector.ImportReport, reportPath string, upsert bool) {
	duplicated := 0
	failedByCode := map[string]int{}
	for _, f := range report.Failed {
		if f.Code == auth0.DuplicatedUserCode {
			duplicated++
			continue
		}
		failedByCode[f.Code]++
	}
	failed := len(report.Failed) - duplicated

	if duplicated == 0 {
		fmt.Fprintf(w, "imported: %d succeeded, %d failed -> report %s\n", len(report.Succeeded), failed, reportPath)
	} else {
		fmt.Fprintf(w, "imported: %d succeeded, %d already exist, %d failed -> report %s\n",
			len(report.Succeeded), duplicated, failed, reportPath)
		if upsert {
			fmt.Fprintf(w, "  %d already exist: left over in Auth0's user store outside this connection; delete them via the Connection Users endpoint and re-import\n", duplicated)
		} else {
			fmt.Fprintf(w, "  %d already exist: not updated; re-run with --upsert to update them\n", duplicated)
		}
	}

	codes := make([]string, 0, len(failedByCode))
	for code := range failedByCode {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		fmt.Fprintf(w, "  %d failed: %s\n", failedByCode[code], code)
	}
}

func loadOrganizations(dir string) ([]cmf.Organization, error) {
	f, err := os.Open(filepath.Join(dir, "organizations.cmf.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return cmf.ReadOrganizations(f)
}

func loadRoles(dir string) ([]cmf.Role, error) {
	f, err := os.Open(filepath.Join(dir, "roles.cmf.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return cmf.ReadRoles(f)
}
