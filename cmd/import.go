package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "import", Short: "Import CMF identities into a target"}
	cmd.AddCommand(newImportAuth0Cmd())
	return cmd
}

func newImportAuth0Cmd() *cobra.Command {
	var (
		in           string
		mappingPath  string
		connectionID string
		upsert       bool
		domain       string
		token        string
		reportPath   string
	)

	cmd := &cobra.Command{
		Use:   "auth0",
		Short: "Chunk, submit, poll, and import a CMF file into an Auth0 tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if domain == "" {
				domain = os.Getenv("AUTH0_DOMAIN")
			}
			if token == "" {
				token = os.Getenv("AUTH0_TOKEN")
			}
			if domain == "" || token == "" {
				return fmt.Errorf("--domain/--token (or AUTH0_DOMAIN/AUTH0_TOKEN) are required")
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
			if m.ConnectionID == "" {
				return fmt.Errorf("--connection-id is required (or set in mapping.yaml)")
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

			client := auth0.NewClient("https://"+domain+"/api/v2", token)
			target := auth0.New(client)

			report, err := target.Import(cmd.Context(), r, m, opts)
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

			fmt.Fprintf(cmd.OutOrStdout(), "imported: %d succeeded, %d failed -> report %s\n",
				len(report.Succeeded), len(report.Failed), reportPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	cmd.Flags().StringVar(&connectionID, "connection-id", "", "Auth0 database connection ID")
	cmd.Flags().BoolVar(&upsert, "upsert", false, "allow re-running this import against existing users")
	cmd.Flags().StringVar(&domain, "domain", "", "Auth0 tenant domain (or $AUTH0_DOMAIN)")
	cmd.Flags().StringVar(&token, "token", "", "Auth0 Management API token (or $AUTH0_TOKEN)")
	cmd.Flags().StringVar(&reportPath, "report", "", "import-report.json output path (default: alongside --in)")
	_ = cmd.MarkFlagRequired("in")
	return cmd
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
