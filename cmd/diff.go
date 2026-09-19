package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var (
		in     string
		domain string
		token  string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Reconcile a CMF file against a live Auth0 tenant",
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

			client := auth0.NewClient("https://"+domain+"/api/v2", token)
			report, err := auth0.New(client).Verify(cmd.Context(), r)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "missing in target: %d, attribute drift: %d\n",
				len(report.MissingInTarget), len(report.AttributeDrift))
			for _, id := range report.MissingInTarget {
				fmt.Fprintln(cmd.OutOrStdout(), " missing:", id)
			}
			for _, d := range report.AttributeDrift {
				fmt.Fprintln(cmd.OutOrStdout(), " drift:", d.SourceID, d.Fields)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&domain, "domain", "", "Auth0 tenant domain (or $AUTH0_DOMAIN)")
	cmd.Flags().StringVar(&token, "token", "", "Auth0 Management API token (or $AUTH0_TOKEN)")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}
