package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "diff", Short: "Reconcile a CMF file against a live target"}
	cmd.AddCommand(newDiffAuth0Cmd())
	cmd.AddCommand(newDiffKratosCmd())
	return cmd
}

func newDiffAuth0Cmd() *cobra.Command {
	var (
		in     string
		domain string
		token  string
	)

	cmd := &cobra.Command{
		Use:   auth0.Name,
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

			r, closeFn, err := openReader(in)
			if err != nil {
				return err
			}
			defer closeFn()

			client := auth0.NewClient("https://"+domain+"/api/v2", token)
			report, err := auth0.New(client).Verify(cmd.Context(), r)
			if err != nil {
				return err
			}
			printDiffReport(cmd, report)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&domain, "domain", "", "Auth0 tenant domain (or $AUTH0_DOMAIN)")
	cmd.Flags().StringVar(&token, "token", "", "Auth0 Management API token (or $AUTH0_TOKEN)")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

func newDiffKratosCmd() *cobra.Command {
	var (
		in       string
		adminURL string
	)

	cmd := &cobra.Command{
		Use:   kratos.Name,
		Short: "Reconcile a CMF file against a live Ory Kratos instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			if adminURL == "" {
				adminURL = os.Getenv("KRATOS_ADMIN_URL")
			}
			if adminURL == "" {
				return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required")
			}

			r, closeFn, err := openReader(in)
			if err != nil {
				return err
			}
			defer closeFn()

			client := kratos.NewClient(adminURL)
			report, err := kratos.New(client, "").Verify(cmd.Context(), r)
			if err != nil {
				return err
			}
			printDiffReport(cmd, report)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL)")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

func openReader(in string) (*cmf.Reader, func(), error) {
	f, err := os.Open(in)
	if err != nil {
		return nil, nil, err
	}
	r, err := cmf.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, func() { r.Close(); f.Close() }, nil
}

func printDiffReport(cmd *cobra.Command, report connector.DiffReport) {
	fmt.Fprintf(cmd.OutOrStdout(), "missing in target: %d, attribute drift: %d\n",
		len(report.MissingInTarget), len(report.AttributeDrift))
	for _, id := range report.MissingInTarget {
		fmt.Fprintln(cmd.OutOrStdout(), " missing:", id)
	}
	for _, d := range report.AttributeDrift {
		fmt.Fprintln(cmd.OutOrStdout(), " drift:", d.SourceID, d.Fields)
	}
}
