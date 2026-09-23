package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "diff", Short: "Reconcile a CMF file against a live target"}
	cmd.AddCommand(newDiffAuth0Cmd())
	cmd.AddCommand(newDiffKratosCmd())
	cmd.AddCommand(newDiffKeycloakCmd())
	return cmd
}

func newDiffAuth0Cmd() *cobra.Command {
	var (
		in   string
		auth auth0Flags
	)

	cmd := &cobra.Command{
		Use:   auth0.Name,
		Short: "Reconcile a CMF file against a live Auth0 tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := auth.client()
			if err != nil {
				return err
			}

			r, closeFn, err := openReader(in)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("checking users", countUsers(bar, in))
			report, err := auth0.New(client).Verify(ctx, r)
			bar.Done()
			if err != nil {
				return err
			}
			printDiffReport(cmd, report)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	auth.register(cmd)
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
			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("checking users", countUsers(bar, in))
			report, err := kratos.New(client, "").Verify(ctx, r)
			bar.Done()
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

func newDiffKeycloakCmd() *cobra.Command {
	var (
		in   string
		auth keycloakFlags
	)

	cmd := &cobra.Command{
		Use:   keycloak.Name,
		Short: "Reconcile a CMF file against a live Keycloak realm",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := auth.client()
			if err != nil {
				return err
			}

			r, closeFn, err := openReader(in)
			if err != nil {
				return err
			}
			defer closeFn()

			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("checking users", countUsers(bar, in))
			report, err := keycloak.New(client).Verify(ctx, r)
			bar.Done()
			if err != nil {
				return err
			}
			printDiffReport(cmd, report)
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	auth.register(cmd)
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
	fmt.Fprintf(cmd.OutOrStdout(), "missing in target: %d, attribute drift: %d, no identifier: %d\n",
		len(report.MissingInTarget), len(report.AttributeDrift), len(report.NoIdentifier))
	for _, id := range report.MissingInTarget {
		fmt.Fprintln(cmd.OutOrStdout(), " missing:", id)
	}
	for _, d := range report.AttributeDrift {
		fmt.Fprintln(cmd.OutOrStdout(), " drift:", d.SourceID, d.Fields)
	}
	for _, id := range report.NoIdentifier {
		fmt.Fprintln(cmd.OutOrStdout(), " no identifier:", id)
	}
}
