package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var (
		in          string
		mappingPath string
		target      string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Dry-run a CMF file against a target's Capabilities (no network calls)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var caps connector.Capabilities
			switch target {
			case auth0.Name:
				caps = (&auth0.Connector{}).Capabilities()
			case kratos.Name:
				caps = (&kratos.Connector{}).Capabilities()
			default:
				return fmt.Errorf("unsupported --target %q (supports \"auth0\" and \"kratos\")", target)
			}

			if mappingPath != "" {
				m, err := mapping.Load(mappingPath)
				if err != nil {
					return err
				}
				if err := m.Validate(); err != nil {
					return err
				}
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

			_, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("checking users", countUsers(bar, in))

			var problems []string
			count := 0
			for {
				u, err := r.ReadUser()
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				count++
				bar.Add(1)
				problems = append(problems, checkUser(u, caps)...)
			}

			bar.Done()
			fmt.Fprintf(cmd.OutOrStdout(), "checked %d users against %s: %d problem(s)\n", count, target, len(problems))
			for _, p := range problems {
				fmt.Fprintln(cmd.OutOrStdout(), " -", p)
			}
			if len(problems) > 0 {
				return fmt.Errorf("validate failed: %d problem(s) found", len(problems))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl.gz path")
	cmd.Flags().StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	cmd.Flags().StringVar(&target, "target", "", "target connector name: auth0|kratos")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func checkUser(u cmf.User, caps connector.Capabilities) []string {
	var problems []string
	if u.Password != nil && !caps.SupportsAlgorithm(u.Password.Algorithm) {
		problems = append(problems, fmt.Sprintf("%s: unsupported password algorithm %q", u.SourceID, u.Password.Algorithm))
	}
	for _, f := range u.MFAFactors {
		if f.Portable && !caps.SupportsMFAType(f.Type) {
			problems = append(problems, fmt.Sprintf("%s: unsupported MFA type %q", u.SourceID, f.Type))
		}
	}
	return problems
}
