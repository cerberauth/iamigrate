package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/lifecycle"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/cerberauth/iamigrate/pkg/validate"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var (
		in               string
		mappingPath      string
		target           string
		schemaFile       string
		connectionConfig string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Dry-run a CMF file against a target's Capabilities and field rules (no network calls)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if schemaFile != "" && target != kratos.Name {
				return fmt.Errorf("--schema-file only applies to --target %s", kratos.Name)
			}
			if connectionConfig != "" && target != auth0.Name {
				return fmt.Errorf("--connection-config only applies to --target %s", auth0.Name)
			}

			var tc connector.TargetConnector
			switch target {
			case auth0.Name:
				c := &auth0.Connector{}
				if connectionConfig != "" {
					cc, err := auth0.LoadConnectionConfig(connectionConfig)
					if err != nil {
						return err
					}
					c.ConnectionConfig = cc
				}
				tc = c
			case kratos.Name:
				c := &kratos.Connector{}
				if schemaFile != "" {
					s, err := kratos.LoadIdentitySchema(schemaFile)
					if err != nil {
						return err
					}
					c.IdentitySchema = s
				}
				tc = c
			case keycloak.Name:
				tc = &keycloak.Connector{}
			case firebase.Name:
				tc = &firebase.Connector{}
			default:
				return fmt.Errorf("unsupported --target %q (supports \"auth0\", \"kratos\", \"keycloak\", and \"firebase\")", target)
			}
			caps := tc.Capabilities()

			var idStrategy *mapping.IDStrategy
			var hooked *strategy.Validator
			if mappingPath != "" {
				m, err := mapping.Load(mappingPath)
				if err != nil {
					return err
				}
				if err := m.Validate(); err != nil {
					return err
				}
				if err := importprep.Check(m, tc); err != nil {
					return err
				}
				if err := strategy.Check(m); err != nil {
					return err
				}
				set, err := strategy.New(strategy.Only(m, strategy.ValidateUser, strategy.ValidateDedupKey), hooks.FromContext(cmd.Context()))
				if err != nil {
					return err
				}
				idStrategy, hooked = m.IDs.Target, strategy.NewValidator(set)
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

			ctx, bar := startProgress(cmd)
			defer bar.Done()
			bar.Stage("checking users", countUsers(bar, in))

			var problems []connector.Problem
			dups := validate.NewDupTracker()
			targetIDs := ids.NewChecker(idStrategy, target, caps)
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
				problems = append(problems, validate.CheckUser(u, caps)...)
				problems = append(problems, tc.ValidateUser(u)...)
				problems = append(problems, dups.Check(u)...)
				problems = append(problems, targetIDs.Check(u)...)
				ps, err := hooked.Add(ctx, u)
				if err != nil {
					return err
				}
				problems = append(problems, ps...)
			}
			ps, err := hooked.Flush(ctx)
			if err != nil {
				return err
			}
			problems = append(problems, ps...)

			bar.Done()
			problems, warnings, fail, err := lifecycle.ValidateAfter(ctx, problems)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "checked %d users against %s: %d problem(s)\n", count, target, len(problems))
			for _, p := range problems {
				fmt.Fprintln(cmd.OutOrStdout(), " -", p)
			}
			if len(warnings) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "%d warning(s), downgraded by the %s hook:\n", len(warnings), hooks.ValidateAfter)
				for _, p := range warnings {
					fmt.Fprintln(cmd.OutOrStdout(), " -", p)
				}
			}
			if fail && len(problems) == 0 {
				return fmt.Errorf("validate failed: the %s hook failed it", hooks.ValidateAfter)
			}
			if fail {
				return fmt.Errorf("validate failed: %d problem(s) found", len(problems))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CMF users.cmf.jsonl[.gz] path (gzip detected automatically)")
	cmd.Flags().StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	cmd.Flags().StringVar(&target, "target", "", "target connector name: auth0|kratos|keycloak|firebase")
	cmd.Flags().StringVar(&schemaFile, "schema-file", "", "Kratos identity schema JSON path, to check traits against (only with --target kratos)")
	cmd.Flags().StringVar(&connectionConfig, "connection-config", "", "Auth0 connection JSON path, to tighten username/identifier rules (only with --target auth0)")
	addHooksFlag(cmd)
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}
