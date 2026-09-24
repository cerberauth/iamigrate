package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
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
			default:
				return fmt.Errorf("unsupported --target %q (supports \"auth0\", \"kratos\", and \"keycloak\")", target)
			}
			caps := tc.Capabilities()

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

			var problems []connector.Problem
			dups := newDupTracker()
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
				problems = append(problems, tc.ValidateUser(u)...)
				problems = append(problems, dups.check(u)...)
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
	cmd.Flags().StringVar(&target, "target", "", "target connector name: auth0|kratos|keycloak")
	cmd.Flags().StringVar(&schemaFile, "schema-file", "", "Kratos identity schema JSON path, to check traits against (only with --target kratos)")
	cmd.Flags().StringVar(&connectionConfig, "connection-config", "", "Auth0 connection JSON path, to tighten username/identifier rules (only with --target auth0)")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func checkUser(u cmf.User, caps connector.Capabilities) []connector.Problem {
	var problems []connector.Problem
	if u.Password != nil && !caps.SupportsAlgorithm(u.Password.Algorithm) {
		problems = append(problems, connector.Problem{
			SourceID: u.SourceID, Field: "password.algorithm",
			Rule: "unsupported by target", Value: string(u.Password.Algorithm),
		})
	}
	for _, f := range u.MFAFactors {
		if f.Portable && !caps.SupportsMFAType(f.Type) {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "mfa_factors.type",
				Rule: "unsupported by target", Value: string(f.Type),
			})
		}
	}
	return problems
}

// dupTracker flags emails, usernames, and phones reused across more than
// one user within the same CMF file -- a target-agnostic check, since a
// duplicate breaks uniqueness in any target, per issue #57's "Both"
// checks.
type dupTracker struct {
	emails    map[string]string
	usernames map[string]string
	phones    map[string]string
}

func newDupTracker() *dupTracker {
	return &dupTracker{
		emails:    map[string]string{},
		usernames: map[string]string{},
		phones:    map[string]string{},
	}
}

func (d *dupTracker) check(u cmf.User) []connector.Problem {
	var problems []connector.Problem
	for _, e := range u.Emails {
		key := strings.ToLower(e.Value)
		if first, ok := d.emails[key]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "emails",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: e.Value,
			})
		} else {
			d.emails[key] = u.SourceID
		}
	}
	if u.Username != "" {
		if first, ok := d.usernames[u.Username]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "username",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: u.Username,
			})
		} else {
			d.usernames[u.Username] = u.SourceID
		}
	}
	for _, p := range u.Phones {
		if first, ok := d.phones[p.Value]; ok {
			problems = append(problems, connector.Problem{
				SourceID: u.SourceID, Field: "phones",
				Rule: fmt.Sprintf("duplicate of %s within file", first), Value: p.Value,
			})
		} else {
			d.phones[p.Value] = u.SourceID
		}
	}
	return problems
}
