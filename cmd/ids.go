package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newIDsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ids",
		Short: "Assign the user IDs a target is to give the imported users",
	}
	cmd.AddCommand(newIDsAssignCmd())
	return cmd
}

func newIDsAssignCmd() *cobra.Command {
	var in, out, mappingPath, target, hooksPath string

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Write a copy of a CMF users file with each user's target ID assigned by the mapping's ids.target",
		Long: "Apply the mapping's ids.target strategy to every user of --in that has no ID for --target yet, " +
			"and write the result to --out, so every import of it sends the same IDs. " +
			"A job's export does this itself; use it for a users file that didn't come from one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if filepath.Clean(in) == filepath.Clean(out) {
				return fmt.Errorf("--out must differ from --in")
			}
			tc, err := offlineTarget(target)
			if err != nil {
				return err
			}
			m, err := mapping.Load(mappingPath)
			if err != nil {
				return err
			}
			if err := m.Validate(); err != nil {
				return err
			}
			if !m.IDs.Target.Assigns() {
				return fmt.Errorf("%s has no ids.target strategy assigning IDs", mappingPath)
			}
			d, err := loadHooks(hooksPath)
			if err != nil {
				return err
			}
			a, err := ids.NewAssigner(m.IDs.Target, tc.Name(), tc.Capabilities(), d)
			if err != nil {
				return err
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

			// Written aside and renamed on success, so a failed call never
			// leaves a partial file at --out.
			part := out + ".part"
			defer os.Remove(part)
			o, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer o.Close()
			w := cmf.NewPlainWriter(o)
			if strings.HasSuffix(out, ".gz") {
				w = cmf.NewWriter(o)
			}
			n, err := a.Rewrite(cmd.Context(), r, w)
			if err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
			if err := o.Close(); err != nil {
				return err
			}
			if err := os.Rename(part, out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "assigned %s IDs to %d users -> %s\n", target, n, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&in, "in", "", "CMF users file to read (gzip detected automatically)")
	cmd.Flags().StringVar(&out, "out", "", "CMF users file to write (gzipped when it ends in .gz)")
	cmd.Flags().StringVar(&mappingPath, "mapping", "", "mapping.yaml path holding the ids.target strategy")
	cmd.Flags().StringVar(&target, "target", "", "target connector name: auth0|firebase (kratos and keycloak generate their own IDs)")
	cmd.Flags().StringVar(&hooksPath, "hooks", "", "hooks.yaml path declaring the handler an ids.target delegates to")
	for _, f := range []string{"in", "out", "mapping", "target"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}
