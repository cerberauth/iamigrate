// Package cmd drives export, mapping, validation, import, and
// verification for migrating CIAM identities between providers.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "iamigrate",
		Short:         "Migrate CIAM identities between providers via the Canonical Migration Format",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newTestdataCmd(),
		newExportCmd(),
		newMapCmd(),
		newValidateCmd(),
		newImportCmd(),
		newDiffCmd(),
	)
	return root
}

// Execute adds all child commands to the root command and runs it.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "iamigrate:", err)
		os.Exit(1)
	}
}
