// Package cmd drives export, mapping, validation, import, and
// verification for migrating CIAM identities between providers.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

// argvioAPIKey is iamigrate's public_ingest-scoped Argvio API key, selecting the
// "iamigrate" tenant its usage analytics land in. It is not committed: the release
// build injects it with -ldflags -X from the ARGVIO_API_KEY secret, and a build
// without one reports nothing.
var argvioAPIKey string

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "iamigrate",
		Short:         "Migrate CIAM identities between providers via the Canonical Migration Format",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newTestdataCmd(),
		newPrepareCmd(),
		newExportCmd(),
		newMapCmd(),
		newValidateCmd(),
		newSetPasswordsCmd(),
		newImportCmd(),
		newDiffCmd(),
		newRollbackCmd(),
		newJobCmd(),
		newServeCmd(),
		newIDsCmd(),
	)
	root.PersistentFlags().Bool("sqa-opt-out", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")
	return root
}

// Execute adds all child commands to the root command and runs it.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	root := newRootCmd()
	telemetryShutdown := telemetryx.Instrument(root, version, argvioAPIKey)
	defer func() { _ = telemetryShutdown(context.Background()) }()

	if err := telemetryx.Execute(root); err != nil {
		_ = telemetryShutdown(context.Background())
		fmt.Fprintln(os.Stderr, "iamigrate:", err)
		os.Exit(1) //nolint:gocritic // telemetryShutdown was already run explicitly above, not relying on the deferred call
	}
}
