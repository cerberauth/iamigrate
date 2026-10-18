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
// "iamigrate" tenant its usage analytics land in. It only allows sending usage
// data, so it is safe to embed.
const argvioAPIKey = "argv_live_pub_bkjcWtoMNbieOHvX_cY4tuFGrBefuEPY" //nolint:gosec // ingest-only key, not a secret

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
		newJobCmd(),
		newServeCmd(),
		newIDsCmd(),
	)
	root.PersistentFlags().Bool("sqa-opt-out", false, "Opt out of sending anonymous usage statistics to help improve the tool")
	return root
}

// Execute adds all child commands to the root command and runs it.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	root := newRootCmd()
	telemetryShutdown := telemetryx.Instrument(root, version, argvioAPIKey)
	defer func() { _ = telemetryShutdown(context.Background()) }()

	if err := root.Execute(); err != nil {
		_ = telemetryShutdown(context.Background())
		fmt.Fprintln(os.Stderr, "iamigrate:", err)
		os.Exit(1) //nolint:gocritic // telemetryShutdown was already run explicitly above, not relying on the deferred call
	}
}
