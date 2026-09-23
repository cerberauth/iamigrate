package cmd

import (
	"context"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/spf13/cobra"
)

// startProgress returns a progress bar drawn on cmd's stderr, and a copy of
// cmd's context carrying it for connectors to report into. Callers must
// call Done on the bar before printing their summary.
func startProgress(cmd *cobra.Command) (context.Context, *progress.Bar) {
	bar := progress.New(cmd.ErrOrStderr())
	return progress.NewContext(cmd.Context(), bar), bar
}

// countUsers sizes a progress bar for the CMF file at path. It only reads
// the file when the bar is actually shown, and falls back to 0 (unknown
// total) on any error, leaving the real read to surface it.
func countUsers(bar *progress.Bar, path string) int {
	if !bar.Enabled() {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n, err := cmf.CountUsers(f)
	if err != nil {
		return 0
	}
	return n
}
