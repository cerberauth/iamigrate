package cmd

import (
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

// maxSkippedShown caps how many skipped records prepare spells out.
const maxSkippedShown = 10

func newPrepareCmd() *cobra.Command {
	var (
		in         string
		format     string
		mappingArg string
		out        string
		outFormat  string
	)

	cmd := &cobra.Command{
		Use:   "prepare",
		Short: "Rewrite a CSV or JSON file into the columns `export --source flatfile` reads",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mapping.Load(mappingArg)
			if err != nil {
				return err
			}
			if outFormat == "" {
				outFormat = format
			}
			report, err := flatfile.Prepare(flatfile.PrepareOptions{
				In:        in,
				InFormat:  flatfile.Format(format),
				Out:       out,
				OutFormat: flatfile.Format(outFormat),
				Mapping:   m,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "prepared %d records -> %s\n", report.Records, out)
			if n := len(report.Skipped); n > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "iamigrate: %d records will be skipped by export:\n", n)
				for i, s := range report.Skipped {
					if i == maxSkippedShown {
						fmt.Fprintf(cmd.ErrOrStderr(), "  ... and %d more\n", n-i)
						break
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %s\n", s.SourceID, s.Reason)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&in, "in", "", "CSV or JSON file to read")
	_ = cmd.MarkFlagRequired("in")
	cmd.Flags().StringVar(&format, "format", "csv", "input format: csv|json")
	cmd.Flags().StringVar(&mappingArg, "mapping", "", "mapping.yaml path describing how the file's columns map to CMF fields")
	_ = cmd.MarkFlagRequired("mapping")
	cmd.Flags().StringVar(&out, "out", "", "file to write; must differ from --in")
	_ = cmd.MarkFlagRequired("out")
	cmd.Flags().StringVar(&outFormat, "out-format", "", "output format: csv|json (default: the input format)")
	return cmd
}
