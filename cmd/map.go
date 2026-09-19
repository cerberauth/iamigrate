package cmd

import (
	"fmt"

	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/spf13/cobra"
)

func newMapCmd() *cobra.Command {
	var (
		mappingPath  string
		target       string
		connectionID string
	)

	cmd := &cobra.Command{
		Use:   "map",
		Short: "Scaffold or update the CMF -> target field mapping",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mapping.Load(mappingPath)
			if err != nil {
				// A missing file just means this is the first scaffold.
				m = mapping.Mapping{}
			}
			m.Target = target
			if connectionID != "" {
				m.ConnectionID = connectionID
			}
			if err := m.Validate(); err != nil {
				return err
			}
			if err := mapping.Save(mappingPath, m); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d manual steps flagged)\n", mappingPath, len(m.ManualSteps))
			return nil
		},
	}

	cmd.Flags().StringVar(&mappingPath, "mapping", "mapping.yaml", "mapping.yaml path")
	cmd.Flags().StringVar(&target, "target", "auth0", "target connector name")
	cmd.Flags().StringVar(&connectionID, "connection-id", "", "target connection ID (Auth0 database connection)")
	return cmd
}
