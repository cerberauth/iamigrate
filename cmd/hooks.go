package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/exportpass"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/cerberauth/x/fsx"
	"github.com/spf13/cobra"
)

// loadHooks returns the Dispatcher of the hooks file at path, nil for no
// path, which fires no hooks.
func loadHooks(path string) (*hooks.Dispatcher, error) {
	if path == "" {
		return nil, nil
	}
	cfg, err := hooks.Load(path)
	if err != nil {
		return nil, err
	}
	return hooks.New(cfg)
}

// addHooksFlag gives cmd, and its subcommands, a --hooks flag, and puts
// the Dispatcher of the hooks file it names in the command's context before
// it runs, for the steps to fire their events through.
func addHooksFlag(cmd *cobra.Command) {
	var path string
	cmd.PersistentFlags().StringVar(&path, "hooks", "", "hooks.yaml path: the hooks this command fires")
	cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		d, err := loadHooks(path)
		if err != nil || d == nil {
			return err
		}
		c.SetContext(hooks.WithDispatcher(c.Context(), d))
		return nil
	}
}

// offlineTarget returns the target connector name, unconfigured: enough for
// what it declares (Name, Capabilities), not to reach it.
func offlineTarget(name string) (connector.TargetConnector, error) {
	switch name {
	case auth0.Name:
		return &auth0.Connector{}, nil
	case kratos.Name:
		return &kratos.Connector{}, nil
	case keycloak.Name:
		return &keycloak.Connector{}, nil
	case firebase.Name:
		return &firebase.Connector{}, nil
	}
	return nil, fmt.Errorf("unsupported --target %q (supports \"auth0\", \"kratos\", \"keycloak\", and \"firebase\")", name)
}

// exportPass returns the export-side strategies of m (export.user,
// ids.target), nil if it has none. IDs are assigned for m's target.
func exportPass(ctx context.Context, m mapping.Mapping) (*exportpass.Pass, error) {
	if !m.IDs.Target.Assigns() && m.Strategies[strategy.ExportUser].Handler == "" {
		return nil, nil
	}
	d := hooks.FromContext(ctx)
	set, err := strategy.New(strategy.Only(m, strategy.ExportUser), d)
	if err != nil {
		return nil, err
	}
	var a *ids.Assigner
	if m.IDs.Target.Assigns() {
		tc, err := offlineTarget(m.Target)
		if err != nil {
			return nil, fmt.Errorf("mapping: ids.target needs the mapping's target: %w", err)
		}
		if a, err = ids.NewAssigner(m.IDs.Target, tc.Name(), tc.Capabilities(), d); err != nil {
			return nil, err
		}
	}
	return exportpass.New(set, a), nil
}

// rewriteExport rewrites the users file in to out through pass.
func rewriteExport(ctx context.Context, pass *exportpass.Pass, in, out string, newWriter func(io.Writer) *cmf.Writer, manifest *connector.Manifest) error {
	r, closeIn, err := openReader(in)
	if err != nil {
		return err
	}
	defer closeIn()
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	w := newWriter(f)
	if err := pass.Rewrite(ctx, r, w, manifest); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return f.Close()
}

// conflicts applies m's conflict.on_duplicate to an import's report, once
// m is known to suit the target.
func conflicts(m mapping.Mapping, target string, report *connector.ImportReport) error {
	tc, err := offlineTarget(target)
	if err != nil {
		return err
	}
	importprep.Conflicts(m, tc, report)
	return nil
}

// checkImportMapping checks m suits the target an import command runs
// against, before anything is sent (an upsert it can't do, say).
func checkImportMapping(m mapping.Mapping, target string) error {
	tc, err := offlineTarget(target)
	if err != nil {
		return err
	}
	return importprep.Check(m, tc)
}

// addVerifyFlags gives cmd, and its subcommands, the --mapping and --report
// flags of the verify strategies (see verifyOptions).
func addVerifyFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("mapping", "", "mapping.yaml path: its verify.lookup and verify.compare strategies (optional)")
	cmd.PersistentFlags().String("report", "", "import-report.json of the import to verify: its target IDs, for verify.lookup's target_id (optional)")
}

// verifyOptions returns ctx carrying the mapping and import report the
// --mapping and --report flags name, for reconcile.Run.
func verifyOptions(cmd *cobra.Command, ctx context.Context) (context.Context, error) {
	var m mapping.Mapping
	var report *connector.ImportReport
	if p, _ := cmd.Flags().GetString("mapping"); p != "" {
		var err error
		if m, err = mapping.Load(p); err != nil {
			return ctx, err
		}
		if err := strategy.Check(m); err != nil {
			return ctx, err
		}
	}
	if p, _ := cmd.Flags().GetString("report"); p != "" {
		b, err := fsx.ReadFile(p)
		if err != nil {
			return ctx, err
		}
		report = &connector.ImportReport{}
		if err := json.Unmarshal(b, report); err != nil {
			return ctx, fmt.Errorf("reading %s: %w", p, err)
		}
	}
	return reconcile.WithOptions(ctx, reconcile.OptionsFor(m, report)), nil
}
