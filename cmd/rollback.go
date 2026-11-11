package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/x/fsx"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Delete the users of a CMF file from a target",
		Long: "Delete from a target the users of a CMF file, each one alone: by the ID the import gave it, " +
			"else by looking it up by identifier. Nothing else is deleted. With --report, only the users " +
			"that import created are.",
	}
	cmd.AddCommand(newRollbackAuth0Cmd())
	cmd.AddCommand(newRollbackKratosCmd())
	return cmd
}

// rollbackFlags are the flags every rollback subcommand shares.
type rollbackFlags struct {
	in         string
	importPath string
	out        string
	dryRun     bool
	yes        bool
}

func (f *rollbackFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.in, "in", "", "CMF users.cmf.jsonl[.gz] path (gzip detected automatically)")
	cmd.Flags().StringVar(&f.importPath, "report", "", "import-report.json of the import to undo: only its succeeded users are deleted, by the target IDs it recorded (optional)")
	cmd.Flags().StringVar(&f.out, "out", "", "rollback-report.json output path (default: alongside --in)")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "list the users that would be deleted, without deleting them")
	cmd.Flags().BoolVarP(&f.yes, "yes", "y", false, "delete without asking for confirmation (required when not run interactively)")
	_ = cmd.MarkFlagRequired("in")
}

func newRollbackAuth0Cmd() *cobra.Command {
	var (
		flags rollbackFlags
		auth  auth0Flags
	)
	cmd := &cobra.Command{
		Use:   auth0.Name,
		Short: "Delete the users of a CMF file from an Auth0 tenant (needs the read:users and delete:users scopes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := auth.client()
			if err != nil {
				return err
			}
			return runRollback(cmd, flags, auth0.Name, auth0.New(client))
		},
	}
	flags.register(cmd)
	auth.register(cmd)
	return cmd
}

func newRollbackKratosCmd() *cobra.Command {
	var (
		flags    rollbackFlags
		adminURL string
	)
	cmd := &cobra.Command{
		Use:   kratos.Name,
		Short: "Delete the users of a CMF file from an Ory Kratos instance via the Admin API",
		RunE: func(cmd *cobra.Command, args []string) error {
			adminURL = flagOrEnv(adminURL, "KRATOS_ADMIN_URL")
			if adminURL == "" {
				return fmt.Errorf("--admin-url (or $KRATOS_ADMIN_URL) is required")
			}
			return runRollback(cmd, flags, kratos.Name, kratos.New(kratos.NewClient(adminURL), ""))
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&adminURL, "admin-url", "", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL)")
	return cmd
}

func runRollback(cmd *cobra.Command, flags rollbackFlags, target string, deleter connector.Deleter) error {
	var importReport *connector.ImportReport
	if flags.importPath != "" {
		b, err := os.ReadFile(flags.importPath)
		if err != nil {
			return err
		}
		importReport = &connector.ImportReport{}
		if err := json.Unmarshal(b, importReport); err != nil {
			return fmt.Errorf("reading %s: %w", flags.importPath, err)
		}
	}
	reqs, err := rollbackRequests(flags.in, importReport)
	if err != nil {
		return err
	}

	if !flags.dryRun && !flags.yes && len(reqs) > 0 {
		if err := confirmRollback(cmd, len(reqs), target); err != nil {
			return err
		}
	}

	ctx, bar := startProgress(cmd)
	defer bar.Done()
	stage := "deleting users"
	if flags.dryRun {
		stage = "looking up users"
	}
	bar.Stage(stage, len(reqs))
	report, err := deleter.DeleteUsers(ctx, reqs, flags.dryRun)
	bar.Done()
	if err != nil {
		return err
	}

	if report.Deleted == nil {
		report.Deleted = []connector.DeletedUser{}
	}
	if report.NotFound == nil {
		report.NotFound = []string{}
	}
	if report.Failed == nil {
		report.Failed = []connector.ImportError{}
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	out := flags.out
	if out == "" {
		out = filepath.Join(filepath.Dir(flags.in), "rollback-report.json")
	}
	if err := fsx.WriteFile(out, b, 0o600); err != nil {
		return err
	}
	printRollbackSummary(cmd.OutOrStdout(), report, out)
	return nil
}

// rollbackRequests reads the users of the CMF file at in, keeping only
// those importReport (when set) succeeded with, along with the target ID it
// recorded for them.
func rollbackRequests(in string, importReport *connector.ImportReport) ([]connector.DeleteRequest, error) {
	r, closeFn, err := openReader(in)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	var succeeded map[string]bool
	if importReport != nil {
		succeeded = make(map[string]bool, len(importReport.Succeeded))
		for _, id := range importReport.Succeeded {
			succeeded[id] = true
		}
	}
	var reqs []connector.DeleteRequest
	for {
		u, err := r.ReadUser()
		if errors.Is(err, io.EOF) {
			return reqs, nil
		}
		if err != nil {
			return nil, err
		}
		req := connector.DeleteRequest{User: u}
		if importReport != nil {
			if !succeeded[u.SourceID] {
				continue
			}
			req.TargetID = importReport.TargetIDs[u.SourceID]
		}
		reqs = append(reqs, req)
	}
}

// errNotConfirmed is returned when the user declines the confirmation.
var errNotConfirmed = errors.New("rollback cancelled")

// confirmRollback asks on the terminal before deleting n users, and refuses
// to go on when there is no terminal to ask on.
func confirmRollback(cmd *cobra.Command, n int, target string) error {
	in := cmd.InOrStdin()
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // fd fits in int
		return fmt.Errorf("refusing to delete up to %d users from %s without confirmation: pass --yes, or --dry-run to only list them", n, target)
	}
	return askConfirmation(in, cmd.ErrOrStderr(), n, target)
}

func askConfirmation(in io.Reader, out io.Writer, n int, target string) error {
	fmt.Fprintf(out, "Delete up to %d users from %s? This cannot be undone. Type \"yes\" to go on: ", n, target)
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(answer) != "yes" {
		return errNotConfirmed
	}
	return nil
}

func printRollbackSummary(w io.Writer, report connector.RollbackReport, reportPath string) {
	verb := "deleted"
	if report.DryRun {
		verb = "would delete"
	}
	fmt.Fprintf(w, "rollback: %s %d, not found %d, failed %d -> report %s\n",
		verb, len(report.Deleted), len(report.NotFound), len(report.Failed), reportPath)
	if report.DryRun {
		for _, d := range report.Deleted {
			fmt.Fprintf(w, "  would delete: %s (%s)\n", d.SourceID, d.TargetID)
		}
	}
	if n := len(report.NoIdentifier); n > 0 {
		fmt.Fprintf(w, "  %d with no identifier to look them up by\n", n)
	}
}
