package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/spf13/cobra"
)

func newJobCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "job",
		Short: "Run export, validate, import, and verify as one resumable job",
	}
	cmd.PersistentFlags().StringVar(&dir, "dir", "./jobs/", "directory the jobs' state is kept in")
	cmd.AddCommand(newJobCreateCmd(&dir), newJobRunCmd(&dir), newJobRetryCmd(&dir), newJobStatusCmd(&dir))
	return cmd
}

func openJobRunner(dir string) (*jobs.Runner, error) {
	store, err := jobs.NewFileStore(dir)
	if err != nil {
		return nil, err
	}
	return &jobs.Runner{Store: store, Steps: jobs.NewSteps(jobConnectors())}, nil
}

func newJobCreateCmd(dir *string) *cobra.Command {
	var (
		source, target, users, mappingPath, connectionID string
		upsert                                           bool
		p                                                = map[string]*string{}
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Queue a job, checking its connectors and credentials first",
		Long: "Queue a job that exports from --source (or starts from an existing --users file), " +
			"validates, imports into --target, and verifies. Credentials are never stored with the job: " +
			"they are read from the environment each time a step runs, so the same variables must be set for `job run`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if connectionID != "" && *p[paramConnection] != "" {
				return fmt.Errorf("--connection-id and --connection are mutually exclusive")
			}
			params := map[string]string{jobs.ParamTarget: target, jobs.ParamUsers: users}
			set := func(k, v string) {
				if v != "" {
					params[k] = v
				}
			}
			set(jobs.ParamSource, source)
			set(jobs.ParamMapping, mappingPath)
			set(jobs.ParamConnectionID, connectionID)
			if upsert {
				params[jobs.ParamUpsert] = "true"
			}
			for k, v := range p {
				set(k, *v)
			}

			// Everything that can be checked without running a step is, so a
			// mistake surfaces now instead of after a long export.
			probe := &jobs.Job{Params: params}
			if source != "" {
				if _, _, err := jobSource(probe); err != nil {
					return err
				}
			}
			if _, err := jobTarget(probe); err != nil {
				return err
			}

			r, err := openJobRunner(*dir)
			if err != nil {
				return err
			}
			j, err := r.Create(params)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), j.ID)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&source, "source", "", "source connector name: flatfile|kratos|keycloak|firebase|auth0 (default: no export, start from the existing --users file)")
	f.StringVar(&target, "target", "", "target connector name: auth0|kratos|keycloak|firebase")
	f.StringVar(&users, "users", "", "CMF users file: written by the export, read by the other steps (.gz is gzipped)")
	f.StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	f.BoolVar(&upsert, "upsert", false, "allow re-running the import against existing users")
	f.StringVar(&connectionID, "connection-id", "", "Auth0 database connection ID")
	strParam := func(key, flag, usage string) {
		p[key] = new(string)
		f.StringVar(p[key], flag, "", usage)
	}
	strParam(paramInput, "in", "input file (flatfile source), or a kc.sh export realm file or directory (keycloak source)")
	strParam(paramFormat, "format", "input format: csv|json (flatfile source; default csv)")
	strParam(paramSourceMapping, "source-mapping", "mapping.yaml path renaming the file's own columns into CMF fields (flatfile source)")
	strParam(paramAdminURL, "admin-url", "Kratos Admin API base URL (or $KRATOS_ADMIN_URL)")
	strParam(paramSchemaID, "schema-id", "Kratos identity schema ID to create identities against (default \"default\")")
	strParam(paramSchemaFile, "schema-file", "Kratos identity schema JSON path, to check traits against (kratos target)")
	strParam(paramConnection, "connection", "Auth0 database connection name (default: the tenant's only database connection)")
	strParam(paramConnectionConfig, "connection-config", "Auth0 connection JSON path, to tighten username/identifier rules (auth0 target)")
	strParam(paramExportConnection, "export-connection-id", "export only the users of this Auth0 connection (auth0 source)")
	strParam(paramExportFields, "export-fields", "export only these Auth0 user attributes, comma-separated (auth0 source)")
	strParam(paramExportLimit, "export-limit", "export at most this many Auth0 users (auth0 source)")
	strParam(paramHashRounds, "hash-rounds", "Firebase project's scrypt rounds (firebase source; default 8)")
	strParam(paramHashMemCost, "hash-mem-cost", "Firebase project's scrypt memory cost (firebase source; default 14)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("users")
	return cmd
}

func newJobRunCmd(dir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "run <id>",
		Short: "Run a job to completion, or resume it where an interrupted run left off",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := openJobRunner(*dir)
			if err != nil {
				return err
			}
			// An interrupt cancels the run instead of killing the process,
			// leaving the job in the state it was interrupted in.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			bar := progress.New(cmd.ErrOrStderr())
			defer bar.Done()
			ctx = progress.NewContext(ctx, bar)
			r.OnState = func(j *jobs.Job) {
				switch {
				case j.State.Terminal():
					bar.Done()
				case j.State != jobs.Queued:
					bar.Stage(string(j.State), 0)
				}
			}

			j, err := r.Run(ctx, args[0])
			bar.Done()
			if j != nil {
				printJob(cmd.OutOrStdout(), j)
			}
			if err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("interrupted: resume with `iamigrate job run %s`", args[0])
				}
				return err
			}
			if j.State == jobs.Failed {
				return fmt.Errorf("job %s failed while %s: %s (fix the cause, then `iamigrate job retry %s` and `iamigrate job run %s`)",
					j.ID, j.FailedIn, j.Error, j.ID, j.ID)
			}
			return nil
		},
	}
}

func newJobRetryCmd(dir *string) *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "retry <id>",
		Short: "Put a failed job back in a state, ready for `job run`",
		Long: "Put a failed job back in the state it failed in, keeping the results of the earlier steps " +
			"and the import's progress. With --from, go back to an earlier state instead, for a failure whose " +
			"cause is upstream (a validation problem that only exporting again fixes); that discards the " +
			"results of the state and of the steps after it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := openJobRunner(*dir)
			if err != nil {
				return err
			}
			j, err := r.Retry(args[0], jobs.State(from))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "job %s: %s\n", j.ID, j.State)
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "state to go back to: exporting|validating|importing|verifying (default: the state the job failed in)")
	return cmd
}

func newJobStatusCmd(dir *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status <id>",
		Short: "Show where a job is and what each finished step found",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := openJobRunner(*dir)
			if err != nil {
				return err
			}
			j, err := r.Store.Load(args[0])
			if err != nil {
				return err
			}
			if asJSON {
				b, err := json.MarshalIndent(j, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			printJob(cmd.OutOrStdout(), j)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the whole job record as JSON")
	return cmd
}

func printJob(w io.Writer, j *jobs.Job) {
	fmt.Fprintf(w, "job %s: %s\n", j.ID, j.State)
	if j.State == jobs.Failed {
		fmt.Fprintf(w, "  failed in %s: %s\n", j.FailedIn, j.Error)
	}
	if j.Manifest != nil {
		fmt.Fprintf(w, "  exported: %d users (%d skipped)\n", j.Manifest.RecordCount, len(j.Manifest.SkippedRecords))
	}
	if len(j.Problems) > 0 {
		fmt.Fprintf(w, "  validate: %d problem(s)\n", len(j.Problems))
		for _, p := range j.Problems {
			fmt.Fprintln(w, "   -", p)
		}
	}
	if j.Report != nil {
		duplicated := 0
		byCode := map[string]int{}
		for _, f := range j.Report.Failed {
			if f.Code == auth0.DuplicatedUserCode {
				duplicated++
			} else {
				byCode[f.Code]++
			}
		}
		fmt.Fprintf(w, "  imported: %d succeeded, %d already exist, %d failed\n",
			len(j.Report.Succeeded), duplicated, len(j.Report.Failed)-duplicated)
		codes := make([]string, 0, len(byCode))
		for c := range byCode {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		for _, c := range codes {
			fmt.Fprintf(w, "   %d failed: %s\n", byCode[c], c)
		}
	} else if n := len(j.Chunks); n > 0 {
		done := 0
		for _, c := range j.Chunks {
			if c.Done {
				done++
			}
		}
		fmt.Fprintf(w, "  import in progress: %d of %d known chunk(s) finished\n", done, n)
	}
	if j.Diff != nil {
		fmt.Fprintf(w, "  verify: %d found of %d, %d missing, %d with drift\n",
			j.Diff.TargetCount, j.Diff.SourceCount, len(j.Diff.MissingInTarget), len(j.Diff.AttributeDrift))
	}
}
