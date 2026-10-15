package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cerberauth/iamigrate/internal/api"
	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/progress"
	"github.com/spf13/cobra"
)

// Environment variables the job commands read when --api-url is used, and
// `serve` reads for the token it requires.
const (
	envAPIURL   = "IAMIGRATE_API_URL"
	envAPIToken = "IAMIGRATE_API_TOKEN"
)

// pollInterval is how often `job run --api-url` asks the server how the job
// is doing.
const pollInterval = time.Second

// jobFlags say which jobs the job commands act on: the jobs kept in dir and run in process, or
// those of the `iamigrate serve` instance at apiURL.
type jobFlags struct {
	dir, apiURL string
}

// client returns the client of the server --api-url names, or nil if the
// jobs are the local ones.
func (f *jobFlags) client() *api.Client {
	if f.apiURL == "" {
		return nil
	}
	return &api.Client{BaseURL: f.apiURL, Token: os.Getenv(envAPIToken)}
}

func (f *jobFlags) runner() (*jobs.Runner, error) {
	return openJobRunner(f.dir)
}

func newJobCmd() *cobra.Command {
	var f jobFlags

	cmd := &cobra.Command{
		Use:   "job",
		Short: "Run export, validate, import, and verify as one resumable job",
	}
	cmd.PersistentFlags().StringVar(&f.dir, "dir", "./jobs/", "directory the jobs' state is kept in")
	cmd.PersistentFlags().StringVar(&f.apiURL, "api-url", os.Getenv(envAPIURL),
		"drive the jobs of a running `iamigrate serve` at this URL instead of running them in process (or $"+envAPIURL+"; its bearer token is $"+envAPIToken+")")
	cmd.AddCommand(newJobCreateCmd(&f), newJobRunCmd(&f), newJobRetryCmd(&f), newJobStatusCmd(&f), newJobReportCmd(&f))
	return cmd
}

func openJobRunner(dir string) (*jobs.Runner, error) {
	store, err := jobs.NewFileStore(dir)
	if err != nil {
		return nil, err
	}
	return &jobs.Runner{Store: store, Steps: jobs.NewSteps(jobConnectors())}, nil
}

// checkJobParams checks everything about a new job that can be checked
// without running a step, so a mistake surfaces now instead of after a long
// export.
func checkJobParams(params map[string]string) error {
	probe := &jobs.Job{Params: params}
	if params[jobs.ParamSource] != "" {
		if _, _, err := jobSource(probe); err != nil {
			return err
		}
	}
	_, err := jobTarget(probe)
	return err
}

func newJobCreateCmd(f *jobFlags) *cobra.Command {
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

			// A server checks the params itself, against its own
			// environment, and starts the job as soon as it's queued.
			if c := f.client(); c != nil {
				j, err := c.Create(cmd.Context(), params)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), j.ID)
				return nil
			}

			if err := checkJobParams(params); err != nil {
				return err
			}
			r, err := f.runner()
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

	fl := cmd.Flags()
	fl.StringVar(&source, "source", "", "source connector name: flatfile|kratos|keycloak|firebase|auth0 (default: no export, start from the existing --users file)")
	fl.StringVar(&target, "target", "", "target connector name: auth0|kratos|keycloak|firebase")
	fl.StringVar(&users, "users", "", "CMF users file: written by the export, read by the other steps (.gz is gzipped)")
	fl.StringVar(&mappingPath, "mapping", "", "mapping.yaml path (optional)")
	fl.BoolVar(&upsert, "upsert", false, "allow re-running the import against existing users")
	fl.StringVar(&connectionID, "connection-id", "", "Auth0 database connection ID")
	strParam := func(key, flag, usage string) {
		p[key] = new(string)
		fl.StringVar(p[key], flag, "", usage)
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

func newJobRunCmd(f *jobFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "run <id>",
		Short: "Run a job to completion, or resume it where an interrupted run left off",
		Long: "Run a job to completion, or resume it where an interrupted run left off. " +
			"With --api-url the server runs its jobs on its own as soon as they are created: " +
			"this only waits for the job to finish, and interrupting it leaves the job running.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			// An interrupt cancels the run instead of killing the process,
			// leaving the job in the state it was interrupted in.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			bar := progress.New(cmd.ErrOrStderr())
			defer bar.Done()
			ctx = progress.NewContext(ctx, bar)
			stage := func(j *jobs.Job) {
				switch {
				case j.State.Terminal():
					bar.Done()
				case j.State != jobs.Queued:
					bar.Stage(string(j.State), 0)
				}
			}

			var (
				j   *jobs.Job
				err error
			)
			if c := f.client(); c != nil {
				last := jobs.State("")
				j, err = c.Wait(ctx, id, pollInterval, func(j *jobs.Job) {
					if j.State != last {
						last = j.State
						stage(j)
					}
				})
			} else {
				var r *jobs.Runner
				if r, err = f.runner(); err != nil {
					return err
				}
				r.OnState = stage
				j, err = r.Run(ctx, id)
			}
			bar.Done()
			if j != nil {
				printJob(cmd.OutOrStdout(), j)
			}
			if err != nil {
				if ctx.Err() != nil {
					if f.client() != nil {
						return fmt.Errorf("interrupted: the job keeps running on the server; wait for it with `iamigrate job run %s`", id)
					}
					return fmt.Errorf("interrupted: resume with `iamigrate job run %s`", id)
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

func newJobRetryCmd(f *jobFlags) *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "retry <id>",
		Short: "Put a failed job back in a state, ready for `job run`",
		Long: "Put a failed job back in the state it failed in, keeping the results of the earlier steps " +
			"and the import's progress. With --from, go back to an earlier state instead, for a failure whose " +
			"cause is upstream (a validation problem that only exporting again fixes); that discards the " +
			"results of the state and of the steps after it. Not available with --api-url.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var j *jobs.Job
			if c := f.client(); c != nil {
				// The server runs the job again as soon as it's put back.
				var err error
				if j, err = c.Retry(cmd.Context(), args[0], jobs.State(from)); err != nil {
					return err
				}
			} else {
				r, err := f.runner()
				if err != nil {
					return err
				}
				if j, err = r.Retry(args[0], jobs.State(from)); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "job %s: %s\n", j.ID, j.State)
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "state to go back to: exporting|validating|importing|verifying (default: the state the job failed in)")
	return cmd
}

// loadJob reads a job from the server --api-url names, or from the jobs
// directory.
func (f *jobFlags) loadJob(ctx context.Context, id string) (*jobs.Job, error) {
	if c := f.client(); c != nil {
		return c.Get(ctx, id)
	}
	r, err := f.runner()
	if err != nil {
		return nil, err
	}
	return r.Store.Load(id)
}

func newJobStatusCmd(f *jobFlags) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status <id>",
		Short: "Show where a job is and what each finished step found",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := f.loadJob(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), j)
			}
			printJob(cmd.OutOrStdout(), j)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the whole job record as JSON")
	return cmd
}

func newJobReportCmd(f *jobFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "report <id>",
		Short: "Print what a finished job's steps found, as JSON",
		Long: "Print the manifest, validation problems, import report and verification of a job that is done " +
			"or failed, as JSON: what `GET /jobs/{id}/report` answers. Fails for a job that is still running.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if c := f.client(); c != nil {
				r, err := c.Report(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(cmd.OutOrStdout(), r)
			}
			j, err := f.loadJob(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !j.State.Terminal() {
				return fmt.Errorf("job %s is still %s", j.ID, j.State)
			}
			return printJSON(cmd.OutOrStdout(), api.NewReport(j))
		},
	}
}

func printJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(b))
	return nil
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
