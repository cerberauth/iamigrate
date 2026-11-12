package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cerberauth/iamigrate/internal/api"
	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/azblobstore"
	"github.com/cerberauth/iamigrate/internal/jobs/gcsstore"
	"github.com/cerberauth/iamigrate/internal/jobs/s3store"
	"github.com/cerberauth/iamigrate/internal/watch"
	"github.com/spf13/cobra"
)

// shutdownTimeout is how long `serve` lets in-flight requests finish once
// it's asked to stop.
const shutdownTimeout = 10 * time.Second

func newServeCmd() *cobra.Command {
	var (
		listen, store, hooksPath, watchPath string
		rescan                              time.Duration
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve jobs over a REST API",
		Long: "Serve the jobs of `iamigrate job` over HTTP: POST /jobs queues a job and starts running it, " +
			"GET /jobs/{id} shows it, and GET /jobs/{id}/report shows what its finished steps found. " +
			"Drive it with `iamigrate job --api-url`. " +
			"A job's connectors read their credentials from the environment of this process, and its file paths " +
			"are paths on this machine. Set $" + envAPIToken + " to require it as a bearer token; " +
			"without it only a loopback --listen address is accepted. " +
			"With --watch, jobs also start on their own, from a template, for each new object in a bucket.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv(envAPIToken)
			if token == "" && !isLoopback(listen) {
				return fmt.Errorf("--listen %s is not a loopback address: set $%s to require a bearer token", listen, envAPIToken)
			}
			runner, err := openJobRunner(store)
			if err != nil {
				return err
			}
			// Hooks come only from this flag: a job's params, which API
			// clients send, can't add one or change where it points.
			if runner.Hooks, err = loadHooks(hooksPath); err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}

			// An interrupt stops the server and cancels the running jobs,
			// which stay in the state they were in; the next `serve` resumes them.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			opts := api.Options{Validate: checkJobParams, Token: token}
			var srv *api.Server
			var watchers *watch.Set
			if watchPath != "" {
				cfg, templates, err := watch.LoadConfig(watchPath)
				if err != nil {
					return err
				}
				watchers, err = watch.Open(ctx, cfg, templates, watch.Options{
					Runner:   runner,
					Start:    func(id string) bool { return srv.Start(id) },
					Validate: checkJobParams,
					Buckets:  watchBuckets,
				})
				if err != nil {
					_ = ln.Close()
					return err
				}
				opts.Watchers = watchers.Status
			}
			srv = api.New(ctx, runner, opts)
			httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
			serveErr := make(chan error, 1)
			go func() { serveErr <- httpSrv.Serve(ln) }()
			fmt.Fprintf(cmd.OutOrStdout(), "listening on http://%s\n", ln.Addr())
			// Jobs a crash or an earlier shutdown interrupted carry on.
			if n, err := srv.Resume(); err != nil {
				_ = httpSrv.Close()
				srv.Wait()
				return err
			} else if n > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "resuming %d unfinished job(s)\n", n)
			}
			if rescan > 0 {
				srv.Rescan(rescan)
			}
			if watchers != nil {
				watchers.Run(ctx)
			}
			// The watchers start jobs: they stop before the server waits
			// for its jobs.
			wait := func() {
				if watchers != nil {
					watchers.Wait()
				}
				srv.Wait()
			}

			select {
			case err := <-serveErr:
				stop()
				wait()
				return err
			case <-ctx.Done():
			}
			shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			err = httpSrv.Shutdown(shutCtx)
			wait()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "address to listen on")
	addStoreFlag(cmd.Flags(), &store)
	cmd.Flags().DurationVar(&rescan, "rescan", 30*time.Second,
		"how often to look for unfinished jobs nobody runs, such as those of a replica that stopped (0 to only look at start)")
	cmd.Flags().StringVar(&watchPath, "watch", "", "watchers.yaml path: watchers that start a job from a template for each new object in a bucket")
	cmd.Flags().StringVar(&hooksPath, "hooks", "", "hooks.yaml path: the hooks every job fires, and the handlers job mappings can delegate strategies to")
	return cmd
}

// watchBuckets open the buckets --watch watchers list, read-only.
var watchBuckets = map[string]jobs.BucketOpener{
	s3store.Scheme:     s3store.OpenReadOnly,
	gcsstore.Scheme:    gcsstore.Open,
	azblobstore.Scheme: azblobstore.Open,
}

// isLoopback reports whether addr, a host:port, only accepts connections
// from the machine itself.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
