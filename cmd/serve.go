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
	"github.com/spf13/cobra"
)

// shutdownTimeout is how long `serve` lets in-flight requests finish once
// it's asked to stop.
const shutdownTimeout = 10 * time.Second

func newServeCmd() *cobra.Command {
	var listen, dir, hooksPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve jobs over a REST API",
		Long: "Serve the jobs of `iamigrate job` over HTTP: POST /jobs queues a job and starts running it, " +
			"GET /jobs/{id} shows it, and GET /jobs/{id}/report shows what its finished steps found. " +
			"Drive it with `iamigrate job --api-url`. " +
			"A job's connectors read their credentials from the environment of this process, and its file paths " +
			"are paths on this machine. Set $" + envAPIToken + " to require it as a bearer token; " +
			"without it only a loopback --listen address is accepted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv(envAPIToken)
			if token == "" && !isLoopback(listen) {
				return fmt.Errorf("--listen %s is not a loopback address: set $%s to require a bearer token", listen, envAPIToken)
			}
			runner, err := openJobRunner(dir)
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

			srv := api.New(ctx, runner, api.Options{Validate: checkJobParams, Token: token})
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

			select {
			case err := <-serveErr:
				stop()
				srv.Wait()
				return err
			case <-ctx.Done():
			}
			shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			err = httpSrv.Shutdown(shutCtx)
			srv.Wait()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "address to listen on")
	cmd.Flags().StringVar(&dir, "dir", "./jobs/", "directory the jobs' state is kept in")
	cmd.Flags().StringVar(&hooksPath, "hooks", "", "hooks.yaml path: the hooks every job fires, and the handlers job mappings can delegate strategies to")
	return cmd
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
