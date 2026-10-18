// Package api exposes the jobs of package jobs over HTTP, for `iamigrate
// serve`, and the client `iamigrate --api-url` drives it with.
//
// The endpoints are thin wrappers over jobs.Runner, so a job behaves the
// same whether the CLI runs it in process or a server does:
//
//	POST /jobs               queue a job and start running it in the background
//	GET  /jobs/{id}          the job record
//	GET  /jobs/{id}/report   what the finished steps found
//	POST /jobs/{id}/retry    put a failed job back in a state and run it again
//
// Credentials are never part of a request. As with `iamigrate job`, the
// steps read them from the environment of the process that runs them, which
// here is the server.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
)

// maxBodyBytes caps a request body; a job's params are a handful of strings.
const maxBodyBytes = 1 << 20

// CreateRequest is the body of POST /jobs.
type CreateRequest struct {
	// Params are the job's params, the same keys `iamigrate job create`
	// sets from its flags.
	Params map[string]string `json:"params"`
}

// RetryRequest is the optional body of POST /jobs/{id}/retry.
type RetryRequest struct {
	// From is the state to go back to: the one the job failed in if empty.
	From jobs.State `json:"from,omitempty"`
}

// Report is the body of GET /jobs/{id}/report: the results of the steps a
// job has finished, without the params and chunk checkpoints that make up
// the rest of its record.
type Report struct {
	ID       string     `json:"id"`
	State    jobs.State `json:"state"`
	Error    string     `json:"error,omitempty"`
	FailedIn jobs.State `json:"failed_in,omitempty"`

	Manifest *connector.Manifest     `json:"manifest,omitempty"`
	Problems []connector.Problem     `json:"problems,omitempty"`
	Warnings []connector.Problem     `json:"warnings,omitempty"`
	Import   *connector.ImportReport `json:"import,omitempty"`
	Verify   *connector.DiffReport   `json:"verify,omitempty"`
	Hooks    []hooks.Result          `json:"hooks,omitempty"`
}

// ErrorResponse is the body of every error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Options configures a Server.
type Options struct {
	// Validate, if set, checks a new job's params before it is queued, so a
	// mistake is a 400 instead of a job that fails. Its error is returned
	// to the client.
	Validate func(params map[string]string) error

	// Token, if set, is the bearer token every request must carry.
	Token string

	// Logger receives the errors a background run ends with; slog's default
	// if nil.
	Logger *slog.Logger
}

// Server serves jobs over HTTP and runs them in the background.
type Server struct {
	runner *jobs.Runner
	opts   Options
	log    *slog.Logger

	// ctx is what background runs are bound to: cancelling it interrupts
	// them, leaving their jobs in the state they were in, to be resumed.
	ctx context.Context
	wg  sync.WaitGroup
}

// New returns a Server driving jobs with runner. Background runs stop when
// ctx is cancelled.
func New(ctx context.Context, runner *jobs.Runner, opts Options) *Server {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{runner: runner, opts: opts, log: log, ctx: ctx}
}

// Wait blocks until the background runs have returned, which they do soon
// after the context given to New is cancelled.
func (s *Server) Wait() { s.wg.Wait() }

// Resume starts running every job found unfinished in the store, the ones a
// crash or a restart of the server interrupted, and returns how many it
// started. A job another process is running is left to it.
func (s *Server) Resume() (int, error) {
	ids, err := s.runner.Store.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		j, err := s.runner.Store.Load(id)
		if err != nil {
			s.log.Error("job not resumed", "job", id, "error", err)
			continue
		}
		if !j.State.Terminal() {
			s.start(id)
			n++
		}
	}
	return n, nil
}

// Handler returns the HTTP handler of the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", s.create)
	mux.HandleFunc("GET /jobs/{id}", s.get)
	mux.HandleFunc("GET /jobs/{id}/report", s.report)
	mux.HandleFunc("POST /jobs/{id}/retry", s.retry)
	return s.authenticate(mux)
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	if s.opts.Token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, errors.New("missing or invalid bearer token"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.opts.Validate != nil {
		if err := s.opts.Validate(req.Params); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	j, err := s.runner.Create(req.Params)
	if err != nil {
		s.fail(w, err)
		return
	}

	s.start(j.ID)

	w.Header().Set("Location", "/jobs/"+j.ID)
	writeJSON(w, http.StatusAccepted, j)
}

// start runs the job id in the background.
func (s *Server) start(id string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// A step's failure is the job's outcome, recorded on it; what Run
		// returns is only that it couldn't carry on.
		if _, err := s.runner.Run(s.ctx, id); err != nil && s.ctx.Err() == nil {
			s.log.Error("job run failed", "job", id, "error", err)
		}
	}()
}

func (s *Server) retry(w http.ResponseWriter, r *http.Request) {
	var req RetryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	// The body is optional.
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	j, err := s.runner.Retry(r.PathValue("id"), req.From)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.start(j.ID)
	writeJSON(w, http.StatusAccepted, j)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Store.Load(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	j, err := s.runner.Store.Load(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if !j.State.Terminal() {
		writeError(w, http.StatusConflict, errors.New("job "+j.ID+" is still "+string(j.State)))
		return
	}
	writeJSON(w, http.StatusOK, NewReport(j))
}

// NewReport returns the report of j.
func NewReport(j *jobs.Job) Report {
	return Report{
		ID: j.ID, State: j.State, Error: j.Error, FailedIn: j.FailedIn,
		Manifest: j.Manifest, Problems: j.Problems, Warnings: j.Warnings, Import: j.Report, Verify: j.Diff,
		Hooks: j.Hooks,
	}
}

// fail answers with the status err calls for.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrInvalidID):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, jobs.ErrNotFailed), errors.Is(err, jobs.ErrLocked):
		writeError(w, http.StatusConflict, err)
	case errors.As(err, new(*jobs.TransitionError)):
		writeError(w, http.StatusBadRequest, err)
	default:
		s.log.Error("request failed", "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("internal error"))
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
