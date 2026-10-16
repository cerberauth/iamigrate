package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/api"
	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, steps jobs.Steps, opts api.Options) (*api.Client, *jobs.Runner) {
	t.Helper()
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	runner := &jobs.Runner{Store: store, Steps: steps}

	ctx, cancel := context.WithCancel(context.Background())
	srv := api.New(ctx, runner, opts)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		cancel()
		srv.Wait()
	})
	return &api.Client{BaseURL: ts.URL}, runner
}

func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var apiErr *api.Error
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, status, apiErr.Status)
}

func TestCreateRunsJobToCompletion(t *testing.T) {
	c, _ := newTestServer(t, jobs.Steps{
		Import: func(_ context.Context, j *jobs.Job) error {
			j.Report = &connector.ImportReport{Succeeded: []string{"u1", "u2"}}
			return nil
		},
	}, api.Options{})
	ctx := context.Background()

	j, err := c.Create(ctx, map[string]string{"users": "u.jsonl"})
	require.NoError(t, err)
	require.NotEmpty(t, j.ID)
	require.Equal(t, map[string]string{"users": "u.jsonl"}, j.Params)

	done, err := c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, done.State)

	report, err := c.Report(ctx, j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, report.State)
	require.Equal(t, []string{"u1", "u2"}, report.Import.Succeeded)
}

func TestFailedJobHasReport(t *testing.T) {
	c, _ := newTestServer(t, jobs.Steps{
		Validate: func(_ context.Context, j *jobs.Job) error {
			j.Problems = []connector.Problem{{SourceID: "u1", Rule: "bad"}}
			return errors.New("validate failed: 1 problem(s) found")
		},
	}, api.Options{})
	ctx := context.Background()

	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)

	report, err := c.Report(ctx, j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, report.State)
	require.Equal(t, jobs.Validating, report.FailedIn)
	require.Contains(t, report.Error, "validate failed")
	require.Len(t, report.Problems, 1)
}

func TestReportConflictWhileRunning(t *testing.T) {
	release := make(chan struct{})
	c, _ := newTestServer(t, jobs.Steps{
		Import: func(ctx context.Context, _ *jobs.Job) error {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		},
	}, api.Options{})
	ctx := context.Background()

	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	_, err = c.Report(ctx, j.ID)
	requireStatus(t, err, http.StatusConflict)

	close(release)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	_, err = c.Report(ctx, j.ID)
	require.NoError(t, err)
}

func TestUnknownAndInvalidIDsAreNotFound(t *testing.T) {
	c, _ := newTestServer(t, jobs.Steps{}, api.Options{})
	ctx := context.Background()

	for _, id := range []string{"0123456789abcdef", "bad.id"} {
		_, err := c.Get(ctx, id)
		requireStatus(t, err, http.StatusNotFound)
		_, err = c.Report(ctx, id)
		requireStatus(t, err, http.StatusNotFound)
	}
}

func TestCreateRejectsInvalidParams(t *testing.T) {
	c, runner := newTestServer(t, jobs.Steps{}, api.Options{
		Validate: func(p map[string]string) error {
			if p["target"] == "" {
				return errors.New(`param "target" is required`)
			}
			return nil
		},
	})

	_, err := c.Create(context.Background(), map[string]string{"users": "u"})
	requireStatus(t, err, http.StatusBadRequest)
	require.ErrorContains(t, err, `param "target" is required`)
	_, err = runner.Store.Load("anything")
	require.Error(t, err)
}

func TestCreateRejectsMalformedBody(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	srv := api.New(context.Background(), &jobs.Runner{Store: store}, api.Options{})
	h := srv.Handler()

	for _, body := range []string{`not json`, `{"params":{"a":1}}`, `{"unknown":{}}`} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/jobs", stringsReader(body)))
		require.Equal(t, http.StatusBadRequest, rec.Code, body)
	}
}

func TestBearerToken(t *testing.T) {
	c, _ := newTestServer(t, jobs.Steps{}, api.Options{Token: "s3cret"})
	ctx := context.Background()

	_, err := c.Create(ctx, nil)
	requireStatus(t, err, http.StatusUnauthorized)

	c.Token = "wrong"
	_, err = c.Get(ctx, "0123456789abcdef")
	requireStatus(t, err, http.StatusUnauthorized)

	c.Token = "s3cret"
	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
}

func TestShutdownInterruptsRunAndLeavesJobResumable(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	started := make(chan struct{})
	runner := &jobs.Runner{Store: store, Steps: jobs.Steps{
		Import: func(ctx context.Context, _ *jobs.Job) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	srv := api.New(ctx, runner, api.Options{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := &api.Client{BaseURL: ts.URL}

	j, err := c.Create(context.Background(), nil)
	require.NoError(t, err)
	<-started
	cancel()
	srv.Wait()

	got, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Importing, got.State)
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

func TestRetryRunsAFailedJobAgain(t *testing.T) {
	fail := true
	c, _ := newTestServer(t, jobs.Steps{
		Import: func(_ context.Context, j *jobs.Job) error {
			if fail {
				return errors.New("boom")
			}
			j.Report = &connector.ImportReport{Succeeded: []string{"u1"}}
			return nil
		},
	}, api.Options{})
	ctx := context.Background()

	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	failed, err := c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, failed.State)

	fail = false
	retried, err := c.Retry(ctx, j.ID, "")
	require.NoError(t, err)
	require.Equal(t, jobs.Importing, retried.State)

	done, err := c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, done.State)
	require.Empty(t, done.Error)
}

func TestRetryFromAnEarlierState(t *testing.T) {
	var exports int
	fail := true
	c, _ := newTestServer(t, jobs.Steps{
		Export: func(_ context.Context, _ *jobs.Job) error { exports++; return nil },
		Import: func(_ context.Context, _ *jobs.Job) error {
			if fail {
				return errors.New("boom")
			}
			return nil
		},
	}, api.Options{})
	ctx := context.Background()

	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)

	fail = false
	retried, err := c.Retry(ctx, j.ID, jobs.Exporting)
	require.NoError(t, err)
	require.Equal(t, jobs.Exporting, retried.State)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	require.Equal(t, 2, exports)
}

func TestRetryRejections(t *testing.T) {
	c, runner := newTestServer(t, jobs.Steps{
		Import: func(_ context.Context, _ *jobs.Job) error { return errors.New("boom") },
	}, api.Options{})
	ctx := context.Background()

	_, err := c.Retry(ctx, "0123456789abcdef", "")
	requireStatus(t, err, http.StatusNotFound)

	// A job that hasn't failed can't be retried.
	queued, err := runner.Create(nil)
	require.NoError(t, err)
	_, err = c.Retry(ctx, queued.ID, "")
	requireStatus(t, err, http.StatusConflict)

	// A failed job can't go back to a state after the one it failed in.
	j, err := c.Create(ctx, nil)
	require.NoError(t, err)
	_, err = c.Wait(ctx, j.ID, 5*time.Millisecond, nil)
	require.NoError(t, err)
	_, err = c.Retry(ctx, j.ID, jobs.Verifying)
	requireStatus(t, err, http.StatusBadRequest)
	_, err = c.Retry(ctx, j.ID, "nonsense")
	requireStatus(t, err, http.StatusBadRequest)
}

func TestRetryBodyIsOptional(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	runner := &jobs.Runner{Store: store, Steps: jobs.Steps{
		Import: func(_ context.Context, _ *jobs.Job) error { return errors.New("boom") },
	}}
	j, err := runner.Create(nil)
	require.NoError(t, err)
	_, err = runner.Run(context.Background(), j.ID)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	srv := api.New(ctx, runner, api.Options{})
	defer func() { cancel(); srv.Wait() }()

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/jobs/"+j.ID+"/retry", nil))
	require.Equal(t, http.StatusAccepted, rec.Code)
}

func TestResumeRunsUnfinishedJobsOnly(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	var imports sync.Map
	runner := &jobs.Runner{Store: store, Steps: jobs.Steps{
		Import: func(_ context.Context, j *jobs.Job) error { imports.Store(j.ID, true); return nil },
	}}

	queued, err := runner.Create(nil)
	require.NoError(t, err)
	interrupted, err := runner.Create(nil)
	require.NoError(t, err)
	interrupted.State = jobs.Importing
	require.NoError(t, store.Save(interrupted))
	finished, err := runner.Create(nil)
	require.NoError(t, err)
	_, err = runner.Run(context.Background(), finished.ID)
	require.NoError(t, err)
	imports.Delete(finished.ID)

	srv := api.New(context.Background(), runner, api.Options{})
	n, err := srv.Resume()
	require.NoError(t, err)
	require.Equal(t, 2, n)
	srv.Wait()

	for _, id := range []string{queued.ID, interrupted.ID} {
		j, err := store.Load(id)
		require.NoError(t, err)
		require.Equal(t, jobs.Done, j.State, id)
	}
	_, reran := imports.Load(finished.ID)
	require.False(t, reran)
}
