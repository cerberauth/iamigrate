package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

const allEvents = `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: JOBS_EVENTS_SECRET, retries: 0}}}
events:
  job.before_run: {handler: rx}
  state.enter: {handler: rx}
  state.exit: {handler: rx}
  job.done: {handler: rx}
  job.failed: {handler: rx}
`

// eventLog is a webhook receiver noting "hook@state" of every event, and
// answering each with answer.
type eventLog struct {
	mu     sync.Mutex
	got    []string
	ids    []string
	answer func(hook, state string) (int, string)
}

func newEventRunner(t *testing.T, steps jobs.Steps, yaml string, answer func(hook, state string) (int, string)) (*jobs.Runner, *eventLog) {
	t.Helper()
	log := &eventLog{answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env struct{ Hook, State, Event_ID string }
		var raw map[string]any
		require.NoError(t, json.Unmarshal(b, &raw))
		require.NoError(t, json.Unmarshal(b, &env))
		log.mu.Lock()
		log.got = append(log.got, env.Hook+"@"+env.State)
		log.ids = append(log.ids, raw["event_id"].(string))
		log.mu.Unlock()
		status, body := 200, ""
		if log.answer != nil {
			status, body = log.answer(env.Hook, env.State)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("JOBS_EVENTS_SECRET", "s")
	cfg, err := hooks.Parse([]byte(strings.ReplaceAll(yaml, "URL", srv.URL)))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	r, _ := newRunner(t, steps)
	r.Hooks = d
	return r, log
}

func ok(context.Context, *jobs.Job) error { return nil }

func TestRunFiresJobAndStateEventsInOrder(t *testing.T) {
	r, log := newEventRunner(t, jobs.Steps{Export: ok, Import: ok}, allEvents, nil)
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []string{
		"job.before_run@queued",
		"state.enter@queued", "state.exit@queued",
		"state.enter@exporting", "state.exit@exporting",
		"state.enter@validating", "state.exit@validating",
		"state.enter@importing", "state.exit@importing",
		"state.enter@verifying", "state.exit@verifying",
		"job.done@done",
	}, log.got)
	require.Empty(t, j.Hooks)
}

func TestJobBeforeRunVetoFailsTheJob(t *testing.T) {
	ran := false
	r, log := newEventRunner(t, jobs.Steps{Export: func(context.Context, *jobs.Job) error { ran = true; return nil }}, allEvents,
		func(hook, _ string) (int, string) {
			if hook == hooks.JobBeforeRun {
				return 200, `{"allow": false, "reason": "change freeze"}`
			}
			return 200, ""
		})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.False(t, ran)
	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Queued, j.FailedIn)
	require.Equal(t, "hook job.before_run vetoed: change freeze", j.Error)
	require.Equal(t, []string{"job.before_run@queued", "job.failed@failed"}, log.got)
	require.Len(t, j.Hooks, 1)
	require.Equal(t, hooks.Vetoed, j.Hooks[0].Outcome)

	stored, err := r.Store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, j.Hooks, stored.Hooks, "hook results are persisted")
}

func TestStepFailureFiresJobFailedButNotStateExit(t *testing.T) {
	r, log := newEventRunner(t, jobs.Steps{Import: func(context.Context, *jobs.Job) error { return errors.New("boom") }}, allEvents, nil)
	j, err := r.Create(nil)
	require.NoError(t, err)
	_, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"state.enter@importing", "job.failed@failed"}, log.got[len(log.got)-2:])
}

func TestFailingStateEventFailsTheJobOnlyWhenAskedTo(t *testing.T) {
	failEnter := func(hook, state string) (int, string) {
		if hook == hooks.StateEnter && state == "importing" {
			return 500, "down"
		}
		return 200, ""
	}
	r, _ := newEventRunner(t, jobs.Steps{}, allEvents, failEnter)
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State, "a notify event ignores failures by default")
	require.Len(t, j.Hooks, 1)
	require.Equal(t, hooks.Ignored, j.Hooks[0].Outcome)
	require.Equal(t, "importing", j.Hooks[0].State)

	r, _ = newEventRunner(t, jobs.Steps{}, strings.Replace(allEvents, "state.enter: {handler: rx}", "state.enter: {handler: rx, on_failure: fail}", 1), failEnter)
	j, err = r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Importing, j.FailedIn)
	require.Contains(t, j.Error, "hook state.enter: webhook answered 500: down")
}

func TestResumeRefiresEventsWithTheSameIDs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	crash := true
	r, log := newEventRunner(t, jobs.Steps{Import: func(context.Context, *jobs.Job) error {
		if crash {
			crash = false
			cancel()
		}
		return nil
	}}, allEvents, nil)
	j, err := r.Create(nil)
	require.NoError(t, err)
	_, err = r.Run(ctx, j.ID)
	require.ErrorIs(t, err, context.Canceled)
	first := len(log.got)
	require.Equal(t, "state.enter@importing", log.got[first-1])

	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []string{"job.before_run@importing", "state.enter@importing"}, log.got[first:first+2])
	require.Equal(t, log.ids[first-1], log.ids[first+1], "the resumed state.enter has the interrupted one's event ID")
}

func TestNoHooksFiresNothingAndRecordsNothing(t *testing.T) {
	r, _ := newRunner(t, jobs.Steps{Export: ok})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Nil(t, j.Hooks)
}

const stepEvents = `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: JOBS_EVENTS_SECRET, retries: 0}}}
events:
  export.after: {handler: rx}
  validate.after: {handler: rx}
  import.before: {handler: rx}
  import.after: {handler: rx}
`

func TestStepEvents(t *testing.T) {
	answers := map[string]string{}
	src := &fakeSource{users: fakeUsers(2)}
	tgt := &fakeTarget{chunkSize: 10, problems: []connector.Problem{{SourceID: "u1", Field: "username", Rule: "too short"}}}
	steps := jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) { return src, nil, nil },
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
		ResolveConnection: func(_ context.Context, _ *jobs.Job, current string) (string, error) {
			return "resolved", nil
		},
	})
	r, log := newEventRunner(t, steps, stepEvents, func(hook, _ string) (int, string) { return 200, answers[hook] })
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	params := map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: users}

	t.Run("vetoed export leaves no users file", func(t *testing.T) {
		answers[hooks.ExportAfter] = `{"allow": false, "reason": "too few"}`
		defer delete(answers, hooks.ExportAfter)
		j, err := r.Create(params)
		require.NoError(t, err)
		j, err = r.Run(context.Background(), j.ID)
		require.NoError(t, err)
		require.Equal(t, jobs.Exporting, j.FailedIn)
		require.Nil(t, j.Manifest)
		_, err = os.Stat(users)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("downgraded problems and a chosen connection", func(t *testing.T) {
		answers[hooks.ValidateAfter] = `{"downgrade": [0]}`
		answers[hooks.ImportBefore] = `{"connection_id": "from-hook"}`
		j, err := r.Create(params)
		require.NoError(t, err)
		j, err = r.Run(context.Background(), j.ID)
		require.NoError(t, err)
		require.Equal(t, jobs.Done, j.State, j.Error)
		require.Empty(t, j.Problems)
		require.Equal(t, tgt.problems, j.Warnings)
		require.Equal(t, "from-hook", tgt.opts.ConnectionID, "import.before has the last word, after the built-in resolution")
		require.Contains(t, log.got, "import.after@importing")
	})
}
