package jobs_test

import (
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

func hooksFile(t *testing.T, body string) *hooks.Dispatcher {
	t.Helper()
	cfg, err := hooks.Parse([]byte(body))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	return d
}

// runInterrupted runs job id until its import step, which cancels the run.
func runInterrupted(t *testing.T, r *jobs.Runner, id string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.Steps = jobs.Steps{Import: func(context.Context, *jobs.Job) error { cancel(); return nil }}
	_, err := r.Run(ctx, id)
	require.ErrorIs(t, err, context.Canceled)
}

func TestResumingUnderAnotherHooksFileIsRecorded(t *testing.T) {
	a, b := hooksFile(t, "version: 1\n"), hooksFile(t, "version: 1\n# changed\n")
	r, store := newRunner(t, jobs.Steps{})
	j, err := r.Create(nil)
	require.NoError(t, err)

	r.Hooks = a
	runInterrupted(t, r, j.ID)
	stored, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, a.Config().Fingerprint(), stored.HooksFingerprint)
	require.Empty(t, stored.Hooks)

	r.Hooks = a
	runInterrupted(t, r, j.ID)
	stored, _ = store.Load(j.ID)
	require.Empty(t, stored.Hooks, "the same file again is no change")

	r.Hooks = b
	runInterrupted(t, r, j.ID)
	stored, _ = store.Load(j.ID)
	require.Len(t, stored.Hooks, 1)
	require.Equal(t, hooks.Changed, stored.Hooks[0].Outcome)
	require.Equal(t, "importing", stored.Hooks[0].State)
	require.Contains(t, stored.Hooks[0].Reason, "the hooks file changed since the job's last run ("+a.Config().Fingerprint()[:12]+" -> "+b.Config().Fingerprint()[:12]+")")
	require.Equal(t, b.Config().Fingerprint(), stored.HooksFingerprint)

	r.Hooks = nil
	r.Steps = jobs.Steps{}
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Len(t, j.Hooks, 2)
	require.Contains(t, j.Hooks[1].Reason, "this one has none")
	require.Equal(t, b.Config().Fingerprint(), j.HooksFingerprint, "kept, to compare with a later run")
}

func TestAJobFirstRunWithoutHooksHasNoFingerprint(t *testing.T) {
	r, _ := newRunner(t, jobs.Steps{})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Empty(t, j.HooksFingerprint)
	require.Empty(t, j.Hooks)
}
