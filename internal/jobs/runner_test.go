package jobs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func newRunner(t *testing.T, steps jobs.Steps) (*jobs.Runner, *jobs.FileStore) {
	t.Helper()
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	return &jobs.Runner{Store: store, Steps: steps}, store
}

// recordingSteps returns steps that note, in *seen, the state persisted for
// the job while each step runs.
func recordingSteps(t *testing.T, store jobs.Store, seen *[]jobs.State) jobs.Steps {
	record := func(ctx context.Context, j *jobs.Job) error {
		stored, err := store.Load(j.ID)
		require.NoError(t, err)
		require.Equal(t, j.State, stored.State, "state is persisted before its step runs")
		*seen = append(*seen, j.State)
		return nil
	}
	return jobs.Steps{Export: record, Validate: record, Import: record, Verify: record}
}

func TestRunWalksEveryStateInOrder(t *testing.T) {
	var seen []jobs.State
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	r := &jobs.Runner{Store: store, Steps: recordingSteps(t, store, &seen)}

	j, err := r.Create(map[string]string{"in": "users.cmf.jsonl"})
	require.NoError(t, err)
	require.Equal(t, jobs.Queued, j.State)

	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []jobs.State{jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying}, seen)

	stored, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, stored.State)
	require.Equal(t, "users.cmf.jsonl", stored.Params["in"])
}

func TestRunFailsTheJobWhenAStepFails(t *testing.T) {
	for _, failing := range []jobs.State{jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying} {
		t.Run(string(failing), func(t *testing.T) {
			var ran []jobs.State
			step := func(ctx context.Context, j *jobs.Job) error {
				ran = append(ran, j.State)
				if j.State == failing {
					return errors.New("boom")
				}
				return nil
			}
			r, store := newRunner(t, jobs.Steps{Export: step, Validate: step, Import: step, Verify: step})
			j, err := r.Create(nil)
			require.NoError(t, err)

			j, err = r.Run(context.Background(), j.ID)
			require.NoError(t, err, "a step failure is the job's outcome, not Run's error")
			require.Equal(t, jobs.Failed, j.State)
			require.Equal(t, failing, j.FailedIn)
			require.Equal(t, "boom", j.Error)
			require.Equal(t, failing, ran[len(ran)-1], "no step runs after the failing one")

			stored, err := store.Load(j.ID)
			require.NoError(t, err)
			require.Equal(t, jobs.Failed, stored.State)
			require.Equal(t, "boom", stored.Error)
		})
	}
}

func TestRunPassesThroughStatesWithoutAStep(t *testing.T) {
	var ran []jobs.State
	r, _ := newRunner(t, jobs.Steps{Import: func(ctx context.Context, j *jobs.Job) error {
		ran = append(ran, j.State)
		return nil
	}})
	j, err := r.Create(nil)
	require.NoError(t, err)

	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []jobs.State{jobs.Importing}, ran)
}

func TestRunLeavesTerminalJobsAlone(t *testing.T) {
	for _, terminal := range []jobs.State{jobs.Done, jobs.Failed} {
		called := false
		step := func(ctx context.Context, j *jobs.Job) error { called = true; return nil }
		r, store := newRunner(t, jobs.Steps{Export: step, Validate: step, Import: step, Verify: step})
		j, err := r.Create(nil)
		require.NoError(t, err)
		j.State = terminal
		require.NoError(t, store.Save(j))

		got, err := r.Run(context.Background(), j.ID)
		require.NoError(t, err)
		require.Equal(t, terminal, got.State)
		require.False(t, called)
	}
}

func TestRunRejectsUnknownJobsAndStates(t *testing.T) {
	r, store := newRunner(t, jobs.Steps{})
	_, err := r.Run(context.Background(), "missing")
	require.ErrorIs(t, err, jobs.ErrNotFound)

	j, err := r.Create(nil)
	require.NoError(t, err)
	j.State = "bogus"
	require.NoError(t, store.Save(j))
	_, err = r.Run(context.Background(), j.ID)
	require.Error(t, err)
}

// A crash is simulated by cancelling the context mid-step: the job must stay
// in the state it was interrupted in, and a new Runner over the same
// directory (a restarted process) must pick it up there, re-running only
// that step and the ones after it.
func TestRunResumesAfterCrashFromThePersistedState(t *testing.T) {
	dir := t.TempDir()
	open := func(steps jobs.Steps) *jobs.Runner {
		store, err := jobs.NewFileStore(dir)
		require.NoError(t, err)
		return &jobs.Runner{Store: store, Steps: steps}
	}

	var firstRun []jobs.State
	ctx, crash := context.WithCancel(context.Background())
	defer crash()
	noop := func(name jobs.State) jobs.StepFunc {
		return func(ctx context.Context, j *jobs.Job) error { firstRun = append(firstRun, name); return nil }
	}
	r1 := open(jobs.Steps{
		Export:   noop(jobs.Exporting),
		Validate: noop(jobs.Validating),
		Import: func(ctx context.Context, j *jobs.Job) error {
			firstRun = append(firstRun, jobs.Importing)
			crash()
			return ctx.Err()
		},
		Verify: noop(jobs.Verifying),
	})
	j, err := r1.Create(nil)
	require.NoError(t, err)

	got, err := r1.Run(ctx, j.ID)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, jobs.Importing, got.State)
	require.Equal(t, []jobs.State{jobs.Exporting, jobs.Validating, jobs.Importing}, firstRun)

	var secondRun []jobs.State
	record := func(ctx context.Context, j *jobs.Job) error { secondRun = append(secondRun, j.State); return nil }
	r2 := open(jobs.Steps{Export: record, Validate: record, Import: record, Verify: record})

	got, err = r2.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, got.State)
	require.Equal(t, []jobs.State{jobs.Importing, jobs.Verifying}, secondRun)
}

func TestRunStopsBeforeAStepWhenContextIsAlreadyDone(t *testing.T) {
	called := false
	r, store := newRunner(t, jobs.Steps{Export: func(ctx context.Context, j *jobs.Job) error { called = true; return nil }})
	j, err := r.Create(nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.Run(ctx, j.ID)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)

	stored, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Queued, stored.State)
}

// Chunk checkpoints a step saves are persisted at once, so they survive a
// crash in the same step, and are handed back to it on resume.
func TestImportCheckpointsSurviveACrashAndAreSeenOnResume(t *testing.T) {
	dir := t.TempDir()
	open := func(importStep jobs.StepFunc) *jobs.Runner {
		store, err := jobs.NewFileStore(dir)
		require.NoError(t, err)
		return &jobs.Runner{Store: store, Steps: jobs.Steps{Import: importStep}}
	}

	ctx, crash := context.WithCancel(context.Background())
	defer crash()
	r1 := open(func(ctx context.Context, j *jobs.Job) error {
		store := connector.ChunkStoreFromContext(ctx)
		require.NotNil(t, store)
		require.NoError(t, store.SaveChunk(connector.ChunkCheckpoint{
			Index: 1, Fingerprint: "f1", JobID: "job_1", Done: true,
			Report: connector.ImportReport{Succeeded: []string{"a", "b"}},
		}))
		require.NoError(t, store.SaveChunk(connector.ChunkCheckpoint{Index: 2, Fingerprint: "f2", JobID: "job_2"}))
		crash()
		return ctx.Err()
	})
	j, err := r1.Create(nil)
	require.NoError(t, err)
	_, err = r1.Run(ctx, j.ID)
	require.ErrorIs(t, err, context.Canceled)

	var resumed []connector.ChunkCheckpoint
	r2 := open(func(ctx context.Context, j *jobs.Job) error {
		store := connector.ChunkStoreFromContext(ctx)
		for i := 1; i <= 3; i++ {
			if cp, ok := store.Chunk(i); ok {
				resumed = append(resumed, cp)
			}
		}
		return nil
	})
	got, err := r2.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, got.State)

	require.Len(t, resumed, 2)
	require.True(t, resumed[0].Done)
	require.Equal(t, []string{"a", "b"}, resumed[0].Report.Succeeded)
	require.Equal(t, "job_2", resumed[1].JobID)
	require.False(t, resumed[1].Done)
	require.Len(t, got.ChunkCheckpoints(), 2)
}

func TestFileStoreSaveLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	store, err := jobs.NewFileStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.Save(&jobs.Job{ID: "abc", State: jobs.Queued}))

	entries, err := readDirNames(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"abc.json"}, entries)
}

func TestFileStoreRejectsPathLikeIDs(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	require.Error(t, store.Save(&jobs.Job{ID: "../escape"}))
	_, err = store.Load("../escape")
	require.Error(t, err)
}

func TestRunNotifiesEachStateAndTheOutcome(t *testing.T) {
	var seen []jobs.State
	noop := func(ctx context.Context, j *jobs.Job) error { return nil }
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	r := &jobs.Runner{
		Store: store, Steps: jobs.Steps{Export: noop, Validate: noop, Import: noop, Verify: noop},
		OnState: func(j *jobs.Job) { seen = append(seen, j.State) },
	}
	j, err := r.Create(nil)
	require.NoError(t, err)
	_, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, []jobs.State{jobs.Queued, jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying, jobs.Done}, seen)
}
