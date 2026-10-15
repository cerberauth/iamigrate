package jobs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func TestRetryResumesAFailedJobInTheStateItFailedIn(t *testing.T) {
	fail := true
	var ran []jobs.State
	step := func(ctx context.Context, j *jobs.Job) error {
		ran = append(ran, j.State)
		if j.State == jobs.Importing && fail {
			return errors.New("boom")
		}
		return nil
	}
	r, store := newRunner(t, jobs.Steps{Export: step, Validate: step, Import: step, Verify: step})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)

	ran, fail = nil, false
	j, err = r.Retry(j.ID, "")
	require.NoError(t, err)
	require.Equal(t, jobs.Importing, j.State)
	require.Empty(t, j.Error)
	require.Empty(t, j.FailedIn)
	stored, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Importing, stored.State, "retry is persisted")

	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []jobs.State{jobs.Importing, jobs.Verifying}, ran, "earlier steps are not repeated")
}

func TestRetryKeepsChunkCheckpoints(t *testing.T) {
	attempt := 0
	r, _ := newRunner(t, jobs.Steps{Import: func(ctx context.Context, j *jobs.Job) error {
		attempt++
		store := connector.ChunkStoreFromContext(ctx)
		if attempt == 1 {
			require.NoError(t, store.SaveChunk(connector.ChunkCheckpoint{Index: 1, Fingerprint: "f", Done: true}))
			return errors.New("chunk 2 failed")
		}
		cp, ok := store.Chunk(1)
		require.True(t, ok)
		require.True(t, cp.Done)
		return nil
	}})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)

	_, err = r.Retry(j.ID, "")
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
}

func TestRetryRejectsJobsThatHaveNotFailed(t *testing.T) {
	r, _ := newRunner(t, jobs.Steps{})
	j, err := r.Create(nil)
	require.NoError(t, err)

	_, err = r.Retry(j.ID, "")
	require.ErrorIs(t, err, jobs.ErrNotFailed)

	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	_, err = r.Retry(j.ID, "")
	require.ErrorIs(t, err, jobs.ErrNotFailed)

	_, err = r.Retry("missing", "")
	require.ErrorIs(t, err, jobs.ErrNotFound)
}

// Two Runners over one directory stand in for two processes: the second Run
// of a job the first is still driving is refused, and goes through once the
// first is done.
func TestRunRefusesAJobAnotherRunIsDriving(t *testing.T) {
	dir := t.TempDir()
	open := func(steps jobs.Steps) *jobs.Runner {
		store, err := jobs.NewFileStore(dir)
		require.NoError(t, err)
		return &jobs.Runner{Store: store, Steps: steps}
	}

	started, release := make(chan struct{}), make(chan struct{})
	first := open(jobs.Steps{Export: func(ctx context.Context, j *jobs.Job) error {
		close(started)
		<-release
		return nil
	}})
	j, err := first.Create(nil)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := first.Run(context.Background(), j.ID)
		done <- err
	}()
	<-started

	second := open(jobs.Steps{})
	_, err = second.Run(context.Background(), j.ID)
	require.ErrorIs(t, err, jobs.ErrLocked)
	_, err = second.Retry(j.ID, "")
	require.ErrorIs(t, err, jobs.ErrLocked)

	close(release)
	require.NoError(t, <-done)

	got, err := second.Run(context.Background(), j.ID)
	require.NoError(t, err, "the lock is released when Run returns")
	require.Equal(t, jobs.Done, got.State)
}

func TestLockIsPerJob(t *testing.T) {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	unlockA, err := store.Lock("a")
	require.NoError(t, err)
	defer unlockA()
	unlockB, err := store.Lock("b")
	require.NoError(t, err)
	unlockB()

	_, err = store.Lock("a")
	require.ErrorIs(t, err, jobs.ErrLocked)
	unlockA()
	unlockAgain, err := store.Lock("a")
	require.NoError(t, err)
	unlockAgain()
}

func TestRetryFromAnEarlierStateDiscardsLaterResults(t *testing.T) {
	var ran []jobs.State
	failValidate := true
	step := func(ctx context.Context, j *jobs.Job) error {
		ran = append(ran, j.State)
		switch j.State {
		case jobs.Exporting:
			j.Manifest = &connector.Manifest{RecordCount: len(ran)}
		case jobs.Validating:
			if failValidate {
				j.Problems = []connector.Problem{{SourceID: "u"}}
				return errors.New("bad data")
			}
		}
		return nil
	}
	r, _ := newRunner(t, jobs.Steps{Export: step, Validate: step, Import: step, Verify: step})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.NotNil(t, j.Manifest)
	require.NotEmpty(t, j.Problems)

	j, err = r.Retry(j.ID, jobs.Exporting)
	require.NoError(t, err)
	require.Equal(t, jobs.Exporting, j.State)
	require.Nil(t, j.Manifest)
	require.Empty(t, j.Problems)

	ran, failValidate = nil, false
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, []jobs.State{jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying}, ran)
}

func TestRetryDiscardsChunkCheckpointsOnlyWhenGoingBackToImport(t *testing.T) {
	for _, tc := range []struct {
		from       jobs.State
		wantChunks int
	}{{"", 1}, {jobs.Verifying, 1}, {jobs.Importing, 0}, {jobs.Exporting, 0}} {
		t.Run(string(tc.from), func(t *testing.T) {
			r, _ := newRunner(t, jobs.Steps{
				Import: func(ctx context.Context, j *jobs.Job) error {
					return connector.ChunkStoreFromContext(ctx).SaveChunk(connector.ChunkCheckpoint{Index: 1, Done: true})
				},
				Verify: func(ctx context.Context, j *jobs.Job) error { return errors.New("drift") },
			})
			j, err := r.Create(nil)
			require.NoError(t, err)
			j, err = r.Run(context.Background(), j.ID)
			require.NoError(t, err)
			require.Equal(t, jobs.Verifying, j.FailedIn)

			j, err = r.Retry(j.ID, tc.from)
			require.NoError(t, err)
			require.Len(t, j.Chunks, tc.wantChunks)
		})
	}
}

func TestRetryRejectsStatesAfterTheFailureOrNotWorking(t *testing.T) {
	r, _ := newRunner(t, jobs.Steps{Validate: func(ctx context.Context, j *jobs.Job) error { return errors.New("boom") }})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Validating, j.FailedIn)

	for _, from := range []jobs.State{jobs.Importing, jobs.Done, jobs.Failed, jobs.Queued, "bogus"} {
		_, err = r.Retry(j.ID, from)
		var terr *jobs.TransitionError
		require.ErrorAs(t, err, &terr, from)
	}
	stored, err := r.Store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, stored.State, "a rejected retry changes nothing")
}

func TestFileStoreListReturnsSavedJobsOnly(t *testing.T) {
	dir := t.TempDir()
	store, err := jobs.NewFileStore(dir)
	require.NoError(t, err)
	r := &jobs.Runner{Store: store}

	a, err := r.Create(nil)
	require.NoError(t, err)
	b, err := r.Create(nil)
	require.NoError(t, err)
	// Leftovers of a lock and of an interrupted save are not jobs.
	unlock, err := store.Lock(a.ID)
	require.NoError(t, err)
	unlock()
	require.NoError(t, os.WriteFile(filepath.Join(dir, b.ID+".json.tmp"), []byte("{"), 0o600))

	ids, err := store.List()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{a.ID, b.ID}, ids)
}
