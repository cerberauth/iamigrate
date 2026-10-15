package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/connector"
)

// StepFunc runs the work of one state against j, recording its results on
// it. It may run more than once for the same job, after a crash or a
// restart, so it must pick up where an earlier run left off or redo its
// work harmlessly. An import step gets the job's chunk checkpoints through
// connector.ChunkStoreFromContext.
type StepFunc func(ctx context.Context, j *Job) error

// Steps maps each working state to its step. A state with no step passes
// straight through, for a migration that starts from an existing CMF file
// and so has nothing to export, say.
type Steps struct {
	Export, Validate, Import, Verify StepFunc
}

func (s Steps) forState(st State) StepFunc {
	switch st {
	case Exporting:
		return s.Export
	case Validating:
		return s.Validate
	case Importing:
		return s.Import
	case Verifying:
		return s.Verify
	}
	return nil
}

// Runner creates jobs and drives them through their states.
type Runner struct {
	Store Store
	Steps Steps

	// OnState, if set, is called with the job whenever Run is about to work
	// on a state (the one it resumes in included), and once more when the
	// job reaches Done or Failed.
	OnState func(j *Job)

	// Now is the clock; time.Now if nil.
	Now func() time.Time
}

func (r *Runner) notify(j *Job) {
	if r.OnState != nil {
		r.OnState(j)
	}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Create stores a new queued job.
func (r *Runner) Create(params map[string]string) (*Job, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := r.now()
	j := &Job{ID: id, State: Queued, Params: params, CreatedAt: now, UpdatedAt: now}
	if err := r.Store.Save(j); err != nil {
		return nil, err
	}
	return j, nil
}

// Run drives the stored job id to a terminal state, starting from the state
// it was persisted in, so it both runs a new job and resumes one a crash
// interrupted. A job already in a terminal state is returned as is. Only one
// Run drives a job at a time: another gets ErrLocked.
//
// A step error fails the job, which Run records and returns the job for,
// with a nil error: the failure is the job's outcome. Run returns an error
// only when it couldn't carry the job any further, namely when ctx is done
// or the store fails. A cancelled ctx leaves the job in the state it was
// interrupted in, to be resumed by another Run.
func (r *Runner) Run(ctx context.Context, id string) (*Job, error) {
	unlock, err := r.Store.Lock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()

	j, err := r.Store.Load(id)
	if err != nil {
		return nil, err
	}
	if !j.State.Valid() {
		return j, fmt.Errorf("jobs: job %s is in unknown state %q", id, j.State)
	}

	defer func() {
		if j.State.Terminal() {
			r.notify(j)
		}
	}()
	for !j.State.Terminal() {
		if err := ctx.Err(); err != nil {
			return j, err
		}
		r.notify(j)
		if step := r.Steps.forState(j.State); step != nil {
			err := r.runStep(ctx, j, step)
			if ctxErr := ctx.Err(); ctxErr != nil {
				// Interrupted rather than failed: leave the state as
				// persisted so the step is run again on resume.
				return j, ctxErr
			}
			if err != nil {
				if serr := r.fail(j, err); serr != nil {
					return j, serr
				}
				return j, nil
			}
		}
		next, _ := j.State.Next()
		if err := r.transition(j, next); err != nil {
			return j, err
		}
	}
	return j, nil
}

// Retry puts a failed job back in a state, ready for Run to try its step
// again: the state it failed in if from is empty, else an earlier one, for a
// failure whose cause lies upstream (say, a validation problem that only
// re-exporting fixes). Going back to a state discards the results of it and
// of every later step, the import's chunk checkpoints included. Retrying the
// state the job failed in keeps the results of the earlier steps and the
// chunk checkpoints, so a retried import carries on rather than starting
// over.
//
// It returns ErrNotFailed for a job that hasn't failed, and a
// TransitionError for a from that isn't a working state at or before the
// one the job failed in.
func (r *Runner) Retry(id string, from State) (*Job, error) {
	unlock, err := r.Store.Lock(id)
	if err != nil {
		return nil, err
	}
	defer unlock()

	j, err := r.Store.Load(id)
	if err != nil {
		return nil, err
	}
	if j.State != Failed || !j.FailedIn.Valid() || j.FailedIn == Failed {
		return j, fmt.Errorf("%w: job %s is %s", ErrNotFailed, id, j.State)
	}
	if from == "" {
		from = j.FailedIn
	}
	if from == Queued || from.index() < 0 || from.index() > j.FailedIn.index() {
		return j, &TransitionError{From: j.FailedIn, To: from}
	}

	if from != j.FailedIn {
		if from.index() <= Exporting.index() {
			j.Manifest = nil
		}
		if from.index() <= Validating.index() {
			j.Problems = nil
		}
		if from.index() <= Importing.index() {
			j.Report, j.Chunks = nil, nil
		}
		if from.index() <= Verifying.index() {
			j.Diff = nil
		}
	}
	j.State, j.FailedIn, j.Error = from, "", ""
	j.UpdatedAt = r.now()
	if err := r.Store.Save(j); err != nil {
		return nil, err
	}
	return j, nil
}

// runStep runs step with j's chunk checkpoints in the context, and saves j
// when it's done.
func (r *Runner) runStep(ctx context.Context, j *Job, step StepFunc) error {
	cp := &checkpoints{job: j, store: r.Store, now: r.now}
	err := step(connector.WithChunkStore(ctx, cp), j)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if serr := cp.save(); serr != nil && err == nil {
		return serr
	}
	return err
}

// transition moves j to state to and persists it.
func (r *Runner) transition(j *Job, to State) error {
	if !CanTransition(j.State, to) {
		return &TransitionError{From: j.State, To: to}
	}
	prev := j.State
	j.State = to
	j.UpdatedAt = r.now()
	if err := r.Store.Save(j); err != nil {
		j.State = prev
		return err
	}
	return nil
}

// fail moves j to Failed, remembering the state and error behind it in the
// same save.
func (r *Runner) fail(j *Job, cause error) error {
	from := j.State
	j.FailedIn, j.Error = from, cause.Error()
	if err := r.transition(j, Failed); err != nil {
		j.FailedIn, j.Error = "", ""
		return err
	}
	return nil
}

// checkpoints is the connector.ChunkStore of a running job: it keeps
// the checkpoints on the job and persists the whole job on every save.
type checkpoints struct {
	job   *Job
	store Store
	now   func() time.Time

	mu sync.Mutex
}

func (c *checkpoints) Chunk(index int) (connector.ChunkCheckpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.job.Chunks[index]
	return cp, ok
}

func (c *checkpoints) SaveChunk(cp connector.ChunkCheckpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.job.Chunks == nil {
		c.job.Chunks = map[int]connector.ChunkCheckpoint{}
	}
	c.job.Chunks[cp.Index] = cp
	return c.save()
}

// save persists the job. The caller holds c.mu.
func (c *checkpoints) save() error {
	c.job.UpdatedAt = c.now()
	return c.store.Save(c.job)
}
