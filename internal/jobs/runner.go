package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
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

	// Hooks, if set, fire the hooks of the operator's hooks file: the steps
	// find it, scoped to the job and its state, through
	// hooks.FromContext. It is the runner's, never a job's, so a job's
	// params can't point a hook anywhere.
	Hooks *hooks.Dispatcher

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
	if j.State.Terminal() {
		return j, nil
	}

	// One checkpoints for the whole run: it is also where the hooks of the
	// run record their results, under its lock.
	cp := &checkpoints{job: j, store: r.Store, now: r.now}
	d := r.Hooks.ForJob(j.ID, cp.recordHook)
	// stop ends the run on err, from a step or a hook: an interruption
	// leaves the job to be resumed, anything else fails it.
	stop := func(err error) (*Job, error) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Interrupted rather than failed: leave the state as
			// persisted so the step is run again on resume.
			return j, ctxErr
		}
		if serr := r.fail(j, err); serr != nil {
			return j, serr
		}
		return j, r.finish(ctx, d, j)
	}

	r.noteHooksFile(j, cp)

	// Fired on every run, a resumed one included, with the same event ID.
	if _, err := d.InState(string(j.State)).Event(ctx, hooks.JobBeforeRun, jobData(j)); err != nil {
		return stop(err)
	}
	for !j.State.Terminal() {
		if err := ctx.Err(); err != nil {
			return j, err
		}
		r.notify(j)
		sd := d.InState(string(j.State))
		if _, err := sd.Event(ctx, hooks.StateEnter, jobData(j)); err != nil {
			return stop(err)
		}
		if step := r.Steps.forState(j.State); step != nil {
			if err := r.runStep(ctx, j, step, cp, sd); err != nil {
				return stop(err)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return j, ctxErr
			}
		}
		if _, err := sd.Event(ctx, hooks.StateExit, jobData(j)); err != nil {
			return stop(err)
		}
		next, _ := j.State.Next()
		if err := r.transition(j, next); err != nil {
			return j, err
		}
	}
	return j, r.finish(ctx, d, j)
}

// noteHooksFile records on j the hooks file this run has, and a Changed
// result when it isn't the one an earlier run had: strategies feeding the
// import must answer a resumed job as they did before, which another hooks
// file may not. A job first run without hooks has nothing to compare with.
func (r *Runner) noteHooksFile(j *Job, cp *checkpoints) {
	fp := r.Hooks.Config().Fingerprint()
	if fp == j.HooksFingerprint || (fp != "" && j.HooksFingerprint == "") {
		j.HooksFingerprint = fp
		return
	}
	reason := "the hooks file changed since the job's last run (" + short(j.HooksFingerprint) + " -> " + short(fp) + ")"
	if fp == "" {
		reason = "the job's last run had a hooks file (" + short(j.HooksFingerprint) + "), this one has none"
	} else {
		j.HooksFingerprint = fp
	}
	cp.recordHook(hooks.Result{Hook: "hooks", State: string(j.State), Outcome: hooks.Changed, Reason: reason, At: r.now()})
}

func short(fp string) string { return fp[:min(len(fp), 12)] }

// finish fires job.done or job.failed for j, just terminal, and saves the
// results of the hook calls, if any were recorded.
func (r *Runner) finish(ctx context.Context, d *hooks.Dispatcher, j *Job) error {
	hook := hooks.JobDone
	if j.State == Failed {
		hook = hooks.JobFailed
	}
	n := len(j.Hooks)
	// The job is over whatever the hook answers: its failure is recorded,
	// not acted on.
	_, _ = d.InState(string(j.State)).Event(ctx, hook, jobData(j))
	if len(j.Hooks) == n {
		return nil
	}
	j.UpdatedAt = r.now()
	return r.Store.Save(j)
}

// jobData is what job and state events tell of j: where it is, not the
// results of its steps, which their own events carry.
func jobData(j *Job) map[string]any {
	return map[string]any{
		"id":         j.ID,
		"state":      j.State,
		"failed_in":  j.FailedIn,
		"error":      j.Error,
		"params":     j.Params,
		"created_at": j.CreatedAt,
		"updated_at": j.UpdatedAt,
	}
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
			j.Problems, j.Warnings = nil, nil
		}
		if from.index() <= Importing.index() {
			j.Report, j.Chunks = nil, nil
		}
		if from.index() <= Verifying.index() {
			j.Diff = nil
		}
		j.Hooks = hooksBefore(j.Hooks, from)
	}
	j.State, j.FailedIn, j.Error = from, "", ""
	j.UpdatedAt = r.now()
	if err := r.Store.Save(j); err != nil {
		return nil, err
	}
	return j, nil
}

// hooksBefore returns the hook results recorded in states before from,
// those of the states a retry goes back over being discarded with the rest
// of their results.
func hooksBefore(rs []hooks.Result, from State) []hooks.Result {
	var kept []hooks.Result
	for _, r := range rs {
		if i := State(r.State).index(); i >= 0 && i < from.index() {
			kept = append(kept, r)
		}
	}
	return kept
}

// runStep runs step with j's chunk checkpoints and hooks, d, in the
// context, and saves j when it's done.
func (r *Runner) runStep(ctx context.Context, j *Job, step StepFunc, cp *checkpoints, d *hooks.Dispatcher) error {
	ctx = hooks.WithDispatcher(ctx, d)
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

// recordHook keeps a hook result on the job, saved with it. Hooks may fire
// from concurrent chunks, hence the lock.
func (c *checkpoints) recordHook(res hooks.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.job.Hooks = append(c.job.Hooks, res)
}

// save persists the job. The caller holds c.mu.
func (c *checkpoints) save() error {
	c.job.UpdatedAt = c.now()
	return c.store.Save(c.job)
}
