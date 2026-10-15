// Package jobs runs iamigrate's export, validate, import and verify steps
// as one resumable job, so `iamigrate serve` can drive them as long-running
// work that survives a process restart.
//
// A job moves through a fixed sequence of states, persisting its state
// before running each step. A job interrupted mid-step is therefore found in
// that step's state and resumed by running the step again: steps must be
// safe to repeat, and an import resumes from its chunk checkpoints (see
// connector.ChunkStore) rather than from the start.
package jobs

import "fmt"

// State is where a Job is in its lifecycle.
type State string

const (
	Queued     State = "queued"
	Exporting  State = "exporting"
	Validating State = "validating"
	Importing  State = "importing"
	Verifying  State = "verifying"
	Done       State = "done"
	Failed     State = "failed"
)

// pipeline is the order a job runs its states in.
var pipeline = []State{Queued, Exporting, Validating, Importing, Verifying, Done}

// Terminal reports whether no further step runs in s.
func (s State) Terminal() bool { return s == Done || s == Failed }

// Valid reports whether s is one of the defined states.
func (s State) Valid() bool {
	return s == Failed || s.index() >= 0
}

func (s State) index() int {
	for i, p := range pipeline {
		if p == s {
			return i
		}
	}
	return -1
}

// Next returns the state that follows s when its step succeeds, and false
// for a terminal state.
func (s State) Next() (State, bool) {
	i := s.index()
	if i < 0 || i == len(pipeline)-1 {
		return "", false
	}
	return pipeline[i+1], true
}

// CanTransition reports whether a job may move from one state to another:
// to the next state in the pipeline, or to Failed from any non-terminal
// state.
func CanTransition(from, to State) bool {
	if from.Terminal() {
		return false
	}
	if to == Failed {
		return from.Valid()
	}
	next, ok := from.Next()
	return ok && next == to
}

// TransitionError is returned for a move CanTransition rejects.
type TransitionError struct {
	From, To State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("jobs: invalid transition %s -> %s", e.From, e.To)
}
