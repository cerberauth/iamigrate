// Package hooks lets an operator customize a migration without forking
// iamigrate: lifecycle events they can react to (and sometimes veto), and
// strategies, the per-user decisions (IDs, field mapping, conflicts, ...)
// they can hand to their own code.
//
// Both reach that code through a Handler. The only kind today is an HTTP
// webhook; the hook points, the Envelope and the configuration are kept
// independent of it so other kinds (a subprocess speaking JSONL, an
// in-process expression) can be added without changing either.
//
// A Dispatcher, built from the operator's hooks.yaml, travels in the
// context like connector.ChunkStore, so connectors reach it without their
// signatures changing. With no Dispatcher every call is a no-op and the
// pipeline behaves exactly as it does without hooks.
package hooks

import (
	"context"
	"encoding/json"
	"time"
)

// Version is the Envelope version sent to handlers, bumped on any change a
// receiver could trip over.
const Version = "1"

// Handler delivers an Envelope to the operator's code and returns what it
// answered, nil for an empty answer.
type Handler interface {
	Call(ctx context.Context, env Envelope) (json.RawMessage, error)
}

// Envelope is the request every handler gets.
type Envelope struct {
	Version string `json:"version"`
	Hook    string `json:"hook"`
	// EventID is the same every time the same job fires the same hook for
	// the same state and batch, a resumed job's re-fired events included,
	// so a receiver can deduplicate on it.
	EventID string `json:"event_id"`
	// JobID is empty for a standalone command, which runs no job.
	JobID string     `json:"job_id"`
	State string     `json:"state,omitempty"`
	Batch *BatchInfo `json:"batch,omitempty"`
	Data  any        `json:"data"`
}

// BatchInfo locates a batch of per-user strategy items within a step.
type BatchInfo struct {
	Index int `json:"index"`
	Size  int `json:"size"`
}

// Outcome is what became of a hook call worth remembering: one that
// vetoed the step, failed it, or failed and was ignored; or, for a job, that
// it ran under another hooks file.
type Outcome string

const (
	Vetoed  Outcome = "vetoed"
	Failed  Outcome = "failed"
	Ignored Outcome = "ignored"
	// Changed is a job run under another hooks file than its last run.
	Changed Outcome = "changed"
)

// Result records a hook call that vetoed, failed, or was ignored, on the
// job it ran for so `job status` and the REST API can show it, or a job run
// under a changed hooks file. Successful calls aren't recorded: there could
// be one per batch of users.
type Result struct {
	Hook    string    `json:"hook"`
	EventID string    `json:"event_id"`
	State   string    `json:"state,omitempty"`
	Outcome Outcome   `json:"outcome"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"at"`
}
