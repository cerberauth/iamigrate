package jobs

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"time"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
)

// Job is the persisted record of one migration: where it is, what each
// finished step produced, and the checkpoints of its chunked import.
type Job struct {
	ID    string `json:"id"`
	State State  `json:"state"`

	// Params is what the steps need to find their inputs (connector names,
	// file paths, ...). The package treats it as opaque.
	Params map[string]string `json:"params,omitempty"`

	// Error and FailedIn are set when the job is Failed: the error, and the
	// state whose step produced it.
	Error    string `json:"error,omitempty"`
	FailedIn State  `json:"failed_in,omitempty"`

	// Results of the steps, each set by its step.
	Manifest *connector.Manifest `json:"manifest,omitempty"`
	Problems []connector.Problem `json:"problems,omitempty"`
	// Warnings are problems a validate.after hook downgraded: shown, but
	// not failing the job.
	Warnings []connector.Problem     `json:"warnings,omitempty"`
	Report   *connector.ImportReport `json:"report,omitempty"`
	Diff     *connector.DiffReport   `json:"diff,omitempty"`

	// Hooks records the hook calls that vetoed a step, failed, or failed
	// and were ignored.
	Hooks []hooks.Result `json:"hooks,omitempty"`
	// HooksFingerprint identifies the hooks file the job last ran with, to
	// notice it changed when the job is resumed.
	HooksFingerprint string `json:"hooks_fingerprint,omitempty"`

	// Chunks are the import's checkpoints, by chunk index.
	Chunks map[int]connector.ChunkCheckpoint `json:"chunks,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ChunkCheckpoints returns the saved chunk checkpoints in chunk order.
func (j *Job) ChunkCheckpoints() []connector.ChunkCheckpoint {
	out := make([]connector.ChunkCheckpoint, 0, len(j.Chunks))
	for _, c := range j.Chunks {
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	return out
}

func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
