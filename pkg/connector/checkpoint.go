package connector

import "context"

// ChunkCheckpoint is what a chunked import remembers about one chunk, so a
// re-run after a crash neither re-submits a chunk that already finished nor
// re-creates a job that is still running on the target.
type ChunkCheckpoint struct {
	// Index is the chunk's position in the import, from 1. Chunking is
	// deterministic for a given input, so the same index is the same users
	// on every run.
	Index int `json:"index"`
	// Fingerprint identifies the chunk's content, so a changed input file
	// is noticed instead of being matched to stale checkpoints.
	Fingerprint string `json:"fingerprint"`
	// JobID is the target's job for this chunk, recorded as soon as it is
	// created: a resumed import waits for that job rather than submitting
	// the chunk again.
	JobID string `json:"job_id,omitempty"`
	// Done is set once the chunk's outcome is known; Report holds it.
	Done   bool         `json:"done,omitempty"`
	Report ImportReport `json:"report"`
}

// ChunkStore persists ChunkCheckpoints. Implementations must be safe for
// concurrent use, as chunks finish concurrently.
type ChunkStore interface {
	// Chunk returns the checkpoint saved for chunk index, if any.
	Chunk(index int) (ChunkCheckpoint, bool)
	// SaveChunk durably records c before returning.
	SaveChunk(c ChunkCheckpoint) error
}

type chunkStoreKey struct{}

// WithChunkStore returns a context carrying s, for a chunked import to
// checkpoint to. Like progress.Bar it travels in the context so
// TargetConnector.Import keeps its signature.
func WithChunkStore(ctx context.Context, s ChunkStore) context.Context {
	return context.WithValue(ctx, chunkStoreKey{}, s)
}

// ChunkStoreFromContext returns the ChunkStore in ctx, or nil if there is
// none, in which case an import runs without checkpoints.
func ChunkStoreFromContext(ctx context.Context) ChunkStore {
	s, _ := ctx.Value(chunkStoreKey{}).(ChunkStore)
	return s
}
