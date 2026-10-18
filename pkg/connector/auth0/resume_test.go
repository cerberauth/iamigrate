package auth0_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

// memChunkStore is an in-memory connector.ChunkStore.
type memChunkStore struct {
	mu     sync.Mutex
	chunks map[int]connector.ChunkCheckpoint
}

func newMemChunkStore() *memChunkStore {
	return &memChunkStore{chunks: map[int]connector.ChunkCheckpoint{}}
}

func (s *memChunkStore) Chunk(i int) (connector.ChunkCheckpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.chunks[i]
	return c, ok
}

func (s *memChunkStore) SaveChunk(c connector.ChunkCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks[c.Index] = c
	return nil
}

func (s *memChunkStore) get(i int) connector.ChunkCheckpoint {
	c, _ := s.Chunk(i)
	return c
}

func (s *jobServer) setStatus(firstUser, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[firstUser] = status
}

func (s *jobServer) submittedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.submitted)
}

// A crash while chunk 2's job is still running on Auth0 must, on resume,
// neither resubmit chunk 1 (done) nor chunk 2 (its job exists): the job is
// waited for and the merged report covers every user once.
func TestRunBulkImportResumesWithoutResubmittingChunks(t *testing.T) {
	defer setFastPolling(t)()
	// 1001 users: the 1000-user cap makes two chunks. Chunk 2's job stays
	// "processing" until the test lets it finish.
	srv := newJobServer(t, map[string]string{"u1000": "processing"})
	client := auth0.NewClient(srv.URL, "test-token")
	store := newMemChunkStore()

	crashCtx, crash := context.WithCancel(connector.WithChunkStore(context.Background(), store))
	defer crash()
	go func() {
		// The crash: once chunk 1 is done and chunk 2's job exists and is
		// checkpointed.
		for srv.submittedCount() < 2 || store.get(2).JobID == "" || !store.get(1).Done {
			time.Sleep(time.Millisecond)
		}
		crash()
	}()
	_, _, err := auth0.RunBulkImport(crashCtx, client, writeUsers(t, manyUsers(1001)), "conn_123", false)
	require.Error(t, err)
	require.True(t, store.get(1).Done)
	require.Len(t, store.get(1).Report.Succeeded, 1000)
	require.False(t, store.get(2).Done)
	require.NotEmpty(t, store.get(2).JobID)
	require.Equal(t, 2, srv.submittedCount())

	srv.setStatus("u1000", "completed")
	ctx := connector.WithChunkStore(context.Background(), store)
	report, _, err := auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(1001)), "conn_123", false)
	require.NoError(t, err)

	require.Equal(t, 2, srv.submittedCount(), "resume must not create any new job")
	require.Len(t, report.Succeeded, 1001)
	require.Empty(t, report.Failed)
	require.True(t, store.get(2).Done)
}

func TestRunBulkImportSkipsChunksDoneInAnEarlierRun(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)
	client := auth0.NewClient(srv.URL, "test-token")
	store := newMemChunkStore()
	ctx := connector.WithChunkStore(context.Background(), store)

	first, _, err := auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(1001)), "conn_123", false)
	require.NoError(t, err)
	require.Equal(t, 2, srv.submittedCount())

	again, _, err := auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(1001)), "conn_123", false)
	require.NoError(t, err)
	require.Equal(t, 2, srv.submittedCount(), "finished chunks are not submitted again")
	require.ElementsMatch(t, first.Succeeded, again.Succeeded)
}

func TestRunBulkImportResubmitsAChunkWhoseJobFailed(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, map[string]string{"u0000": "failed"})
	client := auth0.NewClient(srv.URL, "test-token")
	store := newMemChunkStore()
	ctx := connector.WithChunkStore(context.Background(), store)

	report, _, err := auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(2)), "conn_123", true)
	require.NoError(t, err)
	require.Len(t, report.Failed, 2)
	require.False(t, store.get(1).Done, "a failed job is not a final outcome")
	require.Empty(t, store.get(1).JobID)

	srv.setStatus("u0000", "completed")
	report, _, err = auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(2)), "conn_123", true)
	require.NoError(t, err)
	require.Equal(t, 2, srv.submittedCount())
	require.Len(t, report.Succeeded, 2)
	require.Empty(t, report.Failed)
}

func TestRunBulkImportRefusesCheckpointsOfADifferentInput(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)
	client := auth0.NewClient(srv.URL, "test-token")
	store := newMemChunkStore()
	ctx := connector.WithChunkStore(context.Background(), store)

	_, _, err := auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(2)), "conn_123", false)
	require.NoError(t, err)

	_, _, err = auth0.RunBulkImport(ctx, client, writeUsers(t, manyUsers(3)), "conn_123", false)
	require.ErrorContains(t, err, "input changed")
	require.Equal(t, 1, srv.submittedCount())
}
