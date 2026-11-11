package api_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/api"
	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

// Several replicas of the server over one remote store: every queued job
// runs to the end, each on one replica only, including those a replica
// finds by rescanning rather than at start.
func TestReplicasRunEachJobOnce(t *testing.T) {
	bucket := jobstest.NewMemBucket()
	var mu sync.Mutex
	runs := map[string]int{}
	steps := jobs.Steps{Export: func(ctx context.Context, j *jobs.Job) error {
		mu.Lock()
		runs[j.ID]++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		return nil
	}}
	newReplica := func() (*jobs.Runner, *api.Server) {
		runner := &jobs.Runner{Store: jobs.NewObjectStore(bucket), Steps: steps}
		ctx, cancel := context.WithCancel(context.Background())
		srv := api.New(ctx, runner, api.Options{})
		t.Cleanup(func() { cancel(); srv.Wait() })
		return runner, srv
	}

	r1, s1 := newReplica()
	_, s2 := newReplica()
	_, s3 := newReplica()
	var ids []string
	for range 10 {
		j, err := r1.Create(nil)
		require.NoError(t, err)
		ids = append(ids, j.ID)
	}
	for _, s := range []*api.Server{s1, s2, s3} {
		_, err := s.Resume()
		require.NoError(t, err)
		s.Rescan(10 * time.Millisecond)
	}
	// Queued after the start: found by a rescan.
	late, err := r1.Create(nil)
	require.NoError(t, err)
	ids = append(ids, late.ID)

	require.Eventually(t, func() bool {
		for _, id := range ids {
			j, err := r1.Store.Load(id)
			if err != nil || j.State != jobs.Done {
				return false
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		require.Equal(t, 1, runs[id], "job %s", id)
	}
}
