package jobs_test

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

// A run whose lease is taken over (it stalled past the TTL) stops before
// its next save, leaving the job as the new holder has it.
func TestRunStopsWhenItLosesItsLease(t *testing.T) {
	ctx := context.Background()
	bucket := jobstest.NewMemBucket()
	store := &jobs.ObjectStore{Bucket: bucket, LeaseTTL: 300 * time.Millisecond}

	entered := make(chan struct{})
	release := make(chan struct{})
	r := &jobs.Runner{Store: store, Steps: jobs.Steps{
		Export: func(ctx context.Context, j *jobs.Job) error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			j.Error = "written by the stalled run"
			return nil
		},
	}}
	j, err := r.Create(nil)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, j.ID)
		done <- err
	}()
	<-entered

	// Another replica finds the lease expired and takes it over.
	_, version, err := bucket.Get(ctx, j.ID+".lease")
	require.NoError(t, err)
	expired, err := json.Marshal(map[string]any{"holder": "stalled", "expires_at": time.Now().Add(-time.Second)})
	require.NoError(t, err)
	_, err = bucket.Put(ctx, j.ID+".lease", expired, version)
	require.NoError(t, err)
	other := &jobs.ObjectStore{Bucket: bucket, LeaseTTL: time.Minute}
	lease, err := other.Lock(j.ID)
	require.NoError(t, err)
	defer lease.Release()

	select {
	case err := <-done:
		require.ErrorIs(t, err, jobs.ErrLeaseLost)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the run didn't stop on losing its lease")
	}
	stored, err := store.Load(j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Exporting, stored.State)
	require.Empty(t, stored.Error, "the stalled run saved nothing after losing its lease")
}

func TestOpenStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	s, err := jobs.OpenStore(ctx, filepath.Join(dir, "a"))
	require.NoError(t, err)
	require.IsType(t, &jobs.FileStore{}, s)
	s, err = jobs.OpenStore(ctx, "file://"+filepath.Join(dir, "b"))
	require.NoError(t, err)
	require.IsType(t, &jobs.FileStore{}, s)

	_, err = jobs.OpenStore(ctx, "nope://bucket/prefix")
	require.ErrorContains(t, err, `unsupported scheme "nope"`)

	var opened *url.URL
	jobs.RegisterBucket("memtest", func(_ context.Context, u *url.URL) (jobs.Bucket, error) {
		opened = u
		return jobstest.NewMemBucket(), nil
	})
	s, err = jobs.OpenStore(ctx, "memtest://bucket/some/prefix/")
	require.NoError(t, err)
	require.IsType(t, &jobs.ObjectStore{}, s)
	require.Equal(t, "bucket", opened.Host)
	require.Equal(t, "some/prefix/", jobs.KeyPrefix(opened))
	require.Contains(t, jobs.Schemes(), "memtest")
}
