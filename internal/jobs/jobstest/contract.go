package jobstest

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/stretchr/testify/require"
)

// StoreContract runs the tests every jobs.Store must pass on stores
// newStore returns: each call must return an empty store.
func StoreContract(t *testing.T, newStore func(t *testing.T) jobs.Store) {
	t.Run("LoadMissing", func(t *testing.T) {
		_, err := newStore(t).Load("missing")
		require.ErrorIs(t, err, jobs.ErrNotFound)
	})

	t.Run("InvalidID", func(t *testing.T) {
		s := newStore(t)
		_, err := s.Load("../x")
		require.ErrorIs(t, err, jobs.ErrInvalidID)
		require.ErrorIs(t, s.Save(&jobs.Job{ID: "a/b"}), jobs.ErrInvalidID)
		_, err = s.Lock("a b")
		require.ErrorIs(t, err, jobs.ErrInvalidID)
	})

	t.Run("SaveLoadList", func(t *testing.T) {
		s := newStore(t)
		j := newJob("a")
		require.NoError(t, s.Save(j))
		require.NotEmpty(t, j.Version(), "Save records the new version")
		require.NoError(t, s.Save(newJob("b")))

		got, err := s.Load("a")
		require.NoError(t, err)
		require.Equal(t, j.Version(), got.Version())
		require.Equal(t, jobs.Queued, got.State)
		require.Equal(t, map[string]string{"k": "v"}, got.Params)

		got.State = jobs.Exporting
		require.NoError(t, s.Save(got))
		again, err := s.Load("a")
		require.NoError(t, err)
		require.Equal(t, jobs.Exporting, again.State)

		ids, err := s.List()
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"a", "b"}, ids)
	})

	t.Run("CreateConflictsWithAnExistingJob", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.Save(newJob("a")))
		require.ErrorIs(t, s.Save(newJob("a")), jobs.ErrConflict)
	})

	t.Run("StaleSaveConflicts", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.Save(newJob("a")))
		first, err := s.Load("a")
		require.NoError(t, err)
		second, err := s.Load("a")
		require.NoError(t, err)

		first.State = jobs.Exporting
		require.NoError(t, s.Save(first))
		second.State = jobs.Failed
		require.ErrorIs(t, s.Save(second), jobs.ErrConflict)

		got, err := s.Load("a")
		require.NoError(t, err)
		require.Equal(t, jobs.Exporting, got.State, "a conflicting save changes nothing")
	})

	t.Run("ConcurrentCreatesHaveOneWinner", func(t *testing.T) {
		s := newStore(t)
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.Save(newJob("a"))
			}()
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else {
				require.ErrorIs(t, err, jobs.ErrConflict)
			}
		}
		require.Equal(t, 1, wins)
	})

	t.Run("LockIsExclusivePerJob", func(t *testing.T) {
		s := newStore(t)
		a, err := s.Lock("a")
		require.NoError(t, err)
		b, err := s.Lock("b")
		require.NoError(t, err)
		b.Release()

		_, err = s.Lock("a")
		require.ErrorIs(t, err, jobs.ErrLocked)
		a.Release()
		a.Release() // idempotent

		again, err := s.Lock("a")
		require.NoError(t, err)
		again.Release()
	})
}

// BucketContract runs the tests every jobs.Bucket must pass on buckets
// newBucket returns, each one empty, then StoreContract on an ObjectStore
// in such buckets, and the lease tests.
func BucketContract(t *testing.T, newBucket func(t *testing.T) jobs.Bucket) {
	ctx := context.Background()

	t.Run("Bucket", func(t *testing.T) {
		b := newBucket(t)
		_, _, err := b.Get(ctx, "k")
		require.ErrorIs(t, err, jobs.ErrObjectNotFound)

		v1, err := b.Put(ctx, "k", []byte("one"), "")
		require.NoError(t, err)
		require.NotEmpty(t, v1)
		_, err = b.Put(ctx, "k", []byte("again"), "")
		require.ErrorIs(t, err, jobs.ErrPrecondition, "an empty match only creates")

		data, v, err := b.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, "one", string(data))
		require.Equal(t, v1, v)

		v2, err := b.Put(ctx, "k", []byte("two"), v1)
		require.NoError(t, err)
		require.NotEqual(t, v1, v2)
		_, err = b.Put(ctx, "k", []byte("stale"), v1)
		require.ErrorIs(t, err, jobs.ErrPrecondition)
		_, err = b.Put(ctx, "missing", []byte("x"), v2)
		require.Error(t, err, "a match on a missing object fails")

		_, err = b.Put(ctx, "other", []byte("x"), "")
		require.NoError(t, err)
		keys, err := b.List(ctx, "")
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"k", "other"}, keys)
		keys, err = b.List(ctx, "ot")
		require.NoError(t, err)
		require.Equal(t, []string{"other"}, keys)

		require.ErrorIs(t, b.Delete(ctx, "k", v1), jobs.ErrPrecondition)
		require.NoError(t, b.Delete(ctx, "k", v2))
		require.ErrorIs(t, b.Delete(ctx, "k", ""), jobs.ErrObjectNotFound)
	})

	StoreContract(t, func(t *testing.T) jobs.Store { return jobs.NewObjectStore(newBucket(t)) })

	t.Run("LeaseIsRenewedWhileHeld", func(t *testing.T) {
		s := &jobs.ObjectStore{Bucket: newBucket(t), LeaseTTL: leaseTTL}
		lease, err := s.Lock("a")
		require.NoError(t, err)
		defer lease.Release()
		time.Sleep(s.LeaseTTL * 2)
		select {
		case <-lease.Lost():
			t.Fatal("a renewed lease is not lost")
		default:
		}
		_, err = s.Lock("a")
		require.ErrorIs(t, err, jobs.ErrLocked)
	})

	t.Run("ExpiredLeaseIsTakenOver", func(t *testing.T) {
		b := newBucket(t)
		if _, native := b.(jobs.LeaseBucket); native {
			t.Skip("the bucket's own leases expire as it decides")
		}
		ttl := leaseTTL
		holder := &jobs.ObjectStore{Bucket: b, LeaseTTL: ttl}
		lease, err := holder.Lock("a")
		require.NoError(t, err)
		defer lease.Release()

		// A holder that stopped renewing (it crashed) left an expired
		// lease behind.
		_, version, err := b.Get(ctx, "a.lease")
		require.NoError(t, err)
		expired, err := json.Marshal(map[string]any{"holder": "crashed", "expires_at": time.Now().Add(-time.Second)})
		require.NoError(t, err)
		_, err = b.Put(ctx, "a.lease", expired, version)
		require.NoError(t, err)

		other := &jobs.ObjectStore{Bucket: b, LeaseTTL: ttl}
		taken, err := other.Lock("a")
		require.NoError(t, err)
		defer taken.Release()

		select {
		case <-lease.Lost():
		case <-time.After(ttl * 2):
			t.Fatal("the old holder's lease is lost once taken over")
		}
	})
}

// leaseTTL is the lease TTL of the lease tests: short, but long enough for a
// remote bucket's round trips.
const leaseTTL = 600 * time.Millisecond

func newJob(id string) *jobs.Job {
	now := time.Now().UTC()
	return &jobs.Job{ID: id, State: jobs.Queued, Params: map[string]string{"k": "v"}, CreatedAt: now, UpdatedAt: now}
}
