package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrObjectNotFound is returned by a Bucket for a key it has no object at.
var ErrObjectNotFound = errors.New("jobs: object not found")

// ErrPrecondition is returned by a Bucket's conditional Put or Delete when
// the object isn't at the version the call expected.
var ErrPrecondition = errors.New("jobs: object version precondition failed")

// Bucket is the object storage an ObjectStore keeps jobs in: a flat
// key/value space with a version per object and conditional writes, such as
// an S3, Google Cloud Storage or Azure Blob Storage bucket under a prefix.
type Bucket interface {
	// Get returns the object at key and its version, or ErrObjectNotFound.
	Get(ctx context.Context, key string) (data []byte, version string, err error)
	// Put writes the object at key if it is at version match, or, with an
	// empty match, if there is no object there yet. It returns
	// ErrPrecondition otherwise, and the new version on success.
	Put(ctx context.Context, key string, data []byte, match string) (version string, err error)
	// Delete removes the object at key if it is at version match (any
	// version for an empty match), returning ErrPrecondition otherwise. A
	// missing object is ErrObjectNotFound.
	Delete(ctx context.Context, key string, match string) error
	// List returns the keys under prefix, in no particular order.
	List(ctx context.Context, prefix string) ([]string, error)
}

// Object is an entry of an ObjectLister's listing.
type Object struct {
	// Key is relative to the bucket's prefix.
	Key string
	// Version is the object's version, as Get returns it: it changes
	// whenever the object is written.
	Version string
}

// ObjectLister is a Bucket that lists its objects with their versions in
// one call, which watching a bucket for new objects needs.
type ObjectLister interface {
	// ListObjects returns the objects under prefix, in no particular order.
	ListObjects(ctx context.Context, prefix string) ([]Object, error)
}

// LeaseBucket is a Bucket with native leases on its objects, which an
// ObjectStore then uses for Lock instead of lease objects of its own.
type LeaseBucket interface {
	Bucket
	// AcquireLease leases the object at key (creating it empty if needed)
	// for ttl, returning ErrLocked when someone else holds it.
	AcquireLease(ctx context.Context, key string, ttl time.Duration) (leaseID string, err error)
	// RenewLease extends a lease AcquireLease returned.
	RenewLease(ctx context.Context, key, leaseID string) error
	// ReleaseLease gives a lease up.
	ReleaseLease(ctx context.Context, key, leaseID string) error
}

// Default lease timings of an ObjectStore: a holder renews its lease every
// third of its TTL, so it survives two failed renewals in a row.
const (
	DefaultLeaseTTL = 60 * time.Second
	// opTimeout bounds each call to the bucket, as the Store methods take
	// no context.
	opTimeout = 30 * time.Second
)

// ObjectStore is a Store in a Bucket: each job is the object <id>.json, and
// its lock a lease, held for LeaseTTL and renewed while held, as the object
// <id>.lease (or the bucket's native lease, for a LeaseBucket).
type ObjectStore struct {
	Bucket Bucket
	// LeaseTTL is how long a lease outlives its last renewal, so how long a
	// crashed holder keeps its jobs locked: DefaultLeaseTTL if zero.
	LeaseTTL time.Duration
	// Now is the clock; time.Now if nil. The lease objects' expiry is
	// compared against it, so holders' clocks must roughly agree.
	Now func() time.Time
}

// NewObjectStore returns an ObjectStore in b.
func NewObjectStore(b Bucket) *ObjectStore { return &ObjectStore{Bucket: b} }

func (s *ObjectStore) ttl() time.Duration {
	if s.LeaseTTL > 0 {
		return s.LeaseTTL
	}
	return DefaultLeaseTTL
}

func (s *ObjectStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

// Save writes j as <id>.json, conditionally on its version.
func (s *ObjectStore) Save(j *Job) error {
	if err := checkID(j.ID); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	ctx, cancel := opContext()
	defer cancel()
	v, err := s.Bucket.Put(ctx, j.ID+".json", b, j.version)
	if errors.Is(err, ErrPrecondition) || (j.version != "" && errors.Is(err, ErrObjectNotFound)) {
		return fmt.Errorf("%w: job %s", ErrConflict, j.ID)
	}
	if err != nil {
		return fmt.Errorf("jobs: saving job %s: %w", j.ID, err)
	}
	j.version = v
	return nil
}

// Load reads <id>.json.
func (s *ObjectStore) Load(id string) (*Job, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()
	b, v, err := s.Bucket.Get(ctx, id+".json")
	if errors.Is(err, ErrObjectNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("jobs: loading job %s: %w", id, err)
	}
	return decodeJob(id, b, v)
}

// List returns the IDs of the <id>.json objects.
func (s *ObjectStore) List() ([]string, error) {
	ctx, cancel := opContext()
	defer cancel()
	keys, err := s.Bucket.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("jobs: listing jobs: %w", err)
	}
	var ids []string
	for _, k := range keys {
		if id, ok := strings.CutSuffix(k, ".json"); ok && ValidID(id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// leaseRecord is the content of a lease object.
type leaseRecord struct {
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Lock takes the lease on the job: a fresh one, or one whose holder let it
// expire. The lease is renewed in the background until released or lost.
func (s *ObjectStore) Lock(id string) (Lease, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	key := id + ".lease"
	ctx, cancel := opContext()
	defer cancel()

	var renew func(ctx context.Context) error
	var release func(ctx context.Context)
	if lb, ok := s.Bucket.(LeaseBucket); ok {
		leaseID, err := lb.AcquireLease(ctx, key, s.ttl())
		if err != nil {
			return nil, err
		}
		renew = func(ctx context.Context) error { return lb.RenewLease(ctx, key, leaseID) }
		release = func(ctx context.Context) { _ = lb.ReleaseLease(ctx, key, leaseID) }
	} else {
		holder, err := newHolder()
		if err != nil {
			return nil, err
		}
		version, err := s.acquire(ctx, key, holder)
		if err != nil {
			return nil, err
		}
		var mu sync.Mutex
		renew = func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			b, err := json.Marshal(leaseRecord{Holder: holder, ExpiresAt: s.now().Add(s.ttl())})
			if err != nil {
				return err
			}
			v, err := s.Bucket.Put(ctx, key, b, version)
			if err == nil {
				version = v
			}
			return err
		}
		release = func(ctx context.Context) {
			mu.Lock()
			defer mu.Unlock()
			_ = s.Bucket.Delete(ctx, key, version)
		}
	}
	return startLease(s.ttl(), s.now, renew, release), nil
}

// acquire writes a lease object for holder, over none or an expired one.
func (s *ObjectStore) acquire(ctx context.Context, key, holder string) (string, error) {
	b, err := json.Marshal(leaseRecord{Holder: holder, ExpiresAt: s.now().Add(s.ttl())})
	if err != nil {
		return "", err
	}
	current, version, err := s.Bucket.Get(ctx, key)
	switch {
	case errors.Is(err, ErrObjectNotFound):
		version = ""
	case err != nil:
		return "", fmt.Errorf("jobs: reading lease %s: %w", key, err)
	default:
		var rec leaseRecord
		if err := json.Unmarshal(current, &rec); err == nil && rec.ExpiresAt.After(s.now()) {
			return "", ErrLocked
		}
	}
	v, err := s.Bucket.Put(ctx, key, b, version)
	if errors.Is(err, ErrPrecondition) {
		return "", ErrLocked
	}
	if err != nil {
		return "", fmt.Errorf("jobs: writing lease %s: %w", key, err)
	}
	return v, nil
}

func newHolder() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// renewedLease renews itself every third of its TTL, and is lost when a
// renewal is refused, or fails until the lease has expired.
type renewedLease struct {
	lost    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	release func(ctx context.Context)
}

func startLease(ttl time.Duration, now func() time.Time, renew func(ctx context.Context) error, release func(ctx context.Context)) *renewedLease {
	l := &renewedLease{lost: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{}), release: release}
	go func() {
		defer close(l.done)
		ticker := time.NewTicker(ttl / 3)
		defer ticker.Stop()
		expires := now().Add(ttl)
		for {
			select {
			case <-l.stop:
				return
			case <-ticker.C:
			}
			ctx, cancel := context.WithTimeout(context.Background(), ttl/3)
			err := renew(ctx)
			cancel()
			switch {
			case err == nil:
				expires = now().Add(ttl)
			case errors.Is(err, ErrPrecondition), errors.Is(err, ErrObjectNotFound), errors.Is(err, ErrLocked),
				!now().Before(expires):
				close(l.lost)
				return
			}
		}
	}()
	return l
}

func (l *renewedLease) Lost() <-chan struct{} { return l.lost }

func (l *renewedLease) Release() {
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		select {
		case <-l.lost:
			// Someone else holds it now: theirs to release.
		default:
			ctx, cancel := opContext()
			defer cancel()
			l.release(ctx)
		}
	})
}
