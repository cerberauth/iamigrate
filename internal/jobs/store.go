package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cerberauth/x/fsx"
)

// ErrNotFound is returned by Store.Load for an unknown job ID.
var ErrNotFound = errors.New("jobs: job not found")

// ErrInvalidID is returned for a job ID that can't name a job.
var ErrInvalidID = errors.New("jobs: invalid job id")

// ErrNotFailed is returned by Runner.Retry for a job that hasn't failed.
var ErrNotFailed = errors.New("jobs: only a failed job can be retried")

// ErrLocked is returned by Store.Lock for a job another Run already holds.
var ErrLocked = errors.New("jobs: job is being run by another process")

// ErrConflict is returned by Store.Save when the stored job is no longer the
// version the caller loaded: someone else wrote it in between.
var ErrConflict = errors.New("jobs: job was changed by another process")

// ErrLeaseLost is what a Run ends with when its lease on the job expired or
// was taken over: it stops before its next save, leaving the job to the new
// holder.
var ErrLeaseLost = errors.New("jobs: lost the lease on the job")

// Store persists jobs. Save must be durable and atomic: after a crash, Load
// returns either the previous or the new version of a job, never a torn one.
type Store interface {
	// Save writes j if the stored job is still the version j was loaded
	// at (or last saved as), and returns ErrConflict otherwise. A job that
	// was never loaded or saved is created, and conflicts with an existing
	// one. Save records the new version on j.
	Save(j *Job) error
	Load(id string) (*Job, error)
	// List returns the IDs of all the jobs, in no particular order.
	List() ([]string, error)
	// Lock claims the job for the caller without waiting, returning
	// ErrLocked if someone else holds it, so two runs never drive one job
	// at once. A lock must not outlive its holder: a crashed process
	// releases it, or its lease expires, or the job could never be resumed.
	Lock(id string) (Lease, error)
}

// Lease is a held Store lock.
type Lease interface {
	// Lost is closed when the lease is lost: it expired before its holder
	// could renew it, or another holder took it over. A lease that can't
	// be lost returns nil.
	Lost() <-chan struct{}
	// Release gives the lease up.
	Release()
}

// Version is the stored version of j that a Store's Save checks against,
// as last set by SetVersion: an opaque token, such as a hash or an ETag.
func (j *Job) Version() string { return j.version }

// SetVersion records the stored version of j, for a Store implementation.
func (j *Job) SetVersion(v string) { j.version = v }

// FileStore keeps each job as <dir>/<id>.json.
type FileStore struct {
	dir string
	// mu makes Save's check-and-write atomic within the process. Across
	// processes, every writer of an existing job holds its lock.
	mu sync.Mutex
}

// NewFileStore returns a FileStore in dir, creating it if needed.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

var validID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidID reports whether id can name a job.
func ValidID(id string) bool { return validID.MatchString(id) }

func checkID(id string) error {
	if !ValidID(id) {
		return fmt.Errorf("%w %q", ErrInvalidID, id)
	}
	return nil
}

func (s *FileStore) path(id string) (string, error) {
	if err := checkID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// contentVersion is the version of a stored job's bytes.
func contentVersion(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Save writes j to a temporary file and moves it into place, so a crash
// mid-write leaves the previous version intact.
func (s *FileStore) Save(j *Job) error {
	path, err := s.path(j.ID)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tmp := path + ".tmp"
	if err := fsx.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if j.version == "" {
		// Create: a link fails, atomically, if the job exists.
		err := os.Link(tmp, path)
		_ = os.Remove(tmp)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: job %s already exists", ErrConflict, j.ID)
		}
		if err != nil {
			return err
		}
	} else {
		current, err := fsx.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(tmp)
			return err
		}
		if err != nil || contentVersion(current) != j.version {
			_ = os.Remove(tmp)
			return fmt.Errorf("%w: job %s", ErrConflict, j.ID)
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	j.version = contentVersion(b)
	return nil
}

// Load reads the job with the given ID.
func (s *FileStore) Load(id string) (*Job, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	b, err := fsx.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeJob(id, b, contentVersion(b))
}

func decodeJob(id string, b []byte, version string) (*Job, error) {
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("jobs: decoding job %s: %w", id, err)
	}
	j.version = version
	return &j, nil
}

// List returns the IDs of the <id>.json files in the store's directory.
func (s *FileStore) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && !e.IsDir() && ValidID(id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Lock holds an exclusive file lock on <dir>/<id>.lock, a file of its own
// as Save replaces the job file on every write. The kernel releases it when
// the process dies, so the lease is never lost while the process lives.
func (s *FileStore) Lock(id string) (Lease, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(strings.TrimSuffix(path, ".json")+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLease{f: f}, nil
}

type fileLease struct {
	f    *os.File
	once sync.Once
}

func (*fileLease) Lost() <-chan struct{} { return nil }

func (l *fileLease) Release() {
	l.once.Do(func() {
		_ = unlockFile(l.f)
		l.f.Close()
	})
}
