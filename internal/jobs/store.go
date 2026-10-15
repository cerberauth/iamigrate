package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cerberauth/x/fsx"
)

// ErrNotFound is returned by Store.Load for an unknown job ID.
var ErrNotFound = errors.New("jobs: job not found")

// ErrNotFailed is returned by Runner.Retry for a job that hasn't failed.
var ErrNotFailed = errors.New("jobs: only a failed job can be retried")

// ErrLocked is returned by Store.Lock for a job another Run already holds.
var ErrLocked = errors.New("jobs: job is being run by another process")

// Store persists jobs. Save must be durable and atomic: after a crash, Load
// returns either the previous or the new version of a job, never a torn one.
type Store interface {
	Save(j *Job) error
	Load(id string) (*Job, error)
	// Lock claims the job for the caller without waiting, returning
	// ErrLocked if someone else holds it, so two runs never drive one job
	// at once. A lock must not outlive its holder: a crashed process
	// releases it, or the job could never be resumed.
	Lock(id string) (unlock func(), err error)
}

// FileStore keeps each job as <dir>/<id>.json.
type FileStore struct {
	dir string
}

// NewFileStore returns a FileStore in dir, creating it if needed.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

var validID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (s *FileStore) path(id string) (string, error) {
	if !validID.MatchString(id) {
		return "", fmt.Errorf("jobs: invalid job id %q", id)
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Save writes j to a temporary file and renames it into place, so a crash
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
	tmp := path + ".tmp"
	if err := fsx.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("jobs: decoding job %s: %w", id, err)
	}
	return &j, nil
}

// Lock holds an exclusive file lock on <dir>/<id>.lock, a file of its own
// as Save replaces the job file on every write.
func (s *FileStore) Lock(id string) (func(), error) {
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
	return func() {
		_ = unlockFile(f)
		f.Close()
	}, nil
}
