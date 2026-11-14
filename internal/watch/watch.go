package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
)

// Options are what watchers need from the server they run in.
type Options struct {
	// Runner creates the jobs, in its Store.
	Runner *jobs.Runner
	// Start runs a job just created in the background.
	Start func(id string) bool
	// Validate, if set, checks a new job's params, as for POST /jobs.
	Validate func(params map[string]string) error
	// Buckets open remote buckets, by URI scheme. Each must return a
	// jobs.ObjectLister for a watcher that lists its bucket.
	Buckets map[string]jobs.BucketOpener
	// Queues open the queues of watchers that read event notifications,
	// by URI scheme.
	Queues map[string]QueueOpener
	// Logger is slog's default if nil.
	Logger *slog.Logger
	// Now is the clock; time.Now if nil.
	Now func() time.Time
}

// Status is what GET / shows of a watcher.
type Status struct {
	Name   string `json:"name"`
	Bucket string `json:"bucket"`
	Match  string `json:"match,omitempty"`
	// Queue is set for a watcher that reads event notifications instead
	// of listing its bucket.
	Queue string `json:"queue,omitempty"`
	// JobsCreated counts the jobs this watcher created since the server
	// started, LastJob being the latest.
	JobsCreated int    `json:"jobs_created"`
	LastJob     string `json:"last_job,omitempty"`
	// LastCheckAt is when the bucket was last listed, or the queue last
	// polled, successfully.
	LastCheckAt *time.Time `json:"last_check_at,omitempty"`
	// LastError is the latest error the watcher hit, at LastErrorAt. It
	// stays until another one replaces it: compare it with LastCheckAt.
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// Set is the watchers of a watchers file.
type Set struct {
	watchers []*Watcher
	wg       sync.WaitGroup
}

// Watcher creates a job from its template for each new object version in
// its bucket.
type Watcher struct {
	cfg      WatcherConfig
	template *Template
	workDir  string
	opts     Options
	log      *slog.Logger

	// The bucket: a local directory (dir), or a remote bucket at
	// scheme://host/prefix.
	dir                  *dirBucket
	bucket               jobs.Bucket
	lister               jobs.ObjectLister
	scheme, host, prefix string
	queue                Queue

	// seen are the job IDs known to exist (or to be refused for good),
	// not to look them up again.
	seen map[string]bool
	// settling are a local directory's files and the version they had at
	// the last listing: a file starts a job once unchanged across two.
	settling map[string]string

	mu     sync.Mutex
	status Status
}

// Open opens the bucket (and queue) of each watcher of cfg, and checks its
// template with opts.Validate.
func Open(ctx context.Context, cfg *Config, templates map[string]*Template, opts Options) (*Set, error) {
	if opts.Runner == nil || opts.Start == nil {
		return nil, errors.New("watch: Runner and Start are required")
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Set{}
	for _, wc := range cfg.Watchers {
		w := &Watcher{
			cfg: wc, template: templates[wc.Name], workDir: cfg.WorkDir, opts: opts,
			log: log.With("watcher", wc.Name), seen: map[string]bool{}, settling: map[string]string{},
			status: Status{Name: wc.Name, Bucket: wc.Bucket, Match: wc.Match, Queue: wc.Queue},
		}
		if w.template == nil {
			return nil, fmt.Errorf("watcher %q: no template", wc.Name)
		}
		if err := w.open(ctx); err != nil {
			return nil, fmt.Errorf("watcher %q: %w", wc.Name, err)
		}
		if opts.Validate != nil {
			if err := opts.Validate(w.template.Expand(sampleVars())); err != nil {
				return nil, fmt.Errorf("watcher %q: template: %w", wc.Name, err)
			}
		}
		s.watchers = append(s.watchers, w)
	}
	return s, nil
}

func sampleVars() map[string]string {
	return map[string]string{
		VarInput: "/watch/job/object", VarURI: "file:///watch/object", VarKey: "object",
		VarVersion: "1", VarWork: "/watch/job", VarJob: "job",
	}
}

func (w *Watcher) open(ctx context.Context) error {
	if isLocal(w.cfg.Bucket) {
		d, err := openDir(w.cfg.Bucket)
		if err != nil {
			return err
		}
		if within(w.workDir, d.dir) {
			return fmt.Errorf("work_dir %s is inside the watched directory %s: the jobs' outputs would start jobs", w.workDir, d.dir)
		}
		w.dir, w.bucket, w.lister = d, nil, d
		return nil
	}

	u, err := url.Parse(w.cfg.Bucket)
	if err != nil {
		return fmt.Errorf("bucket %q: %w", w.cfg.Bucket, err)
	}
	if u.User != nil || u.RawQuery != "" {
		return fmt.Errorf("bucket %q: credentials come from the environment, not the URI", w.cfg.Bucket)
	}
	open, ok := w.opts.Buckets[u.Scheme]
	if !ok {
		return fmt.Errorf("bucket %q: unsupported scheme %q (supported: a local directory%s)", w.cfg.Bucket, u.Scheme, schemeList(w.opts.Buckets))
	}
	if w.bucket, err = open(ctx, u); err != nil {
		return fmt.Errorf("bucket %q: %w", w.cfg.Bucket, err)
	}
	w.scheme, w.host, w.prefix = u.Scheme, u.Host, jobs.KeyPrefix(u)

	if w.cfg.Queue == "" {
		lister, ok := w.bucket.(jobs.ObjectLister)
		if !ok {
			return fmt.Errorf("bucket %q can't be listed with versions", w.cfg.Bucket)
		}
		w.lister = lister
		return nil
	}
	qu, err := url.Parse(w.cfg.Queue)
	if err != nil || qu.Scheme == "" {
		return fmt.Errorf("queue %q is not a URI", w.cfg.Queue)
	}
	openQueue, ok := w.opts.Queues[qu.Scheme]
	if !ok {
		if len(w.opts.Queues) == 0 {
			return fmt.Errorf("queue %q: unsupported scheme %q (no queue provider is available)", w.cfg.Queue, qu.Scheme)
		}
		return fmt.Errorf("queue %q: unsupported scheme %q (supported: %s)", w.cfg.Queue, qu.Scheme, strings.TrimPrefix(schemeList(w.opts.Queues), ", "))
	}
	if w.queue, err = openQueue(ctx, qu); err != nil {
		return fmt.Errorf("queue %q: %w", w.cfg.Queue, err)
	}
	return nil
}

func schemeList[V any](m map[string]V) string {
	var out string
	for _, s := range slices.Sorted(maps.Keys(m)) {
		out += ", " + s + "://"
	}
	return out
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Run starts the watchers, until ctx is done.
func (s *Set) Run(ctx context.Context) {
	for _, w := range s.watchers {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			w.Run(ctx)
		}()
	}
}

// Wait blocks until the watchers Run started have returned.
func (s *Set) Wait() { s.wg.Wait() }

// Status returns the status of each watcher, in the file's order.
func (s *Set) Status() []Status {
	out := make([]Status, len(s.watchers))
	for i, w := range s.watchers {
		out[i] = w.Status()
	}
	return out
}

// Status returns the watcher's status.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *Watcher) interval() time.Duration {
	if w.cfg.Interval > 0 {
		return w.cfg.Interval
	}
	return DefaultInterval
}

func (w *Watcher) now() time.Time {
	if w.opts.Now != nil {
		return w.opts.Now().UTC()
	}
	return time.Now().UTC()
}

// Run watches until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	for ctx.Err() == nil {
		wait := w.interval()
		if w.queue != nil {
			switch n, err := w.Poll(ctx); {
			case err != nil:
			case n > 0:
				wait = 0
			default:
				// Receive long-polls; this only paces a queue that doesn't.
				wait = min(wait, time.Second)
			}
		} else {
			w.Scan(ctx)
		}
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
	}
}

// Scan lists the bucket once and starts a job for each new object version.
func (w *Watcher) Scan(ctx context.Context) {
	objects, err := w.lister.ListObjects(ctx, "")
	if err != nil {
		w.fail(fmt.Errorf("listing: %w", err))
		return
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a].Key < objects[b].Key })
	settling := map[string]string{}
	for _, o := range objects {
		if ctx.Err() != nil {
			return
		}
		if !w.matches(o.Key) {
			continue
		}
		if w.dir != nil {
			// A file being written changes between two listings; an object
			// in a remote bucket appears only once complete.
			settling[o.Key] = o.Version
			if w.settling[o.Key] != o.Version {
				continue
			}
		}
		if err := w.trigger(ctx, o.Key, o.Version); err != nil {
			if ctx.Err() != nil {
				return
			}
			var invalid *invalidJobError
			if errors.As(err, &invalid) {
				// The same params would be refused again.
				w.markSeen(invalid.id)
			}
			w.fail(fmt.Errorf("%s: %w", o.Key, err))
		}
	}
	w.settling = settling
	w.checked()
}

// Poll receives messages from the queue once and handles them, returning
// how many it received.
func (w *Watcher) Poll(ctx context.Context) (int, error) {
	msgs, err := w.queue.Receive(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.fail(fmt.Errorf("receiving: %w", err))
		}
		return 0, err
	}
	w.checked()
	for _, m := range msgs {
		if ctx.Err() != nil {
			// Not acknowledged: redelivered once its visibility ends.
			break
		}
		w.handle(ctx, m)
	}
	return len(msgs), nil
}

// handle starts the jobs a message notifies of and acknowledges it once
// they are all in the store, or hands it back if one can't be.
func (w *Watcher) handle(ctx context.Context, m Message) {
	if err := w.handleMessage(ctx, m); err != nil {
		if ctx.Err() != nil {
			return
		}
		w.fail(fmt.Errorf("message %s: %w", m.ID(), err))
		if err := m.Nack(ctx); err != nil {
			w.fail(fmt.Errorf("message %s: handing it back: %w", m.ID(), err))
		}
		return
	}
	if err := m.Ack(ctx); err != nil {
		// Redelivered, and then found to have its jobs already.
		w.fail(fmt.Errorf("message %s: acknowledging: %w", m.ID(), err))
	}
}

func (w *Watcher) handleMessage(ctx context.Context, m Message) error {
	events, err := parseNotification(m.Body(), m.Attributes())
	if err != nil {
		return err
	}
	for _, ev := range events {
		if ev.Scheme != w.scheme || ev.Bucket != w.host || !strings.HasPrefix(ev.Key, w.prefix) {
			// Another bucket's or prefix's object: not this watcher's.
			continue
		}
		key := strings.TrimPrefix(ev.Key, w.prefix)
		if !w.matches(key) {
			continue
		}
		version := ev.Version
		if version == "" {
			version = "message-" + m.ID()
		}
		if err := w.trigger(ctx, key, version); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

// matches reports whether the object at key is one the watcher starts
// jobs for: a file, not hidden, matching the watcher's pattern.
func (w *Watcher) matches(key string) bool {
	if key == "" || strings.HasSuffix(key, "/") {
		return false
	}
	base := path.Base(key)
	if strings.HasPrefix(base, ".") {
		return false
	}
	if w.cfg.Match == "" {
		return true
	}
	ok, _ := path.Match(w.cfg.Match, base)
	return ok
}

// invalidJobError is a job whose params the template expands to are
// refused: the same trigger would be again.
type invalidJobError struct {
	id  string
	err error
}

func (e *invalidJobError) Error() string { return "job params refused: " + e.err.Error() }
func (e *invalidJobError) Unwrap() error { return e.err }

// JobID is the ID of the job the watcher named watcher creates for the
// version of the object at uri.
func JobID(watcher, uri, version string) string {
	sum := sha256.Sum256([]byte(watcher + "\x00" + uri + "\x00" + version))
	return "w" + hex.EncodeToString(sum[:16])
}

// trigger creates and starts the job of an object version, unless it
// exists. It returns once the job is in the store.
func (w *Watcher) trigger(ctx context.Context, key, version string) error {
	version = strings.Trim(version, `"`)
	uri := w.objectURI(key)
	id := JobID(w.cfg.Name, uri, version)
	if w.isSeen(id) {
		return nil
	}
	store := w.opts.Runner.Store
	if _, err := store.Load(id); err == nil {
		w.markSeen(id)
		return nil
	} else if !errors.Is(err, jobs.ErrNotFound) {
		return err
	}

	work := filepath.Join(w.workDir, id)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	var input string
	if w.dir != nil {
		input = w.dir.path(key)
	} else {
		var err error
		if input, err = w.download(ctx, key, work); err != nil {
			return err
		}
	}
	params := w.template.Expand(map[string]string{
		VarInput: input, VarURI: uri, VarKey: key, VarVersion: version, VarWork: work, VarJob: id,
	})
	if w.opts.Validate != nil {
		if err := w.opts.Validate(params); err != nil {
			return &invalidJobError{id: id, err: err}
		}
	}
	if _, err := w.opts.Runner.CreateWithID(id, params); err != nil {
		if errors.Is(err, jobs.ErrConflict) {
			// Another replica got there first, and runs it.
			w.markSeen(id)
			return nil
		}
		return err
	}
	w.markSeen(id)
	w.mu.Lock()
	w.status.JobsCreated++
	w.status.LastJob = id
	w.mu.Unlock()
	w.log.Info("job created", "job", id, "object", uri, "version", version)
	w.opts.Start(id)
	return nil
}

// download copies the object at key into dir, through a temporary file so
// a job never sees a partial copy, and returns the copy's path.
func (w *Watcher) download(ctx context.Context, key, dir string) (string, error) {
	data, _, err := w.bucket.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	name := fileName(key)
	f, err := os.CreateTemp(dir, "."+name+".*.part")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	if err := os.Rename(f.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}

// fileName is the name an object's copy gets: the key's base name, made
// safe as a file name.
func fileName(key string) string {
	name := strings.ReplaceAll(path.Base(key), `\`, "_")
	if name == "." || name == ".." || name == "/" || name == "" {
		return "object"
	}
	return name
}

func (w *Watcher) objectURI(key string) string {
	if w.dir != nil {
		return (&url.URL{Scheme: "file", Path: filepath.ToSlash(w.dir.path(key))}).String()
	}
	return (&url.URL{Scheme: w.scheme, Host: w.host, Path: "/" + w.prefix + key}).String()
}

func (w *Watcher) isSeen(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen[id]
}

func (w *Watcher) markSeen(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen[id] = true
}

func (w *Watcher) checked() {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastCheckAt = &now
}

func (w *Watcher) fail(err error) {
	now := w.now()
	w.log.Error("watcher error", "error", err)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastError = err.Error()
	w.status.LastErrorAt = &now
}
