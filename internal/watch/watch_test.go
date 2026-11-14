package watch

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

// prefixBucket is a jobs.Bucket under a key prefix of another, as the
// store buckets are under the prefix of their URI.
type prefixBucket struct {
	*jobstest.MemBucket
	prefix string
}

func (b prefixBucket) Get(ctx context.Context, key string) ([]byte, string, error) {
	return b.MemBucket.Get(ctx, b.prefix+key)
}

func (b prefixBucket) ListObjects(ctx context.Context, prefix string) ([]jobs.Object, error) {
	objects, err := b.MemBucket.ListObjects(ctx, b.prefix+prefix)
	for i := range objects {
		objects[i].Key = strings.TrimPrefix(objects[i].Key, b.prefix)
	}
	return objects, err
}

// harness is a store, a runner on it, and the jobs started.
type harness struct {
	t      *testing.T
	runner *jobs.Runner
	mem    *jobstest.MemBucket

	mu      sync.Mutex
	started []string
}

func newHarness(t *testing.T) *harness {
	store, err := jobs.NewFileStore(t.TempDir())
	require.NoError(t, err)
	return &harness{t: t, runner: &jobs.Runner{Store: store}, mem: jobstest.NewMemBucket()}
}

func (h *harness) options() Options {
	return Options{
		Runner: h.runner,
		Start: func(id string) bool {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.started = append(h.started, id)
			return true
		},
		Validate: func(params map[string]string) error {
			if params["target"] == "" {
				return errors.New("param target is required")
			}
			if strings.Contains(params["users"], "refuse") {
				return errors.New("refused")
			}
			return nil
		},
		Buckets: map[string]jobs.BucketOpener{
			"mem": func(_ context.Context, u *url.URL) (jobs.Bucket, error) {
				return prefixBucket{MemBucket: h.mem, prefix: jobs.KeyPrefix(u)}, nil
			},
		},
	}
}

func (h *harness) startedJobs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.started...)
}

func (h *harness) put(key, data string) {
	h.t.Helper()
	ctx := context.Background()
	_, v, err := h.mem.Get(ctx, key)
	if errors.Is(err, jobs.ErrObjectNotFound) {
		v = ""
	}
	_, err = h.mem.Put(ctx, key, []byte(data), v)
	require.NoError(h.t, err)
}

func (h *harness) jobs() map[string]*jobs.Job {
	h.t.Helper()
	ids, err := h.runner.Store.List()
	require.NoError(h.t, err)
	out := map[string]*jobs.Job{}
	for _, id := range ids {
		j, err := h.runner.Store.Load(id)
		require.NoError(h.t, err)
		out[id] = j
	}
	return out
}

var testTemplate = &Template{Params: map[string]string{
	"target": "kratos",
	"users":  "${input}",
	"note":   "${uri}@${version} key=${key} job=${job} work=${work}",
}}

func openOne(t *testing.T, h *harness, wc WatcherConfig, opts Options) *Watcher {
	t.Helper()
	if wc.Name == "" {
		wc.Name = "test"
	}
	cfg := &Config{Version: 1, WorkDir: t.TempDir(), Watchers: []WatcherConfig{wc}}
	set, err := Open(context.Background(), cfg, map[string]*Template{wc.Name: testTemplate}, opts)
	require.NoError(t, err)
	return set.watchers[0]
}

func TestScanStartsOneJobPerObjectVersion(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.put("drops/users-1.cmf.jsonl", "one")
	h.put("drops/.hidden.cmf.jsonl", "hidden")
	h.put("drops/notes.txt", "not matched")
	h.put("elsewhere/users-9.cmf.jsonl", "outside the prefix")

	w := openOne(t, h, WatcherConfig{Bucket: "mem://bkt/drops/", Match: "*.cmf.jsonl"}, h.options())
	w.Scan(ctx)

	all := h.jobs()
	require.Len(t, all, 1)
	id := JobID("test", "mem://bkt/drops/users-1.cmf.jsonl", "1")
	j := all[id]
	require.NotNil(t, j, "the job ID is derived from the watcher, the object and its version")
	require.Equal(t, jobs.Queued, j.State)
	require.Equal(t, "kratos", j.Params["target"])
	work := filepath.Join(w.workDir, id)
	require.Equal(t, filepath.Join(work, "users-1.cmf.jsonl"), j.Params["users"])
	require.Equal(t, "mem://bkt/drops/users-1.cmf.jsonl@1 key=users-1.cmf.jsonl job="+id+" work="+work, j.Params["note"])
	b, err := os.ReadFile(j.Params["users"])
	require.NoError(t, err)
	require.Equal(t, "one", string(b), "the object is downloaded for the job")
	require.Equal(t, []string{id}, h.startedJobs())

	// Listed again, the same version starts nothing.
	w.Scan(ctx)
	require.Len(t, h.jobs(), 1)

	// A new version starts a new job.
	h.put("drops/users-1.cmf.jsonl", "one, rewritten")
	w.Scan(ctx)
	require.Len(t, h.jobs(), 2)

	st := w.Status()
	require.Equal(t, 2, st.JobsCreated)
	require.NotNil(t, st.LastCheckAt)
	require.Empty(t, st.LastError)
}

func TestScanDedupsAcrossRestartsAndReplicas(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.put("a.cmf.jsonl", "a")

	// Two replicas on the same store, or one restarted: each sees the
	// object, one job is created.
	first := openOne(t, h, WatcherConfig{Bucket: "mem://bkt"}, h.options())
	second := openOne(t, h, WatcherConfig{Bucket: "mem://bkt"}, h.options())
	first.Scan(ctx)
	second.Scan(ctx)
	require.Len(t, h.jobs(), 1)
	require.Len(t, h.startedJobs(), 1)
	require.Equal(t, 0, second.Status().JobsCreated)

	// A replica that finds the job missing at Load but loses the create
	// race doesn't start it either.
	h.put("b.cmf.jsonl", "b")
	id := JobID("test", "mem://bkt/b.cmf.jsonl", "2")
	_, err := h.runner.CreateWithID(id, map[string]string{"target": "kratos"})
	require.NoError(t, err)
	second.Scan(ctx)
	require.Len(t, h.jobs(), 2)
	require.Len(t, h.startedJobs(), 1)
}

func TestScanRecordsErrorsAndSkipsRefusedParams(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.put("refuse.cmf.jsonl", "x")
	w := openOne(t, h, WatcherConfig{Bucket: "mem://bkt"}, h.options())
	w.Scan(ctx)
	require.Empty(t, h.jobs())
	st := w.Status()
	require.Contains(t, st.LastError, "refuse.cmf.jsonl: job params refused: refused")
	require.NotNil(t, st.LastErrorAt)
	at := *st.LastErrorAt

	// Refused for good: not tried again until a restart.
	w.Scan(ctx)
	require.Equal(t, at, *w.Status().LastErrorAt)
}

func TestScanLocalDirectoryWaitsForFilesToSettle(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o700))
	p := filepath.Join(dir, "sub", "users.cmf.jsonl")
	require.NoError(t, os.WriteFile(p, []byte("partial"), 0o600))

	w := openOne(t, h, WatcherConfig{Bucket: dir}, h.options())
	w.Scan(ctx)
	require.Empty(t, h.jobs(), "a file is picked up once unchanged across two listings")

	require.NoError(t, os.WriteFile(p, []byte("complete"), 0o600))
	require.NoError(t, os.Chtimes(p, time.Now(), time.Now().Add(time.Second)))
	w.Scan(ctx)
	require.Empty(t, h.jobs())

	w.Scan(ctx)
	all := h.jobs()
	require.Len(t, all, 1)
	for _, j := range all {
		require.Equal(t, p, j.Params["users"], "a local file is read in place")
		require.True(t, strings.HasPrefix(j.Params["note"], "file://"))
	}
}

func TestOpenRefusesBadWatchers(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	open := func(wc WatcherConfig, workDir string, opts Options) error {
		wc.Name = "w"
		cfg := &Config{Version: 1, WorkDir: workDir, Watchers: []WatcherConfig{wc}}
		_, err := Open(context.Background(), cfg, map[string]*Template{"w": testTemplate}, opts)
		return err
	}
	require.ErrorContains(t, open(WatcherConfig{Bucket: "nope://b"}, dir, h.options()),
		`unsupported scheme "nope" (supported: a local directory, mem://)`)
	require.ErrorContains(t, open(WatcherConfig{Bucket: "mem://b", Queue: "sqs://q"}, dir, h.options()),
		`unsupported scheme "sqs" (no queue provider is available)`)
	require.ErrorContains(t, open(WatcherConfig{Bucket: "mem://user:pw@b"}, dir, h.options()), "credentials")
	require.ErrorContains(t, open(WatcherConfig{Bucket: dir}, filepath.Join(dir, "work"), h.options()), "inside the watched directory")

	opts := h.options()
	opts.Validate = func(map[string]string) error { return errors.New("no such target") }
	require.ErrorContains(t, open(WatcherConfig{Bucket: dir}, t.TempDir(), opts), "template: no such target")
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		return p
	}
	write("job.yaml", "params:\n  target: kratos\n  users: ${input}\n")
	p := write("watchers.yaml", `version: 1
watchers:
  - name: nightly
    bucket: drops/
    match: "*.gz"
    template: job.yaml
    interval: 5m
`)
	cfg, templates, err := LoadConfig(p)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "watch"), cfg.WorkDir, "relative to the file")
	w := cfg.Watchers[0]
	require.Equal(t, filepath.Join(dir, "drops"), w.Bucket)
	require.Equal(t, 5*time.Minute, w.Interval)
	require.Equal(t, "${input}", templates["nightly"].Params["users"])

	for content, want := range map[string]string{
		"version: 2\nwatchers: []\n": "version must be 1",
		"version: 1\nwatchers: []\n": "no watchers declared",
		"version: 1\nwatchers:\n  - {name: a, bucket: b, template: job.yaml}\n  - {name: a, bucket: b, template: job.yaml}\n": "declared twice",
		"version: 1\nwatchers:\n  - {name: 'a b', bucket: b, template: job.yaml}\n":                                           "watcher name",
		"version: 1\nwatchers:\n  - {name: a, template: job.yaml}\n":                                                          "bucket is required",
		"version: 1\nwatchers:\n  - {name: a, bucket: b, template: job.yaml, match: '['}\n":                                   "match",
		"version: 1\nwatchers:\n  - {name: a, bucket: ./b, template: job.yaml, queue: 'sqs://q'}\n":                           "no event notifications",
		"version: 1\nwatchers:\n  - {name: a, bucket: b, template: job.yaml, nope: 1}\n":                                      "field nope not found",
	} {
		_, _, err := LoadConfig(write("bad.yaml", content))
		require.ErrorContains(t, err, want, content)
	}
}

func TestTemplate(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"params:\n  users: ${input}\n  x: ${nope}\n": "unknown variable ${nope}",
		"params:\n  users: /fixed\n":                 "no param uses ${input}",
		"params: {}\n":                               "params are required",
	} {
		p := filepath.Join(dir, "t.yaml")
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		_, err := LoadTemplate(p)
		require.ErrorContains(t, err, want, content)
	}
	tpl := &Template{Params: map[string]string{"users": "${work}/users-${key}.jsonl", "in": "${input}"}}
	require.Equal(t, map[string]string{"users": "/w/users-k.jsonl", "in": "/i"},
		tpl.Expand(map[string]string{VarWork: "/w", VarKey: "k", VarInput: "/i"}))
}

func TestFileName(t *testing.T) {
	require.Equal(t, "users.csv", fileName("a/b/users.csv"))
	require.Equal(t, "object", fileName("a/.."))
	require.Equal(t, "a_b", fileName(`a\b`))
}
