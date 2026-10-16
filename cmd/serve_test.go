package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// syncBuffer is a bytes.Buffer safe to read while a command writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeKratosAdmin accepts every identity it is given and finds them again by
// email, as a Kratos Admin API would.
func fakeKratosAdmin(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var (
		mu     sync.Mutex
		emails = map[string]bool{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			var body struct {
				Traits map[string]any `json:"traits"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			email, _ := body.Traits["email"].(string)
			emails[email] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "id-" + email, "traits": body.Traits})
			return
		}
		found := []map[string]any{}
		if id := r.URL.Query().Get("credentials_identifier"); emails[id] {
			found = append(found, map[string]any{"id": "id-" + id, "state": "active"})
		}
		_ = json.NewEncoder(w).Encode(found)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(emails)
	}
}

// runCLI runs the iamigrate command line to completion and returns its
// standard output.
func runCLI(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	require.NoError(t, root.Execute(), strings.Join(args, " "))
	return out.String()
}

// startServe runs `serve` on a free port, with its jobs kept in dir, until
// the test ends, and returns its URL.
func startServe(t *testing.T, dir string) string {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	out := &syncBuffer{}
	root := newRootCmd()
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"serve", "--listen", "127.0.0.1:0", "--dir", dir})
	served := make(chan error, 1)
	go func() { served <- root.ExecuteContext(ctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-served:
			require.NoError(t, err)
		case <-time.After(15 * time.Second):
			t.Error("serve did not stop")
		}
	})

	var apiURL string
	require.Eventually(t, func() bool {
		first, _, _ := strings.Cut(out.String(), "\n")
		line, ok := strings.CutPrefix(first, "listening on ")
		apiURL = line
		return ok
	}, 5*time.Second, 10*time.Millisecond)
	return apiURL
}

func TestServeRunsTestdataImportJobOverHTTP(t *testing.T) {
	const count = 5
	work := t.TempDir()
	runCLI(t, "testdata", "generate", "--count", "5", "--hash", "bcrypt:cost=4", "--no-gzip", "--no-answer-key", "--out", work)
	users := filepath.Join(work, "users.cmf.jsonl")

	kratosSrv, imported := fakeKratosAdmin(t)

	apiURL := startServe(t, filepath.Join(work, "server-jobs"))

	// Submit the job over HTTP: an import from the generated users file.
	id := strings.TrimSpace(runCLI(t, "job", "--api-url", apiURL, "create",
		"--target", "kratos", "--admin-url", kratosSrv.URL, "--users", users))
	require.NotEmpty(t, id)

	// Poll to completion; `job run` does that against a server.
	runOut := runCLI(t, "job", "--api-url", apiURL, "run", id)
	require.Contains(t, runOut, "job "+id+": done")
	require.Equal(t, count, imported())

	var report struct {
		State  string `json:"state"`
		Import struct {
			Succeeded []string `json:"succeeded"`
		} `json:"import"`
		Verify struct {
			SourceCount int `json:"source_count"`
			TargetCount int `json:"target_count"`
		} `json:"verify"`
	}
	require.NoError(t, json.Unmarshal([]byte(runCLI(t, "job", "--api-url", apiURL, "report", id)), &report))
	require.Equal(t, "done", report.State)
	require.Len(t, report.Import.Succeeded, count)
	require.Equal(t, count, report.Verify.TargetCount)

	// The job lives in the server's directory, not the CLI's.
	status := runCLI(t, "job", "--api-url", apiURL, "status", id)
	require.Contains(t, status, "job "+id+": done")
}

func TestServeRefusesNonLoopbackWithoutToken(t *testing.T) {
	t.Setenv(envAPIToken, "")
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"serve", "--listen", "0.0.0.0:0", "--dir", t.TempDir()})
	require.ErrorContains(t, root.Execute(), envAPIToken)
}

func TestRetryOverHTTPRunsAFailedJobAgain(t *testing.T) {
	work := t.TempDir()
	users := filepath.Join(work, "users.cmf.jsonl")
	kratosSrv, imported := fakeKratosAdmin(t)
	apiURL := startServe(t, filepath.Join(work, "server-jobs"))

	// The users file doesn't exist yet, so validation fails the job.
	id := strings.TrimSpace(runCLI(t, "job", "--api-url", apiURL, "create",
		"--target", "kratos", "--admin-url", kratosSrv.URL, "--users", users))
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"job", "--api-url", apiURL, "run", id})
	require.ErrorContains(t, root.Execute(), "failed while validating")

	runCLI(t, "testdata", "generate", "--count", "3", "--hash", "bcrypt:cost=4", "--no-gzip", "--no-answer-key", "--out", work)
	require.Contains(t, runCLI(t, "job", "--api-url", apiURL, "retry", id), "job "+id+": validating")
	require.Contains(t, runCLI(t, "job", "--api-url", apiURL, "run", id), "job "+id+": done")
	require.Equal(t, 3, imported())
}

func TestServeResumesUnfinishedJobsOnStart(t *testing.T) {
	work := t.TempDir()
	runCLI(t, "testdata", "generate", "--count", "3", "--hash", "bcrypt:cost=4", "--no-gzip", "--no-answer-key", "--out", work)
	kratosSrv, imported := fakeKratosAdmin(t)

	// A job queued by a server that went away before running it.
	dir := filepath.Join(work, "server-jobs")
	runner, err := openJobRunner(dir)
	require.NoError(t, err)
	j, err := runner.Create(map[string]string{
		"target": "kratos", "admin_url": kratosSrv.URL, "users": filepath.Join(work, "users.cmf.jsonl"),
	})
	require.NoError(t, err)

	apiURL := startServe(t, dir)
	require.Contains(t, runCLI(t, "job", "--api-url", apiURL, "run", j.ID), "job "+j.ID+": done")
	require.Equal(t, 3, imported())
}
