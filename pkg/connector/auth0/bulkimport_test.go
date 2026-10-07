package auth0_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

// jobServer is a fake Management API whose Nth import job (1-based) gets
// the status in statuses, and whose submit/poll handlers can be told to
// fail first.
type jobServer struct {
	*httptest.Server

	mu             sync.Mutex
	submitted      [][]string // user_ids per submitted job
	completedEmail []string
	statuses       map[int]string
	failSubmits    int32 // leading submits answered 429
	failPolls      int32 // leading polls answered 503
}

func newJobServer(t *testing.T, statuses map[int]string) *jobServer {
	t.Helper()
	s := &jobServer{statuses: statuses}

	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-imports", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&s.failSubmits, -1) >= 0 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		require.NoError(t, r.ParseMultipartForm(10<<20))
		file, _, err := r.FormFile("users")
		require.NoError(t, err)
		defer file.Close()
		var users []map[string]any
		require.NoError(t, json.NewDecoder(file).Decode(&users))

		ids := make([]string, 0, len(users))
		for _, u := range users {
			ids = append(ids, u["user_id"].(string))
		}
		s.mu.Lock()
		s.submitted = append(s.submitted, ids)
		s.completedEmail = append(s.completedEmail, r.FormValue("send_completion_email"))
		n := len(s.submitted)
		s.mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("job_%d", n), "status": "pending"})
	})
	mux.HandleFunc("/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&s.failPolls, -1) >= 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/errors") {
			_, _ = w.Write([]byte("[]"))
			return
		}
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/jobs/job_"))
		require.NoError(t, err)
		status := "completed"
		if st, ok := s.statuses[n]; ok {
			status = st
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func manyUsers(n int) []cmf.User {
	users := make([]cmf.User, n)
	for i := range users {
		users[i] = bcryptUser(fmt.Sprintf("u%04d", i))
	}
	return users
}

func TestRunBulkImportDisablesCompletionEmail(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)

	client := auth0.NewClient(srv.URL, "test-token")
	_, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, manyUsers(2)), "conn_123", false)
	require.NoError(t, err)
	require.Equal(t, []string{"false"}, srv.completedEmail)
}

func TestRunBulkImportFailedJobDoesNotAbortRemainingChunks(t *testing.T) {
	defer setFastPolling(t)()
	// 1001 users: the 1000-user cap splits them into two jobs, the first of
	// which fails.
	srv := newJobServer(t, map[int]string{1: "failed"})

	client := auth0.NewClient(srv.URL, "test-token")
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, manyUsers(1001)), "conn_123", false)
	require.NoError(t, err)

	require.Len(t, srv.submitted, 2)
	require.Len(t, report.Failed, 1000)
	require.Equal(t, auth0.JobFailedCode, report.Failed[0].Code)
	require.Equal(t, []string{"u1000"}, report.Succeeded)
}

func TestRunBulkImportRetriesTransientPollFailures(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)
	srv.failPolls = 2

	client := auth0.NewClient(srv.URL, "test-token")
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, manyUsers(2)), "conn_123", false)
	require.NoError(t, err)
	require.Len(t, report.Succeeded, 2)
	require.Empty(t, report.Failed)
}

func TestRunBulkImportRetriesRateLimitedSubmit(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)
	srv.failSubmits = 2

	client := auth0.NewClient(srv.URL, "test-token")
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, manyUsers(2)), "conn_123", false)
	require.NoError(t, err)
	require.Len(t, srv.submitted, 1, "a retried 429 must not create a second job")
	require.Len(t, report.Succeeded, 2)
}

func TestRunBulkImportDoesNotRetryServerErrorOnSubmit(t *testing.T) {
	defer setFastPolling(t)()
	var submits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&submits, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	client := auth0.NewClient(srv.URL, "test-token")
	_, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, manyUsers(1)), "conn_123", false)
	require.Error(t, err)
	// The job may have been created before the 502, so resubmitting would
	// report every user as a duplicate.
	require.EqualValues(t, 1, atomic.LoadInt32(&submits))
}
