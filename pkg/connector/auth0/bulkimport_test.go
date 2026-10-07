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
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/mapping"
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
	jobErrors      []map[string]any
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
			if s.jobErrors == nil {
				_, _ = w.Write([]byte("[]"))
				return
			}
			_ = json.NewEncoder(w).Encode(s.jobErrors)
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

func TestRunBulkImportStripsAuth0PrefixFromUserID(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)
	srv.jobErrors = []map[string]any{{
		"user":   map[string]string{"user_id": "u2"},
		"errors": []map[string]string{{"code": auth0.DuplicatedUserCode, "message": "already exists"}},
	}}

	client := auth0.NewClient(srv.URL, "test-token")
	users := []cmf.User{bcryptUser("auth0|u1"), bcryptUser("auth0|u2"), bcryptUser("u3")}
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, users), "conn_123", false)
	require.NoError(t, err)

	// Auth0 adds the prefix back, so it must not be sent.
	require.Equal(t, [][]string{{"u1", "u2", "u3"}}, srv.submitted)
	// The report refers to users by the source IDs they came with.
	require.Equal(t, []string{"auth0|u1", "u3"}, report.Succeeded)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "auth0|u2", report.Failed[0].SourceID)
}

func TestImportAddressesOrgsAndRolesByFinalAuth0UserID(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)

	var mu sync.Mutex
	var paths []string
	orig := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/roles" || r.URL.Path == "/organizations"):
			_, _ = w.Write([]byte("[]"))
		case r.Method == http.MethodPost && (r.URL.Path == "/roles" || r.URL.Path == "/organizations"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "id_" + strings.TrimPrefix(r.URL.Path, "/")})
		case strings.HasPrefix(r.URL.Path, "/users/") || strings.HasPrefix(r.URL.Path, "/organizations/"):
			mu.Lock()
			paths = append(paths, r.URL.EscapedPath())
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			orig.ServeHTTP(w, r)
		}
	})

	withRoles := func(id string) cmf.User {
		u := bcryptUser(id)
		u.GlobalRoles = []string{"admin"}
		u.Memberships = []cmf.Membership{{Organization: "acme", Roles: []string{"admin"}}}
		return u
	}
	client := auth0.NewClient(srv.URL, "test-token")
	_, err := auth0.New(client).Import(context.Background(),
		writeUsers(t, []cmf.User{withRoles("auth0|u1"), withRoles("u2")}),
		mapping.Mapping{ConnectionID: "conn_123"},
		connector.ImportOptions{
			ConnectionID:  "conn_123",
			Roles:         []cmf.Role{{SourceID: "admin", Name: "admin"}},
			Organizations: []cmf.Organization{{SourceID: "acme", Name: "acme"}},
		})
	require.NoError(t, err)

	require.ElementsMatch(t, []string{
		"/users/auth0%7Cu1/roles",
		"/users/auth0%7Cu2/roles",
		"/organizations/id_organizations/members",
		"/organizations/id_organizations/members",
		"/organizations/id_organizations/members/auth0%7Cu1/roles",
		"/organizations/id_organizations/members/auth0%7Cu2/roles",
	}, paths)
}
