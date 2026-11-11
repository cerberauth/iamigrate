package auth0_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

// fakeUsersServer serves Get User and Delete User for the user_ids in
// users, recording the ones deleted.
func fakeUsersServer(t *testing.T, users ...string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	live := map[string]bool{}
	for _, u := range users {
		live[u] = true
	}
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		mu.Lock()
		defer mu.Unlock()
		if !live[id] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"statusCode":404,"error":"Not Found","errorCode":"inexistent_user"}`))
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"` + id + `"}`))
		case http.MethodDelete:
			delete(live, id)
			deleted = append(deleted, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), deleted...)
	}
}

func deleteRequests(users ...cmf.User) []connector.DeleteRequest {
	reqs := make([]connector.DeleteRequest, len(users))
	for i, u := range users {
		reqs[i] = connector.DeleteRequest{User: u}
	}
	return reqs
}

// requestURIMatcher matches on method and path plus query, ignoring the
// host, which differs between recording and replay.
func requestURIMatcher(r *http.Request, i cassette.Request) bool {
	u, err := url.Parse(i.URL)
	return err == nil && r.Method == i.Method && r.URL.RequestURI() == u.RequestURI()
}

// TestDeleteUsersRecordedCassette records DeleteUsers against a fake
// tenant, then replays the cassette with no server at all.
func TestDeleteUsersRecordedCassette(t *testing.T) {
	restore := setFastPolling(t)
	defer restore()
	server, deleted := fakeUsersServer(t, "auth0|u1", "auth0|custom-2")
	defer server.Close()

	u2 := bcryptUser("u2")
	u2.TargetIDs = map[string]string{auth0.Name: "custom-2"}
	reqs := deleteRequests(bcryptUser("u1"), u2, bcryptUser("u3"))

	cassettePath := filepath.Join(t.TempDir(), "rollback")
	rec, err := recorder.New(cassettePath)
	require.NoError(t, err)
	rec.SetMatcher(requestURIMatcher)
	client := auth0.NewClient(server.URL, "test-token")
	client.HTTP = rec.GetDefaultClient()

	report, err := auth0.New(client).DeleteUsers(context.Background(), reqs, false)
	require.NoError(t, err)
	require.NoError(t, rec.Stop())

	want := connector.RollbackReport{
		Deleted: []connector.DeletedUser{
			{SourceID: "u1", TargetID: "auth0|u1"},
			{SourceID: "u2", TargetID: "auth0|custom-2"},
		},
		NotFound: []string{"u3"},
	}
	require.Equal(t, want, report)
	require.ElementsMatch(t, []string{"auth0|u1", "auth0|custom-2"}, deleted())

	replay, err := recorder.NewWithOptions(&recorder.Options{CassetteName: cassettePath, Mode: recorder.ModeReplayOnly})
	require.NoError(t, err)
	replay.SetMatcher(requestURIMatcher)
	defer replay.Stop()
	replayClient := auth0.NewClient("http://127.0.0.1:1", "test-token")
	replayClient.HTTP = replay.GetDefaultClient()

	replayReport, err := auth0.New(replayClient).DeleteUsers(context.Background(), reqs, false)
	require.NoError(t, err)
	require.Equal(t, want, replayReport)
}

func TestDeleteUsersUsesReportTargetID(t *testing.T) {
	server, deleted := fakeUsersServer(t, "auth0|from-report")
	defer server.Close()

	reqs := []connector.DeleteRequest{{User: bcryptUser("u1"), TargetID: "auth0|from-report"}}
	report, err := auth0.New(auth0.NewClient(server.URL, "test-token")).DeleteUsers(context.Background(), reqs, false)
	require.NoError(t, err)
	require.Equal(t, []connector.DeletedUser{{SourceID: "u1", TargetID: "auth0|from-report"}}, report.Deleted)
	require.Equal(t, []string{"auth0|from-report"}, deleted())
}

func TestDeleteUsersDryRunDeletesNothing(t *testing.T) {
	server, deleted := fakeUsersServer(t, "auth0|u1")
	defer server.Close()

	report, err := auth0.New(auth0.NewClient(server.URL, "test-token")).
		DeleteUsers(context.Background(), deleteRequests(bcryptUser("u1"), bcryptUser("u2")), true)
	require.NoError(t, err)
	require.True(t, report.DryRun)
	require.Equal(t, []connector.DeletedUser{{SourceID: "u1", TargetID: "auth0|u1"}}, report.Deleted)
	require.Equal(t, []string{"u2"}, report.NotFound)
	require.Empty(t, deleted())
}

func TestDeleteUsersReportsFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Insufficient scope, expected any of: delete:users"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	report, err := auth0.New(auth0.NewClient(server.URL, "test-token")).
		DeleteUsers(context.Background(), deleteRequests(bcryptUser("u1")), false)
	require.NoError(t, err)
	require.Empty(t, report.Deleted)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "u1", report.Failed[0].SourceID)
	require.Contains(t, report.Failed[0].Message, "delete:users")
}
