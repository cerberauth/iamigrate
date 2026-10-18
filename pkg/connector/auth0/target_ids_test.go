package auth0_test

import (
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/stretchr/testify/require"
)

func TestRunBulkImportSendsAndRecordsTargetIDs(t *testing.T) {
	defer setFastPolling(t)()
	srv := newJobServer(t, nil)

	assigned := bcryptUser("u1")
	assigned.TargetIDs = map[string]string{"auth0": "legacy-1", "firebase": "ignored"}
	prefixed := bcryptUser("auth0|u2")
	users := []cmf.User{assigned, prefixed, bcryptUser("u3")}

	client := auth0.NewClient(srv.URL, "test-token")
	report, _, err := auth0.RunBulkImport(context.Background(), client, writeUsers(t, users), "conn_123", false)
	require.NoError(t, err)
	require.Equal(t, [][]string{{"legacy-1", "u2", "u3"}}, srv.submitted)
	require.Equal(t, map[string]string{
		"u1":       "auth0|legacy-1",
		"auth0|u2": "auth0|u2",
		"u3":       "auth0|u3",
	}, report.TargetIDs)
}

func TestValidateChecksTheAssignedUserID(t *testing.T) {
	u := bcryptUser("u1")
	u.TargetIDs = map[string]string{"auth0": ""}
	require.Empty(t, (&auth0.Connector{}).ValidateUser(u), "an empty assignment falls back to the source ID")

	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	u.TargetIDs = map[string]string{"auth0": string(long)}
	ps := (&auth0.Connector{}).ValidateUser(u)
	require.Len(t, ps, 1)
	require.Equal(t, "target_ids.auth0", ps[0].Field)
}
