package firebase_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportUsesAndRecordsTheAssignedUID(t *testing.T) {
	rec := &batchRecorder{reject: map[string]string{"uid-dup": "DUPLICATE_LOCAL_ID"}}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	assigned := bcryptUser("u1")
	assigned.TargetIDs = map[string]string{"firebase": "uid-1"}
	dup := bcryptUser("u2")
	dup.TargetIDs = map[string]string{"firebase": "uid-dup"}
	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{assigned, dup, bcryptUser("u3")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	var sent []string
	for _, u := range rec.requests[0]["users"].([]any) {
		sent = append(sent, u.(map[string]any)["localId"].(string))
	}
	require.Equal(t, []string{"uid-1", "uid-dup", "u3"}, sent)
	require.Equal(t, map[string]string{"u1": "uid-1", "u3": "u3"}, report.TargetIDs)
	require.Equal(t, "u2", report.Failed[0].SourceID)
}

func TestValidateChecksTheAssignedUIDLength(t *testing.T) {
	u := bcryptUser("u1")
	u.TargetIDs = map[string]string{"firebase": strings.Repeat("x", 129)}
	ps := (&firebase.Connector{}).ValidateUser(u)
	require.Len(t, ps, 1)
	require.Equal(t, "target_ids.firebase", ps[0].Field)
}
