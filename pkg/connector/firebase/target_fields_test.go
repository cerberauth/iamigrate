package firebase_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportAppliesTargetFields(t *testing.T) {
	rec := &batchRecorder{}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	u := bcryptUser("u1")
	u.AppMetadata = map[string]any{"plan": "pro"}
	big := bcryptUser("big")
	big.UserMetadata = map[string]any{"bio": strings.Repeat("x", 1200)}
	m := mapping.Mapping{TargetFields: []mapping.TargetField{
		{CMF: "source_id", Target: "custom_claims.legacy_id"},
		{CMF: "emails.0.value", Target: "displayName"},
		{CMF: "user_metadata.bio", Target: "custom_claims.bio"},
	}}
	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(), writeUsers(t, []cmf.User{u, big}), m, connector.ImportOptions{})
	require.NoError(t, err)

	sent := rec.requests[0]["users"].([]any)[0].(map[string]any)
	require.Equal(t, "u1@example.com", sent["displayName"])
	var claims map[string]any
	require.NoError(t, json.Unmarshal([]byte(sent["customAttributes"].(string)), &claims))
	require.Equal(t, map[string]any{"plan": "pro", "legacy_id": "u1"}, claims, "merged with app_metadata's claims")

	require.Equal(t, []string{"u1"}, report.Succeeded)
	require.Equal(t, "big", report.Failed[0].SourceID)
	require.Contains(t, report.Failed[0].Message, "over Firebase's 1000")

	require.ErrorContains(t, (&firebase.Connector{}).CheckTargetField("custom_claims.sub"), "reserved")
}
