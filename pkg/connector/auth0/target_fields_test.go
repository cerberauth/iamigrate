package auth0_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestImportAppliesTargetFields(t *testing.T) {
	defer setFastPolling(t)()
	var payload []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/jobs/users-imports", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(10<<20))
		f, _, err := r.FormFile("users")
		require.NoError(t, err)
		b, _ := io.ReadAll(f)
		require.NoError(t, json.Unmarshal(b, &payload))
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "pending"})
	})
	mux.HandleFunc("/jobs/job_1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job_1", "status": "completed"})
	})
	mux.HandleFunc("/jobs/job_1/errors", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u := bcryptUser("u1")
	u.UserMetadata = map[string]any{"theme": "dark"}
	u.Profile.Locale = "FR"
	m := mapping.Mapping{TargetFields: []mapping.TargetField{
		{CMF: "profile.locale", Target: "user_metadata.locale", Transform: "lowercase"},
		{CMF: "source_id", Target: "app_metadata.legacy_id"},
		{CMF: "emails.0.value", Target: "nickname"},
	}}
	_, err := auth0.New(auth0.NewClient(srv.URL, "t")).Import(context.Background(), writeUsers(t, []cmf.User{u}), m, connector.ImportOptions{ConnectionID: "con_1"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"theme": "dark", "locale": "fr"}, payload[0]["user_metadata"])
	require.Equal(t, map[string]any{"legacy_id": "u1"}, payload[0]["app_metadata"])
	require.Equal(t, "u1@example.com", payload[0]["nickname"])
	require.ErrorContains(t, (&auth0.Connector{}).CheckTargetField("email"), "auth0 can't set")
}
