package kratos_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func bcryptUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
		Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
	}
}

func writeUsers(t *testing.T, users []cmf.User) *cmf.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	return r
}

func TestConnectorImport(t *testing.T) {
	var created []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		created = append(created, body)

		if body["traits"].(map[string]any)["email"] == "dup@example.com" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": "conflict"}})
			return
		}

		body["id"] = fmt.Sprintf("id-%d", len(created))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := kratos.NewClient(server.URL)
	target := kratos.New(client, "default")

	users := []cmf.User{bcryptUser("u1")}
	dup := bcryptUser("dup")
	dup.SourceID = "dup"
	dup.Emails = []cmf.Contact{{Value: "dup@example.com", Verified: true, Primary: true}}
	users = append(users, dup)

	report, err := target.Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"u1"}, report.Succeeded)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "dup", report.Failed[0].SourceID)
	require.Len(t, created, 2)
}

func TestConnectorExportPaginates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page_token")
		w.Header().Set("Content-Type", "application/json")
		if page == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/admin/identities?page_token=2>; rel="next"`, "http://ignored-host"))
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id":     "id-1",
					"traits": map[string]any{"email": "u1@example.com"},
					"state":  "active",
					"credentials": map[string]any{
						"password": map[string]any{"config": map[string]any{"hashed_password": "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW"}},
					},
				},
			})
			return
		}
		require.Equal(t, "2", page)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":     "id-2",
				"traits": map[string]any{"email": "u2@example.com"},
				"state":  "inactive",
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := kratos.NewClient(server.URL)
	source := kratos.New(client, "default")

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := source.Export(context.Background(), w, kratos.ExportOptions{})
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 2, manifest.RecordCount)

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	u1, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "id-1", u1.SourceID)
	require.NotNil(t, u1.Password)

	u2, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "id-2", u2.SourceID)
	require.True(t, u2.Blocked)
}

func TestConnectorVerify(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("credentials_identifier") {
		case "u1@example.com":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "id-1", "state": "active"}})
		default:
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := kratos.NewClient(server.URL)
	target := kratos.New(client, "default")

	users := []cmf.User{bcryptUser("u1"), bcryptUser("u2")}
	report, err := target.Verify(context.Background(), writeUsers(t, users))
	require.NoError(t, err)
	require.Equal(t, []string{"u2"}, report.MissingInTarget)
}

func TestConnectorVerifyFallsBackToUsernameAndPhone(t *testing.T) {
	var lookups []string
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		identifier := r.URL.Query().Get("credentials_identifier")
		lookups = append(lookups, identifier)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": identifier, "state": "active"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	byUsername := bcryptUser("by-username")
	byUsername.Emails = nil
	byUsername.Username = "jane.doe"
	byPhone := bcryptUser("by-phone")
	byPhone.Emails = nil
	byPhone.Phones = []cmf.Contact{{Value: "+12025550142"}}
	none := bcryptUser("none")
	none.Emails = nil

	target := kratos.New(kratos.NewClient(server.URL), "default")
	report, err := target.Verify(context.Background(), writeUsers(t, []cmf.User{byUsername, byPhone, none}))
	require.NoError(t, err)
	require.Equal(t, []string{"jane.doe", "+12025550142"}, lookups)
	require.Empty(t, report.MissingInTarget)
	require.Equal(t, []string{"none"}, report.NoIdentifier)
}
