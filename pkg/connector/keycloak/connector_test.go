package keycloak_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
)

func pbkdf2User(t *testing.T, id string) cmf.User {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key := pbkdf2.Key([]byte("secret"), salt, 1000, 32, sha256.New)
	p, err := iamhash.Normalize("$pbkdf2-sha256$i=1000$"+base64.RawStdEncoding.EncodeToString(salt)+"$"+base64.RawStdEncoding.EncodeToString(key), iamhash.Hint{})
	require.NoError(t, err)
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Password:   &p,
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

// tokenHandler serves a password-grant token endpoint for admin/admin.
func tokenHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "password", r.PostForm.Get("grant_type"))
		require.Equal(t, "admin-cli", r.PostForm.Get("client_id"))
		require.Equal(t, "admin", r.PostForm.Get("username"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 60})
	}
}

func newTestClient(serverURL string) *keycloak.Client {
	return keycloak.NewClient(serverURL, "acme", &keycloak.Credentials{
		TokenURL: keycloak.TokenURL(serverURL, "master"),
		ClientID: "admin-cli",
		Username: "admin",
		Password: "admin",
	})
}

func TestConnectorImport(t *testing.T) {
	var created []map[string]any
	tokenRequests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		tokenHandler(t)(w, r)
	})
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		created = append(created, body)
		if body["username"] == "dup@example.com" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errorMessage":"User exists with same username"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	bcrypt := pbkdf2User(t, "bcrypt")
	bcrypt.Password = &cmf.Password{Algorithm: cmf.AlgBcrypt, Portable: true, Hash: cmf.HashValue{Value: "$2a$10$x", Encoding: cmf.EncodingUTF8}}
	users := []cmf.User{pbkdf2User(t, "u1"), pbkdf2User(t, "dup"), bcrypt}

	target := keycloak.New(newTestClient(server.URL))
	report, err := target.Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, report.Succeeded)
	require.Len(t, report.Failed, 2)
	require.Equal(t, "dup", report.Failed[0].SourceID)
	require.Equal(t, keycloak.UserExistsCode, report.Failed[0].Code)
	require.Equal(t, "bcrypt", report.Failed[1].SourceID)
	require.Equal(t, "TRANSLATION_ERROR", report.Failed[1].Code)

	// The bcrypt user never reaches the API, and the token is reused.
	require.Len(t, created, 2)
	require.Equal(t, 1, tokenRequests)
	require.Equal(t, "u1@example.com", created[0]["username"])
	creds := created[0]["credentials"].([]any)
	require.Len(t, creds, 1)
	require.Equal(t, "password", creds[0].(map[string]any)["type"])
	require.Contains(t, creds[0].(map[string]any)["credentialData"], `"algorithm":"pbkdf2-sha256"`)
}

func TestConnectorVerify(t *testing.T) {
	var lookups []string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", tokenHandler(t))
	mux.HandleFunc("/admin/realms/acme/users", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		require.Equal(t, "true", q.Get("exact"))
		lookups = append(lookups, q.Get("email")+q.Get("username"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case q.Get("email") == "u1@example.com":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "1", "enabled": true}})
		case q.Get("email") == "blocked@example.com":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "2", "enabled": true}})
		case q.Get("username") != "":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "3", "enabled": true}})
		default:
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	blocked := pbkdf2User(t, "blocked")
	blocked.Blocked = true
	byUsername := pbkdf2User(t, "by-username")
	byUsername.Emails = nil
	byUsername.Username = "jane.doe"
	byPhone := pbkdf2User(t, "by-phone")
	byPhone.Emails = nil
	byPhone.Phones = []cmf.Contact{{Value: "+12025550142"}}
	none := pbkdf2User(t, "none")
	none.Emails = nil

	users := []cmf.User{pbkdf2User(t, "u1"), pbkdf2User(t, "missing"), blocked, byUsername, byPhone, none}
	report, err := keycloak.New(newTestClient(server.URL)).Verify(context.Background(), writeUsers(t, users))
	require.NoError(t, err)
	require.Equal(t, []string{"u1@example.com", "missing@example.com", "blocked@example.com", "jane.doe", "+12025550142"}, lookups)
	require.Equal(t, []string{"missing"}, report.MissingInTarget)
	require.Equal(t, []connector.DriftEntry{{SourceID: "blocked", Fields: []string{"blocked"}}}, report.AttributeDrift)
	require.Equal(t, []string{"none"}, report.NoIdentifier)
}

// exportedUser is a user as `kc.sh export` writes it, with the argon2
// credential Keycloak 26 stored for the password "secret".
const exportedUser = `{
  "id": "a1",
  "username": "jane.doe",
  "email": "jane@example.com",
  "emailVerified": true,
  "firstName": "Jane",
  "lastName": "Doe",
  "enabled": false,
  "attributes": {"phoneNumber": ["+12025550142"], "phoneNumberVerified": ["true"], "plan": ["gold"], "tags": ["a", "b"]},
  "credentials": [
    {"type": "password", "secretData": "{\"value\":\"xKjWvB9+0sSP6wTqI1JoEI7w+iA0x9VDhPgmrOHRG80=\",\"salt\":\"LRScGShC7shkdoU5B1UgUQ==\",\"additionalParameters\":{}}", "credentialData": "{\"hashIterations\":5,\"algorithm\":\"argon2\",\"additionalParameters\":{\"hashLength\":[\"32\"],\"memory\":[\"7168\"],\"type\":[\"id\"],\"version\":[\"1.3\"],\"parallelism\":[\"1\"]}}"},
    {"type": "otp", "secretData": "{\"value\":\"JBSWY3DPEHPK3PXP\"}", "credentialData": "{\"subType\":\"totp\",\"digits\":6,\"period\":30,\"algorithm\":\"HmacSHA1\",\"counter\":0,\"secretEncoding\":\"BASE32\"}"},
    {"type": "webauthn", "userLabel": "YubiKey"}
  ]
}`

func TestConnectorExportDirectory(t *testing.T) {
	dir := t.TempDir()
	realm := `{"id": "acme", "realm": "acme", "users": [` + exportedUser + `], "clients": [{"clientId": "x"}]}`
	users := `{"realm": "acme", "users": [
	  {"id": "a2", "username": "service-account-x", "enabled": true, "serviceAccountClientLink": "x"},
	  {"id": "a3", "username": "legacy", "enabled": true, "credentials": [{"type": "password", "secretData": "{\"value\":\"AAAA\",\"salt\":\"AAAA\"}", "credentialData": "{\"hashIterations\":10,\"algorithm\":\"bcrypt\"}"}]}
	]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme-realm.json"), []byte(realm), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme-users-0.json"), []byte(users), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unrelated.json"), []byte(`[]`), 0o600))

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := keycloak.New(nil).Export(context.Background(), w, keycloak.ExportOptions{Path: dir})
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 1, manifest.RecordCount)
	require.Equal(t, map[cmf.Algorithm]int{cmf.AlgArgon2: 1}, manifest.HashAlgorithmCounts)
	require.Equal(t, map[cmf.MFAType]int{cmf.MFAWebAuthn: 1}, manifest.NonPortableMFACounts)
	require.Len(t, manifest.SkippedRecords, 2)
	require.Equal(t, "a2", manifest.SkippedRecords[0].SourceID)
	require.Equal(t, "a3", manifest.SkippedRecords[1].SourceID)

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()
	u, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "a1", u.SourceID)
	require.Equal(t, "jane.doe", u.Username)
	require.True(t, u.Blocked)
	require.Equal(t, []cmf.Contact{{Value: "jane@example.com", Verified: true, Primary: true}}, u.Emails)
	require.Equal(t, []cmf.Contact{{Value: "+12025550142", Verified: true, Primary: true}}, u.Phones)
	require.Equal(t, cmf.Profile{GivenName: "Jane", FamilyName: "Doe", Name: "Jane Doe"}, u.Profile)
	require.Equal(t, map[string]any{"plan": "gold", "tags": []any{"a", "b"}}, u.UserMetadata)
	require.Equal(t, cmf.AlgArgon2, u.Password.Algorithm)
	require.Len(t, u.MFAFactors, 2)
	require.Equal(t, cmf.MFAFactor{Type: cmf.MFATOTP, Value: "JBSWY3DPEHPK3PXP", Portable: true}, u.MFAFactors[0])
	require.Equal(t, cmf.MFAWebAuthn, u.MFAFactors[1].Type)
}

func TestConnectorExportRejectsMultiRealmFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "all.json")
	require.NoError(t, os.WriteFile(path, []byte(`[{"realm": "a"}, {"realm": "b"}]`), 0o600))

	w := cmf.NewWriter(&bytes.Buffer{})
	_, err := keycloak.New(nil).Export(context.Background(), w, keycloak.ExportOptions{Path: path})
	require.ErrorContains(t, err, "single realm object")
}
