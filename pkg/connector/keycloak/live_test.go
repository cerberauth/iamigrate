package keycloak_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// liveClientID is the public client, with direct access grants enabled,
// that setupRealm creates for the tests to log in through.
const liveClientID = "iamigrate-e2e"

// TestLiveKeycloakLogin is the gated, live-instance integration test:
// testdata generate -> import keycloak -> log in as every fixture user with
// their real password (and TOTP code, where enrolled) through the direct
// access grant, against a disposable Keycloak instance (see
// .docker/keycloak/docker-compose.yml). Each test creates, then deletes,
// its own realm.
//
// It only runs when KEYCLOAK_URL is set, so it's silently skipped in
// ordinary `go test ./...` runs.
//
// Env vars:
//
//	KEYCLOAK_URL             e.g. http://127.0.0.1:8080 (required)
//	KEYCLOAK_ADMIN_USERNAME  master realm admin (default: admin)
//	KEYCLOAK_ADMIN_PASSWORD  (default: admin)
func TestLiveKeycloakLogin(t *testing.T) {
	admin := newLiveAdmin(t)
	ctx := context.Background()

	users, key := generateFixture(t, []fixture.IdentifierSpec{
		{fixture.IdentifierEmail},
		{fixture.IdentifierUsername},
		{fixture.IdentifierPhone},
		{fixture.IdentifierEmail, fixture.IdentifierUsername, fixture.IdentifierPhone},
	})

	realm := admin.setupRealm(t)
	target := keycloak.New(admin.client(realm))
	importUsers(t, target, users)
	loginAll(t, admin.baseURL, realm, key)

	// diff finds every imported user by its identifier.
	diff, err := target.Verify(ctx, readerOf(t, users))
	require.NoError(t, err)
	require.Empty(t, diff.MissingInTarget)
	require.Empty(t, diff.NoIdentifier)
	require.Empty(t, diff.AttributeDrift)
}

// TestLiveKeycloakExportRoundTrip imports fixture users into one realm,
// exports that realm with `kc.sh export` inside the Keycloak container,
// exports the realm file to CMF, imports the result into a second realm,
// and logs in there: proving exported hashes and TOTP secrets survive the
// trip.
//
// On top of TestLiveKeycloakLogin's env vars, it needs:
//
//	KEYCLOAK_CONTAINER  the Keycloak container name, for `docker exec`
//	                    (iamigrate-keycloak with the compose file)
func TestLiveKeycloakExportRoundTrip(t *testing.T) {
	admin := newLiveAdmin(t)
	container := os.Getenv("KEYCLOAK_CONTAINER")
	if container == "" {
		t.Skip("skipping live Keycloak export test: KEYCLOAK_CONTAINER not set")
	}
	ctx := context.Background()

	users, key := generateFixture(t, []fixture.IdentifierSpec{
		{fixture.IdentifierEmail},
		{fixture.IdentifierUsername},
		{fixture.IdentifierPhone},
	})

	source := admin.setupRealm(t)
	importUsers(t, keycloak.New(admin.client(source)), users)

	exportPath := filepath.Join(t.TempDir(), "realm.json")
	kcExport(t, container, source, exportPath)

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := keycloak.New(nil).Export(ctx, w, keycloak.ExportOptions{Path: exportPath})
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, len(key.Entries), manifest.RecordCount, "skipped: %+v", manifest.SkippedRecords)

	// Every identifier comes back as it was imported.
	exported := map[string]bool{}
	r := readerOf(t, buf.Bytes())
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		exported["username:"+u.Username] = true
		for _, e := range u.Emails {
			exported["email:"+e.Value] = true
		}
		for _, p := range u.Phones {
			exported["phone:"+p.Value] = true
		}
	}
	for _, entry := range key.Entries {
		for kind, v := range map[string]string{"email": entry.Email, "username": entry.Username, "phone": entry.Phone} {
			if v != "" {
				require.True(t, exported[kind+":"+strings.ToLower(v)] || exported[kind+":"+v], "%s %s not exported", kind, v)
			}
		}
	}

	dest := admin.setupRealm(t)
	importUsers(t, keycloak.New(admin.client(dest)), buf.Bytes())
	loginAll(t, admin.baseURL, dest, key)
}

// generateFixture generates one user per identifier spec and hash
// algorithm Keycloak verifies natively, half of them TOTP-enrolled,
// returning the CMF bytes and the answer key.
func generateFixture(t *testing.T, identifiers []fixture.IdentifierSpec) ([]byte, fixture.AnswerKey) {
	t.Helper()
	hashes := []fixture.HashSpec{
		{Algorithm: cmf.AlgPBKDF2, Params: map[string]string{"digest": "sha256", "iterations": "1000"}},
		{Algorithm: cmf.AlgPBKDF2, Params: map[string]string{"digest": "sha512", "iterations": "1000", "keylen": "64"}},
		{Algorithm: cmf.AlgPBKDF2, Params: map[string]string{"digest": "sha1", "iterations": "1000", "keylen": "20"}},
		{Algorithm: cmf.AlgArgon2, Params: map[string]string{"memory": "7168", "time": "2", "parallelism": "1"}},
	}
	opts := fixture.ExportOptions{
		Count:         len(identifiers) * len(hashes),
		Hashes:        hashes,
		MFAs:          []fixture.MFASpec{{Type: cmf.MFATOTP, Rate: 0.5}},
		Identifiers:   identifiers,
		Seed:          time.Now().UnixNano(),
		AnswerKeyPath: filepath.Join(t.TempDir(), "answer-key.json"),
	}

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := fixture.New().Export(context.Background(), w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	b, err := os.ReadFile(opts.AnswerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(b, &key))
	return buf.Bytes(), key
}

func readerOf(t *testing.T, users []byte) *cmf.Reader {
	t.Helper()
	r, err := cmf.NewReader(bytes.NewReader(users))
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	return r
}

func importUsers(t *testing.T, target *keycloak.Connector, users []byte) {
	t.Helper()
	report, err := target.Import(context.Background(), readerOf(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Failed, "import had failures: %+v", report.Failed)
}

// loginAll logs in as every answer-key user with each identifier Keycloak
// accepts for them: their email, and their username -- which is the
// phone for a user with neither username nor email.
func loginAll(t *testing.T, baseURL, realm string, key fixture.AnswerKey) {
	t.Helper()
	for _, entry := range key.Entries {
		entry := entry
		t.Run(entry.SourceID, func(t *testing.T) {
			identifiers := []string{entry.Email, entry.Username}
			if entry.Email == "" && entry.Username == "" {
				identifiers = []string{entry.Phone}
			}
			for _, identifier := range identifiers {
				if identifier != "" {
					require.NoError(t, login(baseURL, realm, identifier, entry.Password, entry.TOTPSecret))
				}
			}
		})
	}
}

// login runs Keycloak's direct access grant (resource owner password
// credentials), which also checks a TOTP code for OTP-enrolled users.
func login(baseURL, realm, identifier, password, totpSecret string) error {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {liveClientID},
		"username":   {identifier},
		"password":   {password},
	}
	if totpSecret != "" {
		code, err := totp.GenerateCode(totpSecret, time.Now())
		if err != nil {
			return err
		}
		form.Set("totp", code)
	}

	resp, err := http.PostForm(keycloak.TokenURL(baseURL, realm), form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.AccessToken == "" {
		return fmt.Errorf("login for %s failed (status %d): %s: %s", identifier, resp.StatusCode, out.Error, out.ErrorDescription)
	}
	return nil
}

// kcExport runs `kc.sh export` for realm inside container and copies the
// realm file to dest. The export runs next to the live server, so its
// management interface is moved off the server's port.
func kcExport(t *testing.T, container, realm, dest string) {
	t.Helper()
	file := "/tmp/" + realm + ".json"
	out, err := exec.Command("docker", "exec", container, "/opt/keycloak/bin/kc.sh", "export",
		"--realm", realm, "--file", file, "--users", "same_file", "--http-management-port", "9001").CombinedOutput()
	require.NoError(t, err, "kc.sh export: %s", out)

	out, err = exec.Command("docker", "cp", container+":"+file, dest).CombinedOutput()
	require.NoError(t, err, "docker cp: %s", out)
	_ = exec.Command("docker", "exec", container, "rm", "-f", file).Run()
}

// liveAdmin is a master realm admin session on the live Keycloak.
type liveAdmin struct {
	baseURL string
	creds   *keycloak.Credentials
	http    *http.Client
}

func newLiveAdmin(t *testing.T) *liveAdmin {
	t.Helper()
	baseURL := os.Getenv("KEYCLOAK_URL")
	if baseURL == "" {
		t.Skip("skipping live Keycloak integration test: KEYCLOAK_URL not set")
	}
	username := envOr("KEYCLOAK_ADMIN_USERNAME", "admin")
	password := envOr("KEYCLOAK_ADMIN_PASSWORD", "admin")
	return &liveAdmin{
		baseURL: baseURL,
		creds: &keycloak.Credentials{
			TokenURL: keycloak.TokenURL(baseURL, "master"),
			ClientID: "admin-cli",
			Username: username,
			Password: password,
		},
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *liveAdmin) client(realm string) *keycloak.Client {
	return keycloak.NewClient(a.baseURL, realm, a.creds)
}

// setupRealm creates a uniquely named realm configured the way the
// connector's docs ask for, deleting it when t ends:
//   - unmanaged user attributes enabled, so phoneNumber and metadata
//     attributes are kept;
//   - the Verify Profile required action off, so users without an email or
//     name can log in without first completing their profile;
//   - TOTP codes reusable within their period;
//   - a public client with direct access grants, to log in through.
func (a *liveAdmin) setupRealm(t *testing.T) string {
	t.Helper()
	realm := fmt.Sprintf("iamigrate-%d", time.Now().UnixNano())

	a.do(t, http.MethodPost, "/admin/realms", map[string]any{
		"realm":   realm,
		"enabled": true,
		// loginAll logs a user in once per identifier, all within one
		// TOTP period. Keycloak only reads the OTP policy as a whole.
		"otpPolicyType":            "totp",
		"otpPolicyAlgorithm":       "HmacSHA1",
		"otpPolicyDigits":          6,
		"otpPolicyPeriod":          30,
		"otpPolicyLookAheadWindow": 1,
		"otpPolicyCodeReusable":    true,
		"clients": []map[string]any{{
			"clientId":                  liveClientID,
			"publicClient":              true,
			"directAccessGrantsEnabled": true,
			"standardFlowEnabled":       false,
		}},
	}, nil)
	t.Cleanup(func() { a.do(t, http.MethodDelete, "/admin/realms/"+realm, nil, nil) })

	a.do(t, http.MethodPut, "/admin/realms/"+realm+"/authentication/required-actions/VERIFY_PROFILE",
		map[string]any{"alias": "VERIFY_PROFILE", "enabled": false}, nil)

	var profile map[string]any
	a.do(t, http.MethodGet, "/admin/realms/"+realm+"/users/profile", nil, &profile)
	profile["unmanagedAttributePolicy"] = "ENABLED"
	a.do(t, http.MethodPut, "/admin/realms/"+realm+"/users/profile", profile, nil)

	return realm
}

func (a *liveAdmin) do(t *testing.T, method, path string, body, out any) {
	t.Helper()
	var reqBody bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&reqBody).Encode(body))
	}
	req, err := http.NewRequest(method, a.baseURL+path, &reqBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	token, err := a.creds.Token(context.Background(), a.http)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.http.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var msg bytes.Buffer
		_, _ = msg.ReadFrom(resp.Body)
		require.Failf(t, "admin request failed", "%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(msg.String()))
	}
	if out != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
