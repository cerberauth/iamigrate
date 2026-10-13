package firebase_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// The live tests come in two kinds, gated on different environments so
// they're silently skipped in ordinary `go test ./...` runs.
//
// Emulator tests (TestLiveFirebaseEmulator*) run against the Firebase Auth
// emulator (see .docker/firebase/docker-compose.yml). The emulator stores and
// returns imported password hashes but never verifies them, so these prove
// the wire contract -- request shapes, batching, pagination, lookup,
// duplicates, upsert, and that an export imports back unchanged -- and not
// that a hash translates correctly.
//
//	FIREBASE_AUTH_EMULATOR_HOST  e.g. 127.0.0.1:9099 (required)
//	FIREBASE_PROJECT_ID          default demo-iamigrate
//
// TestLiveFirebaseLogin runs against a real Firebase project, and is the only
// thing that proves a translated hash verifies: it signs in as every imported
// user. Use a disposable project; the test creates users under a unique uid
// prefix and deletes just those afterwards.
//
//	FIREBASE_PROJECT_ID              the project (required)
//	FIREBASE_API_KEY                 its Web API key, for signInWithPassword (required)
//	GOOGLE_APPLICATION_CREDENTIALS   a service account key file, or
//	FIREBASE_ACCESS_TOKEN            an OAuth2 access token (one required)
//
// It's skipped when FIREBASE_AUTH_EMULATOR_HOST is set.

const (
	defaultEmulatorProject = "demo-iamigrate"

	// vectorPassword is the cleartext behind vectorHash/vectorSalt/
	// vectorConfig (Firebase's own scrypt test vector).
	vectorPassword = "user1password"
)

// emulatorClient returns a client for the Auth emulator, or skips.
func emulatorClient(t *testing.T) *firebase.Client {
	t.Helper()
	host := os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")
	if host == "" {
		t.Skip("skipping live Firebase emulator test: FIREBASE_AUTH_EMULATOR_HOST not set")
	}
	project := os.Getenv("FIREBASE_PROJECT_ID")
	if project == "" {
		project = defaultEmulatorProject
	}
	return firebase.NewEmulatorClient(host, project)
}

// realClient returns a client for a real Firebase project plus its Web API
// key, or skips.
func realClient(t *testing.T) (*firebase.Client, string) {
	t.Helper()
	if os.Getenv("FIREBASE_AUTH_EMULATOR_HOST") != "" {
		t.Skip("skipping live Firebase project test: FIREBASE_AUTH_EMULATOR_HOST is set")
	}
	project, apiKey := os.Getenv("FIREBASE_PROJECT_ID"), os.Getenv("FIREBASE_API_KEY")
	if project == "" || apiKey == "" {
		t.Skip("skipping live Firebase project test: FIREBASE_PROJECT_ID/FIREBASE_API_KEY not both set")
	}

	creds := &firebase.Credentials{}
	switch {
	case os.Getenv("FIREBASE_ACCESS_TOKEN") != "":
		creds.AccessToken = os.Getenv("FIREBASE_ACCESS_TOKEN")
	case os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "":
		sa, err := firebase.LoadServiceAccount(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		require.NoError(t, err)
		creds.ServiceAccount = sa
	default:
		t.Skip("skipping live Firebase project test: neither GOOGLE_APPLICATION_CREDENTIALS nor FIREBASE_ACCESS_TOKEN set")
	}
	return firebase.NewClient(project, creds), apiKey
}

// adminPost sends a JSON POST to the project's accounts API (suffix is e.g.
// ":update"), returning the status and body.
func adminPost(ctx context.Context, c *firebase.Client, suffix string, body any) (int, []byte, error) {
	token, err := c.Credentials.Token(ctx, c.HTTP)
	if err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/projects/"+c.ProjectID+"/accounts"+suffix, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

// uniquePrefix returns a uid/email prefix no other run shares, so a test
// only ever touches (and deletes) its own users.
func uniquePrefix() string {
	return fmt.Sprintf("it%d_%04d_", time.Now().UnixNano(), rand.IntN(10000))
}

// deleteOnCleanup deletes the users with these uids once the test is done.
func deleteOnCleanup(t *testing.T, c *firebase.Client, uids func() []string) {
	t.Helper()
	t.Cleanup(func() {
		ids := uids()
		for len(ids) > 0 {
			n := min(len(ids), 1000)
			status, body, err := adminPost(context.Background(), c, ":batchDelete", map[string]any{"localIds": ids[:n], "force": true})
			if err != nil || status >= 300 {
				t.Logf("cleanup: deleting %d users failed (status %d): %v %s", n, status, err, body)
			}
			ids = ids[n:]
		}
	})
}

// liveUser returns a user with no password, an email, and a unique uid.
func liveUser(prefix, name string) cmf.User {
	u := bcryptUser(prefix + name)
	u.Password = nil
	u.Emails = []cmf.Contact{{Value: prefix + name + "@example.com", Verified: true, Primary: true}}
	return u
}

// phoneNumber returns a random E.164 number for the test to give one user.
func phoneNumber() string { return fmt.Sprintf("+1415%07d", rand.IntN(10_000_000)) }

func sourceIDs(users []cmf.User) func() []string {
	return func() []string {
		ids := make([]string, len(users))
		for i, u := range users {
			ids[i] = u.SourceID
		}
		return ids
	}
}

// exportPrefixed exports the whole project, and returns the users and
// skipped records under prefix, so other users in the project are ignored.
func exportPrefixed(t *testing.T, c *firebase.Client, prefix string, cfg *iamhash.FirebaseScryptConfig) (map[string]cmf.User, []connector.SkippedRecord) {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := firebase.New(c).Export(context.Background(), w, firebase.ExportOptions{Scrypt: cfg})
	require.NoError(t, err)
	require.NoError(t, w.Close())

	users := map[string]cmf.User{}
	for _, u := range readAll(t, buf.Bytes()) {
		if strings.HasPrefix(u.SourceID, prefix) {
			users[u.SourceID] = u
		}
	}
	var skipped []connector.SkippedRecord
	for _, s := range manifest.SkippedRecords {
		if strings.HasPrefix(s.SourceID, prefix) {
			skipped = append(skipped, s)
		}
	}
	return users, skipped
}

func importUsers(t *testing.T, c *firebase.Client, users []cmf.User, upsert bool) connector.ImportReport {
	t.Helper()
	report, err := firebase.New(c).Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{Upsert: upsert})
	require.NoError(t, err)
	return report
}

// countingTransport counts the requests that go through it per API method
// (":batchCreate", ":batchGet", ":lookup").
type countingTransport struct {
	base   http.RoundTripper
	mu     sync.Mutex
	counts map[string]int
}

func (ct *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if i := strings.LastIndex(req.URL.Path, ":"); i >= 0 {
		ct.mu.Lock()
		ct.counts[req.URL.Path[i:]]++
		ct.mu.Unlock()
	}
	return ct.base.RoundTrip(req)
}

func (ct *countingTransport) count(method string) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.counts[method]
}

func TestLiveFirebaseEmulatorRoundTrip(t *testing.T) {
	c := emulatorClient(t)
	prefix := uniquePrefix()

	enrolled := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)

	scrypt := firebaseScryptUser(t, prefix+"scrypt")
	scrypt.Profile = cmf.Profile{Name: "Ada Lovelace", Picture: "https://example.com/ada.png"}
	scrypt.AppMetadata = map[string]any{"plan": "pro", "beta": true, "seats": float64(3)}

	phoneOnly := liveUser(prefix, "phone")
	phoneOnly.Emails = nil
	phoneOnly.Phones = []cmf.Contact{{Value: phoneNumber(), Verified: true, Primary: true}}
	phoneOnly.Blocked = true

	withMFA := liveUser(prefix, "mfa")
	mfaPhone := phoneNumber()
	withMFA.Phones = []cmf.Contact{{Value: mfaPhone, Verified: true, Primary: true}}
	withMFA.MFAFactors = []cmf.MFAFactor{{Type: cmf.MFASMS, Value: mfaPhone, Portable: true, EnrolledAt: &enrolled}}

	unverified := liveUser(prefix, "unverified")
	unverified.Emails[0].Verified = false

	users := []cmf.User{scrypt, phoneOnly, withMFA, unverified}
	deleteOnCleanup(t, c, sourceIDs(users))

	// 1. Import everything.
	report := importUsers(t, c, users, false)
	require.Empty(t, report.Failed)
	require.ElementsMatch(t, sourceIDs(users)(), report.Succeeded)
	require.Empty(t, report.RequiresPasswordReset)
	require.Empty(t, report.RequiresReenrollment)

	// 2. Export it back, with the project's scrypt parameters.
	cfg := vectorConfig
	got, skipped := exportPrefixed(t, c, prefix, &cfg)
	require.Empty(t, skipped)
	require.Len(t, got, len(users))

	// 3. Every field the import wrote comes back unchanged.
	for _, want := range users {
		g, ok := got[want.SourceID]
		require.True(t, ok, "%s missing from export", want.SourceID)
		require.NoError(t, cmf.ValidateUser(g))
		require.Equal(t, want.Emails, g.Emails, want.SourceID)
		require.Equal(t, want.Blocked, g.Blocked, want.SourceID)
		require.Equal(t, want.Profile, g.Profile, want.SourceID)
		require.Equal(t, want.AppMetadata, g.AppMetadata, want.SourceID)
		require.Equal(t, firebase.Name, g.Provenance.SourceConnector)
		if len(want.Phones) > 0 {
			require.Equal(t, want.Phones[0].Value, g.Phones[0].Value, want.SourceID)
		}
	}

	// The scrypt hash and the project parameters survive byte for byte.
	p := got[scrypt.SourceID].Password
	require.NotNil(t, p)
	require.True(t, p.Portable)
	require.Equal(t, scrypt.Password.Hash, p.Hash)
	require.Equal(t, scrypt.Password.Salt, p.Salt)
	require.Equal(t, scrypt.Password.Key, p.Key)
	require.Equal(t, "firebase", p.Params["variant"])
	require.EqualValues(t, 8, p.Params["rounds"])
	require.EqualValues(t, 14, p.Params["mem_cost"])
	require.Equal(t, "Bw==", p.Params["salt_separator"])
	require.Nil(t, got[phoneOnly.SourceID].Password)

	// The SMS second factor round-trips with its enrollment date.
	require.Len(t, got[withMFA.SourceID].MFAFactors, 1)
	f := got[withMFA.SourceID].MFAFactors[0]
	require.Equal(t, cmf.MFASMS, f.Type)
	require.Equal(t, mfaPhone, f.Value)
	require.True(t, f.Portable)
	require.NotNil(t, f.EnrolledAt)
	require.True(t, enrolled.Equal(*f.EnrolledAt), "enrolled_at %s, want %s", f.EnrolledAt, enrolled)

	// 4. The export imports into the project again, as an upsert, and the
	// result is identical.
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, u := range got {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	report, err = firebase.New(c).Import(context.Background(), r, mapping.Mapping{}, connector.ImportOptions{Upsert: true})
	require.NoError(t, err)
	require.Empty(t, report.Failed)
	require.Len(t, report.Succeeded, len(users))

	again, skipped := exportPrefixed(t, c, prefix, &cfg)
	require.Empty(t, skipped)
	for id, u := range got {
		require.Equal(t, u.Emails, again[id].Emails, id)
		require.Equal(t, u.Password, again[id].Password, id)
		require.Equal(t, u.AppMetadata, again[id].AppMetadata, id)
		require.Equal(t, u.MFAFactors, again[id].MFAFactors, id)
	}
}

func TestLiveFirebaseEmulatorExportWithoutScryptConfig(t *testing.T) {
	c := emulatorClient(t)
	prefix := uniquePrefix()

	u := firebaseScryptUser(t, prefix+"scrypt")
	users := []cmf.User{u}
	deleteOnCleanup(t, c, sourceIDs(users))
	require.Empty(t, importUsers(t, c, users, false).Failed)

	got, skipped := exportPrefixed(t, c, prefix, nil)
	require.Empty(t, skipped)
	p := got[u.SourceID].Password
	require.NotNil(t, p)
	require.False(t, p.Portable, "a hash without the project's parameters can't be verified elsewhere")
	require.Nil(t, p.Key)
}

func TestLiveFirebaseEmulatorBatchingAndPagination(t *testing.T) {
	c := emulatorClient(t)
	ct := &countingTransport{base: c.HTTP.Transport, counts: map[string]int{}}
	c.HTTP.Transport = ct
	prefix := uniquePrefix()

	// One more than twice a page, so both import and export need to split.
	users := make([]cmf.User, 2*1000+5)
	for i := range users {
		users[i] = liveUser(prefix, fmt.Sprintf("u%04d", i))
	}
	deleteOnCleanup(t, c, sourceIDs(users))

	report := importUsers(t, c, users, false)
	require.Empty(t, report.Failed)
	require.Len(t, report.Succeeded, len(users))
	require.Equal(t, 3, ct.count(":batchCreate"), "users sharing a hash configuration are sent in batches of 1000")

	got, skipped := exportPrefixed(t, c, prefix, nil)
	require.Empty(t, skipped)
	require.Len(t, got, len(users), "every page of the export is read")
	require.GreaterOrEqual(t, ct.count(":batchGet"), 3, "the export follows nextPageToken")

	r := writeUsers(t, users)
	diff, err := firebase.New(c).Verify(context.Background(), r)
	require.NoError(t, err)
	require.Empty(t, diff.MissingInTarget)
	require.Empty(t, diff.AttributeDrift)
	require.Equal(t, len(users), ct.count(":lookup"))
}

func TestLiveFirebaseEmulatorDuplicatesAndUpsert(t *testing.T) {
	c := emulatorClient(t)
	prefix := uniquePrefix()

	users := []cmf.User{liveUser(prefix, "a"), liveUser(prefix, "b"), liveUser(prefix, "c")}
	deleteOnCleanup(t, c, sourceIDs(users))
	require.Empty(t, importUsers(t, c, users, false).Failed)

	// Without --upsert, an existing user is a failure with a code and a
	// message, and the other users in the batch don't notice.
	fresh := liveUser(prefix, "d")
	deleteOnCleanup(t, c, sourceIDs([]cmf.User{fresh}))
	report := importUsers(t, c, append(slices.Clone(users), fresh), false)
	require.Equal(t, []string{fresh.SourceID}, report.Succeeded)
	require.Len(t, report.Failed, len(users))
	for _, f := range report.Failed {
		require.NotEmpty(t, f.Code)
		require.NotEmpty(t, f.Message)
	}

	// With it, they're overwritten.
	changed := make([]cmf.User, len(users))
	for i, u := range users {
		u.Profile.Name = "Renamed " + u.SourceID
		u.Blocked = true
		changed[i] = u
	}
	report = importUsers(t, c, changed, true)
	require.Empty(t, report.Failed)
	require.Len(t, report.Succeeded, len(users))

	got, _ := exportPrefixed(t, c, prefix, nil)
	for _, u := range changed {
		require.Equal(t, u.Profile.Name, got[u.SourceID].Profile.Name)
		require.True(t, got[u.SourceID].Blocked)
	}
}

func TestLiveFirebaseEmulatorVerifyFindsDrift(t *testing.T) {
	c := emulatorClient(t)
	ctx := context.Background()
	prefix := uniquePrefix()

	intact := liveUser(prefix, "intact")
	disabled := liveUser(prefix, "disabled")
	unverified := liveUser(prefix, "unverified")
	gone := liveUser(prefix, "gone")
	phoneOnly := liveUser(prefix, "phone")
	phoneOnly.Emails = nil
	phoneOnly.Phones = []cmf.Contact{{Value: phoneNumber(), Verified: true, Primary: true}}
	nothing := liveUser(prefix, "nothing")
	nothing.Emails = nil

	imported := []cmf.User{intact, disabled, unverified, gone, phoneOnly}
	deleteOnCleanup(t, c, sourceIDs(imported))
	require.Empty(t, importUsers(t, c, imported, false).Failed)

	// Change the project behind iamigrate's back.
	for _, change := range []struct {
		suffix string
		body   map[string]any
	}{
		{":update", map[string]any{"localId": disabled.SourceID, "disableUser": true}},
		{":update", map[string]any{"localId": unverified.SourceID, "emailVerified": false}},
		{":batchDelete", map[string]any{"localIds": []string{gone.SourceID}, "force": true}},
	} {
		status, resp, err := adminPost(ctx, c, change.suffix, change.body)
		require.NoError(t, err)
		require.Less(t, status, 300, string(resp))
	}

	diff, err := firebase.New(c).Verify(ctx, writeUsers(t, []cmf.User{intact, disabled, unverified, gone, phoneOnly, nothing}))
	require.NoError(t, err)

	require.Equal(t, []string{gone.SourceID}, diff.MissingInTarget)
	require.Equal(t, []string{nothing.SourceID}, diff.NoIdentifier)
	require.Equal(t, []connector.DriftEntry{
		{SourceID: disabled.SourceID, Fields: []string{"blocked"}},
		{SourceID: unverified.SourceID, Fields: []string{"email_verified"}},
	}, diff.AttributeDrift)
}

// TestLiveFirebaseLogin imports users hashed with bcrypt, standard scrypt,
// and Firebase's own modified scrypt into a real project, then signs in as
// each with their cleartext password. The modified-scrypt user comes from
// Firebase's public test vector, so its password is known without ever
// seeing a project's signer key. See the file comment for the env vars.
func TestLiveFirebaseLogin(t *testing.T) {
	c, apiKey := realClient(t)
	ctx := context.Background()
	prefix := uniquePrefix()

	answerKeyPath := t.TempDir() + "/answer-key.json"
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := fixture.New().Export(ctx, w, fixture.ExportOptions{
		Count: 4,
		Hashes: []fixture.HashSpec{
			{Algorithm: cmf.AlgBcrypt, Params: map[string]string{"cost": "8"}},
			{Algorithm: cmf.AlgScrypt, Params: map[string]string{"cost": "16384", "blockSize": "8", "parallelization": "1", "keylen": "32"}},
		},
		Seed:          time.Now().UnixNano(),
		AnswerKeyPath: answerKeyPath,
	})
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Re-key the fixture users under the unique prefix, so they can be
	// deleted afterwards and can't collide with anything in the project.
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	var users []cmf.User
	logins := map[string]string{} // email -> password
	keyBytes, err := os.ReadFile(answerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(keyBytes, &key))
	passwords := map[string]string{}
	for _, e := range key.Entries {
		passwords[e.SourceID] = e.Password
	}
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		password := passwords[u.SourceID]
		u.SourceID = prefix + u.SourceID
		u.Emails = []cmf.Contact{{Value: u.SourceID + "@example.com", Verified: true, Primary: true}}
		u.Phones = nil
		u.MFAFactors = nil
		logins[u.Emails[0].Value] = password
		users = append(users, u)
	}
	require.NotEmpty(t, users)

	vector := firebaseScryptUser(t, prefix+"vector")
	logins[vector.Emails[0].Value] = vectorPassword
	users = append(users, vector)

	deleteOnCleanup(t, c, sourceIDs(users))
	report := importUsers(t, c, users, false)
	require.Empty(t, report.Failed, "import had failures: %+v", report.Failed)

	for email, password := range logins {
		t.Run(email, func(t *testing.T) {
			require.NoError(t, signIn(ctx, apiKey, email, password))
			require.Error(t, signIn(ctx, apiKey, email, password+"-wrong"), "a wrong password must not sign in")
		})
	}
}

// signIn signs email in with password through Firebase's public
// signInWithPassword endpoint, returning the server's error message if it's
// refused.
func signIn(ctx context.Context, apiKey, email, password string) error {
	body, err := json.Marshal(map[string]any{"email": email, "password": password, "returnSecureToken": true})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="+apiKey, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out struct {
		IDToken string `json:"idToken"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.IDToken == "" {
		return fmt.Errorf("sign in as %s refused (status %d): %s", email, resp.StatusCode, out.Error.Message)
	}
	return nil
}
