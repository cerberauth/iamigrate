package firebase_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	iamhash "github.com/cerberauth/iamigrate/pkg/hash"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

const (
	testProject = "acme-prod"

	// Reference vector from Firebase's scrypt implementation, see
	// pkg/hash/firebase_test.go.
	vectorHash = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ=="
	vectorSalt = "42xEC+ixf3L2lw=="
)

var vectorConfig = iamhash.FirebaseScryptConfig{
	SignerKey:     "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
	SaltSeparator: "Bw==",
	Rounds:        8,
	MemCost:       14,
}

func newTestClient(serverURL string) *firebase.Client {
	c := firebase.NewClient(testProject, &firebase.Credentials{AccessToken: "tok"})
	c.BaseURL = serverURL
	c.RetryDelay = time.Millisecond
	return c
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

func readAll(t *testing.T, data []byte) []cmf.User {
	t.Helper()
	r, err := cmf.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

func bcryptUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
		Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
	}
}

func firebaseScryptUser(t *testing.T, id string) cmf.User {
	t.Helper()
	p, err := iamhash.NormalizeFirebaseScrypt(vectorHash, vectorSalt, vectorConfig)
	require.NoError(t, err)
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Password:   &p,
		Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
	}
}

func TestCapabilities(t *testing.T) {
	caps := (&firebase.Connector{}).Capabilities()
	require.True(t, caps.SupportsAlgorithm(cmf.AlgBcrypt))
	require.True(t, caps.SupportsAlgorithm(cmf.AlgScrypt))
	require.False(t, caps.SupportsAlgorithm(cmf.AlgArgon2))
	require.True(t, caps.SupportsMFAType(cmf.MFASMS))
	require.False(t, caps.SupportsMFAType(cmf.MFATOTP))
	require.False(t, caps.SupportsOrgs)
	require.False(t, caps.SupportsRoles)
}

func TestExportPaginatesAndTranslates(t *testing.T) {
	var auth, ua []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/projects/"+testProject+"/accounts:batchGet", func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		ua = append(ua, r.Header.Get("User-Agent"))
		require.Equal(t, "1000", r.URL.Query().Get("maxResults"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("nextPageToken") {
		case "":
			// Firebase writes passwordHash and salt as URL-safe base64.
			hash, _ := base64.StdEncoding.DecodeString(vectorHash)
			salt, _ := base64.StdEncoding.DecodeString(vectorSalt)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{{
					"localId":          "uid-1",
					"email":            "ada@example.com",
					"emailVerified":    true,
					"displayName":      "Ada Lovelace",
					"photoUrl":         "https://example.com/ada.png",
					"passwordHash":     base64.URLEncoding.EncodeToString(hash),
					"salt":             base64.URLEncoding.EncodeToString(salt),
					"customAttributes": `{"plan":"pro"}`,
					"providerUserInfo": []map[string]any{{"providerId": "password"}},
					"mfaInfo": []map[string]any{
						{"phoneInfo": "+1******0123", "unobfuscatedPhoneInfo": "+14155550123", "enrolledAt": "2024-03-01T10:00:00Z"},
						{"totpInfo": map[string]any{}},
					},
				}},
				"nextPageToken": "page 2/&",
			})
		case "page 2/&":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"localId": "uid-2", "phoneNumber": "+14155550199", "disabled": true, "providerUserInfo": []map[string]any{{"providerId": "phone"}}},
					{"localId": "anon-1"},
					{"localId": "uid-3", "email": "grace@example.com", "passwordHash": "!!!", "salt": vectorSalt},
					{"localId": "uid-4", "email": "bad@example.com", "customAttributes": "{nope"},
				},
			})
		default:
			t.Errorf("unexpected page token %q", r.URL.Query().Get("nextPageToken"))
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	manifest, err := firebase.New(newTestClient(server.URL)).Export(context.Background(), w, firebase.ExportOptions{Scrypt: &vectorConfig})
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.Equal(t, []string{"Bearer tok", "Bearer tok"}, auth)
	for _, v := range ua {
		require.Regexp(t, `^iamigrate/\S+ \(\+https://github\.com/cerberauth/iamigrate\)$`, v)
	}

	require.Equal(t, 2, manifest.RecordCount)
	require.Equal(t, map[cmf.Algorithm]int{cmf.AlgScrypt: 1}, manifest.HashAlgorithmCounts)
	require.Equal(t, map[cmf.MFAType]int{cmf.MFATOTP: 1}, manifest.NonPortableMFACounts)
	require.Equal(t, []connector.SkippedRecord{
		{SourceID: "anon-1", Reason: "no email, phone number, or sign-in provider (anonymous or custom-token user)"},
		{SourceID: "uid-3", Reason: "unrecognized password hash format: hash: Firebase passwordHash is not valid base64"},
		{SourceID: "uid-4", Reason: manifest.SkippedRecords[2].Reason},
	}, manifest.SkippedRecords)
	require.Contains(t, manifest.SkippedRecords[2].Reason, "invalid customAttributes")

	users := readAll(t, buf.Bytes())
	require.Len(t, users, 2)

	ada := users[0]
	require.NoError(t, cmf.ValidateUser(ada))
	require.Equal(t, "uid-1", ada.SourceID)
	require.Equal(t, []cmf.Contact{{Value: "ada@example.com", Verified: true, Primary: true}}, ada.Emails)
	require.Equal(t, "Ada Lovelace", ada.Profile.Name)
	require.Equal(t, "https://example.com/ada.png", ada.Profile.Picture)
	require.Equal(t, map[string]any{"plan": "pro"}, ada.AppMetadata)
	require.Equal(t, firebase.Name, ada.Provenance.SourceConnector)

	// The hash and project parameters survive a CMF round trip intact.
	h, err := iamhash.ToFirebaseHash(*ada.Password)
	require.NoError(t, err)
	require.Equal(t, "SCRYPT", h.Params.HashAlgorithm)
	require.Equal(t, vectorConfig.SignerKey, h.Params.SignerKey)
	gotHash, err := base64.URLEncoding.DecodeString(h.PasswordHash)
	require.NoError(t, err)
	wantHash, _ := base64.StdEncoding.DecodeString(vectorHash)
	require.Equal(t, wantHash, gotHash)

	require.Len(t, ada.MFAFactors, 2)
	require.Equal(t, cmf.MFASMS, ada.MFAFactors[0].Type)
	require.Equal(t, "+14155550123", ada.MFAFactors[0].Value, "the unmasked number wins")
	require.True(t, ada.MFAFactors[0].Portable)
	require.NotNil(t, ada.MFAFactors[0].EnrolledAt)
	require.Equal(t, cmf.MFATOTP, ada.MFAFactors[1].Type)
	require.False(t, ada.MFAFactors[1].Portable)

	phoneUser := users[1]
	require.Equal(t, "uid-2", phoneUser.SourceID)
	require.True(t, phoneUser.Blocked)
	require.Equal(t, []cmf.Contact{{Value: "+14155550199", Verified: true, Primary: true}}, phoneUser.Phones)
	require.Nil(t, phoneUser.Password)
}

func TestExportWithoutScryptConfigMarksHashesNonPortable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []map[string]any{{"localId": "uid-1", "email": "ada@example.com", "passwordHash": "ab-_", "salt": vectorSalt}},
		})
	}))
	defer server.Close()

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := firebase.New(newTestClient(server.URL)).Export(context.Background(), w, firebase.ExportOptions{})
	require.NoError(t, err)
	require.NoError(t, w.Close())

	users := readAll(t, buf.Bytes())
	require.Len(t, users, 1)
	require.NoError(t, cmf.ValidateUser(users[0]))
	require.False(t, users[0].Password.Portable)
	require.Equal(t, "ab+/", users[0].Password.Hash.Value, "URL-safe base64 is rewritten as standard")
}

func TestExportRejectsInvalidScryptConfig(t *testing.T) {
	var buf bytes.Buffer
	_, err := firebase.New(newTestClient("http://unused")).Export(context.Background(), cmf.NewWriter(&buf),
		firebase.ExportOptions{Scrypt: &iamhash.FirebaseScryptConfig{SignerKey: vectorConfig.SignerKey, Rounds: 0, MemCost: 14}})
	require.ErrorContains(t, err, "rounds must be 1-8")
}

func TestExportAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"PERMISSION_DENIED"}}`, http.StatusForbidden)
	}))
	defer server.Close()

	var buf bytes.Buffer
	_, err := firebase.New(newTestClient(server.URL)).Export(context.Background(), cmf.NewWriter(&buf), firebase.ExportOptions{})
	var apiErr *firebase.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

// batchRecorder serves accounts:batchCreate, recording each request and
// rejecting the entries reject names (by localId).
type batchRecorder struct {
	requests []map[string]any
	reject   map[string]string
}

func (b *batchRecorder) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/projects/"+testProject+"/accounts:batchCreate", r.URL.Path)
		var req map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		b.requests = append(b.requests, req)

		resp := map[string]any{}
		var errs []map[string]any
		for i, u := range req["users"].([]any) {
			if msg, ok := b.reject[u.(map[string]any)["localId"].(string)]; ok {
				errs = append(errs, map[string]any{"index": i, "message": msg})
			}
		}
		if errs != nil {
			resp["error"] = errs
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func TestImportGroupsUsersByHashConfiguration(t *testing.T) {
	rec := &batchRecorder{reject: map[string]string{"dup": "DUPLICATE_EMAIL : the email is in use"}}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	nonPortable := bcryptUser("reset")
	nonPortable.Password.Portable = false
	noPassword := bcryptUser("nopw")
	noPassword.Password = nil
	dup := bcryptUser("dup")
	noContact := bcryptUser("nocontact")
	noContact.Emails = nil
	sms := bcryptUser("mfa")
	sms.Phones = []cmf.Contact{{Value: "+14155550123", Verified: true}}
	now := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	sms.MFAFactors = []cmf.MFAFactor{
		{Type: cmf.MFASMS, Value: "+14155550123", Portable: true, EnrolledAt: &now},
		{Type: cmf.MFAWebAuthn, Value: "key", Portable: false},
	}
	sms.AppMetadata = map[string]any{"plan": "pro"}
	sms.Profile = cmf.Profile{GivenName: "Ada", FamilyName: "Lovelace", Picture: "https://example.com/a.png"}
	sms.Blocked = true

	users := []cmf.User{
		bcryptUser("b1"), firebaseScryptUser(t, "s1"), bcryptUser("b2"),
		nonPortable, noPassword, dup, noContact, sms,
	}
	target := firebase.New(newTestClient(server.URL))
	report, err := target.Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	// One request per distinct hash configuration: bcrypt (b1, b2, dup, mfa),
	// no hash (reset, nopw), Firebase scrypt (s1).
	require.Len(t, rec.requests, 3)
	byAlgo := map[string]map[string]any{}
	for _, req := range rec.requests {
		algo, _ := req["hashAlgorithm"].(string)
		byAlgo[algo] = req
		require.Equal(t, true, req["sanityCheck"])
		require.NotContains(t, req, "allowOverwrite")
	}
	require.Len(t, byAlgo["BCRYPT"]["users"], 4)
	require.Len(t, byAlgo[""]["users"], 2)

	scrypt := byAlgo["SCRYPT"]
	require.Len(t, scrypt["users"], 1)
	require.Equal(t, vectorConfig.SignerKey, scrypt["signerKey"])
	require.Equal(t, "Bw==", scrypt["saltSeparator"])
	require.EqualValues(t, 8, scrypt["rounds"])
	require.EqualValues(t, 14, scrypt["memoryCost"])
	s1 := scrypt["users"].([]any)[0].(map[string]any)
	require.Equal(t, "s1", s1["localId"])
	require.Equal(t, "s1@example.com", s1["email"])
	require.Equal(t, true, s1["emailVerified"])
	wantHash, _ := base64.StdEncoding.DecodeString(vectorHash)
	gotHash, err := base64.URLEncoding.DecodeString(s1["passwordHash"].(string))
	require.NoError(t, err)
	require.Equal(t, wantHash, gotHash)

	var mfaUser map[string]any
	for _, u := range byAlgo["BCRYPT"]["users"].([]any) {
		if u.(map[string]any)["localId"] == "mfa" {
			mfaUser = u.(map[string]any)
		}
	}
	require.NotNil(t, mfaUser)
	require.Equal(t, "Ada Lovelace", mfaUser["displayName"])
	require.Equal(t, "https://example.com/a.png", mfaUser["photoUrl"])
	require.Equal(t, "+14155550123", mfaUser["phoneNumber"])
	require.Equal(t, true, mfaUser["disabled"])
	require.JSONEq(t, `{"plan":"pro"}`, mfaUser["customAttributes"].(string))
	require.Equal(t, []any{map[string]any{"phoneInfo": "+14155550123", "enrolledAt": "2024-03-01T10:00:00Z"}}, mfaUser["mfaInfo"])

	require.ElementsMatch(t, []string{"b1", "b2", "mfa", "s1", "reset", "nopw"}, report.Succeeded)
	require.ElementsMatch(t, []connector.ImportError{
		{SourceID: "dup", Code: "DUPLICATE_EMAIL", Message: "DUPLICATE_EMAIL : the email is in use"},
		{SourceID: "nocontact", Code: "TRANSLATION_ERROR", Message: "user has neither an email nor a phone number, which Firebase needs to sign in"},
	}, report.Failed)
	require.Equal(t, []string{"reset"}, report.RequiresPasswordReset)
	require.Equal(t, []string{"mfa"}, report.RequiresReenrollment)
}

func TestImportErrorCodes(t *testing.T) {
	rec := &batchRecorder{reject: map[string]string{
		"coded":     "DUPLICATE_EMAIL : the email is in use",
		"prose":     "localId belongs to an existing account - can not overwrite.",
		"wrapped":   "((Auth Emulator does not support importing duplicate email: a@example.com))",
		"lowercase": "invalid_email",
		"empty":     "",
	}}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	var users []cmf.User
	for _, id := range []string{"coded", "prose", "wrapped", "lowercase", "empty"} {
		users = append(users, bcryptUser(id))
	}
	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	got := map[string]string{}
	for _, f := range report.Failed {
		got[f.SourceID] = f.Code
	}
	require.Equal(t, map[string]string{
		"coded": "DUPLICATE_EMAIL", "prose": "IMPORT_ERROR", "wrapped": "IMPORT_ERROR",
		"lowercase": "IMPORT_ERROR", "empty": "IMPORT_ERROR",
	}, got)
}

func TestImportUpsertAllowsOverwrite(t *testing.T) {
	rec := &batchRecorder{}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	_, err := firebase.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{bcryptUser("u1")}), mapping.Mapping{}, connector.ImportOptions{Upsert: true})
	require.NoError(t, err)
	require.Len(t, rec.requests, 1)
	require.Equal(t, true, rec.requests[0]["allowOverwrite"])
}

func TestImportSplitsBatchesAt1000(t *testing.T) {
	rec := &batchRecorder{}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	users := make([]cmf.User, 2001)
	for i := range users {
		users[i] = bcryptUser(fmt.Sprintf("u%d", i))
	}
	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(), writeUsers(t, users), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	require.Len(t, rec.requests, 3)
	require.Len(t, rec.requests[0]["users"], 1000)
	require.Len(t, rec.requests[1]["users"], 1000)
	require.Len(t, rec.requests[2]["users"], 1)
	require.Len(t, report.Succeeded, 2001)
}

func TestImportRequestFailureFailsTheBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer server.Close()

	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{bcryptUser("u1"), bcryptUser("u2")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Succeeded)
	require.Len(t, report.Failed, 2)
	require.Equal(t, "REQUEST_ERROR", report.Failed[0].Code)
	require.Contains(t, report.Failed[0].Message, "status 400")
}

func TestRequestsAreRetriedWhenThrottled(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{bcryptUser("u1")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, report.Succeeded)
	require.EqualValues(t, 3, calls.Load())
}

func TestThrottlingGivesUpAfterAFewAttempts(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer server.Close()

	report, err := firebase.New(newTestClient(server.URL)).Import(context.Background(),
		writeUsers(t, []cmf.User{bcryptUser("u1")}), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Len(t, report.Failed, 1)
	require.Contains(t, report.Failed[0].Message, "status 429")
	require.EqualValues(t, 5, calls.Load())
}

func TestVerify(t *testing.T) {
	existing := map[string]map[string]any{
		"present@example.com":    {"localId": "present", "email": "present@example.com", "emailVerified": true},
		"blocked@example.com":    {"localId": "blocked", "email": "blocked@example.com", "emailVerified": true, "disabled": true},
		"unverified@example.com": {"localId": "unverified", "email": "unverified@example.com"},
		"+14155550123":           {"localId": "phone", "phoneNumber": "+14155550123"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/projects/"+testProject+"/accounts:lookup", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		var body map[string][]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		key := ""
		for _, k := range []string{"email", "phoneNumber"} {
			if v := body[k]; len(v) == 1 {
				key = v[0]
			}
		}
		resp := map[string]any{}
		if a, ok := existing[key]; ok {
			resp["users"] = []any{a}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	mk := func(id, email string, verified, blocked bool) cmf.User {
		u := bcryptUser(id)
		u.Emails = []cmf.Contact{{Value: email, Verified: verified}}
		u.Blocked = blocked
		return u
	}
	phoneOnly := bcryptUser("phone")
	phoneOnly.Emails = nil
	phoneOnly.Phones = []cmf.Contact{{Value: "+14155550123"}}
	nothing := bcryptUser("nothing")
	nothing.Emails = nil

	report, err := firebase.New(newTestClient(server.URL)).Verify(context.Background(), writeUsers(t, []cmf.User{
		mk("present", "present@example.com", true, false),
		mk("missing", "missing@example.com", true, false),
		mk("blocked", "blocked@example.com", true, false),
		mk("unverified", "unverified@example.com", true, false),
		phoneOnly,
		nothing,
	}))
	require.NoError(t, err)

	require.Equal(t, []string{"missing"}, report.MissingInTarget)
	require.Equal(t, []string{"nothing"}, report.NoIdentifier)
	require.Equal(t, []connector.DriftEntry{
		{SourceID: "blocked", Fields: []string{"blocked"}},
		{SourceID: "unverified", Fields: []string{"email_verified"}},
	}, report.AttributeDrift)
}

func TestValidateUser(t *testing.T) {
	c := &firebase.Connector{}
	require.Empty(t, c.ValidateUser(bcryptUser("ok")))

	bad := bcryptUser(strings.Repeat("x", 129))
	bad.Emails = []cmf.Contact{{Value: "not an email"}}
	bad.Phones = []cmf.Contact{{Value: "0612345678"}}
	bad.AppMetadata = map[string]any{"sub": "x", "big": strings.Repeat("y", 1000)}
	bad.Password = &cmf.Password{Algorithm: cmf.AlgBcrypt, Hash: cmf.HashValue{Value: "nope", Encoding: cmf.EncodingUTF8}, Portable: true}
	bad.MFAFactors = []cmf.MFAFactor{{Type: cmf.MFASMS, Value: "12", Portable: true}}

	var fields []string
	for _, p := range c.ValidateUser(bad) {
		fields = append(fields, p.Field)
	}
	require.ElementsMatch(t, []string{
		"source_id", "emails", "phones", "app_metadata", "app_metadata", "password", "mfa_factors.value",
	}, fields)

	noContact := bcryptUser("nocontact")
	noContact.Emails = nil
	problems := c.ValidateUser(noContact)
	require.Len(t, problems, 1)
	require.Equal(t, "emails", problems[0].Field)

	// A non-portable password is skipped, not translated, so it's fine.
	reset := bcryptUser("reset")
	reset.Password.Portable = false
	require.Empty(t, c.ValidateUser(reset))
}
