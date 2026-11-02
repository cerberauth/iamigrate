package cognito

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/stretchr/testify/require"
)

const testPool = "eu-west-1_Pool"

// fakeUser is a user of the fake pool.
type fakeUser struct {
	attrs   map[string]string
	status  string
	enabled bool
	pw      string
}

// fakePool is a Cognito user pool answering the admin operations Import and
// Verify use, and recording the calls it gets.
type fakePool struct {
	mu      sync.Mutex
	users   map[string]*fakeUser
	calls   []string
	updates [][]attribute
}

func newFakePool(t *testing.T) (*fakePool, *Client) {
	t.Helper()
	p := &fakePool{users: map[string]*fakeUser{}}
	server := httptest.NewServer(http.HandlerFunc(p.serve(t)))
	t.Cleanup(server.Close)

	c := NewClient("eu-west-1", testPool, Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"})
	c.Endpoint, c.RetryDelay = server.URL, time.Millisecond
	return p, c
}

func (p *fakePool) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), targetPrefix)
		var body struct {
			UserPoolID     string      `json:"UserPoolId"`
			Username       string      `json:"Username"`
			UserAttributes []attribute `json:"UserAttributes"`
			MessageAction  string
			Filter         string
			Password       string
			Permanent      bool
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, testPool, body.UserPoolID)
		p.calls = append(p.calls, op+" "+body.Username)

		fail := func(typ string) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": typ})
		}
		attrs := func(u *fakeUser) []attribute {
			var out []attribute
			for k, v := range u.attrs {
				out = append(out, attribute{Name: k, Value: v})
			}
			return out
		}
		u, exists := p.users[body.Username]

		switch op {
		case "AdminCreateUser":
			if exists {
				fail("UsernameExistsException")
				return
			}
			require.Equal(t, "SUPPRESS", body.MessageAction, "no invitation message")
			u = &fakeUser{attrs: map[string]string{"sub": "sub-" + body.Username}, status: statusForceChangePassword, enabled: true}
			for _, a := range body.UserAttributes {
				u.attrs[a.Name] = a.Value
			}
			p.users[body.Username] = u
			_ = json.NewEncoder(w).Encode(map[string]any{"User": map[string]any{
				"Username": body.Username, "Attributes": attrs(u), "Enabled": true, "UserStatus": u.status,
			}})
		case "ListUsers":
			var found []map[string]any
			for name, u := range p.users {
				if `sub = "`+strings.ReplaceAll(u.attrs["sub"], `"`, `\"`)+`"` == body.Filter {
					found = append(found, map[string]any{"Username": name, "Attributes": attrs(u), "Enabled": u.enabled, "UserStatus": u.status})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Users": found})
		case "AdminGetUser":
			if !exists {
				fail("UserNotFoundException")
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Username": body.Username, "UserAttributes": attrs(u), "Enabled": u.enabled, "UserStatus": u.status,
			})
		case "AdminUpdateUserAttributes":
			p.updates = append(p.updates, body.UserAttributes)
			for _, a := range body.UserAttributes {
				u.attrs[a.Name] = a.Value
			}
			_, _ = w.Write([]byte(`{}`))
		case "AdminSetUserPassword":
			require.True(t, body.Permanent)
			u.pw, u.status = body.Password, "CONFIRMED"
			_, _ = w.Write([]byte(`{}`))
		case "AdminDisableUser":
			u.enabled = false
			_, _ = w.Write([]byte(`{}`))
		case "AdminEnableUser":
			u.enabled = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected operation %s", op)
		}
	}
}

func readerOf(t *testing.T, users ...cmf.User) *cmf.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(io.NopCloser(&buf))
	require.NoError(t, err)
	return r
}

func testUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Username:   "name-" + id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Phones:     []cmf.Contact{{Value: "+14155550123", Verified: false}},
		Profile:    cmf.Profile{GivenName: "Ada", FamilyName: "Lovelace"},
		Password: &cmf.Password{
			Algorithm: cmf.AlgBcrypt,
			Hash:      cmf.HashValue{Value: "$2a$10$jSTQjfDV/IlpY/Ix05MjZu48Y8D0QpllULBdx0U40N/VqKqjN91dW", Encoding: cmf.EncodingUTF8},
			Portable:  true,
		},
		Provenance: cmf.Provenance{SourceConnector: "test", ExportedAt: time.Now().UTC()},
	}
}

func TestImportCreatesConfirmedUsersWithoutAPassword(t *testing.T) {
	pool, client := newFakePool(t)
	blocked := testUser("b")
	blocked.Blocked = true
	noPassword := testUser("n")
	noPassword.Password = nil

	report, err := New(client).Import(context.Background(), readerOf(t, testUser("a"), blocked, noPassword), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Failed)
	require.Equal(t, []string{"a", "b", "n"}, report.Succeeded)
	require.Equal(t, map[string]string{"a": "sub-a@example.com", "b": "sub-b@example.com", "n": "sub-n@example.com"}, report.TargetIDs)
	require.Equal(t, []string{"a", "b"}, report.RequiresPasswordReset, "only users that had a password")

	a := pool.users["a@example.com"]
	require.Equal(t, "CONFIRMED", a.status, "a user can use forgot password only once confirmed")
	require.Len(t, a.pw, passwordLength)
	require.True(t, a.enabled)
	require.Equal(t, map[string]string{
		"sub": "sub-a@example.com", "email": "a@example.com", "email_verified": "true",
		"phone_number": "+14155550123", "phone_number_verified": "false",
		"preferred_username": "name-a", "given_name": "Ada", "family_name": "Lovelace",
	}, a.attrs)

	require.False(t, pool.users["b@example.com"].enabled, "a blocked user is disabled")
	require.Equal(t, "CONFIRMED", pool.users["n@example.com"].status)
}

func TestImportCreatesUnderTheUsernameWhenItIsThePrimaryIdentifier(t *testing.T) {
	pool, client := newFakePool(t)
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"identity.primary": {Strategy: "username_first"}}}

	report, err := New(client).Import(context.Background(), readerOf(t, testUser("a")), m, connector.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, report.Succeeded)
	require.Contains(t, pool.users, "name-a")
	require.NotContains(t, pool.users["name-a"].attrs, "preferred_username")
	require.Equal(t, "a@example.com", pool.users["name-a"].attrs["email"])
}

func TestImportFailsExistingUsersUnlessUpserting(t *testing.T) {
	pool, client := newFakePool(t)
	target := New(client)
	_, err := target.Import(context.Background(), readerOf(t, testUser("a")), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)

	changed := testUser("a")
	changed.Profile.GivenName = "Grace"

	report, err := target.Import(context.Background(), readerOf(t, changed), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Succeeded)
	require.Len(t, report.Failed, 1)
	require.Equal(t, UsernameExistsCode, report.Failed[0].Code)
	require.True(t, target.IsConflict(report.Failed[0]))
	require.Equal(t, "Ada", pool.users["a@example.com"].attrs["given_name"])

	report, err = target.Import(context.Background(), readerOf(t, changed), mapping.Mapping{}, connector.ImportOptions{Upsert: true})
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, report.Succeeded)
	require.Equal(t, "Grace", pool.users["a@example.com"].attrs["given_name"])
	require.Equal(t, [][]attribute{{{Name: "given_name", Value: "Grace"}}}, pool.updates, "only the changed attribute is sent")
	require.Equal(t, "sub-a@example.com", report.TargetIDs["a"])
}

func TestUpsertFinishesAUserLeftInForceChangePassword(t *testing.T) {
	pool, client := newFakePool(t)
	pool.users["a@example.com"] = &fakeUser{
		attrs: map[string]string{"sub": "s", "email": "a@example.com"}, status: statusForceChangePassword, enabled: true,
	}

	report, err := New(client).Import(context.Background(), readerOf(t, testUser("a")), mapping.Mapping{}, connector.ImportOptions{Upsert: true})
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, report.Succeeded)
	require.Equal(t, "CONFIRMED", pool.users["a@example.com"].status)
}

func TestUpsertKeepsAConfirmedUsersPassword(t *testing.T) {
	pool, client := newFakePool(t)
	pool.users["a@example.com"] = &fakeUser{
		attrs: map[string]string{"sub": "s"}, status: "CONFIRMED", enabled: true, pw: "theirs",
	}

	_, err := New(client).Import(context.Background(), readerOf(t, testUser("a")), mapping.Mapping{}, connector.ImportOptions{Upsert: true})
	require.NoError(t, err)
	require.Equal(t, "theirs", pool.users["a@example.com"].pw)
}

func TestImportFailsAUserWithNothingToCreateItUnder(t *testing.T) {
	_, client := newFakePool(t)
	u := testUser("a")
	u.Username, u.Emails, u.Phones = "", nil, nil

	report, err := New(client).Import(context.Background(), readerOf(t, u), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Len(t, report.Failed, 1)
	require.Equal(t, "TRANSLATION_ERROR", report.Failed[0].Code)
}

func TestImportAppliesTargetFields(t *testing.T) {
	pool, client := newFakePool(t)
	m := mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "app_metadata.tier", Target: "custom:tier"}}}
	u := testUser("a")
	u.AppMetadata = map[string]any{"tier": "gold"}

	report, err := New(client).Import(context.Background(), readerOf(t, u), m, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Failed)
	require.Equal(t, "gold", pool.users["a@example.com"].attrs["custom:tier"])
}

func TestCheckTargetField(t *testing.T) {
	c := &Connector{}
	for _, ok := range []string{"birthdate", "custom:tier", "locale"} {
		require.NoError(t, c.CheckTargetField(ok), ok)
	}
	for _, bad := range []string{"sub", "email", "custom:", "traits.x", "app_metadata.x"} {
		require.Error(t, c.CheckTargetField(bad), bad)
	}
}

func TestVerify(t *testing.T) {
	pool, client := newFakePool(t)
	target := New(client)
	_, err := target.Import(context.Background(), readerOf(t, testUser("ok"), testUser("drift")), mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	pool.users["drift@example.com"].enabled = false

	report, err := target.Verify(context.Background(), readerOf(t, testUser("ok"), testUser("drift"), testUser("gone")))
	require.NoError(t, err)
	require.Equal(t, 3, report.SourceCount)
	require.Equal(t, 2, report.TargetCount)
	require.Equal(t, []string{"gone"}, report.MissingInTarget)
	require.Len(t, report.AttributeDrift, 1)
	require.Equal(t, "drift", report.AttributeDrift[0].SourceID)
	require.Equal(t, []string{"blocked"}, report.AttributeDrift[0].Fields)
}

func TestVerifyFindsAUserByItsSub(t *testing.T) {
	pool, client := newFakePool(t)
	target := New(client)
	// Created under a username the CMF user's email doesn't name.
	pool.users["someone"] = &fakeUser{attrs: map[string]string{"sub": `s"1`, "email": "a@example.com"}, status: "CONFIRMED", enabled: true}

	r := readerOf(t, testUser("a"), testUser("b"))
	ctx := reconcile.WithOptions(context.Background(), reconcile.Options{
		Mapping:   mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Strategy: "target_id"}}},
		TargetIDs: map[string]string{"a": `s"1`, "b": "nope"},
	})
	report, err := target.Verify(ctx, r)
	require.NoError(t, err)
	require.Equal(t, 1, report.TargetCount)
	require.Equal(t, []string{"b"}, report.MissingInTarget)
}

func TestCapabilitiesTakeNoPasswordHash(t *testing.T) {
	caps := (&Connector{}).Capabilities()
	require.True(t, caps.NoPasswords)
	require.False(t, caps.SupportsCustomID)
	require.True(t, caps.SupportsUpsert)
}

func TestValidateUser(t *testing.T) {
	c := &Connector{}
	require.Empty(t, c.ValidateUser(testUser("a")))

	bad := testUser("a")
	bad.Emails[0].Value = "not-an-email"
	bad.Phones[0].Value = "0612345678"
	fields := map[string]bool{}
	for _, p := range c.ValidateUser(bad) {
		fields[p.Field] = true
	}
	require.Equal(t, map[string]bool{"emails": true, "phones": true}, fields)

	none := cmf.User{SourceID: "x"}
	require.Len(t, c.ValidateUser(none), 1)

	spaced := testUser("a")
	spaced.Login, spaced.Username = cmf.IdentifierUsername, "has space"
	require.Len(t, c.ValidateUser(spaced), 1)
	spaced.Username = strings.Repeat("x", 129)
	require.Len(t, c.ValidateUser(spaced), 1)
}
