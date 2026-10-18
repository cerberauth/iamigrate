package ids_test

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

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

var custom = connector.Capabilities{SupportsCustomID: true}

func users(srcIDs ...string) []cmf.User {
	out := make([]cmf.User, len(srcIDs))
	for i, id := range srcIDs {
		out[i] = cmf.User{CMFVersion: cmf.Version, SourceID: id, Username: "user-" + id,
			Emails:   []cmf.Contact{{Value: id + "@example.com"}},
			Password: &cmf.Password{Algorithm: cmf.AlgBcrypt, Hash: cmf.HashValue{Value: "secret-hash", Encoding: cmf.EncodingUTF8}}}
	}
	return out
}

func assign(t *testing.T, s mapping.IDStrategy, us []cmf.User) []cmf.User {
	t.Helper()
	a, err := ids.NewAssigner(&s, "auth0", custom, nil)
	require.NoError(t, err)
	require.NoError(t, a.Assign(context.Background(), us))
	return us
}

func TestBuiltins(t *testing.T) {
	us := assign(t, mapping.IDStrategy{Strategy: mapping.IDPrefix, Prefix: "legacy-"}, users("42"))
	require.Equal(t, map[string]string{"auth0": "legacy-42"}, us[0].TargetIDs)

	us = assign(t, mapping.IDStrategy{Strategy: mapping.IDTemplate, Template: "{{.SourceID}}:{{.Username}}:{{.Email}}"}, users("42"))
	require.Equal(t, "42:user-42:42@example.com", us[0].TargetIDs["auth0"])

	// RFC 9562 appendix A.4: the v5 UUID of "www.example.com" in the DNS
	// namespace.
	u := cmf.User{SourceID: "www.example.com"}
	us = assign(t, mapping.IDStrategy{Strategy: mapping.IDUUIDv5, Namespace: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}, []cmf.User{u})
	require.Equal(t, "2ed6657d-e927-568b-95e1-2665a8aea6a2", us[0].TargetIDs["auth0"])
}

func TestAssignKeepsAnAlreadyAssignedID(t *testing.T) {
	us := users("1", "2")
	us[0].TargetIDs = map[string]string{"auth0": "kept", "firebase": "other"}
	us = assign(t, mapping.IDStrategy{Strategy: mapping.IDPrefix, Prefix: "p-"}, us)
	require.Equal(t, map[string]string{"auth0": "kept", "firebase": "other"}, us[0].TargetIDs)
	require.Equal(t, "p-2", us[1].TargetIDs["auth0"])
}

func TestNoAssignerWhenNothingIsAssigned(t *testing.T) {
	for _, s := range []*mapping.IDStrategy{nil, {}, {Strategy: mapping.IDPreserve}} {
		a, err := ids.NewAssigner(s, "kratos", connector.Capabilities{}, nil)
		require.NoError(t, err)
		require.Nil(t, a)
	}
}

func TestNewAssignerRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		s    mapping.IDStrategy
		caps connector.Capabilities
		want string
	}{
		"target generates IDs": {mapping.IDStrategy{Strategy: mapping.IDPrefix, Prefix: "p"}, connector.Capabilities{}, "generates its own user IDs"},
		"bad namespace":        {mapping.IDStrategy{Strategy: mapping.IDUUIDv5, Namespace: "nope"}, custom, "not a UUID"},
		"bad template":         {mapping.IDStrategy{Strategy: mapping.IDTemplate, Template: "{{"}, custom, "template"},
		"handler, no hooks":    {mapping.IDStrategy{Handler: "h"}, custom, "no hooks file given"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ids.NewAssigner(&tc.s, "auth0", tc.caps, nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestTemplateWithAnUnknownFieldFails(t *testing.T) {
	a, err := ids.NewAssigner(&mapping.IDStrategy{Strategy: mapping.IDTemplate, Template: "{{.Nope}}"}, "auth0", custom, nil)
	require.NoError(t, err)
	require.Error(t, a.Assign(context.Background(), users("1")))
}

func TestEmptyIDFails(t *testing.T) {
	a, err := ids.NewAssigner(&mapping.IDStrategy{Strategy: mapping.IDTemplate, Template: "{{.Phone}}"}, "auth0", custom, nil)
	require.NoError(t, err)
	require.ErrorContains(t, a.Assign(context.Background(), users("1")), "empty ID")
}

// handler serves id.target batches, answering "h-" + source_id, and
// records what it was sent.
func handler(t *testing.T) (*hooks.Dispatcher, *[]map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(b, &env))
		mu.Lock()
		got = append(got, env)
		mu.Unlock()
		res := map[string]any{}
		for k := range env["data"].(map[string]any)["items"].(map[string]any) {
			res[k] = map[string]string{"id": "h-" + k}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("IDS_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {ids: {webhook: {url: '" + srv.URL + "', secret_env: IDS_SECRET, batch_size: 2}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	return d.ForJob("job1", nil), &got
}

func TestHandlerAssignsInBatchesWithoutCredentials(t *testing.T) {
	d, got := handler(t)
	a, err := ids.NewAssigner(&mapping.IDStrategy{Handler: "ids"}, "auth0", custom, d)
	require.NoError(t, err)

	var in bytes.Buffer
	w := cmf.NewPlainWriter(&in)
	for _, u := range users("1", "2", "3") {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&in)
	require.NoError(t, err)
	var out bytes.Buffer
	ow := cmf.NewPlainWriter(&out)
	n, err := a.Rewrite(context.Background(), r, ow)
	require.NoError(t, err)
	require.NoError(t, ow.Close())
	require.Equal(t, 3, n)

	require.Len(t, *got, 2, "3 users, batches of 2")
	require.Equal(t, "id.target", (*got)[0]["hook"])
	item := (*got)[0]["data"].(map[string]any)["items"].(map[string]any)["1"].(map[string]any)
	require.Equal(t, "auth0", item["target"])
	require.Equal(t, "user-1", item["username"])
	require.NotContains(t, item, "password", "credentials are never sent to an id.target handler")
	require.NotContains(t, item, "mfa_factors")

	r, err = cmf.NewReader(&out)
	require.NoError(t, err)
	for _, want := range []string{"h-1", "h-2", "h-3"} {
		u, err := r.ReadUser()
		require.NoError(t, err)
		require.Equal(t, want, u.TargetIDs["auth0"])
		require.NotNil(t, u.Password, "the rest of the user is copied as is")
	}
}

func TestHandlerOnFailureIgnoreIsRejected(t *testing.T) {
	d, _ := handler(t)
	_, err := ids.NewAssigner(&mapping.IDStrategy{Handler: "ids", OnFailure: "ignore"}, "auth0", custom, d)
	require.ErrorContains(t, err, "on_failure: ignore")
	_, err = ids.NewAssigner(&mapping.IDStrategy{Handler: "nope"}, "auth0", custom, d)
	require.ErrorContains(t, err, `handler "nope" is not declared`)
}

func TestChecker(t *testing.T) {
	prefix := &mapping.IDStrategy{Strategy: mapping.IDPrefix, Prefix: "p"}
	withID := func(src, id string) cmf.User {
		return cmf.User{SourceID: src, TargetIDs: map[string]string{"auth0": id}}
	}

	c := ids.NewChecker(prefix, "auth0", custom)
	require.Empty(t, c.Check(withID("1", "a")))
	ps := c.Check(withID("2", "a"))
	require.Len(t, ps, 1)
	require.Contains(t, ps[0].Rule, "same as user 1's")
	ps = c.Check(cmf.User{SourceID: "3"})
	require.Len(t, ps, 1)
	require.Equal(t, "target_ids.auth0", ps[0].Field)
	require.Contains(t, ps[0].Rule, "ids assign")

	c = ids.NewChecker(nil, "auth0", custom)
	require.Empty(t, c.Check(cmf.User{SourceID: "3"}), "no strategy, no ID needed")

	c = ids.NewChecker(nil, "kratos", connector.Capabilities{})
	ps = c.Check(cmf.User{SourceID: "1", TargetIDs: map[string]string{"kratos": "x"}})
	require.Len(t, ps, 1)
	require.True(t, strings.Contains(ps[0].Rule, "generates its own user IDs"))
	require.Empty(t, c.Check(cmf.User{SourceID: "1", TargetIDs: map[string]string{"auth0": "x"}}), "another target's ID is no concern")
}

func TestMappingValidate(t *testing.T) {
	m := mapping.Mapping{Target: "auth0"}
	for s, want := range map[mapping.IDStrategy]string{
		{Strategy: "random"}:                                         "unknown strategy",
		{Strategy: mapping.IDPrefix}:                                 "requires prefix",
		{Strategy: mapping.IDUUIDv5}:                                 "requires namespace",
		{Strategy: mapping.IDTemplate}:                               "requires template",
		{Strategy: mapping.IDPrefix, Handler: "h", Prefix: "p"}:      "not both",
		{Strategy: mapping.IDPrefix, Prefix: "p", OnFailure: "fail"}: "only applies to a handler",
	} {
		m.IDs.Target = &s
		require.ErrorContains(t, m.Validate(), want)
	}
	for _, s := range []mapping.IDStrategy{{}, {Strategy: mapping.IDPreserve}, {Handler: "h"}, {Strategy: mapping.IDPrefix, Prefix: "p"}} {
		m.IDs.Target = &s
		require.NoError(t, m.Validate())
	}
}
