package importprep_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func anyPath(string) error { return nil }

func user(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version, SourceID: id,
		Emails:      []cmf.Contact{{Value: id + "@example.com", Verified: true}},
		Profile:     cmf.Profile{Locale: "FR-fr"},
		AppMetadata: map[string]any{"plan": "pro", "seats": 3.0, "beta": true, "org": map[string]any{"id": "o1"}},
	}
}

func resolve(t *testing.T, fields []mapping.TargetField, users ...cmf.User) [][]importprep.Field {
	t.Helper()
	a, err := importprep.New(mapping.Mapping{TargetFields: fields}, anyPath, nil)
	require.NoError(t, err)
	out, err := a.Resolve(context.Background(), users)
	require.NoError(t, err)
	return out
}

func TestResolve(t *testing.T) {
	out := resolve(t, []mapping.TargetField{
		{CMF: "profile.locale", Target: "traits.locale", Transform: "lowercase"},
		{CMF: "emails.0.value", Target: "traits.contact"},
		{CMF: "app_metadata.seats", Target: "traits.seats"},
		{CMF: "app_metadata.beta", Target: "traits.beta_s", Transform: "uppercase"},
		{CMF: "app_metadata.org", Target: "metadata_admin.org"},
		{CMF: "app_metadata.missing", Target: "traits.tier", Default: "free"},
		{CMF: "emails.5.value", Target: "traits.none"},
	}, user("u1"))
	require.Equal(t, [][]importprep.Field{{
		{Path: "traits.locale", Value: "fr-fr"},
		{Path: "traits.contact", Value: "u1@example.com"},
		{Path: "traits.seats", Value: 3.0},
		{Path: "traits.beta_s", Value: "TRUE"},
		{Path: "metadata_admin.org", Value: map[string]any{"id": "o1"}},
		{Path: "traits.tier", Value: "free"},
	}}, out, "untransformed values keep their type; a missing one is left unset")
}

func TestTransformingAnObjectFails(t *testing.T) {
	a, err := importprep.New(mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "app_metadata.org", Target: "x", Transform: "trim"}}}, anyPath, nil)
	require.NoError(t, err)
	_, err = a.Resolve(context.Background(), []cmf.User{user("u1")})
	require.ErrorContains(t, err, "user u1: target field x: a transform needs a string")
}

func TestNewRejects(t *testing.T) {
	a, err := importprep.New(mapping.Mapping{}, anyPath, nil)
	require.NoError(t, err)
	require.Nil(t, a, "no target fields, no applier")

	_, err = importprep.New(mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "x", Target: "bad"}}},
		func(p string) error { return errors.New("can't set " + p) }, nil)
	require.ErrorContains(t, err, "target_fields[0]: can't set bad")
	_, err = importprep.New(mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "x"}}}, anyPath, nil)
	require.ErrorContains(t, err, "cmf and target are required")
	_, err = importprep.New(mapping.Mapping{TargetFields: []mapping.TargetField{{CMF: "x", Target: "y", Transform: "nope"}}}, anyPath, nil)
	require.ErrorContains(t, err, `unknown transform "nope"`)
}

func cmfReader(t *testing.T, users ...cmf.User) *cmf.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	for _, u := range users {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	return r
}

func TestReaderResolvesInBatches(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		var env struct {
			Data struct {
				Items map[string]map[string]string `json:"items"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(b, &env))
		res := map[string]any{}
		for k, it := range env.Data.Items {
			res[k] = map[string]string{"value": "<" + it["value"] + ">"}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	t.Setenv("TF_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {h: {webhook: {url: '" + srv.URL + "', secret_env: TF_SECRET}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)

	m := mapping.Mapping{
		Transforms:   map[string]mapping.TransformRef{"wrap": {Handler: "h"}},
		TargetFields: []mapping.TargetField{{CMF: "source_id", Target: "traits.legacy_id", Transform: "wrap"}},
	}
	a, err := importprep.New(m, anyPath, d)
	require.NoError(t, err)

	var users []cmf.User
	for _, id := range []string{"a", "b", "c"} {
		users = append(users, user(id))
	}
	r := importprep.NewReader(context.Background(), cmfReader(t, users...), a)
	for _, id := range []string{"a", "b", "c"} {
		u, fields, err := r.ReadUser()
		require.NoError(t, err)
		require.Equal(t, id, u.SourceID)
		require.Equal(t, []importprep.Field{{Path: "traits.legacy_id", Value: "<" + id + ">"}}, fields)
	}
	_, _, err = r.ReadUser()
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 1, calls, "one call for the batch, not one per user")
}

func TestReaderWithoutApplierPassesThrough(t *testing.T) {
	r := importprep.NewReader(context.Background(), cmfReader(t, user("a")), nil)
	u, fields, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "a", u.SourceID)
	require.Nil(t, fields)
	_, _, err = r.ReadUser()
	require.ErrorIs(t, err, io.EOF)
}

func TestSetAndUnder(t *testing.T) {
	m := map[string]any{"user_metadata": map[string]any{"a": 1}}
	importprep.Set(m, "user_metadata.b", 2)
	importprep.Set(m, "x.y.z", 3)
	require.Equal(t, map[string]any{"user_metadata": map[string]any{"a": 1, "b": 2}, "x": map[string]any{"y": map[string]any{"z": 3}}}, m)

	k, ok := importprep.Under("traits.locale", "traits")
	require.True(t, ok)
	require.Equal(t, "locale", k)
	for _, p := range []string{"traits", "traits.", "traits.a.b", "traitsx.a"} {
		_, ok := importprep.Under(p, "traits")
		require.False(t, ok, p)
	}
}
