package strategy_test

import (
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	for want, m := range map[string]mapping.Mapping{
		`unknown strategy "nope"`:           {Strategies: map[string]mapping.StrategyRef{"nope": {Handler: "h"}}},
		"see the ids and transforms":        {Strategies: map[string]mapping.StrategyRef{"id.target": {Handler: "h"}}},
		"not both":                          {Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Handler: "h", Strategy: "target_id"}}},
		"needs a handler":                   {Strategies: map[string]mapping.StrategyRef{"import.user": {}}},
		`import.user: unknown strategy "x"`: {Strategies: map[string]mapping.StrategyRef{"import.user": {Strategy: "x"}}},
		"from must be":                      {Metadata: []mapping.MetadataRoute{{Key: "k", From: "metadata", Destination: "drop"}}},
		"on_duplicate must be":              {Conflict: &mapping.Conflict{OnDuplicate: "merge"}},
	} {
		require.ErrorContains(t, strategy.Check(m), want)
	}
	require.NoError(t, strategy.Check(mapping.Mapping{
		Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Strategy: "target_id"}, "import.user": {Handler: "h"}, "id.source": {Handler: "h"}, "identity.primary": {Strategy: "phone_first"}, "hash.detect": {Handler: "h", OnFailure: "ignore"}},
		Metadata:   []mapping.MetadataRoute{{Key: "k", From: "app_metadata", Destination: "drop"}},
		Conflict:   &mapping.Conflict{OnDuplicate: "skip"},
	}))
}

func TestNewBuildsOnlyWhatItIsGiven(t *testing.T) {
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"import.user": {Handler: "h"}, "validate.user": {Handler: "h"}}}
	_, err := strategy.New(m, nil)
	require.ErrorContains(t, err, "no hooks file given")
	set, err := strategy.New(strategy.Only(m, strategy.ExportUser), nil)
	require.NoError(t, err)
	require.False(t, set.Delegated(strategy.ImportUser))
	require.Nil(t, set, "nothing left to build")
}

func TestResolve(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 2, func(hook, key string, item map[string]any) any {
		return map[string]any{"seen": item["username"]}
	}, "")
	set, err := strategy.New(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"import.user": {Handler: "h"}}}, d)
	require.NoError(t, err)
	require.True(t, set.Delegated(strategy.ImportUser))
	require.Equal(t, 2, set.BatchSize(strategy.ImportUser))
	require.Equal(t, 1, set.BatchSize(strategy.ExportUser), "not delegated: one at a time")

	var nilSet *strategy.Set
	res, err := nilSet.Resolve(context.Background(), strategy.ImportUser, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Zero(t, len(rc.Envs))
}

func TestUserViewHasNoCredentials(t *testing.T) {
	v := strategy.UserView(cmf.User{SourceID: "u", Password: &cmf.Password{}, MFAFactors: []cmf.MFAFactor{{}}})
	require.NotContains(t, v, "password")
	require.NotContains(t, v, "mfa_factors")
	require.Equal(t, "u", v["source_id"])
}

func TestUserAnswer(t *testing.T) {
	u := cmf.User{CMFVersion: "1.0", SourceID: "u", Username: "old", Password: &cmf.Password{Algorithm: cmf.AlgBcrypt},
		Provenance: cmf.Provenance{SourceConnector: "src"}}

	got, keep, err := strategy.UserAnswer{}.Apply(u)
	require.NoError(t, err)
	require.True(t, keep)
	require.Equal(t, u, got)

	_, keep, err = strategy.UserAnswer{Action: "drop"}.Apply(u)
	require.NoError(t, err)
	require.False(t, keep)

	got, keep, err = strategy.UserAnswer{Action: "replace", User: []byte(`{"source_id": "u", "username": "new", "password": null}`)}.Apply(u)
	require.NoError(t, err)
	require.True(t, keep)
	require.Equal(t, "new", got.Username)
	require.Equal(t, u.Password, got.Password, "credentials can't be replaced this way")
	require.Equal(t, "src", got.Provenance.SourceConnector)

	_, _, err = strategy.UserAnswer{Action: "replace", User: []byte(`{"source_id": "other"}`)}.Apply(u)
	require.ErrorContains(t, err, `source_id "other"`)
	_, _, err = strategy.UserAnswer{Action: "merge"}.Apply(u)
	require.ErrorContains(t, err, "unknown action")
}

func TestValidator(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		if hook == strategy.ValidateUser {
			if key == "b" {
				return map[string]any{"problems": []map[string]string{{"field": "username", "rule": "reserved", "value": "admin"}}}
			}
			return map[string]any{}
		}
		// dedup: users a and c share a normalized key.
		return map[string]any{"keys": []string{map[string]string{"a": "k1", "b": "k2", "c": "k1"}[key]}}
	}, "")
	set, err := strategy.New(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{
		"validate.user": {Handler: "h"}, "validate.dedup_key": {Handler: "h"},
	}}, d)
	require.NoError(t, err)
	v := strategy.NewValidator(set)
	for _, id := range []string{"a", "b", "c"} {
		ps, err := v.Add(context.Background(), cmf.User{SourceID: id})
		require.NoError(t, err)
		require.Empty(t, ps, "batched until full or flushed")
	}
	ps, err := v.Flush(context.Background())
	require.NoError(t, err)
	require.Len(t, ps, 2)
	require.Equal(t, "b", ps[0].SourceID)
	require.Equal(t, "reserved", ps[0].Rule)
	require.Equal(t, "c", ps[1].SourceID)
	require.Equal(t, "dedup_key", ps[1].Field)
	require.Equal(t, "duplicate of a within file", ps[1].Rule)

	var none *strategy.Validator
	ps, err = none.Add(context.Background(), cmf.User{})
	require.NoError(t, err)
	require.Nil(t, ps)
}

func TestCheckExplainsPlannedStrategies(t *testing.T) {
	for name, want := range map[string]string{
		"import.conflict": "use the conflict section's on_duplicate",
		"map.field":       "see the ids and transforms sections",
	} {
		err := strategy.Check(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{name: {Handler: "h"}}})
		require.ErrorContains(t, err, want, name)
	}
}
