package reconcile_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/stretchr/testify/require"
)

func reader(t *testing.T, ids ...string) *cmf.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	for _, id := range ids {
		require.NoError(t, w.WriteUser(cmf.User{CMFVersion: cmf.Version, SourceID: id}))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	return r
}

// fakeCheck finds every user but "gone" and "anon", with drift on "drifty",
// and notes how it was asked to look each one up.
func fakeCheck(seen map[string]reconcile.Lookup) reconcile.CheckFunc {
	return func(_ context.Context, u cmf.User, l reconcile.Lookup) (reconcile.Found, error) {
		seen[u.SourceID] = l
		switch u.SourceID {
		case "gone":
			return reconcile.Found{Missing: true}, nil
		case "anon":
			return reconcile.Found{NoIdentifier: true}, nil
		case "drifty":
			return reconcile.Found{Record: map[string]any{"state": "inactive"}, Drift: []string{"blocked"}}, nil
		}
		return reconcile.Found{Record: map[string]any{"id": "t-" + u.SourceID}}, nil
	}
}

func TestRunBuildsTheReportAsBefore(t *testing.T) {
	seen := map[string]reconcile.Lookup{}
	report, err := reconcile.Run(context.Background(), reader(t, "a", "gone", "anon", "drifty"), fakeCheck(seen))
	require.NoError(t, err)
	require.Equal(t, connector.DiffReport{
		SourceCount: 4, TargetCount: 2,
		MissingInTarget: []string{"gone"},
		AttributeDrift:  []connector.DriftEntry{{SourceID: "drifty", Fields: []string{"blocked"}}},
		NoIdentifier:    []string{"anon"},
	}, report)
	require.Equal(t, reconcile.Lookup{}, seen["a"], "no strategy: the connector's own lookup")
}

func TestTargetIDLookup(t *testing.T) {
	seen := map[string]reconcile.Lookup{}
	ctx := reconcile.WithOptions(context.Background(), reconcile.Options{
		Mapping:   mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Strategy: "target_id"}}},
		TargetIDs: map[string]string{"a": "id-a"},
	})
	_, err := reconcile.Run(ctx, reader(t, "a", "b"), fakeCheck(seen))
	require.NoError(t, err)
	require.Equal(t, reconcile.Lookup{TargetID: "id-a"}, seen["a"])
	require.Equal(t, reconcile.Lookup{}, seen["b"], "no target ID recorded: looked up as without the strategy")
}

func TestLookupAndCompareHandlers(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		if hook == "verify.lookup" {
			return map[string]any{"identifier": key + "@example.com"}
		}
		require.NotNil(t, item["target"], "verify.compare gets the target's record")
		return map[string]any{"drift": []string{}}
	}, "")
	seen := map[string]reconcile.Lookup{}
	ctx := hooks.WithDispatcher(reconcile.WithOptions(context.Background(), reconcile.Options{
		Mapping: mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"verify.lookup": {Handler: "h"}, "verify.compare": {Handler: "h"}}},
	}), d)
	report, err := reconcile.Run(ctx, reader(t, "a", "gone", "drifty"), fakeCheck(seen))
	require.NoError(t, err)
	require.Equal(t, reconcile.Lookup{Identifier: "drifty@example.com"}, seen["drifty"])
	require.Empty(t, report.AttributeDrift, "verify.compare accepted the drift")
	require.Equal(t, []string{"gone"}, report.MissingInTarget)
	require.Equal(t, 1, rc.Calls("verify.lookup"))
	require.Equal(t, 1, rc.Calls("verify.compare"))
	compareItems := rc.Envs[1]["data"].(map[string]any)["items"].(map[string]any)
	require.NotContains(t, compareItems, "gone", "only users found are compared")
}

func TestUsersTheImportSkippedAreNotLookedFor(t *testing.T) {
	seen := map[string]reconcile.Lookup{}
	ctx := reconcile.WithOptions(context.Background(), reconcile.OptionsFor(mapping.Mapping{}, &connector.ImportReport{
		Skipped: []connector.ImportError{{SourceID: "gone", Code: reconcile.SkippedCode}, {SourceID: "a", Code: "DUPLICATED_USER"}},
	}))
	report, err := reconcile.Run(ctx, reader(t, "a", "gone"), fakeCheck(seen))
	require.NoError(t, err)
	require.Equal(t, connector.DiffReport{SourceCount: 1, TargetCount: 1, Skipped: []string{"gone"}}, report)
	require.NotContains(t, seen, "gone")
	require.Contains(t, seen, "a", "a user skipped as already existing is still verified")
}
