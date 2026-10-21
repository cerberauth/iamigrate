package importprep_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func metaUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version, SourceID: id,
		AppMetadata:  map[string]any{"plan": "pro", "tier": 3.0},
		UserMetadata: map[string]any{"theme": "dark", "plan": "user-plan"},
	}
}

func placing() mapping.Mapping {
	return mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"metadata.place": {Handler: "h"}}}
}

func place(from, key, dest string) map[string]any {
	return map[string]any{"key": key, "from": from, "destination": dest}
}

func TestMetadataPlaceHandler(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		require.Equal(t, "metadata.place", hook)
		require.NotContains(t, item, "password", "the handler is told who the user is, not their credentials")
		require.Contains(t, item, "app_metadata")
		require.Contains(t, item, "user_metadata")
		switch key {
		case "a":
			return []any{place("app_metadata", "plan", "metadata_admin.plan"), place("user_metadata", "theme", "drop")}
		case "b":
			return []any{place("user_metadata", "plan", "metadata_public.plan")}
		}
		return []any{} // no placement
	}, "")
	m := placing()
	m.Metadata = []mapping.MetadataRoute{{Key: "tier", From: "app_metadata", Destination: "metadata_admin.tier"}}
	a, err := importprep.New(m, anyPath, d)
	require.NoError(t, err)

	src := []cmf.User{metaUser("a"), metaUser("b"), metaUser("c"), {CMFVersion: cmf.Version, SourceID: "bare"}}
	batch, err := importprep.NewReader(context.Background(), cmfReader(t, src...), a).ReadBatch()
	require.NoError(t, err)
	require.Equal(t, 1, rc.Calls("metadata.place"), "one call for the whole batch")
	items := rc.Envs[0]["data"].(map[string]any)["items"].(map[string]any)
	require.Len(t, items, 3, "a user without metadata isn't sent")
	require.NotContains(t, items, "bare")

	require.Equal(t, []importprep.Field{
		{Path: "metadata_admin.plan", Value: "pro"},
		{Path: "metadata_admin.tier", Value: 3.0},
	}, batch[0].Fields, "placed keys, then the static routes on the keys left")
	require.Equal(t, map[string]any{}, batch[0].User.AppMetadata)
	require.Equal(t, map[string]any{"theme": "dark"}, batch[1].User.UserMetadata, "the key placed from user_metadata only")
	require.Equal(t, map[string]any{"plan": "pro"}, batch[1].User.AppMetadata, "tier went by the static route")
	require.Equal(t, []importprep.Field{{Path: "metadata_public.plan", Value: "user-plan"}, {Path: "metadata_admin.tier", Value: 3.0}}, batch[1].Fields)
	require.Equal(t, "dark", batch[2].User.UserMetadata["theme"], "no placement leaves the key where the connector puts it")
	require.Empty(t, batch[3].Fields)

	require.Equal(t, "dark", src[0].UserMetadata["theme"], "the source users are not changed")
}

func TestMetadataPlaceChecksDestinations(t *testing.T) {
	for name, tc := range map[string]struct {
		answer any
		want   string
	}{
		"identifier trait": {[]any{place("app_metadata", "plan", "traits.email")}, "identifier trait"},
		"unsettable":       {[]any{place("app_metadata", "plan", "nope.plan")}, "can't set"},
		"missing key":      {[]any{place("app_metadata", "ghost", "metadata_admin.g")}, `has no app_metadata key "ghost"`},
		"twice":            {[]any{place("app_metadata", "plan", "metadata_admin.a"), place("app_metadata", "plan", "metadata_admin.b")}, "placed twice"},
		"bad from":         {[]any{place("profile", "plan", "metadata_admin.a")}, "from must be"},
		"no destination":   {[]any{place("app_metadata", "plan", "")}, "key and destination are required"},
		"not a list":       {map[string]any{"key": "plan"}, "cannot unmarshal object"},
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := hookstest.Dispatcher(t, 10, func(string, string, map[string]any) any { return tc.answer }, "")
			a, err := importprep.New(placing(), (&kratos.Connector{}).CheckTargetField, d)
			require.NoError(t, err)
			_, err = importprep.NewReader(context.Background(), cmfReader(t, metaUser("a")), a).ReadBatch()
			require.ErrorContains(t, err, tc.want)
			require.Regexp(t, `user a:|for "a"`, err.Error())
		})
	}
}

func TestMetadataPlaceBatches(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 2, func(string, string, map[string]any) any { return []any{} }, "")
	a, err := importprep.New(placing(), anyPath, d)
	require.NoError(t, err)
	var users []cmf.User
	for _, id := range strings.Split("a,b,c,d,e", ",") {
		users = append(users, metaUser(id))
	}
	r := importprep.NewReader(context.Background(), cmfReader(t, users...), a)
	for {
		if _, err := r.ReadBatch(); err != nil {
			require.True(t, errors.Is(err, errEOF(t)))
			break
		}
	}
	require.Equal(t, 3, rc.Calls("metadata.place"), "five users, batches of two")
}

func TestMetadataPlaceNeedsATargetThatCheckFields(t *testing.T) {
	require.NoError(t, importprep.Check(placing(), &kratos.Connector{}))
	_, err := importprep.New(placing(), anyPath, nil)
	require.Error(t, err, "a handler needs a hooks file")
}

func errEOF(t *testing.T) error {
	t.Helper()
	_, err := cmfReader(t).ReadUser()
	return err
}
