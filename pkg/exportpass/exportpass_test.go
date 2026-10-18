package exportpass_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/exportpass"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/stretchr/testify/require"
)

func user(id string, alg cmf.Algorithm) cmf.User {
	return cmf.User{CMFVersion: cmf.Version, SourceID: id, Username: "user-" + id,
		Password: &cmf.Password{Algorithm: alg, Portable: true, Hash: cmf.HashValue{Value: "h", Encoding: cmf.EncodingUTF8}}}
}

func TestRewrite(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 2, func(hook, key string, item map[string]any) any {
		switch key {
		case "drop":
			return map[string]any{"action": "drop", "reason": "test account"}
		case "fix":
			return map[string]any{"action": "replace", "user": map[string]any{"source_id": "fix", "username": "fixed"}}
		}
		return map[string]any{"action": "keep"}
	}, "")
	set, err := strategy.New(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"export.user": {Handler: "h"}}}, d)
	require.NoError(t, err)
	a, err := ids.NewAssigner(&mapping.IDStrategy{Strategy: mapping.IDPrefix, Prefix: "p-"}, "auth0", connector.Capabilities{SupportsCustomID: true}, nil)
	require.NoError(t, err)
	pass := exportpass.New(set, a)

	var in bytes.Buffer
	w := cmf.NewPlainWriter(&in)
	for _, u := range []cmf.User{user("keep", cmf.AlgBcrypt), user("drop", cmf.AlgMD5), user("fix", cmf.AlgBcrypt)} {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&in)
	require.NoError(t, err)

	manifest := connector.Manifest{RecordCount: 3, HashAlgorithmCounts: map[cmf.Algorithm]int{cmf.AlgBcrypt: 2, cmf.AlgMD5: 1},
		SkippedRecords: []connector.SkippedRecord{{SourceID: "bad", Reason: "unparsable"}}}
	var out bytes.Buffer
	ow := cmf.NewPlainWriter(&out)
	require.NoError(t, pass.Rewrite(context.Background(), r, ow, &manifest))
	require.NoError(t, ow.Close())

	require.Equal(t, 2, rc.Calls("export.user"), "3 users in batches of 2")
	require.Equal(t, connector.Manifest{
		RecordCount:          2,
		HashAlgorithmCounts:  map[cmf.Algorithm]int{cmf.AlgBcrypt: 2},
		NonPortableMFACounts: map[cmf.MFAType]int{},
		SkippedRecords:       []connector.SkippedRecord{{SourceID: "bad", Reason: "unparsable"}, {SourceID: "drop", Reason: "test account"}},
	}, manifest)

	r, err = cmf.NewReader(&out)
	require.NoError(t, err)
	var got []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		got = append(got, u)
	}
	require.Len(t, got, 2)
	require.Equal(t, "fixed", got[1].Username)
	require.NotNil(t, got[1].Password, "a replaced user keeps its password")
	require.Equal(t, "p-fix", got[1].TargetIDs["auth0"], "ids are assigned after export.user")
}

func TestNoPassWithoutStrategies(t *testing.T) {
	require.Nil(t, exportpass.New(nil, nil))
}
