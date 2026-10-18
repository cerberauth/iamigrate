package importprep_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func credUser(id string) cmf.User {
	u := user(id)
	u.Password = &cmf.Password{Algorithm: cmf.AlgMD5, Portable: true, Hash: cmf.HashValue{Value: "x", Encoding: cmf.EncodingHex}}
	u.MFAFactors = []cmf.MFAFactor{{Type: cmf.MFATOTP, Value: "secret", Portable: true}}
	u.UserMetadata = map[string]any{"email": "legacy@example.com", "theme": "dark"}
	return u
}

func TestReaderAppliesImportStrategies(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		switch hook {
		case "import.user":
			if key == "skip" {
				return map[string]any{"action": "drop", "reason": "inactive"}
			}
			return map[string]any{"action": "keep"}
		case "hash.translate":
			require.NotNil(t, item["password"], "hash.translate gets the password")
			if key == "reset" {
				return map[string]any{"reset": true}
			}
			return map[string]any{"password": map[string]any{"algorithm": "bcrypt", "hash": map[string]any{"value": "$2a$", "encoding": "utf8"}, "portable": true}}
		case "mfa.translate":
			return map[string]any{"mfa_factors": []any{}}
		}
		return nil
	}, "")
	m := mapping.Mapping{
		Strategies: map[string]mapping.StrategyRef{"import.user": {Handler: "h"}, "hash.translate": {Handler: "h"}, "mfa.translate": {Handler: "h"}},
		Metadata: []mapping.MetadataRoute{
			{Key: "email", From: "user_metadata", Destination: "metadata_admin.legacy_email"},
			{Key: "plan", From: "app_metadata", Destination: "drop"},
		},
	}
	a, err := importprep.New(m, (&kratos.Connector{}).CheckTargetField, d)
	require.NoError(t, err)
	r := importprep.NewReader(context.Background(), cmfReader(t, credUser("a"), credUser("skip"), credUser("reset")), a)

	batch, err := r.ReadBatch()
	require.NoError(t, err)
	require.Len(t, batch, 2)
	_, err = r.ReadBatch()
	require.ErrorIs(t, err, io.EOF)

	got := batch[0]
	require.Equal(t, cmf.AlgBcrypt, got.User.Password.Algorithm)
	require.Empty(t, got.User.MFAFactors)
	require.Equal(t, map[string]any{"theme": "dark"}, got.User.UserMetadata, "the routed key leaves user_metadata")
	require.NotContains(t, got.User.AppMetadata, "plan")
	require.Equal(t, []importprep.Field{{Path: "metadata_admin.legacy_email", Value: "legacy@example.com"}}, got.Fields)

	require.Equal(t, "reset", batch[1].User.SourceID)
	require.False(t, batch[1].User.Password.Portable, "a reset password is imported as non-portable")
	require.Equal(t, cmf.AlgMD5, batch[1].User.Password.Algorithm)

	require.Equal(t, []connector.ImportError{{SourceID: "skip", Code: importprep.SkippedCode, Message: "inactive"}}, r.Skipped())
	require.Equal(t, 1, rc.Calls("import.user"))
	for _, e := range rc.Envs {
		if e["hook"] == "import.user" {
			b, _ := json.Marshal(e["data"])
			require.NotContains(t, string(b), "secret", "import.user never sees credentials")
		}
	}
}

func TestReaderSkipsAWholeBatch(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 1, func(hook, key string, item map[string]any) any {
		if key == "a" {
			return map[string]any{"action": "drop"}
		}
		return map[string]any{}
	}, "")
	a, err := importprep.New(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"import.user": {Handler: "h"}}}, anyPath, d)
	require.NoError(t, err)
	importprep.SetBatchForTest(a, 1)
	r := importprep.NewReader(context.Background(), cmfReader(t, user("a"), user("b")), a)
	u, _, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "b", u.SourceID)
	_, _, err = r.ReadUser()
	require.ErrorIs(t, err, io.EOF)
}

func TestPayloads(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		if key == "a" {
			p := item["payload"].(map[string]any)
			p["extra"] = true
			return map[string]any{"payload": p}
		}
		return map[string]any{}
	}, "")
	a, err := importprep.New(mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"import.payload": {Handler: "h"}}}, anyPath, d)
	require.NoError(t, err)
	out, err := a.Payloads(context.Background(), []string{"a", "b"}, []any{map[string]any{"n": 1}, map[string]any{"n": 2}})
	require.NoError(t, err)
	require.JSONEq(t, `{"n": 1, "extra": true}`, string(out[0].(json.RawMessage)))
	require.Equal(t, map[string]any{"n": 2}, out[1], "no payload in the answer keeps the connector's")

	var none *importprep.Applier
	in := []any{1}
	out, err = none.Payloads(context.Background(), []string{"a"}, in)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

// conflictTarget treats code "DUP" as a conflict.
type conflictTarget struct{ connector.TargetConnector }

func (conflictTarget) IsConflict(e connector.ImportError) bool { return e.Code == "DUP" }

func TestConflicts(t *testing.T) {
	report := connector.ImportReport{Failed: []connector.ImportError{{SourceID: "a", Code: "DUP"}, {SourceID: "b", Code: "OTHER"}}}
	importprep.Conflicts(mapping.Mapping{}, conflictTarget{}, &report)
	require.Len(t, report.Failed, 2, "no conflict section: failures stay failures")

	importprep.Conflicts(mapping.Mapping{Conflict: &mapping.Conflict{OnDuplicate: "skip"}}, conflictTarget{}, &report)
	require.Equal(t, []connector.ImportError{{SourceID: "b", Code: "OTHER"}}, report.Failed)
	require.Equal(t, []connector.ImportError{{SourceID: "a", Code: "DUP"}}, report.Skipped)

	require.True(t, importprep.Upsert(mapping.Mapping{Conflict: &mapping.Conflict{OnDuplicate: "upsert"}}, false))
	require.True(t, importprep.Upsert(mapping.Mapping{}, true))
	require.False(t, importprep.Upsert(mapping.Mapping{Conflict: &mapping.Conflict{OnDuplicate: "skip"}}, false))
}

func TestCheckRejectsWhatTheTargetCantDo(t *testing.T) {
	err := importprep.Check(mapping.Mapping{Conflict: &mapping.Conflict{OnDuplicate: "upsert"}}, &kratos.Connector{})
	require.ErrorContains(t, err, "kratos can't update an existing user")
	err = importprep.Check(mapping.Mapping{Metadata: []mapping.MetadataRoute{{Key: "k", From: "user_metadata", Destination: "traits.email"}}}, &kratos.Connector{})
	require.ErrorContains(t, err, "identifier trait")
	require.NoError(t, importprep.Check(mapping.Mapping{Metadata: []mapping.MetadataRoute{{Key: "k", From: "user_metadata", Destination: "drop"}}}, &kratos.Connector{}))
}
