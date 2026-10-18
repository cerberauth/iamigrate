package flatfile_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func exportCSV(t *testing.T, d *hooks.Dispatcher, csv string, m mapping.Mapping) ([]cmf.User, connector.Manifest, error) {
	t.Helper()
	in := filepath.Join(t.TempDir(), "in.csv")
	require.NoError(t, os.WriteFile(in, []byte(csv), 0o600))
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	manifest, err := flatfile.New().Export(hooks.WithDispatcher(context.Background(), d), w, flatfile.ExportOptions{Path: in, Format: flatfile.FormatCSV, Mapping: m})
	if err != nil {
		return nil, manifest, err
	}
	require.NoError(t, w.Close())
	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	var users []cmf.User
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			return users, manifest, nil
		}
		require.NoError(t, err)
		users = append(users, u)
	}
}

func TestExportIDSourceHook(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		rec := item["record"].(map[string]any)
		switch rec["email"] {
		case "gone@example.com":
			return map[string]any{"action": "drop"}
		case "keep@example.com":
			return map[string]any{} // no source_id: the row's own
		}
		if hook == "export.record" {
			return map[string]any{"action": "keep"}
		}
		return map[string]any{"source_id": rec["tenant"].(string) + ":" + rec["email"].(string)}
	}, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"id.source": {Handler: "h"}}}
	csv := "tenant,email,source_id\nt1,ada@example.com,\nt2,keep@example.com,own-1\nt1,ada@example.com,\n"
	users, manifest, err := exportCSV(t, d, csv, m)
	require.NoError(t, err)
	require.Equal(t, 3, manifest.RecordCount)
	require.Equal(t, 1, rc.Calls("id.source"))
	require.Equal(t, "t1:ada@example.com", users[0].SourceID)
	require.Equal(t, "own-1", users[1].SourceID)
	require.Equal(t, "t1:ada@example.com", users[2].SourceID)
	items := rc.Envs[0]["data"].(map[string]any)["items"].(map[string]any)
	require.Equal(t, map[string]any{"record": map[string]any{"tenant": "t1", "email": "ada@example.com", "source_id": ""}}, items["record 1"], "the raw row")

	// With export.record dropping a row, the keys are still the record numbers
	// of the file.
	m.Strategies["export.record"] = mapping.StrategyRef{Handler: "h"}
	csv = "tenant,email\nt1,gone@example.com\nt1,ada@example.com\n"
	rc.Envs = nil
	users, manifest, err = exportCSV(t, d, csv, m)
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "t1:ada@example.com", users[0].SourceID)
	require.Len(t, manifest.SkippedRecords, 1)
	keys := rc.Envs[1]["data"].(map[string]any)["items"].(map[string]any)
	require.Equal(t, "id.source", rc.Envs[1]["hook"])
	require.Contains(t, keys, "record 2")
	require.Len(t, keys, 1)
}

func TestExportIDSourceNeedsHooksFile(t *testing.T) {
	in := filepath.Join(t.TempDir(), "in.csv")
	require.NoError(t, os.WriteFile(in, []byte("email\na@example.com\n"), 0o600))
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"id.source": {Handler: "h"}}}
	_, err := flatfile.New().Export(context.Background(), cmf.NewPlainWriter(io.Discard), flatfile.ExportOptions{Path: in, Format: flatfile.FormatCSV, Mapping: m})
	require.ErrorContains(t, err, "no hooks file given")
}

func TestExportIDSourceRunsBeforeFields(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		return map[string]any{"source_id": "from-hook"}
	}, "")
	m := mapping.Mapping{
		Fields:     []mapping.FieldMapping{{Source: "mail", CMF: "email"}},
		Strategies: map[string]mapping.StrategyRef{"id.source": {Handler: "h"}},
	}
	users, _, err := exportCSV(t, d, "mail\na@example.com\n", m)
	require.NoError(t, err)
	require.Equal(t, "from-hook", users[0].SourceID)
	require.Equal(t, "a@example.com", users[0].Emails[0].Value)
}

const (
	md5Digest  = "5f4dcc3b5aa765d61d8327deb882cf99"
	bcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
)

func TestExportHashDetectHook(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		switch key {
		case "u-md5":
			return map[string]any{"algorithm": "md5", "hash": map[string]any{"value": item["password"], "encoding": "hex"},
				"salt": map[string]any{"value": item["columns"].(map[string]any)["password_salt"], "encoding": "utf8", "position": "prefix"}}
		case "u-skip":
			return map[string]any{"skip": "legacy NTLM, not importable"}
		case "u-bad":
			return map[string]any{"algorithm": "sha256", "hash": map[string]any{"value": item["password"], "encoding": "hex"}}
		}
		return map[string]any{} // u-none: no decision
	}, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"hash.detect": {Handler: "h"}}}
	csv := "source_id,password,password_salt,password_salt_encoding\n" +
		"u-bcrypt," + bcryptHash + ",,\n" +
		"u-md5," + md5Digest + ",pepper,utf8\n" +
		"u-skip," + md5Digest + ",,\n" +
		"u-bad," + md5Digest + ",,\n" +
		"u-none," + md5Digest + ",,\n" +
		"u-nopass,,,\n"
	users, manifest, err := exportCSV(t, d, csv, m)
	require.NoError(t, err)

	require.Equal(t, 1, rc.Calls("hash.detect"), "one batch")
	items := rc.Envs[0]["data"].(map[string]any)["items"].(map[string]any)
	require.Len(t, items, 4, "only the passwords the columns don't settle")
	require.Equal(t, map[string]any{
		"source_id": "u-md5",
		"password":  md5Digest,
		"columns":   map[string]any{"password_salt": "pepper", "password_salt_encoding": "utf8"},
		"reason":    "password normalization failed: hash: raw digest format requires a Hint.Algorithm (md4/md5/sha1/sha256/sha512/hmac cannot be told apart from bytes alone)",
	}, items["u-md5"])

	require.Len(t, users, 3)
	require.Equal(t, []string{"u-bcrypt", "u-md5", "u-nopass"}, []string{users[0].SourceID, users[1].SourceID, users[2].SourceID})
	require.Equal(t, cmf.AlgBcrypt, users[0].Password.Algorithm)
	pw := users[1].Password
	require.Equal(t, cmf.AlgMD5, pw.Algorithm)
	require.True(t, pw.Portable, "portable unless the handler says otherwise")
	require.Equal(t, "pepper", pw.Salt.Value)
	require.Nil(t, users[2].Password)
	require.Equal(t, 3, manifest.RecordCount)
	require.Equal(t, 1, manifest.HashAlgorithmCounts[cmf.AlgMD5])

	reasons := map[string]string{}
	for _, s := range manifest.SkippedRecords {
		reasons[s.SourceID] = s.Reason
	}
	require.Len(t, reasons, 3)
	require.Equal(t, "legacy NTLM, not importable", reasons["u-skip"])
	require.Contains(t, reasons["u-bad"], "hash.detect: hash: not a sha256 digest")
	require.Contains(t, reasons["u-none"], "requires a Hint.Algorithm", "left to the built-in reason")
}

func TestExportHashDetectNotAskedWhenColumnsSettleIt(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		t.Fatal("hash.detect asked for a password the columns settle")
		return nil
	}, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"hash.detect": {Handler: "h"}}}
	users, _, err := exportCSV(t, d, "source_id,password,password_algorithm\nu1,"+md5Digest+",md5\nu2,"+bcryptHash+",\n", m)
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.Zero(t, rc.Calls("hash.detect"))
}

func TestExportHashDetectRejectsDuplicateSourceIDs(t *testing.T) {
	d, _ := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any { return map[string]any{} }, "")
	m := mapping.Mapping{Strategies: map[string]mapping.StrategyRef{"hash.detect": {Handler: "h"}}}
	_, _, err := exportCSV(t, d, "source_id,password\nu1,"+md5Digest+"\nu1,"+md5Digest+"\n", m)
	require.ErrorContains(t, err, `source_id "u1"`)
}
