package flatfile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func TestExportRunsCustomTransformsInOneBatchPerField(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(b, &env))
		got = append(got, env)
		res := map[string]any{}
		for k, it := range env["data"].(map[string]any)["items"].(map[string]any) {
			v := it.(map[string]any)["value"].(string)
			res[k] = map[string]string{"value": strings.ReplaceAll(v, "#", "@")}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	t.Setenv("FF_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {h: {webhook: {url: '" + srv.URL + "', secret_env: FF_SECRET}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)

	in := filepath.Join(t.TempDir(), "in.csv")
	require.NoError(t, os.WriteFile(in, []byte("id,mail\n1, Ada#Example.com \n2,bob#example.com\n"), 0o600))
	m := mapping.Mapping{
		Fields: []mapping.FieldMapping{
			{Source: "id", CMF: "source_id"},
			{Source: "mail", CMF: "email", Transform: "trim|unmangle|lowercase"},
		},
		Transforms: map[string]mapping.TransformRef{"unmangle": {Handler: "h"}},
	}
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	ctx := hooks.WithDispatcher(context.Background(), d)
	manifest, err := flatfile.New().Export(ctx, w, flatfile.ExportOptions{Path: in, Format: flatfile.FormatCSV, Mapping: m})
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 2, manifest.RecordCount)
	require.Len(t, got, 1, "one call for the column")
	require.Equal(t, "map.field", got[0]["hook"])

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	for _, want := range []string{"ada@example.com", "bob@example.com"} {
		u, err := r.ReadUser()
		require.NoError(t, err)
		require.Equal(t, want, u.Emails[0].Value)
	}

	_, err = flatfile.New().Export(context.Background(), cmf.NewPlainWriter(io.Discard), flatfile.ExportOptions{Path: in, Format: flatfile.FormatCSV, Mapping: m})
	require.ErrorContains(t, err, "no hooks file given", "a custom transform needs --hooks")
}

func TestExportRecordHook(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(b, &env))
		got = append(got, env)
		res := map[string]any{}
		for k, it := range env["data"].(map[string]any)["items"].(map[string]any) {
			row := it.(map[string]any)["record"].(map[string]any)
			switch row["id"] {
			case "2":
				res[k] = map[string]any{"action": "drop", "reason": "test row"}
			case "3":
				row["mail"] = "fixed@example.com"
				res[k] = map[string]any{"action": "replace", "record": row}
			default:
				res[k] = map[string]any{"action": "keep"}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	t.Setenv("FF_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {h: {webhook: {url: '" + srv.URL + "', secret_env: FF_SECRET}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)

	in := filepath.Join(t.TempDir(), "in.csv")
	require.NoError(t, os.WriteFile(in, []byte("id,mail\n1,a@example.com\n2,b@example.com\n3,broken\n"), 0o600))
	m := mapping.Mapping{
		Fields:     []mapping.FieldMapping{{Source: "id", CMF: "source_id"}, {Source: "mail", CMF: "email"}},
		Strategies: map[string]mapping.StrategyRef{"export.record": {Handler: "h"}},
	}
	var buf bytes.Buffer
	w := cmf.NewPlainWriter(&buf)
	manifest, err := flatfile.New().Export(hooks.WithDispatcher(context.Background(), d), w, flatfile.ExportOptions{Path: in, Format: flatfile.FormatCSV, Mapping: m})
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, 2, manifest.RecordCount)
	require.Equal(t, "record 2", manifest.SkippedRecords[0].SourceID)
	require.Equal(t, "test row", manifest.SkippedRecords[0].Reason)
	items := got[0]["data"].(map[string]any)["items"].(map[string]any)
	require.Equal(t, map[string]any{"record": map[string]any{"id": "1", "mail": "a@example.com"}}, items["record 1"], "the raw row, before the mapping")

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	u, err := r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "1", u.SourceID)
	u, err = r.ReadUser()
	require.NoError(t, err)
	require.Equal(t, "fixed@example.com", u.Emails[0].Value)
}
