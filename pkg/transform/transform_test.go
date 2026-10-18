package transform_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/transform"
	"github.com/stretchr/testify/require"
)

func TestBuiltins(t *testing.T) {
	p, err := transform.Builtin.Compile(" trim | lowercase ")
	require.NoError(t, err)
	vals := []string{"  Ada@Example.COM ", ""}
	require.NoError(t, p.Apply(context.Background(), "email", []string{"1", "2"}, vals))
	require.Equal(t, []string{"ada@example.com", ""}, vals)

	p, err = transform.Builtin.Compile("not")
	require.NoError(t, err)
	vals = []string{"yes", "0", "", "maybe"}
	err = p.Apply(context.Background(), "blocked", []string{"1", "2", "3", "4"}, vals)
	var ve *transform.ValueError
	require.ErrorAs(t, err, &ve)
	require.Equal(t, 3, ve.Index)

	_, err = transform.Builtin.Compile("trim|reverse")
	require.ErrorContains(t, err, `unknown transform "reverse"`)
	require.Equal(t, []string{"bool", "lowercase", "not", "trim", "uppercase"}, transform.Builtins())
}

func TestCheck(t *testing.T) {
	m := mapping.Mapping{
		Fields:       []mapping.FieldMapping{{CMF: "email", Transform: "trim|my_fn"}},
		Transforms:   map[string]mapping.TransformRef{"my_fn": {Handler: "h"}},
		TargetFields: []mapping.TargetField{{CMF: "profile.locale", Target: "traits.locale", Transform: "lowercase"}},
	}
	require.NoError(t, transform.Check(m))
	m.TargetFields[0].Transform = "nope"
	require.ErrorContains(t, transform.Check(m), `target_fields[0] (traits.locale): unknown transform "nope"`)
}

// handler serves custom transform batches, upper-casing values and
// prefixing them with "x:", and records the envelopes.
func handler(t *testing.T, status int) (*hooks.Dispatcher, *[]map[string]any) {
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
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		res := map[string]any{}
		for k, it := range env["data"].(map[string]any)["items"].(map[string]any) {
			res[k] = map[string]string{"value": "x:" + strings.ToUpper(it.(map[string]any)["value"].(string))}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TR_SECRET", "s")
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {h: {webhook: {url: '" + srv.URL + "', secret_env: TR_SECRET, batch_size: 2, retries: 0}}}"))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	return d, &got
}

func TestCustomTransformIsBatchedAndSkipsEmptyValues(t *testing.T) {
	d, got := handler(t, 200)
	reg, err := transform.New(mapping.Mapping{Transforms: map[string]mapping.TransformRef{"shout": {Handler: "h"}}}, transform.ImportHook, d)
	require.NoError(t, err)
	p, err := reg.Compile("trim|shout|lowercase")
	require.NoError(t, err)

	vals := []string{" a ", "", "b", "c"}
	require.NoError(t, p.Apply(context.Background(), "traits.locale", []string{"u1", "u2", "u3", "u4"}, vals))
	require.Equal(t, []string{"x:a", "", "x:b", "x:c"}, vals)
	require.Len(t, *got, 2, "3 non-empty values in batches of 2")
	require.Equal(t, "map.target_field", (*got)[0]["hook"])
	items := (*got)[0]["data"].(map[string]any)["items"].(map[string]any)
	require.Equal(t, map[string]any{"transform": "shout", "field": "traits.locale", "value": "a"}, items["u1"])
}

func TestCustomTransformFailure(t *testing.T) {
	d, _ := handler(t, 400)
	m := mapping.Mapping{Transforms: map[string]mapping.TransformRef{"shout": {Handler: "h"}, "soft": {Handler: "h", OnFailure: "ignore"}}}
	reg, err := transform.New(m, transform.ExportHook, d)
	require.NoError(t, err)

	p, _ := reg.Compile("shout")
	require.ErrorContains(t, p.Apply(context.Background(), "email", []string{"1"}, []string{"a"}), "webhook answered 400")

	p, _ = reg.Compile("soft|uppercase")
	vals := []string{"a"}
	require.NoError(t, p.Apply(context.Background(), "email", []string{"1"}, vals))
	require.Equal(t, []string{"A"}, vals, "an ignored failure leaves the value for the next steps")
}

func TestNewRejects(t *testing.T) {
	_, err := transform.New(mapping.Mapping{Transforms: map[string]mapping.TransformRef{"trim": {Handler: "h"}}}, transform.ExportHook, nil)
	require.ErrorContains(t, err, `"trim" is a built-in transform`)
	_, err = transform.New(mapping.Mapping{Transforms: map[string]mapping.TransformRef{"a|b": {Handler: "h"}}}, transform.ExportHook, nil)
	require.ErrorContains(t, err, "not a valid name")
	_, err = transform.New(mapping.Mapping{Transforms: map[string]mapping.TransformRef{"my_fn": {Handler: "h"}}}, transform.ExportHook, nil)
	require.ErrorContains(t, err, "no hooks file given")
}
