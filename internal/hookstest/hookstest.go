// Package hookstest serves fake webhook handlers to tests: one HTTP
// endpoint answering every strategy batch item by item.
package hookstest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

// Answer returns the answer for one item of a batch of hook, or nil to
// leave it out of the answer.
type Answer func(hook, key string, item map[string]any) any

// Receiver is a fake handler and what it was sent.
type Receiver struct {
	mu   sync.Mutex
	Envs []map[string]any
}

// Calls returns how many requests hook got.
func (r *Receiver) Calls(hook string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.Envs {
		if e["hook"] == hook {
			n++
		}
	}
	return n
}

// Dispatcher returns a Dispatcher whose one handler, "h", with the given
// batch size, answers with answer, plus extra hooks.yaml lines (events, say).
func Dispatcher(t *testing.T, batchSize int, answer Answer, extra string) (*hooks.Dispatcher, *Receiver) {
	t.Helper()
	rc := &Receiver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(b, &env))
		rc.mu.Lock()
		rc.Envs = append(rc.Envs, env)
		rc.mu.Unlock()
		hook := env["hook"].(string)
		data, _ := env["data"].(map[string]any)
		items, ok := data["items"].(map[string]any)
		if !ok {
			return
		}
		res := map[string]any{}
		for k, it := range items {
			if a := answer(hook, k, it.(map[string]any)); a != nil {
				res[k] = a
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HOOKSTEST_SECRET", "s")
	yaml := "version: 1\nhandlers: {h: {webhook: {url: '" + srv.URL + "', secret_env: HOOKSTEST_SECRET, retries: 0, batch_size: " +
		itoa(batchSize) + "}}}\n" + strings.TrimSpace(extra) + "\n"
	cfg, err := hooks.Parse([]byte(yaml))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	return d, rc
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
