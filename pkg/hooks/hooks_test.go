package hooks_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

const secret = "s3cret"

// receiver is a webhook endpoint recording what it got and answering with
// answer, which gets the decoded envelope.
type receiver struct {
	t      *testing.T
	answer func(env map[string]any) (int, string)

	mu       sync.Mutex
	got      []map[string]any
	headers  []http.Header
	verified []error
}

func newReceiver(t *testing.T, answer func(env map[string]any) (int, string)) (*receiver, *httptest.Server) {
	rc := &receiver{t: t, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var env map[string]any
		require.NoError(t, json.Unmarshal(body, &env))
		rc.mu.Lock()
		rc.got = append(rc.got, env)
		rc.headers = append(rc.headers, r.Header.Clone())
		rc.verified = append(rc.verified, hooks.Verify([]byte(secret), r.Header.Get(hooks.HeaderTimestamp), body,
			r.Header.Get(hooks.HeaderSignature), time.Now(), 5*time.Minute))
		rc.mu.Unlock()
		status, resp := 200, ""
		if rc.answer != nil {
			status, resp = rc.answer(env)
		}
		w.WriteHeader(status)
		io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	return rc, srv
}

func (rc *receiver) calls() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.got)
}

func dispatcher(t *testing.T, yaml string, url string) (*hooks.Dispatcher, *[]hooks.Result) {
	t.Helper()
	t.Setenv("HOOK_SECRET", secret)
	t.Cleanup(hooks.SetRetryBackoffForTest(time.Millisecond))
	cfg, err := hooks.Parse([]byte(strings.ReplaceAll(yaml, "URL", url)))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	var mu sync.Mutex
	var results []hooks.Result
	return d.ForJob("job1", func(r hooks.Result) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	}).InState("importing"), &results
}

const oneHandler = `
version: 1
handlers:
  rx:
    webhook: {url: URL, secret_env: HOOK_SECRET, retries: 2, batch_size: 2}
events:
  import.before: {handler: rx}
  import.after: {handler: rx}
  validate.after: {handler: rx}
`

func TestParseRejects(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"no version":      {"handlers: {}", "version must be 1"},
		"unknown key":     {"version: 1\nhandlerz: {}", "field handlerz not found"},
		"no url":          {"version: 1\nhandlers: {h: {webhook: {secret_env: X}}}", "url is required"},
		"relative url":    {"version: 1\nhandlers: {h: {webhook: {url: /x, secret_env: X}}}", "absolute http(s) URL"},
		"other scheme":    {"version: 1\nhandlers: {h: {webhook: {url: 'file:///etc/passwd', secret_env: X}}}", "absolute http(s) URL"},
		"no secret":       {"version: 1\nhandlers: {h: {webhook: {url: 'http://x'}}}", "secret_env and secret_file"},
		"two secrets":     {"version: 1\nhandlers: {h: {webhook: {url: 'http://x', secret_env: X, secret_file: f}}}", "secret_env and secret_file"},
		"no kind":         {"version: 1\nhandlers: {h: {}}", "no kind set"},
		"unknown event":   {"version: 1\nevents: {import.whenever: {handler: h}}", "unknown event"},
		"strategy event":  {"version: 1\nevents: {id.target: {handler: h}}", "configure it in mapping.yaml"},
		"unknown handler": {"version: 1\nevents: {import.after: {handler: h}}", `handler "h" is not declared`},
		"bad on_failure": {"version: 1\nhandlers: {h: {webhook: {url: 'http://x', secret_env: X}}}\nevents: {import.after: {handler: h, on_failure: retry}}",
			"on_failure must be"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := hooks.Parse([]byte(tc.yaml))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestNewFailsOnAMissingSecret(t *testing.T) {
	cfg, err := hooks.Parse([]byte("version: 1\nhandlers: {h: {webhook: {url: 'http://x', secret_env: IAMIGRATE_TEST_UNSET}}}"))
	require.NoError(t, err)
	_, err = hooks.New(cfg)
	require.ErrorContains(t, err, "$IAMIGRATE_TEST_UNSET is not set")
}

func TestSecretFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(secret+"\n"), 0o600))
	rc, srv := newReceiver(t, nil)
	cfg, err := hooks.Parse(fmt.Appendf(nil, "version: 1\nhandlers: {h: {webhook: {url: %q, secret_file: %q}}}\nevents: {job.done: {handler: h}}", srv.URL, path))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	_, err = d.Event(context.Background(), hooks.JobDone, nil)
	require.NoError(t, err)
	require.NoError(t, rc.verified[0], "trailing newline of the secret file is not part of the secret")
}

func TestNilDispatcherIsANoOp(t *testing.T) {
	var d *hooks.Dispatcher
	a, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.NoError(t, err)
	require.True(t, a.Allow)
	require.False(t, d.Configured(hooks.ImportBefore))
	require.Nil(t, hooks.FromContext(context.Background()))
	require.Nil(t, d.ForJob("j", nil).InState("s"))
}

func TestUnconfiguredEventSendsNothing(t *testing.T) {
	rc, srv := newReceiver(t, nil)
	d, _ := dispatcher(t, oneHandler, srv.URL)
	a, err := d.Event(context.Background(), hooks.JobDone, nil)
	require.NoError(t, err)
	require.True(t, a.Allow)
	require.Zero(t, rc.calls())
}

func TestEventEnvelopeAndSignature(t *testing.T) {
	rc, srv := newReceiver(t, nil)
	d, results := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportAfter, map[string]any{"succeeded": 3})
	require.NoError(t, err)

	require.Equal(t, 1, rc.calls())
	env := rc.got[0]
	require.Equal(t, "1", env["version"])
	require.Equal(t, "import.after", env["hook"])
	require.Equal(t, "job1", env["job_id"])
	require.Equal(t, "importing", env["state"])
	require.Equal(t, hooks.EventID("job1", "import.after", "importing", 0), env["event_id"])
	require.Equal(t, map[string]any{"succeeded": float64(3)}, env["data"])
	require.NotContains(t, env, "batch")

	h := rc.headers[0]
	require.Equal(t, "application/json", h.Get("Content-Type"))
	require.Equal(t, "import.after", h.Get(hooks.HeaderHook))
	require.Equal(t, env["event_id"], h.Get(hooks.HeaderEventID))
	require.True(t, strings.HasPrefix(h.Get(hooks.HeaderSignature), "v1="))
	require.True(t, strings.HasPrefix(h.Get("User-Agent"), "iamigrate/"))
	require.NoError(t, rc.verified[0])
	require.Empty(t, *results, "a successful call isn't recorded")
}

func TestEventIDIsDeterministic(t *testing.T) {
	a := hooks.EventID("job1", "state.enter", "importing", 0)
	require.Equal(t, a, hooks.EventID("job1", "state.enter", "importing", 0))
	require.NotEqual(t, a, hooks.EventID("job1", "state.enter", "exporting", 0))
	require.NotEqual(t, a, hooks.EventID("job2", "state.enter", "importing", 0))
	require.NotEqual(t, a, hooks.EventID("job1", "state.exit", "importing", 0))
	require.NotEqual(t, a, hooks.EventID("job1", "state.enter", "importing", 1))
}

func TestVerifyRejects(t *testing.T) {
	body := []byte(`{"a":1}`)
	now := time.Unix(1_700_000_000, 0)
	ts := "1700000000"
	sig := hooks.Sign([]byte(secret), ts, body)
	require.NoError(t, hooks.Verify([]byte(secret), ts, body, sig, now, time.Minute))
	require.ErrorContains(t, hooks.Verify([]byte("other"), ts, body, sig, now, time.Minute), "signature mismatch")
	require.ErrorContains(t, hooks.Verify([]byte(secret), ts, []byte(`{"a":2}`), sig, now, time.Minute), "signature mismatch")
	require.ErrorContains(t, hooks.Verify([]byte(secret), "1700000001", body, sig, now, time.Minute), "signature mismatch")
	require.ErrorContains(t, hooks.Verify([]byte(secret), ts, body, sig, now.Add(2*time.Minute), time.Minute), "outside tolerance")
	require.ErrorContains(t, hooks.Verify([]byte(secret), "x", body, sig, now, time.Minute), "invalid timestamp")
}

func TestVeto(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) {
		return 200, `{"allow": false, "reason": "change freeze"}`
	})
	d, results := dispatcher(t, oneHandler, srv.URL)
	a, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	var veto *hooks.VetoError
	require.ErrorAs(t, err, &veto)
	require.Equal(t, "change freeze", veto.Reason)
	require.False(t, a.Allow)
	require.Len(t, *results, 1)
	r := (*results)[0]
	require.Equal(t, hooks.Vetoed, r.Outcome)
	require.Equal(t, "import.before", r.Hook)
	require.Equal(t, "importing", r.State)
	require.Equal(t, "change freeze", r.Reason)
	require.False(t, r.At.IsZero())
}

func TestVetoEventAllowsByDefault(t *testing.T) {
	for _, body := range []string{"", `{}`, `{"allow": true}`} {
		_, srv := newReceiver(t, func(map[string]any) (int, string) { return 200, body })
		d, results := dispatcher(t, oneHandler, srv.URL)
		a, err := d.Event(context.Background(), hooks.ImportBefore, nil)
		require.NoError(t, err, body)
		require.True(t, a.Allow, body)
		require.Empty(t, *results)
	}
}

func TestNotifyEventIgnoresAndRecordsFailuresByDefault(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 400, "nope" })
	d, results := dispatcher(t, oneHandler, srv.URL)
	a, err := d.Event(context.Background(), hooks.ImportAfter, nil)
	require.NoError(t, err)
	require.True(t, a.Allow)
	require.Len(t, *results, 1)
	require.Equal(t, hooks.Ignored, (*results)[0].Outcome)
	require.Contains(t, (*results)[0].Reason, "webhook answered 400: nope")
}

func TestVetoEventFailsOnHandlerFailureByDefault(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 400, "" })
	d, results := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.ErrorContains(t, err, "hook import.before: webhook answered 400")
	require.Equal(t, hooks.Failed, (*results)[0].Outcome)
}

func TestOnFailureOverridesTheDefault(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 400, "" })
	d, results := dispatcher(t, `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: HOOK_SECRET}}}
events:
  import.before: {handler: rx, on_failure: ignore}
  import.after: {handler: rx, on_failure: fail}
`, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.NoError(t, err)
	_, err = d.Event(context.Background(), hooks.ImportAfter, nil)
	require.Error(t, err)
	require.Equal(t, hooks.Ignored, (*results)[0].Outcome)
	require.Equal(t, hooks.Failed, (*results)[1].Outcome)
}

func TestDecideEventReturnsTheAnswer(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 200, `{"fail": false}` })
	d, _ := dispatcher(t, oneHandler, srv.URL)
	a, err := d.Event(context.Background(), hooks.ValidateAfter, nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"fail": false}`, string(a.Raw))
}

func TestRetriesTransientFailures(t *testing.T) {
	for _, status := range []int{500, 502, 429} {
		n := 0
		rc, srv := newReceiver(t, func(map[string]any) (int, string) {
			n++
			if n < 3 {
				return status, ""
			}
			return 200, ""
		})
		d, results := dispatcher(t, oneHandler, srv.URL)
		_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
		require.NoError(t, err, status)
		require.Equal(t, 3, rc.calls(), status)
		require.Empty(t, *results)
		require.Equal(t, rc.got[0]["event_id"], rc.got[2]["event_id"], "a retry carries the same event ID")
	}
}

func TestGivesUpAfterRetries(t *testing.T) {
	rc, srv := newReceiver(t, func(map[string]any) (int, string) { return 503, "" })
	d, _ := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.ErrorContains(t, err, "503")
	require.Equal(t, 3, rc.calls(), "one try and retries: 2")
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	rc, srv := newReceiver(t, func(map[string]any) (int, string) { return 422, "" })
	d, _ := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.Error(t, err)
	require.Equal(t, 1, rc.calls())
}

func TestTimeoutIsRetriedThenFails(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	t.Cleanup(srv.Close)
	d, _ := dispatcher(t, `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: HOOK_SECRET, timeout: 50ms, retries: 1}}}
events: {import.before: {handler: rx}}
`, srv.URL)
	start := time.Now()
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.Error(t, err)
	require.Less(t, time.Since(start), 3*time.Second)
	mu.Lock()
	require.Equal(t, 2, calls)
	mu.Unlock()
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	rc, target := newReceiver(t, nil)
	srv := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	t.Cleanup(srv.Close)
	d, _ := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.ErrorContains(t, err, "307")
	require.Zero(t, rc.calls())
}

func TestNonJSONAnswerFails(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 200, "<html>" })
	d, _ := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Event(context.Background(), hooks.ImportBefore, nil)
	require.ErrorContains(t, err, "not JSON")
}

// echoResults answers a strategy batch with one result per item.
func echoResults(env map[string]any) (int, string) {
	items := env["data"].(map[string]any)["items"].(map[string]any)
	res := map[string]any{}
	for k := range items {
		res[k] = map[string]any{"id": "t-" + k}
	}
	b, _ := json.Marshal(map[string]any{"results": res})
	return 200, string(b)
}

func items(keys ...string) []hooks.Item {
	out := make([]hooks.Item, len(keys))
	for i, k := range keys {
		out[i] = hooks.Item{Key: k, Data: map[string]any{"source_id": k}}
	}
	return out
}

func TestBatcherSendsBatchesOfTheHandlersSize(t *testing.T) {
	rc, srv := newReceiver(t, echoResults)
	d, _ := dispatcher(t, oneHandler, srv.URL)
	b := d.Batcher("id.target", hooks.Ref{Handler: "rx"})
	require.Equal(t, 2, b.Size())

	res, err := b.Resolve(context.Background(), items("a", "b", "c"))
	require.NoError(t, err)
	require.Len(t, res, 3)
	require.JSONEq(t, `{"id":"t-c"}`, string(res["c"]))
	res, err = b.Resolve(context.Background(), items("d"))
	require.NoError(t, err)
	require.Len(t, res, 1)

	require.Equal(t, 3, rc.calls(), "3 users in batches of 2, then 1: never one call per user")
	for i, want := range []struct{ index, size int }{{1, 2}, {2, 1}, {3, 1}} {
		env := rc.got[i]
		require.Equal(t, "id.target", env["hook"])
		require.Equal(t, map[string]any{"index": float64(want.index), "size": float64(want.size)}, env["batch"])
		require.Equal(t, hooks.EventID("job1", "id.target", "importing", want.index), env["event_id"])
	}
}

func TestBatcherRejectsAnswersThatDontMatchTheBatch(t *testing.T) {
	for name, body := range map[string]string{
		"missing": `{"results": {"a": {}}}`,
		"extra":   `{"results": {"a": {}, "b": {}, "z": {}}}`,
		"shape":   `[1, 2]`,
		"empty":   ``,
	} {
		t.Run(name, func(t *testing.T) {
			_, srv := newReceiver(t, func(map[string]any) (int, string) { return 200, body })
			d, results := dispatcher(t, oneHandler, srv.URL)
			_, err := d.Batcher("id.target", hooks.Ref{Handler: "rx"}).Resolve(context.Background(), items("a", "b"))
			require.Error(t, err)
			require.Equal(t, hooks.Failed, (*results)[0].Outcome)
		})
	}
}

func TestBatcherIgnoredFailureFallsBackToBuiltIn(t *testing.T) {
	_, srv := newReceiver(t, func(map[string]any) (int, string) { return 400, "" })
	d, results := dispatcher(t, oneHandler, srv.URL)
	res, err := d.Batcher("id.target", hooks.Ref{Handler: "rx", OnFailure: hooks.Ignore}).Resolve(context.Background(), items("a"))
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, hooks.Ignored, (*results)[0].Outcome)
}

func TestBatcherRejectsDuplicateKeys(t *testing.T) {
	rc, srv := newReceiver(t, echoResults)
	d, _ := dispatcher(t, oneHandler, srv.URL)
	_, err := d.Batcher("id.target", hooks.Ref{Handler: "rx"}).Resolve(context.Background(), items("a", "a"))
	require.ErrorContains(t, err, `duplicate item key "a"`)
	require.Zero(t, rc.calls())
}

func TestBatcherWithoutHooksFileFails(t *testing.T) {
	var d *hooks.Dispatcher
	_, err := d.Batcher("id.target", hooks.Ref{Handler: "rx"}).Resolve(context.Background(), items("a"))
	require.ErrorContains(t, err, "no hooks file")
}

func TestFingerprint(t *testing.T) {
	a, err := hooks.Parse([]byte("version: 1\n"))
	require.NoError(t, err)
	b, err := hooks.Parse([]byte("version: 1\nhandlers: {}\n"))
	require.NoError(t, err)
	require.Len(t, a.Fingerprint(), 64)
	require.NotEqual(t, a.Fingerprint(), b.Fingerprint())
}

func TestEventAtGivesEachPartItsOwnEventID(t *testing.T) {
	rc, srv := newReceiver(t, nil)
	d, _ := dispatcher(t, `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: HOOK_SECRET}}}
events: {import.chunk.after: {handler: rx}}
`, srv.URL)
	for i := 1; i <= 2; i++ {
		_, err := d.EventAt(context.Background(), hooks.ImportChunkAfter, i, 10, nil)
		require.NoError(t, err)
	}
	require.Equal(t, map[string]any{"index": float64(1), "size": float64(10)}, rc.got[0]["batch"])
	require.Equal(t, hooks.EventID("job1", "import.chunk.after", "importing", 2), rc.got[1]["event_id"])
	require.NotEqual(t, rc.got[0]["event_id"], rc.got[1]["event_id"])
}

func TestNotifySendsItemsInBatches(t *testing.T) {
	rc, srv := newReceiver(t, func(map[string]any) (int, string) { return 200, `{"ignored": true}` })
	d, _ := dispatcher(t, `
version: 1
handlers: {rx: {webhook: {url: URL, secret_env: HOOK_SECRET, batch_size: 2}}}
events: {import.user.result: {handler: rx}}
`, srv.URL)
	require.NoError(t, d.Notify(context.Background(), hooks.ImportUserResult, []any{"a", "b", "c"}))
	require.Equal(t, 2, rc.calls())
	require.Equal(t, []any{"a", "b"}, rc.got[0]["data"].(map[string]any)["items"])
	require.Equal(t, []any{"c"}, rc.got[1]["data"].(map[string]any)["items"])
	require.Equal(t, map[string]any{"index": float64(2), "size": float64(1)}, rc.got[1]["batch"])

	require.ErrorContains(t, d.Notify(context.Background(), hooks.ImportBefore, nil), "isn't a notify event")
	var nilD *hooks.Dispatcher
	require.NoError(t, nilD.Notify(context.Background(), hooks.ImportUserResult, []any{"a"}))
}
