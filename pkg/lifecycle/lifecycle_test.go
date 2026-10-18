package lifecycle_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/lifecycle"
	"github.com/stretchr/testify/require"
)

// receive returns a context whose hooks send every event to a handler
// answering answers[hook], and the envelopes it got.
func receive(t *testing.T, answers map[string]string) (context.Context, *[]map[string]any) {
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
		io.WriteString(w, answers[env["hook"].(string)])
	}))
	t.Cleanup(srv.Close)
	t.Setenv("LC_SECRET", "s")
	cfg, err := hooks.Parse([]byte(`
version: 1
handlers: {rx: {webhook: {url: '` + srv.URL + `', secret_env: LC_SECRET, batch_size: 2}}}
events:
  export.after: {handler: rx}
  validate.after: {handler: rx}
  import.before: {handler: rx}
  import.user.result: {handler: rx}
  import.after: {handler: rx}
  verify.after: {handler: rx}
`))
	require.NoError(t, err)
	d, err := hooks.New(cfg)
	require.NoError(t, err)
	return hooks.WithDispatcher(context.Background(), d), &got
}

var problems = []connector.Problem{{SourceID: "a", Field: "emails"}, {SourceID: "b", Field: "username"}}

func TestWithoutHooksTheStepsOutcomeStands(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, lifecycle.ExportAfter(ctx, connector.Manifest{}))

	failing, warnings, fail, err := lifecycle.ValidateAfter(ctx, problems)
	require.NoError(t, err)
	require.Equal(t, problems, failing)
	require.Nil(t, warnings)
	require.True(t, fail)
	_, _, fail, _ = lifecycle.ValidateAfter(ctx, nil)
	require.False(t, fail)

	id, err := lifecycle.ImportBefore(ctx, "auth0", "con_1", false)
	require.NoError(t, err)
	require.Equal(t, "con_1", id)
	require.NoError(t, lifecycle.ImportAfter(ctx, connector.ImportReport{Succeeded: []string{"a"}}))

	fail, err = lifecycle.VerifyAfter(ctx, connector.DiffReport{}, true)
	require.NoError(t, err)
	require.True(t, fail)
}

func TestExportAfterVeto(t *testing.T) {
	ctx, got := receive(t, map[string]string{"export.after": `{"allow": false, "reason": "too few users"}`})
	err := lifecycle.ExportAfter(ctx, connector.Manifest{RecordCount: 3})
	var veto *hooks.VetoError
	require.ErrorAs(t, err, &veto)
	require.Equal(t, "too few users", veto.Reason)
	require.Equal(t, float64(3), (*got)[0]["data"].(map[string]any)["manifest"].(map[string]any)["record_count"])
}

func TestValidateAfterDowngrades(t *testing.T) {
	ctx, got := receive(t, map[string]string{"validate.after": `{"downgrade": [1]}`})
	failing, warnings, fail, err := lifecycle.ValidateAfter(ctx, problems)
	require.NoError(t, err)
	require.Equal(t, problems[:1], failing)
	require.Equal(t, problems[1:], warnings)
	require.True(t, fail)
	sent := (*got)[0]["data"].(map[string]any)["problems"].([]any)
	require.Equal(t, map[string]any{"source_id": "b", "field": "username", "rule": "", "value": ""}, sent[1])

	ctx, _ = receive(t, map[string]string{"validate.after": `{"downgrade": [0, 1]}`})
	_, _, fail, err = lifecycle.ValidateAfter(ctx, problems)
	require.NoError(t, err)
	require.False(t, fail, "nothing left to fail on")

	ctx, _ = receive(t, map[string]string{"validate.after": `{"fail": false}`})
	failing, _, fail, err = lifecycle.ValidateAfter(ctx, problems)
	require.NoError(t, err)
	require.Len(t, failing, 2)
	require.False(t, fail, "a threshold the handler applies can pass the problems")

	ctx, _ = receive(t, map[string]string{"validate.after": `{"downgrade": [5]}`})
	_, _, _, err = lifecycle.ValidateAfter(ctx, problems)
	require.ErrorContains(t, err, "no problem at index 5")
}

func TestImportBeforeCanChooseTheConnection(t *testing.T) {
	ctx, got := receive(t, map[string]string{"import.before": `{"connection_id": "con_hook"}`})
	id, err := lifecycle.ImportBefore(ctx, "auth0", "con_1", true)
	require.NoError(t, err)
	require.Equal(t, "con_hook", id)
	require.Equal(t, map[string]any{"target": "auth0", "connection_id": "con_1", "upsert": true}, (*got)[0]["data"])

	ctx, _ = receive(t, map[string]string{"import.before": `{}`})
	id, err = lifecycle.ImportBefore(ctx, "auth0", "con_1", false)
	require.NoError(t, err)
	require.Equal(t, "con_1", id)
}

func TestImportAfterSendsUserResultsInBatchesThenTheReport(t *testing.T) {
	ctx, got := receive(t, nil)
	report := connector.ImportReport{
		Succeeded:             []string{"a", "b"},
		Failed:                []connector.ImportError{{SourceID: "c", Code: "DUP", Message: "exists"}},
		TargetIDs:             map[string]string{"a": "t-a", "b": "t-b"},
		RequiresPasswordReset: []string{"b"},
	}
	require.NoError(t, lifecycle.ImportAfter(ctx, report))
	require.Len(t, *got, 3, "3 users in batches of 2, then import.after")
	require.Equal(t, "import.user.result", (*got)[0]["hook"])
	items := (*got)[0]["data"].(map[string]any)["items"].([]any)
	require.Equal(t, map[string]any{"source_id": "a", "outcome": "succeeded", "target_id": "t-a"}, items[0])
	require.Equal(t, []any{"password_reset"}, items[1].(map[string]any)["follow_ups"])
	items = (*got)[1]["data"].(map[string]any)["items"].([]any)
	require.Equal(t, map[string]any{"source_id": "c", "outcome": "failed", "code": "DUP", "message": "exists"}, items[0])
	require.Equal(t, "import.after", (*got)[2]["hook"])
}

func TestVerifyAfterDecides(t *testing.T) {
	ctx, _ := receive(t, map[string]string{"verify.after": `{"fail": false}`})
	fail, err := lifecycle.VerifyAfter(ctx, connector.DiffReport{MissingInTarget: []string{"a"}}, true)
	require.NoError(t, err)
	require.False(t, fail)

	ctx, _ = receive(t, map[string]string{"verify.after": ``})
	fail, err = lifecycle.VerifyAfter(ctx, connector.DiffReport{}, true)
	require.NoError(t, err)
	require.True(t, fail, "no answer keeps the step's outcome")
}
