// Package lifecycle fires the events of the export, validate, import and
// verify steps, and applies what veto and decide events answer, so a job's
// steps and the standalone commands react to them the same way. Each
// function finds the hooks in the context (see hooks.FromContext), and with
// none returns the step's own outcome unchanged.
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/hooks"
)

// ExportAfter fires export.after with the export's manifest. A veto is
// returned as an error: the export is not to be used.
func ExportAfter(ctx context.Context, manifest connector.Manifest) error {
	_, err := hooks.FromContext(ctx).Event(ctx, hooks.ExportAfter, map[string]any{"manifest": manifest})
	return err
}

// ValidateAfter fires validate.after with the problems validate found, and
// returns those that still fail it and those the handler downgraded to
// warnings.
//
// The handler answers {"downgrade": [i, ...]} to make warnings of the
// problems at those indexes, and may add {"fail": true|false} to decide
// the outcome outright; otherwise validate fails when a problem is left.
func ValidateAfter(ctx context.Context, problems []connector.Problem) (failing, warnings []connector.Problem, fail bool, err error) {
	fail = len(problems) > 0
	a, err := hooks.FromContext(ctx).Event(ctx, hooks.ValidateAfter, map[string]any{"problems": problemsJSON(problems)})
	if err != nil || len(a.Raw) == 0 {
		return problems, nil, fail, err
	}
	var ans struct {
		Fail      *bool `json:"fail"`
		Downgrade []int `json:"downgrade"`
	}
	if err := json.Unmarshal(a.Raw, &ans); err != nil {
		return problems, nil, fail, fmt.Errorf("hook %s: decoding answer: %w", hooks.ValidateAfter, err)
	}
	down := map[int]bool{}
	for _, i := range ans.Downgrade {
		if i < 0 || i >= len(problems) {
			return problems, nil, fail, fmt.Errorf("hook %s: no problem at index %d", hooks.ValidateAfter, i)
		}
		down[i] = true
	}
	for i, p := range problems {
		if down[i] {
			warnings = append(warnings, p)
		} else {
			failing = append(failing, p)
		}
	}
	fail = len(failing) > 0
	if ans.Fail != nil {
		fail = *ans.Fail
	}
	return failing, warnings, fail, nil
}

// problemsJSON gives Problem, which has no JSON tags, snake_case keys.
func problemsJSON(ps []connector.Problem) []map[string]string {
	out := make([]map[string]string, len(ps))
	for i, p := range ps {
		out[i] = map[string]string{"source_id": p.SourceID, "field": p.Field, "rule": p.Rule, "value": p.Value}
	}
	return out
}

// ImportBefore fires import.before, once the connection ID to import into
// is known (possibly empty), and returns the one to use: the handler's
// {"connection_id": "..."} if it answers one. A veto is returned as an
// error.
func ImportBefore(ctx context.Context, target, connectionID string, upsert bool) (string, error) {
	a, err := hooks.FromContext(ctx).Event(ctx, hooks.ImportBefore, map[string]any{
		"target": target, "connection_id": connectionID, "upsert": upsert,
	})
	if err != nil || len(a.Raw) == 0 {
		return connectionID, err
	}
	var ans struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(a.Raw, &ans); err != nil {
		return connectionID, fmt.Errorf("hook %s: decoding answer: %w", hooks.ImportBefore, err)
	}
	if ans.ConnectionID != "" {
		return ans.ConnectionID, nil
	}
	return connectionID, nil
}

// UserResult is one user's outcome in import.user.result.
type UserResult struct {
	SourceID string `json:"source_id"`
	Outcome  string `json:"outcome"` // succeeded | failed
	TargetID string `json:"target_id,omitempty"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	// FollowUps are what the user needs after the import:
	// password_reset, reenrollment, recovery_code_regen.
	FollowUps []string `json:"follow_ups,omitempty"`
}

// ImportAfter fires import.user.result with every user's outcome, in
// batches, then import.after with the whole report.
func ImportAfter(ctx context.Context, report connector.ImportReport) error {
	d := hooks.FromContext(ctx)
	if d.Configured(hooks.ImportUserResult) {
		if err := d.Notify(ctx, hooks.ImportUserResult, userResults(report)); err != nil {
			return err
		}
	}
	_, err := d.Event(ctx, hooks.ImportAfter, map[string]any{"report": report})
	return err
}

// userResults lists the report's users, succeeded ones first, each in
// report order, so the batches are the same on every run over the same
// report.
func userResults(r connector.ImportReport) []any {
	follow := map[string][]string{}
	for name, ids := range map[string][]string{
		"password_reset":      r.RequiresPasswordReset,
		"reenrollment":        r.RequiresReenrollment,
		"recovery_code_regen": r.RequiresRecoveryCodeRegen,
	} {
		for _, id := range ids {
			follow[id] = append(follow[id], name)
		}
	}
	for _, f := range follow {
		sort.Strings(f)
	}
	out := make([]any, 0, len(r.Succeeded)+len(r.Failed))
	for _, id := range r.Succeeded {
		out = append(out, UserResult{SourceID: id, Outcome: "succeeded", TargetID: r.TargetIDs[id], FollowUps: follow[id]})
	}
	for _, e := range r.Failed {
		out = append(out, UserResult{SourceID: e.SourceID, Outcome: "failed", Code: e.Code, Message: e.Message, FollowUps: follow[e.SourceID]})
	}
	return out
}

// VerifyAfter fires verify.after with the diff, and returns whether verify
// fails: the handler's {"fail": true|false} if it answers one, else fail.
func VerifyAfter(ctx context.Context, diff connector.DiffReport, fail bool) (bool, error) {
	a, err := hooks.FromContext(ctx).Event(ctx, hooks.VerifyAfter, map[string]any{"diff": diff})
	if err != nil || len(a.Raw) == 0 {
		return fail, err
	}
	var ans struct {
		Fail *bool `json:"fail"`
	}
	if err := json.Unmarshal(a.Raw, &ans); err != nil {
		return fail, fmt.Errorf("hook %s: decoding answer: %w", hooks.VerifyAfter, err)
	}
	if ans.Fail != nil {
		return *ans.Fail, nil
	}
	return fail, nil
}
