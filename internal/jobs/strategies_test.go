package jobs_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cerberauth/iamigrate/internal/hookstest"
	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func TestJobRunsExportAndValidateStrategies(t *testing.T) {
	d, rc := hookstest.Dispatcher(t, 10, func(hook, key string, item map[string]any) any {
		switch hook {
		case "export.user":
			if key == "u0" {
				return map[string]any{"action": "drop", "reason": "test user"}
			}
			return map[string]any{}
		case "validate.user":
			if key == "u2" {
				return map[string]any{"problems": []map[string]string{{"field": "emails", "rule": "blocked domain"}}}
			}
			return map[string]any{}
		}
		return nil
	}, "")
	dir := t.TempDir()
	users := filepath.Join(dir, "users.cmf.jsonl")
	src := &fakeSource{users: fakeUsers(3)}
	tgt := &fakeTarget{chunkSize: 10}
	r, _ := newRunner(t, jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) { return src, nil, nil },
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
	}))
	r.Hooks = d
	j, err := r.Create(map[string]string{
		jobs.ParamSource: "fake", jobs.ParamUsers: users,
		jobs.ParamMapping: writeMapping(t, dir, "target: fake\nstrategies:\n  export.user: {handler: h}\n  validate.user: {handler: h}\n"),
	})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Validating, j.FailedIn)
	require.Equal(t, 2, j.Manifest.RecordCount)
	require.Equal(t, []connector.SkippedRecord{{SourceID: "u0", Reason: "test user"}}, j.Manifest.SkippedRecords)
	require.Equal(t, []connector.Problem{{SourceID: "u2", Field: "emails", Rule: "blocked domain"}}, j.Problems)
	require.Equal(t, map[string]string{"u1": "", "u2": ""}, readTargetIDs(t, users), "u0 never reached the users file")
	require.Equal(t, 1, rc.Calls("export.user"))
}
