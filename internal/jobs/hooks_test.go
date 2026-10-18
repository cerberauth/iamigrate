package jobs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/stretchr/testify/require"
)

func TestRetryFromAnEarlierStateDiscardsLaterHookResults(t *testing.T) {
	step := func(ctx context.Context, j *jobs.Job) error {
		j.Hooks = append(j.Hooks, hooks.Result{Hook: "h", State: string(j.State), Outcome: hooks.Ignored})
		if j.State == jobs.Importing {
			return errors.New("boom")
		}
		return nil
	}
	r, _ := newRunner(t, jobs.Steps{Export: step, Validate: step, Import: step})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Len(t, j.Hooks, 3)

	j, err = r.Retry(j.ID, jobs.Validating)
	require.NoError(t, err)
	require.Equal(t, []hooks.Result{{Hook: "h", State: string(jobs.Exporting), Outcome: hooks.Ignored}}, j.Hooks)
}

func TestRetryInTheFailedStateKeepsHookResults(t *testing.T) {
	r, _ := newRunner(t, jobs.Steps{Import: func(ctx context.Context, j *jobs.Job) error {
		j.Hooks = append(j.Hooks, hooks.Result{Hook: "h", State: string(j.State), Outcome: hooks.Failed})
		return errors.New("boom")
	}})
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	j, err = r.Retry(j.ID, "")
	require.NoError(t, err)
	require.Len(t, j.Hooks, 1, "the failure that led to the retry stays visible")
}
