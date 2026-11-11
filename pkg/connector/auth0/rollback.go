package auth0

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/cerberauth/iamigrate/pkg/connector"
)

// DeleteUsers deletes each user by the user_id Import gave it (the target
// ID the import report recorded, else the one its CMF record leads to; see
// targetUserID), after checking it exists, on the orgs/roles phase's
// worker pool. Deleting needs the delete:users scope, and the existence
// check read:users. On a dry run it only checks.
func (c *Connector) DeleteUsers(ctx context.Context, users []connector.DeleteRequest, dryRun bool) (connector.RollbackReport, error) {
	type outcome struct {
		id      string
		missing bool
	}
	outcomes := make([]outcome, len(users))
	tasks := make([]poolTask, len(users))
	for i, req := range users {
		id := req.TargetID
		if id == "" {
			id = targetUserID(req.User.TargetID(Name))
		}
		outcomes[i].id = id
		tasks[i] = func(ctx context.Context) (RateLimit, error) {
			path := "/users/" + url.PathEscape(id)
			var rl RateLimit
			err := retryTransient(ctx, isTransient, func() error {
				var err error
				rl, err = c.Client.doJSON(ctx, http.MethodGet, path+"?fields=user_id", nil, nil)
				return err
			})
			if isNotFound(err) {
				outcomes[i].missing = true
				return rl, nil
			}
			if err != nil || dryRun {
				return rl, err
			}
			err = retryTransient(ctx, isTransient, func() error {
				var err error
				rl, err = c.Client.doJSON(ctx, http.MethodDelete, path, nil, nil)
				return err
			})
			if isNotFound(err) {
				outcomes[i].missing = true
				return rl, nil
			}
			return rl, err
		}
	}

	errs := runPool(ctx, c.Concurrency, tasks)
	if err := ctx.Err(); err != nil {
		return connector.RollbackReport{}, err
	}
	report := connector.RollbackReport{DryRun: dryRun}
	for i, req := range users {
		source := req.User.SourceID
		switch {
		case errs[i] != nil:
			report.Failed = append(report.Failed, connector.ImportError{SourceID: source, Code: "REQUEST_ERROR", Message: errs[i].Error()})
		case outcomes[i].missing:
			report.NotFound = append(report.NotFound, source)
		default:
			report.Deleted = append(report.Deleted, connector.DeletedUser{SourceID: source, TargetID: outcomes[i].id})
		}
	}
	return report, nil
}

func isNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
