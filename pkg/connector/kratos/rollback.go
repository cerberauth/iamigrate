package kratos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/progress"
)

// DeleteUsers deletes each user's identity: the one the import report
// recorded for it, else the one its email, username or phone finds through
// the Admin API's credentials_identifier filter. A lookup matching several
// identities deletes none of them. On a dry run it only looks them up.
func (c *Connector) DeleteUsers(ctx context.Context, users []connector.DeleteRequest, dryRun bool) (connector.RollbackReport, error) {
	report := connector.RollbackReport{DryRun: dryRun}
	bar := progress.FromContext(ctx)
	for _, req := range users {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		bar.Add(1)
		source := req.User.SourceID
		id, err := c.resolveIdentity(ctx, req)
		switch {
		case errors.Is(err, errNoIdentifier):
			report.NoIdentifier = append(report.NoIdentifier, source)
			continue
		case err != nil:
			report.Failed = append(report.Failed, connector.ImportError{SourceID: source, Code: requestErrorCode, Message: err.Error()})
			continue
		case id == "":
			report.NotFound = append(report.NotFound, source)
			continue
		}
		if !dryRun {
			_, err := c.Client.doJSON(ctx, http.MethodDelete, "/admin/identities/"+url.PathEscape(id), nil, nil)
			if isNotFound(err) {
				report.NotFound = append(report.NotFound, source)
				continue
			}
			if err != nil {
				report.Failed = append(report.Failed, connector.ImportError{SourceID: source, Code: requestErrorCode, Message: err.Error()})
				continue
			}
		}
		report.Deleted = append(report.Deleted, connector.DeletedUser{SourceID: source, TargetID: id})
	}
	return report, nil
}

var errNoIdentifier = errors.New("kratos: no identifier to look the user up by")

// resolveIdentity returns the ID of req's identity, or "" when there is
// none.
func (c *Connector) resolveIdentity(ctx context.Context, req connector.DeleteRequest) (string, error) {
	if req.TargetID != "" {
		var id identity
		_, err := c.Client.doJSON(ctx, http.MethodGet, "/admin/identities/"+url.PathEscape(req.TargetID), nil, &id)
		if isNotFound(err) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("kratos: looking up identity %s: %w", req.TargetID, err)
		}
		return id.ID, nil
	}
	identifier := loginIdentifier(req.User)
	if identifier == "" {
		return "", errNoIdentifier
	}
	var found []identity
	path := "/admin/identities?credentials_identifier=" + url.QueryEscape(identifier)
	if _, err := c.Client.doJSON(ctx, http.MethodGet, path, nil, &found); err != nil {
		return "", fmt.Errorf("kratos: looking up %s: %w", identifier, err)
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0].ID, nil
	default:
		return "", fmt.Errorf("kratos: %s matches %d identities", identifier, len(found))
	}
}

func isNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// requestErrorCode is the report code of a user whose Admin API call
// failed.
const requestErrorCode = "REQUEST_ERROR"
