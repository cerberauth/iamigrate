package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
)

// chunkMaxBytes is Auth0's per-file limit for a bulk user import job.
const chunkMaxBytes = 500 * 1024

// chunkMaxUsers is a safety net alongside chunkMaxBytes: roughly the count
// Auth0 documents as fitting in 500KB for users with under 10 metadata
// fields each.
const chunkMaxUsers = 1000

// pollInterval and pollMaxInterval bound the backoff used while waiting
// for a bulk import job to finish. Variables (not consts) so tests can
// shrink them.
var (
	pollInterval    = 2 * time.Second
	pollMaxInterval = 30 * time.Second
)

// userRoleInfo carries just enough of a CMF user record to drive the
// second, per-call organizations/roles/memberships phase, buffered in
// memory during the bulk import pass so that phase doesn't need to
// re-read the (potentially gzipped, multi-GB) CMF stream a second time.
type userRoleInfo struct {
	SourceID    string
	GlobalRoles []string
	Memberships []cmf.Membership
}

// RunBulkImport streams users from r, chunks them to Auth0's 500KB job
// limit, submits and polls each chunk, and merges the per-user results
// into one ImportReport. allowUpsert controls whether Import intends to
// call this again later for the same users (opts.Upsert); when true, the
// hash translator always prefers custom_password_hash so a future run can
// correct a bad translation (see DESIGN.md, "Idempotent re-runs").
//
// It also returns per-user global_roles/memberships for every user with
// either set, for the caller to feed into the organizations/roles phase.
func RunBulkImport(ctx context.Context, client *Client, r *cmf.Reader, connectionID string, allowUpsert bool) (connector.ImportReport, []userRoleInfo, error) {
	var report connector.ImportReport
	var roleInfos []userRoleInfo
	var chunk []map[string]any
	chunkBytes := 2 // "[]"

	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		partial, err := submitAndPoll(ctx, client, connectionID, allowUpsert, chunk)
		if err != nil {
			return err
		}
		mergeReport(&report, partial)
		chunk = nil
		chunkBytes = 2
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return report, roleInfos, ctx.Err()
		default:
		}

		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, roleInfos, err
		}

		if len(u.GlobalRoles) > 0 || len(u.Memberships) > 0 {
			roleInfos = append(roleInfos, userRoleInfo{
				SourceID:    u.SourceID,
				GlobalRoles: u.GlobalRoles,
				Memberships: u.Memberships,
			})
		}

		rec, flags, err := buildImportUser(u, allowUpsert)
		if err != nil {
			report.Failed = append(report.Failed, connector.ImportError{
				SourceID: u.SourceID, Code: "TRANSLATION_ERROR", Message: err.Error(),
			})
			continue
		}
		if flags.requiresPasswordReset {
			report.RequiresPasswordReset = append(report.RequiresPasswordReset, u.SourceID)
		}
		if flags.requiresReenrollment {
			report.RequiresReenrollment = append(report.RequiresReenrollment, u.SourceID)
		}
		if flags.requiresRecoveryCodeRegen {
			report.RequiresRecoveryCodeRegen = append(report.RequiresRecoveryCodeRegen, u.SourceID)
		}

		b, err := json.Marshal(rec)
		if err != nil {
			return report, roleInfos, fmt.Errorf("auth0: encoding user %s: %w", u.SourceID, err)
		}
		recBytes := len(b) + 1 // trailing comma/bracket

		if len(chunk) > 0 && (chunkBytes+recBytes > chunkMaxBytes || len(chunk) >= chunkMaxUsers) {
			if err := flush(); err != nil {
				return report, roleInfos, err
			}
		}
		chunk = append(chunk, rec)
		chunkBytes += recBytes
	}

	if err := flush(); err != nil {
		return report, roleInfos, err
	}
	return report, roleInfos, nil
}

func mergeReport(dst *connector.ImportReport, src connector.ImportReport) {
	dst.Succeeded = append(dst.Succeeded, src.Succeeded...)
	dst.Failed = append(dst.Failed, src.Failed...)
}

func submitAndPoll(ctx context.Context, client *Client, connectionID string, upsert bool, chunk []map[string]any) (connector.ImportReport, error) {
	var report connector.ImportReport

	sourceIDs := make(map[string]bool, len(chunk))
	for _, rec := range chunk {
		if id, ok := rec["user_id"].(string); ok {
			sourceIDs[id] = true
		}
	}

	body, err := json.Marshal(chunk)
	if err != nil {
		return report, fmt.Errorf("auth0: encoding chunk: %w", err)
	}

	jobID, err := submitImportJob(ctx, client, connectionID, upsert, body)
	if err != nil {
		return report, err
	}

	status, err := pollJob(ctx, client, jobID)
	if err != nil {
		return report, err
	}

	jobErrors, err := fetchJobErrors(ctx, client, jobID)
	if err != nil {
		return report, err
	}

	failedIDs := map[string]bool{}
	for _, je := range jobErrors {
		failedIDs[je.SourceID] = true
		if je.Code == "DUPLICATED_USER" {
			je.Message = "user exists in Auth0's user store but not this tenant/connection: " +
				"delete via the Connection Users endpoint and re-import (see DESIGN.md)"
		}
		report.Failed = append(report.Failed, je)
	}
	for id := range sourceIDs {
		if !failedIDs[id] {
			report.Succeeded = append(report.Succeeded, id)
		}
	}

	if status == "failed" {
		return report, fmt.Errorf("auth0: import job %s failed", jobID)
	}
	return report, nil
}

func submitImportJob(ctx context.Context, client *Client, connectionID string, upsert bool, usersJSON []byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	fw, err := mw.CreateFormFile("users", "users.json")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(usersJSON); err != nil {
		return "", err
	}
	if err := mw.WriteField("connection_id", connectionID); err != nil {
		return "", err
	}
	if err := mw.WriteField("upsert", boolStr(upsert)); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL+"/jobs/users-imports", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+client.Token)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth0: submitting import job: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("auth0: decoding import job response: %w", err)
	}
	return out.ID, nil
}

func pollJob(ctx context.Context, client *Client, jobID string) (string, error) {
	interval := pollInterval
	for {
		var out struct {
			Status string `json:"status"`
		}
		_, err := client.doJSON(ctx, http.MethodGet, "/jobs/"+jobID, nil, &out)
		if err != nil {
			return "", fmt.Errorf("auth0: polling job %s: %w", jobID, err)
		}
		if out.Status != "pending" && out.Status != "processing" {
			return out.Status, nil
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		interval *= 2
		if interval > pollMaxInterval {
			interval = pollMaxInterval
		}
	}
}

func fetchJobErrors(ctx context.Context, client *Client, jobID string) ([]connector.ImportError, error) {
	var raw []struct {
		User struct {
			UserID string `json:"user_id"`
		} `json:"user"`
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_, err := client.doJSON(ctx, http.MethodGet, "/jobs/"+jobID+"/errors", nil, &raw)
	if err != nil {
		return nil, fmt.Errorf("auth0: fetching job errors for %s: %w", jobID, err)
	}

	var out []connector.ImportError
	for _, r := range raw {
		for _, e := range r.Errors {
			out = append(out, connector.ImportError{
				SourceID: r.User.UserID,
				Code:     e.Code,
				Message:  e.Message,
			})
		}
	}
	return out, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
