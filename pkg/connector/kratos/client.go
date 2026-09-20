// Package kratos implements the Ory Kratos SourceConnector and
// TargetConnector: identity export/import against Kratos' Admin API.
//
// Kratos has no bulk-import job like Auth0's -- identities are created one
// at a time via POST /admin/identities -- and no built-in
// organizations/roles concept (that's Ory Permissions/Keto, a separate
// product), so Capabilities().SupportsOrgs/SupportsRoles are both false.
package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a minimal Ory Kratos Admin API client.
type Client struct {
	// BaseURL is the Kratos Admin API base, e.g. "http://localhost:4434".
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client with a sane default HTTP timeout.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is a non-2xx Kratos Admin API response.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kratos: request failed with status %d: %s", e.StatusCode, e.Body)
}

// doJSON issues a JSON request and decodes a JSON response into out (if
// non-nil), returning the raw response so callers needing response headers
// (pagination's Link header) can inspect them.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("kratos: encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("kratos: building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kratos: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("kratos: reading response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return resp, &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, fmt.Errorf("kratos: decoding response: %w", err)
		}
	}
	return resp, nil
}
