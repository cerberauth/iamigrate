// Package auth0 implements the Auth0 TargetConnector: Management API
// client, bulk user import job chunking/polling, and the post-import
// organizations/roles/memberships phase, per DESIGN.md's Auth0
// import pipeline section.
package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client is a minimal Auth0 Management API client. It's hand-rolled rather
// than built on the official go-auth0 SDK so the bulk import job's
// multipart upload, polling, and per-user error parsing stay under direct
// control (see SPEC_NOTES.md open question 6).
type Client struct {
	// BaseURL is the tenant's Management API base, e.g.
	// "https://tenant.us.auth0.com/api/v2".
	BaseURL string
	// Token is a Management API access token with the scopes the target
	// connector's operations require (create:users, create:roles,
	// create:organizations, etc).
	Token string
	HTTP  *http.Client
}

// NewClient returns a Client with a sane default HTTP timeout.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// RateLimit reports the Auth0 rate-limit headers from a response, used by
// the org/role/membership worker pool to back off.
type RateLimit struct {
	Remaining int
	ResetAt   time.Time
	Limited   bool
}

func parseRateLimit(h http.Header) RateLimit {
	rl := RateLimit{Remaining: -1}
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rl.Remaining = n
		}
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			rl.ResetAt = time.Unix(n, 0)
		}
	}
	return rl
}

// APIError is a non-2xx Management API response.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("auth0: request failed with status %d: %s", e.StatusCode, e.Body)
}

// doJSON issues a JSON request and decodes a JSON response into out (if
// non-nil). It returns the response's rate-limit headers so callers doing
// bulk sequential calls (roles/orgs/memberships) can back off.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) (RateLimit, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return RateLimit{}, fmt.Errorf("auth0: encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return RateLimit{}, fmt.Errorf("auth0: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return RateLimit{}, fmt.Errorf("auth0: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	rl := parseRateLimit(resp.Header)
	if resp.StatusCode == http.StatusTooManyRequests {
		rl.Limited = true
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return rl, fmt.Errorf("auth0: reading response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return rl, &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return rl, fmt.Errorf("auth0: decoding response: %w", err)
		}
	}
	return rl, nil
}
