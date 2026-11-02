// Package cognito implements the AWS Cognito user pool TargetConnector, over
// the Cognito Identity Provider admin API (AdminCreateUser and friends).
//
// Cognito is a destination only: it has no API that returns a password
// hash, and none that takes one, so users land without their password and
// reset it by the "forgot password" flow. A user pool that must keep
// verifying the old passwords does it with Cognito's own Migrate User Lambda
// trigger, which sits outside what this connector does: it creates the users
// the Lambda doesn't.
package cognito

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/httpx"
)

const (
	// serviceName is the SigV4 service name of the Cognito Identity Provider
	// API.
	serviceName = "cognito-idp"

	// targetPrefix prefixes the operation in the X-Amz-Target header.
	targetPrefix = "AWSCognitoIdentityProviderService."

	// maxAttempts bounds how often a throttled request is tried.
	maxAttempts = 6
)

// Credentials are the AWS access keys requests are signed with. SessionToken
// is set for temporary credentials (an assumed role, SSO, ...).
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// Client is a minimal Cognito Identity Provider client for one user pool.
type Client struct {
	// Endpoint is the API root; the regional cognito-idp endpoint unless
	// pointed at an emulator.
	Endpoint   string
	Region     string
	UserPoolID string
	Creds      Credentials
	HTTP       *http.Client
	// RetryDelay is the wait before the first retry of a throttled request;
	// it doubles on each further one.
	RetryDelay time.Duration
	// Now is the clock requests are signed with; time.Now unless a test
	// sets it.
	Now func() time.Time
}

// RegionOf returns the AWS region a user pool ID names: the part before the
// underscore of "eu-west-1_AbCdEfGhI". It is "" for an ID of another shape.
func RegionOf(userPoolID string) string {
	region, _, ok := strings.Cut(userPoolID, "_")
	if !ok {
		return ""
	}
	return region
}

// NewClient returns a Client for the user pool userPoolID in region,
// signing with creds.
func NewClient(region, userPoolID string, creds Credentials) *Client {
	return &Client{
		Endpoint:   fmt.Sprintf("https://cognito-idp.%s.amazonaws.com", region),
		Region:     region,
		UserPoolID: userPoolID,
		Creds:      creds,
		HTTP: &http.Client{
			Timeout:   60 * time.Second,
			Transport: httpx.NewTransport(nil, nil),
		},
		RetryDelay: time.Second,
		Now:        time.Now,
	}
}

// APIError is an error response of the Cognito API: its __type (the
// exception name, such as UsernameExistsException) and message.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cognito: %s (status %d): %s", e.Type, e.StatusCode, e.Message)
}

// throttled reports whether the call is worth retrying later.
func (e *APIError) throttled() bool {
	switch e.Type {
	case "TooManyRequestsException", "ThrottlingException", "LimitExceededException":
		return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusTooManyRequests
	}
	return e.StatusCode >= 500
}

// errorBody is the JSON of an error response. The type may come with a
// namespace and URL ("com.amazon...#UserNotFoundException:http://...").
type errorBody struct {
	Type    string `json:"__type"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Upper   string `json:"Message"`
}

func newAPIError(status int, body []byte) *APIError {
	e := &APIError{StatusCode: status}
	var b errorBody
	if json.Unmarshal(body, &b) != nil {
		e.Message = strings.TrimSpace(string(body))
		return e
	}
	t := b.Type
	if t == "" {
		t = b.Code
	}
	if i := strings.LastIndex(t, "#"); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.Index(t, ":"); i >= 0 {
		t = t[:i]
	}
	e.Type = t
	e.Message = b.Message
	if e.Message == "" {
		e.Message = b.Upper
	}
	return e
}

// call invokes operation with body (a JSON-encodable request) and decodes the
// response into out, if non-nil. Throttled calls are retried with a doubling
// delay, since the admin API is rate limited per operation.
func (c *Client) call(ctx context.Context, operation string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("cognito: encoding %s request: %w", operation, err)
	}

	delay := c.RetryDelay
	for attempt := 1; ; attempt++ {
		status, respBody, err := c.do(ctx, operation, payload)
		if err != nil {
			return err
		}
		if status < 300 {
			if out != nil && len(respBody) > 0 {
				if err := json.Unmarshal(respBody, out); err != nil {
					return fmt.Errorf("cognito: decoding %s response: %w", operation, err)
				}
			}
			return nil
		}
		apiErr := newAPIError(status, respBody)
		if apiErr.throttled() && attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
			continue
		}
		return apiErr
	}
}

// do sends one signed request.
func (c *Client) do(ctx context.Context, operation string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.Endpoint, "/")+"/", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("cognito: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", targetPrefix+operation)
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	c.Creds.sign(req, payload, c.Region, serviceName, now())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cognito: %s: %w", operation, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("cognito: reading %s response: %w", operation, err)
	}
	return resp.StatusCode, respBody, nil
}

// sign adds the AWS Signature Version 4 headers to req, whose body is
// payload. The signed headers are host, content-type and every x-amz-* one
// set on req, plus the date and, for temporary credentials, the session
// token, which sign sets.
func (c Credentials) sign(req *http.Request, payload []byte, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}

	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = strings.TrimSpace(strings.Join(values, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		path,
		req.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		hexSHA256(payload),
	}, "\n")

	scope := day + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, scope, signedHeaders, signature))
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
