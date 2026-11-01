// Package azureb2c implements the Azure AD B2C SourceConnector, over the
// Microsoft Graph users API. It is source-only: B2C tenants can no longer be
// created, and a tenant's custom policies (Identity Experience Framework)
// don't port, so there is no import direction.
//
// Graph never returns a local account's password hash, nor its MFA
// enrollment, so users are exported without a password and will have to
// reset it on the target.
package azureb2c

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/httpx"
)

const (
	// DefaultBaseURL is the Microsoft Graph v1.0 root.
	DefaultBaseURL = "https://graph.microsoft.com/v1.0"

	// DefaultAuthority is the Microsoft Entra ID token service the
	// client_credentials grant is sent to.
	DefaultAuthority = "https://login.microsoftonline.com"

	// graphScope asks for the application permissions granted to the app
	// registration (User.Read.All is what an export needs).
	graphScope = "https://graph.microsoft.com/.default"

	// tokenRefreshMargin is how long before expiry a cached access token is
	// replaced, so a request never goes out with a token that expires in
	// flight.
	tokenRefreshMargin = time.Minute

	// maxErrorBody caps how much of an error response is kept in an APIError.
	maxErrorBody = 4096
)

// Client is a minimal Microsoft Graph client for reading a B2C tenant's
// users.
type Client struct {
	// BaseURL is the Graph API root, DefaultBaseURL unless pointed elsewhere
	// (a national cloud, a test server).
	BaseURL string
	// AccessToken is a ready Graph access token, used when Credentials is
	// nil.
	AccessToken string
	// Credentials, if set, obtains (and renews) the access token through
	// the client_credentials grant instead of using a fixed AccessToken.
	Credentials *ClientCredentials
	HTTP        *http.Client
	// Backoff bounds how often a throttled (429) or failing (5xx) request is
	// retried, and how long it waits between tries.
	Backoff httpx.Backoff
}

func defaultBackoff() httpx.Backoff {
	return httpx.Backoff{Initial: time.Second, Max: 30 * time.Second, Retries: 5}
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: httpx.NewTransport(nil, nil)}
}

// NewClient returns a Client authenticating with a ready Graph access token.
func NewClient(accessToken string) *Client {
	return &Client{BaseURL: DefaultBaseURL, AccessToken: accessToken, HTTP: newHTTPClient(), Backoff: defaultBackoff()}
}

// NewClientCredentialsClient returns a Client that gets its access token for
// the B2C tenant (its domain, e.g. "acme.onmicrosoft.com", or its directory
// ID) through the client_credentials grant of an app registration.
func NewClientCredentialsClient(tenant, clientID, clientSecret string) *Client {
	c := NewClient("")
	c.Credentials = &ClientCredentials{
		TokenURL:     DefaultAuthority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        graphScope,
	}
	return c
}

// ClientCredentials obtains Graph access tokens through the OAuth 2.0
// client_credentials grant, caching each token and fetching a new one
// shortly before it expires so a long export outlives a single token.
type ClientCredentials struct {
	// TokenURL is the tenant's token endpoint, e.g.
	// "https://login.microsoftonline.com/acme.onmicrosoft.com/oauth2/v2.0/token".
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scope        string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// Token returns a cached access token, fetching a new one with httpClient if
// there is none yet or it's about to expire.
func (cc *ClientCredentials) Token(ctx context.Context, httpClient *http.Client) (string, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.token != "" && time.Now().Add(tokenRefreshMargin).Before(cc.expiry) {
		return cc.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cc.ClientID},
		"client_secret": {cc.ClientSecret},
		"scope":         {cc.Scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("azure-ad-b2c: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure-ad-b2c: requesting access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("azure-ad-b2c: reading token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure-ad-b2c: client_credentials grant: %w", newAPIError(resp, body))
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("azure-ad-b2c: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("azure-ad-b2c: token response has no access_token")
	}
	cc.token = out.AccessToken
	cc.expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return cc.token, nil
}

// APIError is a non-2xx response.
type APIError struct {
	StatusCode int
	Body       string
	// Wait is the response's Retry-After, zero if it had none.
	Wait time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("azure-ad-b2c: request failed with status %d: %s", e.StatusCode, e.Body)
}

// RetryAfter implements httpx.RetryAfterer, so a throttled request waits as
// long as Graph asks.
func (e *APIError) RetryAfter() time.Duration { return e.Wait }

func newAPIError(resp *http.Response, body []byte) *APIError {
	if len(body) > maxErrorBody {
		body = body[:maxErrorBody]
	}
	e := &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		e.Wait = time.Duration(secs) * time.Second
	}
	return e
}

// isTransient reports whether err is worth retrying on an idempotent
// request: a 429, a 5xx, or a network failure.
func isTransient(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF)
}

// token returns the bearer token to send.
func (c *Client) token(ctx context.Context) (string, error) {
	if c.Credentials != nil {
		return c.Credentials.Token(ctx, c.HTTP)
	}
	if c.AccessToken == "" {
		return "", fmt.Errorf("azure-ad-b2c: no access token or client credentials configured")
	}
	return c.AccessToken, nil
}

// getJSON issues an authorized GET for target, an absolute URL on the
// client's own host, and decodes the JSON response into out. A throttled or
// failing response is retried.
func (c *Client) getJSON(ctx context.Context, target string, out any) error {
	return httpx.Retry(ctx, c.Backoff, isTransient, func() error {
		return c.getOnce(ctx, target, out)
	})
}

func (c *Client) getOnce(ctx context.Context, target string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("azure-ad-b2c: building request: %w", err)
	}
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("azure-ad-b2c: GET %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("azure-ad-b2c: reading response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return newAPIError(resp, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("azure-ad-b2c: decoding response: %w", err)
	}
	return nil
}

// sameHost reports whether link, a page link Graph returned, points at the
// client's own host, so the access token is never sent anywhere else.
func (c *Client) sameHost(link string) bool {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return false
	}
	u, err := url.Parse(link)
	return err == nil && u.Scheme == base.Scheme && u.Host == base.Host
}
