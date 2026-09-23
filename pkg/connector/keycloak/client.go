// Package keycloak implements the Keycloak SourceConnector and
// TargetConnector.
//
// Import creates users one at a time through the Admin REST API
// (POST /admin/realms/{realm}/users), carrying pre-hashed password and OTP
// credentials as secretData/credentialData. Export reads a `kc.sh export`
// realm file instead of the Admin API, because the Admin API never returns
// a credential's secretData: an export is the only way to get the password
// hashes out of Keycloak.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tokenRefreshMargin is how long before expiry a cached access token is
// replaced. Keycloak's admin tokens are short-lived (60s for admin-cli by
// default), so this stays well under that.
const tokenRefreshMargin = 10 * time.Second

// Client is a minimal Keycloak Admin REST API client for one realm.
type Client struct {
	// BaseURL is the Keycloak server root, e.g. "http://localhost:8080".
	BaseURL string
	// Realm is the realm users are imported into and looked up in.
	Realm       string
	Credentials *Credentials
	HTTP        *http.Client
}

// NewClient returns a Client for realm, authenticating with creds.
func NewClient(baseURL, realm string, creds *Credentials) *Client {
	return &Client{
		BaseURL:     strings.TrimSuffix(baseURL, "/"),
		Realm:       realm,
		Credentials: creds,
		HTTP:        &http.Client{Timeout: 30 * time.Second},
	}
}

// Credentials obtains Admin API access tokens from a realm's token
// endpoint, through the password grant when Username is set, else the
// client_credentials grant of a confidential client with a service
// account. Each token is cached and replaced shortly before it expires, so
// long imports outlive a single token.
type Credentials struct {
	// TokenURL is the token endpoint of the realm the admin user or
	// service account lives in, e.g.
	// "http://localhost:8080/realms/master/protocol/openid-connect/token".
	TokenURL     string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// TokenURL returns the OpenID Connect token endpoint of realm on the
// Keycloak server at baseURL.
func TokenURL(baseURL, realm string) string {
	return strings.TrimSuffix(baseURL, "/") + "/realms/" + url.PathEscape(realm) + "/protocol/openid-connect/token"
}

// Token returns a cached access token, fetching a new one with httpClient
// if there is none yet or it's about to expire.
func (cc *Credentials) Token(ctx context.Context, httpClient *http.Client) (string, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.token != "" && time.Now().Add(tokenRefreshMargin).Before(cc.expiry) {
		return cc.token, nil
	}

	form := url.Values{"client_id": {cc.ClientID}}
	if cc.ClientSecret != "" {
		form.Set("client_secret", cc.ClientSecret)
	}
	if cc.Username != "" {
		form.Set("grant_type", "password")
		form.Set("username", cc.Username)
		form.Set("password", cc.Password)
	} else {
		form.Set("grant_type", "client_credentials")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: requesting access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("keycloak: reading token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak: %s grant: %w", form.Get("grant_type"), &APIError{StatusCode: resp.StatusCode, Body: string(body)})
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("keycloak: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("keycloak: token response has no access_token")
	}

	cc.token = out.AccessToken
	cc.expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return cc.token, nil
}

// APIError is a non-2xx Keycloak response.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("keycloak: request failed with status %d: %s", e.StatusCode, e.Body)
}

// adminPath returns the Admin API path of the client's realm plus suffix.
func (c *Client) adminPath(suffix string) string {
	return "/admin/realms/" + url.PathEscape(c.Realm) + suffix
}

// doJSON issues an authorized JSON request and decodes a JSON response
// into out (if non-nil).
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("keycloak: encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("keycloak: building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.Credentials != nil {
		token, err := c.Credentials.Token(ctx, c.HTTP)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("keycloak: reading response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("keycloak: decoding response: %w", err)
		}
	}
	return nil
}
