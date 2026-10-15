// Package firebase implements the Firebase Authentication (Identity
// Platform) SourceConnector and TargetConnector, over the Identity Toolkit
// REST API's project-level account endpoints: accounts:batchGet to export,
// accounts:batchCreate to import, accounts:lookup to verify.
//
// Firebase hashes passwords with a modified scrypt whose signer key and
// salt separator are per-project secrets that no API returns; Export takes
// them as configuration (ExportOptions.Scrypt). Import groups users into
// accounts:batchCreate requests by hash configuration, since one request
// can only carry a single algorithm. Firebase has no organizations or
// roles, and iamigrate doesn't handle Identity Platform tenants.
package firebase

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/httpx"
	"github.com/cerberauth/x/fsx"
)

const (
	// DefaultBaseURL is the Identity Toolkit API root.
	DefaultBaseURL = "https://identitytoolkit.googleapis.com"

	// defaultTokenURI is where a service account's JWT is exchanged for an
	// access token, unless the key file names another.
	defaultTokenURI = "https://oauth2.googleapis.com/token"

	// scope is the OAuth2 scope requested for the service account token.
	scope = "https://www.googleapis.com/auth/cloud-platform"

	// tokenRefreshMargin is how long before expiry a cached access token is
	// replaced.
	tokenRefreshMargin = 60 * time.Second

	// emulatorToken is the bearer token the Firebase Auth emulator treats as
	// a project owner.
	emulatorToken = "owner"

	// maxAttempts bounds how often a throttled (429) or unavailable (503)
	// request is tried.
	maxAttempts = 5
)

// Client is a minimal Identity Toolkit client for one Firebase project.
type Client struct {
	// BaseURL is the API root, DefaultBaseURL unless pointed at the
	// emulator.
	BaseURL string
	// ProjectID is the Firebase project users are exported from, imported
	// into, and looked up in.
	ProjectID   string
	Credentials *Credentials
	HTTP        *http.Client
	// RetryDelay is the wait before the first retry of a throttled
	// request; it doubles on each further one.
	RetryDelay time.Duration
}

// NewClient returns a Client for projectID, authenticating with creds.
func NewClient(projectID string, creds *Credentials) *Client {
	return &Client{
		BaseURL:     DefaultBaseURL,
		ProjectID:   projectID,
		Credentials: creds,
		HTTP: &http.Client{
			Timeout:   60 * time.Second,
			Transport: httpx.NewTransport(nil, nil),
		},
		RetryDelay: time.Second,
	}
}

// NewEmulatorClient returns a Client for the Firebase Auth emulator
// listening on host (e.g. "127.0.0.1:9099"), which needs no real
// credentials.
func NewEmulatorClient(host, projectID string) *Client {
	c := NewClient(projectID, &Credentials{AccessToken: emulatorToken})
	c.BaseURL = "http://" + host + "/identitytoolkit.googleapis.com"
	return c
}

// ServiceAccount is the part of a Google service account key file the
// client needs to obtain access tokens.
type ServiceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// LoadServiceAccount reads a service account key file, as downloaded from
// the Firebase console (Project settings > Service accounts).
func LoadServiceAccount(path string) (*ServiceAccount, error) {
	b, err := fsx.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("firebase: reading service account %s: %w", path, err)
	}
	var sa ServiceAccount
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, fmt.Errorf("firebase: parsing service account %s: %w", path, err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("firebase: service account %s has no client_email or private_key", path)
	}
	if sa.TokenURI == "" {
		sa.TokenURI = defaultTokenURI
	}
	return &sa, nil
}

// Credentials supplies OAuth2 access tokens: either a fixed AccessToken
// (e.g. from `gcloud auth print-access-token`), or tokens a service account
// obtains through the JWT bearer grant. The latter are cached and replaced
// shortly before they expire, so long runs outlive a single token.
type Credentials struct {
	AccessToken    string
	ServiceAccount *ServiceAccount

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// Token returns an access token, fetching a new one with httpClient if the
// cached one is missing or about to expire.
func (cc *Credentials) Token(ctx context.Context, httpClient *http.Client) (string, error) {
	if cc.AccessToken != "" {
		return cc.AccessToken, nil
	}
	if cc.ServiceAccount == nil {
		return "", fmt.Errorf("firebase: no access token or service account configured")
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.token != "" && time.Now().Add(tokenRefreshMargin).Before(cc.expiry) {
		return cc.token, nil
	}

	assertion, err := cc.ServiceAccount.signedJWT(time.Now())
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.ServiceAccount.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("firebase: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("firebase: requesting access token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("firebase: reading token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("firebase: token request: %w", &APIError{StatusCode: resp.StatusCode, Body: string(body)})
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("firebase: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("firebase: token response has no access_token")
	}
	cc.token = out.AccessToken
	cc.expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return cc.token, nil
}

// signedJWT builds the RS256 assertion exchanged for an access token.
func (sa *ServiceAccount) signedJWT(now time.Time) (string, error) {
	key, err := parseRSAKey(sa.PrivateKey)
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   sa.ClientEmail,
		"scope": scope,
		"aud":   sa.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("firebase: signing service account JWT: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func parseRSAKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("firebase: service account private_key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("firebase: service account private_key is not an RSA key")
		}
		return rk, nil
	}
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("firebase: parsing service account private_key: %w", err)
	}
	return rk, nil
}

// APIError is a non-2xx response.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("firebase: request failed with status %d: %s", e.StatusCode, e.Body)
}

// projectPath returns the project-scoped API path ending in suffix, e.g.
// ":batchGet".
func (c *Client) projectPath(suffix string) string {
	return "/v1/projects/" + url.PathEscape(c.ProjectID) + "/accounts" + suffix
}

// doJSON issues an authorized JSON request and decodes a JSON response into
// out (if non-nil). A throttled (429) or unavailable (503) response is
// retried with a doubling delay, since an account import is rate limited.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("firebase: encoding request body: %w", err)
		}
		payload = b
	}

	delay := c.RetryDelay
	for attempt := 1; ; attempt++ {
		status, respBody, err := c.do(ctx, method, path, payload)
		if err != nil {
			return err
		}
		if (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) && attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
			continue
		}
		if status >= 300 {
			return &APIError{StatusCode: status, Body: string(respBody)}
		}
		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("firebase: decoding response: %w", err)
			}
		}
		return nil
	}
}

// do sends one request, returning the status and body of the response.
func (c *Client) do(ctx context.Context, method, path string, payload []byte) (int, []byte, error) {
	var reqBody io.Reader
	if payload != nil {
		reqBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("firebase: building request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if c.Credentials != nil {
		token, err := c.Credentials.Token(ctx, c.HTTP)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("firebase: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("firebase: reading response body: %w", err)
	}
	return resp.StatusCode, respBody, nil
}
