package auth0

import (
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

// tokenRefreshMargin is how long before expiry a cached client_credentials
// token is replaced, so a request never goes out with a token that
// expires in flight.
const tokenRefreshMargin = time.Minute

// ClientCredentials obtains Management API access tokens through the
// OAuth 2.0 client_credentials grant of a Machine-to-Machine application,
// caching each token and fetching a new one shortly before it expires so
// long-running imports outlive a single token's lifetime.
type ClientCredentials struct {
	// TokenURL is the tenant's token endpoint, e.g.
	// "https://tenant.us.auth0.com/oauth/token".
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Audience is the Management API identifier, e.g.
	// "https://tenant.us.auth0.com/api/v2/".
	Audience string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// Token returns a cached access token, fetching a new one with httpClient
// if there is none yet or it's about to expire.
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
		"audience":      {cc.Audience},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("auth0: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth0: requesting access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("auth0: reading token response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("auth0: client_credentials grant: %w", &APIError{StatusCode: resp.StatusCode, Body: string(body)})
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("auth0: decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("auth0: token response has no access_token")
	}

	cc.token = out.AccessToken
	cc.expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return cc.token, nil
}
