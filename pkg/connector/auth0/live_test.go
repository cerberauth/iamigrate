package auth0_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// TestLiveAuth0Login is the gated, live-tenant integration test from
// DESIGN.md's testing strategy layer 4: testdata generate -> import
// auth0 -> log in as a sample of fixture users with their real password
// (and TOTP code, where enrolled) via a throwaway Resource Owner Password
// Grant client, against a disposable Auth0 dev tenant.
//
// It only runs when every required environment variable is set, so it's
// silently skipped in ordinary `go test ./...` runs and CI's default job;
// wire it into a nightly/pre-release job per the design doc.
//
// Required env vars:
//
//	AUTH0_DOMAIN                tenant domain, e.g. dev-xxx.us.auth0.com
//	AUTH0_TOKEN                 Management API token (create:users scope)
//	AUTH0_CONNECTION_ID         target database connection ID
//	AUTH0_ROPG_CLIENT_ID        throwaway app client_id with ROPG enabled
//	AUTH0_ROPG_CLIENT_SECRET    that client's secret
func TestLiveAuth0Login(t *testing.T) {
	domain := os.Getenv("AUTH0_DOMAIN")
	mgmtToken := os.Getenv("AUTH0_TOKEN")
	connectionID := os.Getenv("AUTH0_CONNECTION_ID")
	clientID := os.Getenv("AUTH0_ROPG_CLIENT_ID")
	clientSecret := os.Getenv("AUTH0_ROPG_CLIENT_SECRET")

	if domain == "" || mgmtToken == "" || connectionID == "" || clientID == "" || clientSecret == "" {
		t.Skip("skipping live Auth0 integration test: AUTH0_DOMAIN/AUTH0_TOKEN/AUTH0_CONNECTION_ID/AUTH0_ROPG_CLIENT_ID/AUTH0_ROPG_CLIENT_SECRET not all set")
	}

	ctx := context.Background()
	dir := t.TempDir()
	answerKeyPath := dir + "/answer-key.json"

	// 1. testdata generate: every algorithm and portable MFA type the
	// design doc marks portable for Auth0 (totp; sms/email are excluded
	// here since this test can't receive a real SMS/email OTP).
	opts := fixture.ExportOptions{
		Count: 22, // one full round of every algorithm below, x2
		Hashes: []fixture.HashSpec{
			{Algorithm: cmf.AlgBcrypt, Params: map[string]string{"cost": "10"}},
			{Algorithm: cmf.AlgScrypt, Params: map[string]string{"cost": "16384", "blockSize": "8", "parallelization": "1", "keylen": "32"}},
			{Algorithm: cmf.AlgPBKDF2, Params: map[string]string{"digest": "sha256", "iterations": "100000", "keylen": "32"}},
			{Algorithm: cmf.AlgArgon2, Params: map[string]string{"memory": "65536", "time": "2", "parallelism": "1"}},
			{Algorithm: cmf.AlgMD5},
			{Algorithm: cmf.AlgSHA1},
			{Algorithm: cmf.AlgSHA256},
			{Algorithm: cmf.AlgSHA512},
			{Algorithm: cmf.AlgMD4},
			{Algorithm: cmf.AlgHMAC},
			{Algorithm: cmf.AlgLDAP},
		},
		MFAs:          []fixture.MFASpec{{Type: cmf.MFATOTP, Rate: 1.0}},
		Seed:          time.Now().UnixNano(), // avoid colliding with a prior run's still-live users
		AnswerKeyPath: answerKeyPath,
	}

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := fixture.New().Export(ctx, w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := cmf.NewReader(&buf)
	require.NoError(t, err)
	defer r.Close()

	// 2. import auth0
	client := auth0.NewClient("https://"+domain+"/api/v2", mgmtToken)
	target := auth0.New(client)
	report, err := target.Import(ctx, r, mapping.Mapping{ConnectionID: connectionID}, connector.ImportOptions{
		ConnectionID: connectionID,
	})
	require.NoError(t, err)
	require.Empty(t, report.Failed, "import had failures: %+v", report.Failed)

	answerKeyBytes, err := os.ReadFile(answerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(answerKeyBytes, &key))

	// 3. log in as every fixture user, proving the translated hash (and
	// TOTP secret, where enrolled) actually verify against Auth0.
	loginClient := &loginClient{domain: domain, clientID: clientID, clientSecret: clientSecret, connectionID: connectionID}
	for _, entry := range key.Entries {
		entry := entry
		t.Run(entry.SourceID, func(t *testing.T) {
			var totpCode string
			if entry.TOTPSecret != "" {
				code, err := totp.GenerateCode(entry.TOTPSecret, time.Now())
				require.NoError(t, err)
				totpCode = code
			}
			require.NoError(t, loginClient.login(ctx, entry.Email, entry.Password, totpCode))
		})
	}
}

// loginClient performs Auth0's Resource Owner Password Grant, following
// up with the MFA-OTP grant when the initial request comes back with
// mfa_required.
type loginClient struct {
	domain       string
	clientID     string
	clientSecret string
	connectionID string
}

func (c *loginClient) login(ctx context.Context, username, password, totpCode string) error {
	form := url.Values{
		"grant_type":    {"http://auth0.com/oauth/grant-type/password-realm"},
		"username":      {username},
		"password":      {password},
		"realm":         {c.connectionID},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"openid"},
	}

	resp, err := c.tokenRequest(ctx, form)
	if err != nil {
		return err
	}

	if resp.Error == "mfa_required" {
		if totpCode == "" {
			return fmt.Errorf("login for %s requires MFA but no TOTP code was available", username)
		}
		mfaForm := url.Values{
			"grant_type":    {"http://auth0.com/oauth/grant-type/mfa-otp"},
			"mfa_token":     {resp.MFAToken},
			"otp":           {totpCode},
			"client_id":     {c.clientID},
			"client_secret": {c.clientSecret},
		}
		resp, err = c.tokenRequest(ctx, mfaForm)
		if err != nil {
			return err
		}
	}

	if resp.Error != "" {
		return fmt.Errorf("login for %s failed: %s: %s", username, resp.Error, resp.ErrorDescription)
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("login for %s returned no access_token", username)
	}
	return nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	MFAToken         string `json:"mfa_token"`
}

func (c *loginClient) tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+c.domain+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer httpResp.Body.Close()

	var out tokenResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return tokenResponse{}, err
	}
	return out, nil
}
