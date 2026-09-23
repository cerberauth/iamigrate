package kratos_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/fixture"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

// TestLiveKratosLogin is the gated, live-instance integration test: testdata
// generate -> import kratos -> log in as every fixture user with their real
// password via Kratos' native (API-style) self-service login flow, against
// a disposable Kratos instance (see .docker/kratos/docker-compose.yml).
//
// It only runs when KRATOS_ADMIN_URL and KRATOS_PUBLIC_URL are both set, so
// it's silently skipped in ordinary `go test ./...` runs.
//
// Required env vars:
//
//	KRATOS_ADMIN_URL   e.g. http://127.0.0.1:4434
//	KRATOS_PUBLIC_URL  e.g. http://127.0.0.1:4433
func TestLiveKratosLogin(t *testing.T) {
	runLiveKratosLogin(t, "default", nil)
}

// TestLiveKratosLoginByUsernameAndPhone is TestLiveKratosLogin for users
// whose login identifier is a username, a phone, or all of email, username,
// and phone, imported against the e2e "identifiers" schema. Each user must
// log in with every identifier they have, and diff must find them all.
func TestLiveKratosLoginByUsernameAndPhone(t *testing.T) {
	runLiveKratosLogin(t, "identifiers", []fixture.IdentifierSpec{
		{fixture.IdentifierUsername},
		{fixture.IdentifierPhone},
		{fixture.IdentifierEmail, fixture.IdentifierUsername, fixture.IdentifierPhone},
	})
}

func runLiveKratosLogin(t *testing.T, schemaID string, identifiers []fixture.IdentifierSpec) {
	adminURL := os.Getenv("KRATOS_ADMIN_URL")
	publicURL := os.Getenv("KRATOS_PUBLIC_URL")
	if adminURL == "" || publicURL == "" {
		t.Skip("skipping live Kratos integration test: KRATOS_ADMIN_URL/KRATOS_PUBLIC_URL not both set")
	}

	ctx := context.Background()

	// 1. testdata generate: bcrypt is the only algorithm this test can
	// prove logs in for real (Kratos' own hasher; argon2id would require
	// generating cleartext-matching PHC strings the fixture generator
	// doesn't produce for that algorithm).
	opts := fixture.ExportOptions{
		Count:       6,
		Hashes:      []fixture.HashSpec{{Algorithm: cmf.AlgBcrypt, Params: map[string]string{"cost": "8"}}},
		Identifiers: identifiers,
		Seed:        time.Now().UnixNano(),
	}
	answerKeyPath := t.TempDir() + "/answer-key.json"
	opts.AnswerKeyPath = answerKeyPath

	var buf bytes.Buffer
	w := cmf.NewWriter(&buf)
	_, err := fixture.New().Export(ctx, w, opts)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	users := buf.Bytes()

	r, err := cmf.NewReader(bytes.NewReader(users))
	require.NoError(t, err)
	defer r.Close()

	// 2. import kratos
	client := kratos.NewClient(adminURL)
	target := kratos.New(client, schemaID)
	report, err := target.Import(ctx, r, mapping.Mapping{}, connector.ImportOptions{})
	require.NoError(t, err)
	require.Empty(t, report.Failed, "import had failures: %+v", report.Failed)

	answerKeyBytes, err := os.ReadFile(answerKeyPath)
	require.NoError(t, err)
	var key fixture.AnswerKey
	require.NoError(t, json.Unmarshal(answerKeyBytes, &key))

	// 3. log in as every fixture user with each of their identifiers,
	// proving the translated hash actually verifies against a real Kratos
	// password check.
	loginClient := &kratosLoginClient{publicURL: publicURL}
	for _, entry := range key.Entries {
		entry := entry
		t.Run(entry.SourceID, func(t *testing.T) {
			for _, identifier := range []string{entry.Email, entry.Username, entry.Phone} {
				if identifier != "" {
					require.NoError(t, loginClient.login(ctx, identifier, entry.Password))
				}
			}
		})
	}

	// 4. diff finds every imported user by its identifier.
	vr, err := cmf.NewReader(bytes.NewReader(users))
	require.NoError(t, err)
	defer vr.Close()
	diff, err := target.Verify(ctx, vr)
	require.NoError(t, err)
	require.Empty(t, diff.MissingInTarget)
	require.Empty(t, diff.NoIdentifier)
}

// kratosLoginClient drives Kratos' API-style (no-browser) self-service
// login flow: initialize, then submit the password method.
type kratosLoginClient struct {
	publicURL string
}

func (c *kratosLoginClient) login(ctx context.Context, identifier, password string) error {
	flowID, err := c.initFlow(ctx)
	if err != nil {
		return fmt.Errorf("initializing login flow: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"method":     "password",
		"identifier": identifier,
		"password":   password,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.publicURL+"/self-service/login?flow="+flowID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out struct {
		SessionToken string `json:"session_token"`
		Error        struct {
			Message string `json:"message"`
			Reason  string `json:"reason"`
		} `json:"error"`
		UI struct {
			Messages []struct {
				Text string `json:"text"`
			} `json:"messages"`
		} `json:"ui"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.SessionToken == "" {
		var msgs []string
		for _, m := range out.UI.Messages {
			msgs = append(msgs, m.Text)
		}
		return fmt.Errorf("login for %s failed (status %d): %s %s", identifier, resp.StatusCode, out.Error.Message, strings.Join(msgs, "; "))
	}
	return nil
}

func (c *kratosLoginClient) initFlow(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.publicURL+"/self-service/login/api", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("login flow init returned no id (status %d)", resp.StatusCode)
	}
	return out.ID, nil
}
