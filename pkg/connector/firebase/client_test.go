package firebase_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/stretchr/testify/require"
)

// writeServiceAccount writes a service account key file whose token_uri is
// tokenURI, returning its path and the public half of its key.
func writeServiceAccount(t *testing.T, tokenURI string, pkcs1 bool) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var block *pem.Block
	if pkcs1 {
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	b, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "acme-prod",
		"client_email": "sa@acme-prod.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(block)),
		"token_uri":    tokenURI,
	})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path, &key.PublicKey
}

func TestServiceAccountTokenGrant(t *testing.T) {
	for _, pkcs1 := range []bool{false, true} {
		var pub *rsa.PublicKey
		var grants atomic.Int32
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			grants.Add(1)
			require.NoError(t, r.ParseForm())
			require.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.PostForm.Get("grant_type"))

			parts := strings.Split(r.PostForm.Get("assertion"), ".")
			require.Len(t, parts, 3)
			var claims map[string]any
			raw, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &claims))
			require.Equal(t, "sa@acme-prod.iam.gserviceaccount.com", claims["iss"])
			require.Equal(t, "https://www.googleapis.com/auth/cloud-platform", claims["scope"])
			require.Contains(t, claims["aud"], "http://127.0.0.1")

			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			require.NoError(t, err)
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))

			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "sa-token", "expires_in": 3600})
		}))

		path, key := writeServiceAccount(t, tokenServer.URL, pkcs1)
		pub = key
		sa, err := firebase.LoadServiceAccount(path)
		require.NoError(t, err)
		require.Equal(t, "acme-prod", sa.ProjectID)

		var apiAuth string
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{}`))
		}))

		client := firebase.NewClient("acme-prod", &firebase.Credentials{ServiceAccount: sa})
		client.BaseURL = api.URL
		// Two calls share one cached token.
		for range 2 {
			_, err = firebase.New(client).Verify(context.Background(), writeUsers(t, nil))
			require.NoError(t, err)
		}
		_, err = firebase.New(client).Verify(context.Background(), writeUsers(t, []cmf.User{bcryptUser("u1")}))
		require.NoError(t, err)

		require.Equal(t, "Bearer sa-token", apiAuth)
		require.EqualValues(t, 1, grants.Load())
		tokenServer.Close()
		api.Close()
	}
}

func TestServiceAccountTokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	path, _ := writeServiceAccount(t, tokenServer.URL, false)
	sa, err := firebase.LoadServiceAccount(path)
	require.NoError(t, err)

	_, err = (&firebase.Credentials{ServiceAccount: sa}).Token(context.Background(), http.DefaultClient)
	require.ErrorContains(t, err, "invalid_grant")
}

func TestLoadServiceAccountErrors(t *testing.T) {
	_, err := firebase.LoadServiceAccount(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)

	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"type":"authorized_user"}`), 0o600))
	_, err = firebase.LoadServiceAccount(path)
	require.ErrorContains(t, err, "no client_email or private_key")
}

func TestCredentialsWithoutAnythingFail(t *testing.T) {
	_, err := (&firebase.Credentials{}).Token(context.Background(), http.DefaultClient)
	require.ErrorContains(t, err, "no access token or service account")
}

func TestEmulatorClient(t *testing.T) {
	var path, auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := firebase.NewEmulatorClient(strings.TrimPrefix(server.URL, "http://"), "demo-project")
	_, err := firebase.New(client).Verify(context.Background(), writeUsers(t, []cmf.User{bcryptUser("u1")}))
	require.NoError(t, err)
	require.Equal(t, "/identitytoolkit.googleapis.com/v1/projects/demo-project/accounts:lookup", path)
	require.Equal(t, "Bearer owner", auth)
}
