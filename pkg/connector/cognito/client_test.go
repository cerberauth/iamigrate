package cognito

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSignMatchesAWSVector checks the signer against AWS's published
// Signature Version 4 test case "get-vanilla".
func TestSignMatchesAWSVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	require.NoError(t, err)

	Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}.
		sign(req, nil, "us-east-1", "service", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))

	require.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "+
		"SignedHeaders=host;x-amz-date, "+
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		req.Header.Get("Authorization"))
}

func TestSignIncludesTheSessionToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://cognito-idp.eu-west-1.amazonaws.com/", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", targetPrefix+"AdminGetUser")

	Credentials{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "tok"}.
		sign(req, []byte("{}"), "eu-west-1", serviceName, time.Now())

	require.Equal(t, "tok", req.Header.Get("X-Amz-Security-Token"))
	require.Contains(t, req.Header.Get("Authorization"),
		"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target")
}

func TestRegionOf(t *testing.T) {
	require.Equal(t, "eu-west-1", RegionOf("eu-west-1_AbCdEfGhI"))
	require.Equal(t, "", RegionOf("nopool"))
}

func TestCallRetriesThrottlingThenDecodes(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, targetPrefix+"AdminGetUser", r.Header.Get("X-Amz-Target"))
		require.Contains(t, r.Header.Get("Authorization"), "Credential=AK/")
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"TooManyRequestsException","message":"slow down"}`))
			return
		}
		_, _ = w.Write([]byte(`{"Username":"u1","Enabled":true}`))
	}))
	defer server.Close()

	c := NewClient("eu-west-1", "eu-west-1_pool", Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"})
	c.Endpoint, c.RetryDelay = server.URL, time.Millisecond

	var out userInfo
	require.NoError(t, c.call(context.Background(), "AdminGetUser", map[string]string{"Username": "u1"}, &out))
	require.Equal(t, "u1", out.Username)
	require.EqualValues(t, 3, calls.Load())
}

func TestCallReturnsTheExceptionType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"com.amazonaws.cognito#UsernameExistsException:http://x","message":"User account already exists"}`))
	}))
	defer server.Close()

	c := NewClient("eu-west-1", "eu-west-1_pool", Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"})
	c.Endpoint = server.URL

	err := c.call(context.Background(), "AdminCreateUser", map[string]string{}, nil)
	require.Error(t, err)
	require.True(t, isCode(err, UsernameExistsCode))
	require.Contains(t, err.Error(), "User account already exists")
}
