package azblobstore

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AZURE_STORAGE_CONNECTION_STRING", "")
	t.Setenv("AZURE_STORAGE_ACCOUNT", "")
	_, err := jobs.OpenStore(ctx, "azblob:///prefix")
	require.ErrorContains(t, err, "names no container")
	_, err = jobs.OpenStore(ctx, "azblob://jobs/prefix")
	require.ErrorContains(t, err, "AZURE_STORAGE_CONNECTION_STRING")

	t.Setenv("AZURE_STORAGE_ACCOUNT", "acme")
	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "?sv=2021&sig=abc")
	b, err := Open(ctx, &url.URL{Scheme: Scheme, Host: "jobs", Path: "/team"})
	require.NoError(t, err)
	require.Equal(t, "https://acme.blob.core.windows.net", b.(*Bucket).Endpoint)
	require.Equal(t, "sv=2021&sig=abc", b.(*Bucket).SAS)
	require.Equal(t, "team/", b.(*Bucket).Prefix)

	t.Setenv("AZURE_STORAGE_CONNECTION_STRING", "DefaultEndpointsProtocol=https;AccountName=other;AccountKey=a2V5;EndpointSuffix=core.chinacloudapi.cn")
	b, err = Open(ctx, &url.URL{Scheme: Scheme, Host: "jobs"})
	require.NoError(t, err)
	require.Equal(t, "https://other.blob.core.chinacloudapi.cn", b.(*Bucket).Endpoint)
	require.Equal(t, []byte("key"), b.(*Bucket).Key)

	t.Setenv("AZURE_STORAGE_CONNECTION_STRING", "UseDevelopmentStorage=true")
	b, err = Open(ctx, &url.URL{Scheme: Scheme, Host: "jobs"})
	require.NoError(t, err)
	require.Equal(t, devEndpoint, b.(*Bucket).Endpoint)
}

// The signature of a request with every part the Shared Key string to sign
// takes, computed independently.
func TestSignature(t *testing.T) {
	b := &Bucket{Account: "myaccount", Key: []byte("secret")}
	req, err := http.NewRequest(http.MethodPut, "https://myaccount.blob.core.windows.net/jobs/a.json?comp=lease", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"0x1"`)
	req.Header.Set("X-Ms-Date", "Mon, 01 Jan 2024 00:00:00 GMT")
	req.Header.Set("X-Ms-Version", apiVersion)
	// Computed with Python's hmac over the string to sign the Blob service documents.
	require.Equal(t, "1yeC8bhdLjxTZYCXhq2ClAEDt3AknbANKgQSNdio68I=", b.signature(req, url.Values{"comp": {"lease"}}))
}

// TestAzuriteContract runs the jobs.Bucket and jobs.Store contracts against
// Azurite (see .docker/azurite), when AZURE_STORAGE_CONNECTION_STRING is
// set, to UseDevelopmentStorage=true for instance.
func TestAzuriteContract(t *testing.T) {
	if os.Getenv("AZURE_STORAGE_CONNECTION_STRING") == "" {
		t.Skip("AZURE_STORAGE_CONNECTION_STRING not set")
	}
	const container = "iamigrate-jobs"
	ctx := context.Background()
	b, err := Open(ctx, &url.URL{Scheme: Scheme, Host: container})
	require.NoError(t, err)
	_, _, err = b.(*Bucket).request(ctx, http.MethodPut, b.(*Bucket).containerPath(), url.Values{"restype": {"container"}}, nil, nil)
	if err != nil && !strings.Contains(err.Error(), "ContainerAlreadyExists") && !strings.Contains(err.Error(), "precondition") {
		require.NoError(t, err)
	}

	jobstest.BucketContract(t, func(t *testing.T) jobs.Bucket {
		prefix := strings.ReplaceAll(t.Name(), "/", "_") + "-" + time.Now().Format("150405.000000000")
		b, err := Open(ctx, &url.URL{Scheme: Scheme, Host: container, Path: "/" + prefix})
		require.NoError(t, err)
		return b
	})
}

// A native lease another process broke and took over is lost to its first
// holder, at its next renewal.
func TestAzuriteLeaseTakenOverIsLost(t *testing.T) {
	if os.Getenv("AZURE_STORAGE_CONNECTION_STRING") == "" {
		t.Skip("AZURE_STORAGE_CONNECTION_STRING not set")
	}
	ctx := context.Background()
	open := func() *Bucket {
		b, err := Open(ctx, &url.URL{Scheme: Scheme, Host: "iamigrate-jobs", Path: "/takeover-" + time.Now().Format("150405.000000000")})
		require.NoError(t, err)
		return b.(*Bucket)
	}
	b := open()
	holder := &jobs.ObjectStore{Bucket: b, LeaseTTL: 600 * time.Millisecond}
	lease, err := holder.Lock("a")
	require.NoError(t, err)
	defer lease.Release()

	_, err = b.leaseOp(ctx, "a.lease", "break", http.Header{"X-Ms-Lease-Break-Period": {"0"}})
	require.NoError(t, err)
	other := &jobs.ObjectStore{Bucket: b, LeaseTTL: time.Minute}
	taken, err := other.Lock("a")
	require.NoError(t, err)
	defer taken.Release()

	select {
	case <-lease.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("a lease taken over is lost")
	}
}
