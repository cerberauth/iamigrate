package gcsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "")
	ctx := context.Background()
	_, err := jobs.OpenStore(ctx, "gs:///prefix")
	require.ErrorContains(t, err, "names no bucket")
	_, err = jobs.OpenStore(ctx, "gs://bucket/prefix")
	require.ErrorContains(t, err, "GOOGLE_APPLICATION_CREDENTIALS")

	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "token")
	b, err := Open(ctx, &url.URL{Scheme: Scheme, Host: "bucket", Path: "/team/jobs"})
	require.NoError(t, err)
	require.Equal(t, "team/jobs/", b.(*Bucket).Prefix)
	require.Equal(t, defaultEndpoint, b.(*Bucket).Endpoint)

	t.Setenv("STORAGE_EMULATOR_HOST", "127.0.0.1:4443")
	b, err = Open(ctx, &url.URL{Scheme: Scheme, Host: "bucket"})
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:4443", b.(*Bucket).Endpoint)
	require.Nil(t, b.(*Bucket).Credentials)
}

func TestRequestsCarryTheAccessToken(t *testing.T) {
	var auth, generation string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, generation = r.Header.Get("Authorization"), r.URL.Query().Get("ifGenerationMatch")
		_, _ = w.Write([]byte(`{"name":"p/a.json","generation":"7"}`))
	}))
	defer server.Close()
	b := &Bucket{Name: "jobs", Prefix: "p/", Endpoint: server.URL, Credentials: &firebase.Credentials{AccessToken: "tok"}}
	v, err := b.Put(context.Background(), "a.json", []byte("{}"), "")
	require.NoError(t, err)
	require.Equal(t, "7", v)
	require.Equal(t, "Bearer tok", auth)
	require.Equal(t, "0", generation, "an empty match creates only")
}

// TestFakeGCSContract runs the jobs.Bucket and jobs.Store contracts against
// fake-gcs-server (see .docker/fake-gcs), when STORAGE_EMULATOR_HOST is set
// to its URL.
func TestFakeGCSContract(t *testing.T) {
	host := os.Getenv("STORAGE_EMULATOR_HOST")
	if host == "" {
		t.Skip("STORAGE_EMULATOR_HOST not set")
	}
	const bucket = "iamigrate-jobs"
	createBucket(t, host, bucket)
	jobstest.BucketContract(t, func(t *testing.T) jobs.Bucket {
		prefix := strings.ReplaceAll(t.Name(), "/", "_") + "-" + time.Now().Format("150405.000000000")
		b, err := Open(context.Background(), &url.URL{Scheme: Scheme, Host: bucket, Path: "/" + prefix})
		require.NoError(t, err)
		return b
	})
}

func createBucket(t *testing.T, host, name string) {
	t.Helper()
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	body, err := json.Marshal(map[string]string{"name": name})
	require.NoError(t, err)
	resp, err := http.Post(host+"/storage/v1/b?project=test", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, []int{http.StatusOK, http.StatusConflict}, resp.StatusCode)
}
