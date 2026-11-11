package s3store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

// The GET Object example of AWS's Signature Version 4 documentation for S3.
func TestSignMatchesAWSExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=0-9")
	Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}.
		sign(req, nil, "us-east-1", time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	require.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "+
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "+
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", req.Header.Get("Authorization"))
}

func TestObjectURL(t *testing.T) {
	b := &Bucket{Name: "jobs", Region: "eu-west-1"}
	u, err := b.objectURL("team a/x.json", url.Values{"prefix": {"p/"}, "list-type": {"2"}})
	require.NoError(t, err)
	require.Equal(t, "https://jobs.s3.eu-west-1.amazonaws.com/team%20a/x.json?list-type=2&prefix=p%2F", u.String())

	b = &Bucket{Name: "my.jobs", Region: "eu-west-1"}
	u, err = b.objectURL("x.json", nil)
	require.NoError(t, err)
	require.Equal(t, "https://s3.eu-west-1.amazonaws.com/my.jobs/x.json", u.String())

	b = &Bucket{Name: "jobs", Region: "us-east-1", Endpoint: "http://127.0.0.1:9000/"}
	u, err = b.objectURL("x.json", nil)
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:9000/jobs/x.json", u.String())
}

// A store that ignores If-None-Match is refused.
func TestCheckConditionalWritesRefusesAStoreIgnoringThem(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
	}))
	defer server.Close()
	b := &Bucket{Name: "jobs", Region: "us-east-1", Endpoint: server.URL, Credentials: Credentials{AccessKeyID: "a", SecretAccessKey: "b"}}
	require.ErrorIs(t, b.CheckConditionalWrites(context.Background()), ErrNoConditionalWrites)
}

func TestOpenNeedsBucketAndCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	_, err := jobs.OpenStore(context.Background(), "s3:///prefix")
	require.ErrorContains(t, err, "names no bucket")
	_, err = jobs.OpenStore(context.Background(), "s3://bucket/prefix")
	require.ErrorContains(t, err, "AWS_ACCESS_KEY_ID")
}

// TestMinIOContract runs the jobs.Bucket and jobs.Store contracts against
// MinIO (see .docker/minio), when IAMIGRATE_TEST_S3_ENDPOINT is set to its
// URL, with its credentials in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
func TestMinIOContract(t *testing.T) {
	endpoint := os.Getenv("IAMIGRATE_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("IAMIGRATE_TEST_S3_ENDPOINT not set")
	}
	t.Setenv("AWS_ENDPOINT_URL_S3", endpoint)
	bucket := os.Getenv("IAMIGRATE_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "iamigrate-jobs"
	}
	jobstest.BucketContract(t, func(t *testing.T) jobs.Bucket {
		prefix := strings.ReplaceAll(t.Name(), "/", "_") + "-" + time.Now().Format("150405.000000000")
		b, err := Open(context.Background(), &url.URL{Scheme: Scheme, Host: bucket, Path: "/" + prefix})
		require.NoError(t, err)
		return b
	})
}
