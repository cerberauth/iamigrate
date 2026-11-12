// Package s3store keeps jobs in an Amazon S3 bucket, or one of an
// S3-compatible store with conditional writes (MinIO, ...), for job stores
// given as s3://bucket/prefix.
//
// Saves and leases are conditional writes: If-None-Match: * to create an
// object, If-Match on its ETag to replace it. A store that ignores them is
// refused when opened, as two writers could then overwrite each other.
package s3store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/httpx"
)

// Scheme is the URI scheme of S3 job stores.
const Scheme = "s3"

func init() { jobs.RegisterBucket(Scheme, Open) }

// Credentials are the AWS access keys requests are signed with.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// Bucket is a jobs.Bucket in an S3 bucket, under a key prefix.
type Bucket struct {
	Name   string
	Prefix string
	Region string
	// Endpoint is the S3 API URL, for an S3-compatible store; AWS's
	// regional endpoint if empty. A custom endpoint is addressed path-style
	// (endpoint/bucket/key).
	Endpoint    string
	Credentials Credentials
	HTTP        *http.Client
	// Now is the clock requests are signed at; time.Now if nil.
	Now func() time.Time
}

// Open opens the bucket of an s3://bucket/prefix URI, with the credentials,
// region and endpoint of the environment variables the AWS tools read:
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION
// (or AWS_DEFAULT_REGION, else us-east-1) and AWS_ENDPOINT_URL_S3 (or
// AWS_ENDPOINT_URL). It checks the bucket honors conditional writes.
func Open(ctx context.Context, u *url.URL) (jobs.Bucket, error) {
	if u.Host == "" {
		return nil, errors.New("s3: the URI names no bucket (s3://bucket/prefix)")
	}
	b := &Bucket{
		Name:   u.Host,
		Prefix: jobs.KeyPrefix(u),
		Region: firstEnv("AWS_REGION", "AWS_DEFAULT_REGION"),
		Credentials: Credentials{
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		},
		Endpoint: firstEnv("AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL"),
	}
	if b.Region == "" {
		b.Region = "us-east-1"
	}
	if b.Credentials.AccessKeyID == "" || b.Credentials.SecretAccessKey == "" {
		return nil, errors.New("s3: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")
	}
	if err := b.CheckConditionalWrites(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// ErrNoConditionalWrites is returned by CheckConditionalWrites for a store
// that ignores If-None-Match or If-Match.
var ErrNoConditionalWrites = errors.New("s3: the store doesn't honor conditional writes (If-None-Match/If-Match), which job stores need so that two writers never overwrite each other")

// CheckConditionalWrites writes a probe object twice with If-None-Match: *
// and once with a wrong If-Match, and returns ErrNoConditionalWrites unless
// the store refuses both of the last two.
func (b *Bucket) CheckConditionalWrites(ctx context.Context) error {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	key := ".iamigrate-probe-" + hex.EncodeToString(nonce[:])
	v, err := b.Put(ctx, key, []byte("probe"), "")
	if err != nil {
		return fmt.Errorf("s3: writing to bucket %s: %w", b.Name, err)
	}
	defer func() { _ = b.Delete(context.WithoutCancel(ctx), key, "") }()
	if _, err := b.Put(ctx, key, []byte("probe again"), ""); !errors.Is(err, jobs.ErrPrecondition) {
		return ErrNoConditionalWrites
	}
	if _, err := b.Put(ctx, key, []byte("probe again"), v+"-stale"); !errors.Is(err, jobs.ErrPrecondition) {
		return ErrNoConditionalWrites
	}
	return nil
}

// Get reads the object at key, with its ETag as the version.
func (b *Bucket) Get(ctx context.Context, key string) ([]byte, string, error) {
	resp, body, err := b.do(ctx, http.MethodGet, b.Prefix+key, nil, nil, nil)
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("ETag"), nil
}

// Put writes the object at key, if it doesn't exist (an empty match) or
// has the ETag match.
func (b *Bucket) Put(ctx context.Context, key string, data []byte, match string) (string, error) {
	h := http.Header{"Content-Type": {"application/json"}}
	if match == "" {
		h.Set("If-None-Match", "*")
	} else {
		h.Set("If-Match", match)
		if b.Endpoint != "" {
			// Some S3-compatible stores (MinIO) create a missing object on
			// If-Match rather than answer 404 as S3 does: check it exists
			// first. Only lease objects are ever deleted, and a job save is
			// itself conditional, so the window this leaves is harmless.
			if _, _, err := b.do(ctx, http.MethodHead, b.Prefix+key, nil, ifMatch(match), nil); err != nil {
				if errors.Is(err, jobs.ErrObjectNotFound) {
					return "", jobs.ErrPrecondition
				}
				return "", err
			}
		}
	}
	resp, _, err := b.do(ctx, http.MethodPut, b.Prefix+key, nil, h, data)
	if errors.Is(err, jobs.ErrObjectNotFound) {
		// If-Match on a missing object.
		return "", jobs.ErrPrecondition
	}
	if err != nil {
		return "", err
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("s3: PUT returned no ETag")
	}
	return etag, nil
}

// Delete removes the object at key, if it has the ETag match (any, for an
// empty match). The match is checked by a conditional HEAD first, as not
// every S3-compatible store takes If-Match on a DELETE.
func (b *Bucket) Delete(ctx context.Context, key, match string) error {
	if _, _, err := b.do(ctx, http.MethodHead, b.Prefix+key, nil, ifMatch(match), nil); err != nil {
		return err
	}
	_, _, err := b.do(ctx, http.MethodDelete, b.Prefix+key, nil, nil, nil)
	return err
}

func ifMatch(match string) http.Header {
	if match == "" {
		return nil
	}
	return http.Header{"If-Match": {match}}
}

type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// List returns the keys under prefix, relative to the bucket's prefix,
// through ListObjectsV2.
func (b *Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {b.Prefix + prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		_, body, err := b.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		var res listResult
		if err := xml.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("s3: decoding the object listing: %w", err)
		}
		for _, c := range res.Contents {
			keys = append(keys, strings.TrimPrefix(c.Key, b.Prefix))
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			return keys, nil
		}
		token = res.NextContinuationToken
	}
}

// Error is an S3 error response.
type Error struct {
	StatusCode int
	Code       string `xml:"Code"`
	Message    string `xml:"Message"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("s3: request failed with status %d", e.StatusCode)
	}
	return fmt.Sprintf("s3: %s (status %d): %s", e.Code, e.StatusCode, e.Message)
}

// objectURL returns the URL of key (the bucket itself if empty).
func (b *Bucket) objectURL(key string, q url.Values) (*url.URL, error) {
	var raw string
	escaped := escapePath(key)
	switch {
	case b.Endpoint != "":
		raw = strings.TrimSuffix(b.Endpoint, "/") + "/" + b.Name + "/" + escaped
	case strings.Contains(b.Name, "."):
		// A dotted bucket name doesn't match the wildcard certificate of
		// virtual-hosted addressing.
		raw = "https://s3." + b.Region + ".amazonaws.com/" + b.Name + "/" + escaped
	default:
		raw = "https://" + b.Name + ".s3." + b.Region + ".amazonaws.com/" + escaped
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	u.RawQuery = canonicalQuery(q)
	return u, nil
}

func (b *Bucket) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: httpx.NewTransport(nil, nil)}
}

func (b *Bucket) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// do sends a signed request and returns the response with its body read. A
// 404 is jobs.ErrObjectNotFound and a 412 (or a 409 from a concurrent
// conditional write) jobs.ErrPrecondition.
func (b *Bucket) do(ctx context.Context, method, key string, q url.Values, h http.Header, body []byte) (*http.Response, []byte, error) {
	u, err := b.objectURL(key, q)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.ContentLength = int64(len(body))
	for k, v := range h {
		req.Header[k] = v
	}
	b.Credentials.sign(req, body, b.Region, b.now())

	resp, err := b.client().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("s3: %s %s: %w", method, u.Path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("s3: reading the response: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp, nil, jobs.ErrObjectNotFound
	case resp.StatusCode == http.StatusPreconditionFailed, resp.StatusCode == http.StatusConflict:
		return resp, nil, jobs.ErrPrecondition
	case resp.StatusCode >= 300:
		e := &Error{StatusCode: resp.StatusCode}
		_ = xml.Unmarshal(respBody, e)
		return resp, nil, e
	}
	return resp, respBody, nil
}

// unsignedHeaders are the request headers sign leaves out.
var unsignedHeaders = map[string]bool{"user-agent": true, "authorization": true, "content-length": true, "accept-encoding": true}

// sign adds the AWS Signature Version 4 headers of S3 to req, whose body is
// payload: every header set on req is signed, along with the host.
func (c Credentials) sign(req *http.Request, payload []byte, region string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	payloadHash := hexSHA256(payload)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}

	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		if lower := strings.ToLower(name); !unsignedHeaders[lower] {
			headers[lower] = strings.TrimSpace(strings.Join(values, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method, path, req.URL.RawQuery, canonicalHeaders.String(), signedHeaders, payloadHash,
	}, "\n")
	scope := day + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonicalRequest))}, "\n")

	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, scope, signedHeaders, hex.EncodeToString(hmacSHA256(key, stringToSign))))
}

// escapePath URI-encodes each segment of a key the way SigV4 expects:
// everything but unreserved characters, and the slashes kept.
func escapePath(key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery encodes q sorted by key, with SigV4's encoding.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
