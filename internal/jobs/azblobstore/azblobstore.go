// Package azblobstore keeps jobs in an Azure Blob Storage container, for
// job stores given as azblob://container/prefix.
//
// Saves are conditional on the blob's ETag (If-Match, or If-None-Match: *
// to create one), and a job's lock is a native lease on the blob
// <id>.lease, renewed while the job runs.
package azblobstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/httpx"
)

// Scheme is the URI scheme of Azure Blob Storage job stores.
const Scheme = "azblob"

func init() { jobs.RegisterBucket(Scheme, Open) }

// apiVersion is the Blob service REST API version requests ask for.
const apiVersion = "2021-12-02"

// Lease durations Azure accepts, in seconds, besides an infinite one.
const (
	minLeaseSeconds = 15
	maxLeaseSeconds = 60
)

// Azurite's well-known development account, for UseDevelopmentStorage=true.
const (
	devAccount  = "devstoreaccount1"
	devKey      = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	devEndpoint = "http://127.0.0.1:10000/devstoreaccount1"
)

// Bucket is a jobs.LeaseBucket in a Blob Storage container, under a key
// prefix.
type Bucket struct {
	Container string
	Prefix    string
	Account   string
	// Endpoint is the account's blob service URL, e.g.
	// https://<account>.blob.core.windows.net.
	Endpoint string
	// Key is the account key requests are signed with (Shared Key), or
	// SAS a shared access signature appended to them instead.
	Key  []byte
	SAS  string
	HTTP *http.Client
	// Now is the clock requests are dated with; time.Now if nil.
	Now func() time.Time
}

// Open opens the container of an azblob://container/prefix URI, with the
// account and credentials of $AZURE_STORAGE_CONNECTION_STRING, else of
// $AZURE_STORAGE_ACCOUNT with $AZURE_STORAGE_KEY or
// $AZURE_STORAGE_SAS_TOKEN.
func Open(_ context.Context, u *url.URL) (jobs.Bucket, error) {
	if u.Host == "" {
		return nil, errors.New("azblob: the URI names no container (azblob://container/prefix)")
	}
	b := &Bucket{Container: u.Host, Prefix: jobs.KeyPrefix(u)}
	if cs := os.Getenv("AZURE_STORAGE_CONNECTION_STRING"); cs != "" {
		if err := b.parseConnectionString(cs); err != nil {
			return nil, err
		}
	} else {
		b.Account = os.Getenv("AZURE_STORAGE_ACCOUNT")
		b.SAS = strings.TrimPrefix(os.Getenv("AZURE_STORAGE_SAS_TOKEN"), "?")
		if key := os.Getenv("AZURE_STORAGE_KEY"); key != "" {
			k, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				return nil, fmt.Errorf("azblob: AZURE_STORAGE_KEY is not base64: %w", err)
			}
			b.Key = k
		}
	}
	if b.Account == "" || (b.Key == nil && b.SAS == "") {
		return nil, errors.New("azblob: AZURE_STORAGE_CONNECTION_STRING, or AZURE_STORAGE_ACCOUNT with AZURE_STORAGE_KEY or AZURE_STORAGE_SAS_TOKEN, is required")
	}
	if b.Endpoint == "" {
		b.Endpoint = "https://" + b.Account + ".blob.core.windows.net"
	}
	b.Endpoint = strings.TrimSuffix(b.Endpoint, "/")
	return b, nil
}

// parseConnectionString reads an Azure Storage connection string.
func (b *Bucket) parseConnectionString(cs string) error {
	fields := map[string]string{}
	for _, part := range strings.Split(cs, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			fields[strings.ToLower(k)] = v
		}
	}
	if strings.EqualFold(fields["usedevelopmentstorage"], "true") {
		b.Account, b.Endpoint = devAccount, devEndpoint
		b.Key, _ = base64.StdEncoding.DecodeString(devKey)
		return nil
	}
	b.Account = fields["accountname"]
	b.Endpoint = fields["blobendpoint"]
	b.SAS = strings.TrimPrefix(fields["sharedaccesssignature"], "?")
	if key := fields["accountkey"]; key != "" {
		k, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("azblob: the connection string's AccountKey is not base64: %w", err)
		}
		b.Key = k
	}
	if b.Endpoint == "" && b.Account != "" {
		protocol := fields["defaultendpointsprotocol"]
		if protocol == "" {
			protocol = "https"
		}
		suffix := fields["endpointsuffix"]
		if suffix == "" {
			suffix = "core.windows.net"
		}
		b.Endpoint = protocol + "://" + b.Account + ".blob." + suffix
	}
	return nil
}

// Get downloads the blob at key, with its ETag as the version.
func (b *Bucket) Get(ctx context.Context, key string) ([]byte, string, error) {
	resp, body, err := b.do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("ETag"), nil
}

// Put uploads the block blob at key, if its ETag is match or, with an
// empty match, if there is none yet.
func (b *Bucket) Put(ctx context.Context, key string, data []byte, match string) (string, error) {
	h := http.Header{"X-Ms-Blob-Type": {"BlockBlob"}, "Content-Type": {"application/json"}}
	if match == "" {
		h.Set("If-None-Match", "*")
	} else {
		h.Set("If-Match", match)
	}
	resp, _, err := b.do(ctx, http.MethodPut, key, nil, h, data)
	if errors.Is(err, jobs.ErrObjectNotFound) {
		return "", jobs.ErrPrecondition
	}
	if err != nil {
		return "", err
	}
	return resp.Header.Get("ETag"), nil
}

// Delete removes the blob at key, if its ETag is match (any, for an empty
// match).
func (b *Bucket) Delete(ctx context.Context, key, match string) error {
	var h http.Header
	if match != "" {
		h = http.Header{"If-Match": {match}}
	}
	_, _, err := b.do(ctx, http.MethodDelete, key, nil, h, nil)
	return err
}

type listResult struct {
	Blobs struct {
		Blob []struct {
			Name string `xml:"Name"`
		} `xml:"Blob"`
	} `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

// List returns the keys under prefix, relative to the bucket's prefix.
func (b *Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	marker := ""
	for {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {b.Prefix + prefix}}
		if marker != "" {
			q.Set("marker", marker)
		}
		_, body, err := b.request(ctx, http.MethodGet, b.containerPath(), q, nil, nil)
		if err != nil {
			return nil, err
		}
		var res listResult
		if err := xml.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("azblob: decoding the blob listing: %w", err)
		}
		for _, bl := range res.Blobs.Blob {
			keys = append(keys, strings.TrimPrefix(bl.Name, b.Prefix))
		}
		if res.NextMarker == "" {
			return keys, nil
		}
		marker = res.NextMarker
	}
}

// AcquireLease takes a lease on the blob at key for ttl (clamped to the
// 15 to 60 seconds Azure accepts), creating the blob empty first if it
// doesn't exist. A blob leased by someone else is jobs.ErrLocked.
func (b *Bucket) AcquireLease(ctx context.Context, key string, ttl time.Duration) (string, error) {
	seconds := min(max(int(ttl/time.Second), minLeaseSeconds), maxLeaseSeconds)
	duration := http.Header{"X-Ms-Lease-Duration": {strconv.Itoa(seconds)}}
	resp, err := b.leaseOp(ctx, key, "acquire", duration)
	if errors.Is(err, jobs.ErrObjectNotFound) {
		if _, err := b.Put(ctx, key, nil, ""); err != nil && !errors.Is(err, jobs.ErrPrecondition) {
			return "", err
		}
		resp, err = b.leaseOp(ctx, key, "acquire", duration)
	}
	if errors.Is(err, jobs.ErrPrecondition) {
		return "", jobs.ErrLocked
	}
	if err != nil {
		return "", err
	}
	return resp.Header.Get("X-Ms-Lease-Id"), nil
}

// RenewLease renews a lease AcquireLease returned. A lease someone else
// took over since is jobs.ErrPrecondition.
func (b *Bucket) RenewLease(ctx context.Context, key, leaseID string) error {
	_, err := b.leaseOp(ctx, key, "renew", http.Header{"X-Ms-Lease-Id": {leaseID}})
	return err
}

// ReleaseLease gives up a lease AcquireLease returned.
func (b *Bucket) ReleaseLease(ctx context.Context, key, leaseID string) error {
	_, err := b.leaseOp(ctx, key, "release", http.Header{"X-Ms-Lease-Id": {leaseID}})
	return err
}

// leaseOp runs the Lease Blob action on the blob at key, with the headers
// h it takes.
func (b *Bucket) leaseOp(ctx context.Context, key, action string, h http.Header) (*http.Response, error) {
	h.Set("X-Ms-Lease-Action", action)
	resp, _, err := b.do(ctx, http.MethodPut, key, url.Values{"comp": {"lease"}}, h, nil)
	return resp, err
}

// Error is a Blob service error response.
type Error struct {
	StatusCode int
	Code       string `xml:"Code"`
	Message    string `xml:"Message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("azblob: %s (status %d): %s", e.Code, e.StatusCode, strings.TrimSpace(e.Message))
}

func (b *Bucket) containerPath() string {
	u, _ := url.Parse(b.Endpoint)
	return strings.TrimSuffix(u.Path, "/") + "/" + url.PathEscape(b.Container)
}

func (b *Bucket) do(ctx context.Context, method, key string, q url.Values, h http.Header, body []byte) (*http.Response, []byte, error) {
	segs := strings.Split(b.Prefix+key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return b.request(ctx, method, b.containerPath()+"/"+strings.Join(segs, "/"), q, h, body)
}

func (b *Bucket) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: httpx.NewTransport(nil, nil)}
}

// conflictCodes are the 409 error codes that mean a precondition on the
// blob or its lease didn't hold.
var conflictCodes = map[string]bool{
	"BlobAlreadyExists":                  true,
	"ConditionNotMet":                    true,
	"LeaseAlreadyPresent":                true,
	"LeaseIdMismatchWithLeaseOperation":  true,
	"LeaseIdMismatchWithBlobOperation":   true,
	"LeaseIdMissing":                     true,
	"LeaseIsBreakingAndCannotBeAcquired": true,
	"LeaseIsBrokenAndCannotBeRenewed":    true,
	"LeaseLost":                          true,
	"LeaseNotPresentWithLeaseOperation":  true,
}

// request sends a signed request to the account path and returns the
// response with its body read. A 404 is jobs.ErrObjectNotFound, and a 412
// or a lease or existence conflict jobs.ErrPrecondition.
func (b *Bucket) request(ctx context.Context, method, path string, q url.Values, h http.Header, body []byte) (*http.Response, []byte, error) {
	base, err := url.Parse(b.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	u := *base
	u.Path = ""
	u.RawPath = ""
	query := q.Encode()
	if b.SAS != "" {
		if query != "" {
			query += "&"
		}
		query += b.SAS
	}
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.URL.Path, _ = url.PathUnescape(path)
	req.URL.RawPath = path
	req.ContentLength = int64(len(body))
	for k, v := range h {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	req.Header.Set("X-Ms-Date", now.UTC().Format(http.TimeFormat))
	req.Header.Set("X-Ms-Version", apiVersion)
	if b.SAS == "" {
		req.Header.Set("Authorization", "SharedKey "+b.Account+":"+b.signature(req, q))
	}

	resp, err := b.client().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("azblob: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("azblob: reading the response: %w", err)
	}
	if resp.StatusCode < 300 {
		return resp, respBody, nil
	}
	e := &Error{StatusCode: resp.StatusCode}
	_ = xml.Unmarshal(respBody, e)
	if e.Code == "" {
		e.Code = resp.Header.Get("X-Ms-Error-Code")
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp, nil, jobs.ErrObjectNotFound
	case resp.StatusCode == http.StatusPreconditionFailed, resp.StatusCode == http.StatusConflict && conflictCodes[e.Code]:
		return resp, nil, fmt.Errorf("%w: %s", jobs.ErrPrecondition, e.Code)
	}
	return resp, nil, e
}

// signature computes the Shared Key signature of req, whose query is q.
func (b *Bucket) signature(req *http.Request, q url.Values) string {
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	hdr := req.Header.Get
	var xms []string
	for name := range req.Header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-ms-") {
			xms = append(xms, lower+":"+strings.TrimSpace(strings.Join(req.Header.Values(name), ",")))
		}
	}
	sort.Strings(xms)

	resource := "/" + b.Account + req.URL.EscapedPath()
	names := make([]string, 0, len(q))
	for name := range q {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := append([]string(nil), q[name]...)
		sort.Strings(values)
		resource += "\n" + strings.ToLower(name) + ":" + strings.Join(values, ",")
	}

	toSign := strings.Join([]string{
		req.Method,
		hdr("Content-Encoding"), hdr("Content-Language"), length, hdr("Content-MD5"), hdr("Content-Type"),
		"", // Date: x-ms-date is used instead
		hdr("If-Modified-Since"), hdr("If-Match"), hdr("If-None-Match"), hdr("If-Unmodified-Since"), hdr("Range"),
	}, "\n") + "\n" + strings.Join(xms, "\n") + "\n" + resource
	m := hmac.New(sha256.New, b.Key)
	m.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}
