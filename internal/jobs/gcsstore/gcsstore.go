// Package gcsstore keeps jobs in a Google Cloud Storage bucket, for job
// stores given as gs://bucket/prefix.
//
// An object's version is its generation: saves and leases are writes with
// an ifGenerationMatch precondition, 0 to create an object.
package gcsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/httpx"
)

// Scheme is the URI scheme of Google Cloud Storage job stores.
const Scheme = "gs"

func init() { jobs.RegisterBucket(Scheme, Open) }

const defaultEndpoint = "https://storage.googleapis.com"

// Bucket is a jobs.Bucket in a Cloud Storage bucket, under a key prefix,
// through the JSON API.
type Bucket struct {
	Name   string
	Prefix string
	// Endpoint is the API's base URL: https://storage.googleapis.com, or
	// an emulator's.
	Endpoint string
	// Credentials supply the access tokens; nil sends none, for an
	// emulator.
	Credentials *firebase.Credentials
	HTTP        *http.Client
}

// Open opens the bucket of a gs://bucket/prefix URI. Credentials are a
// service account key file at $GOOGLE_APPLICATION_CREDENTIALS, or an access
// token in $GOOGLE_OAUTH_ACCESS_TOKEN (from `gcloud auth
// print-access-token`). With $STORAGE_EMULATOR_HOST, requests go to that
// emulator instead, with no credentials.
func Open(_ context.Context, u *url.URL) (jobs.Bucket, error) {
	if u.Host == "" {
		return nil, errors.New("gcs: the URI names no bucket (gs://bucket/prefix)")
	}
	b := &Bucket{Name: u.Host, Prefix: jobs.KeyPrefix(u), Endpoint: defaultEndpoint}
	if host := os.Getenv("STORAGE_EMULATOR_HOST"); host != "" {
		if !strings.Contains(host, "://") {
			host = "http://" + host
		}
		b.Endpoint = strings.TrimSuffix(host, "/")
		return b, nil
	}
	switch {
	case os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN") != "":
		b.Credentials = &firebase.Credentials{AccessToken: os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")}
	case os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "":
		sa, err := firebase.LoadServiceAccount(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		if err != nil {
			return nil, err
		}
		b.Credentials = &firebase.Credentials{ServiceAccount: sa}
	default:
		return nil, errors.New("gcs: GOOGLE_APPLICATION_CREDENTIALS (a service account key file) or GOOGLE_OAUTH_ACCESS_TOKEN is required")
	}
	return b, nil
}

type object struct {
	Name       string `json:"name"`
	Generation string `json:"generation"`
}

// Get downloads the object at key, with its generation as the version.
func (b *Bucket) Get(ctx context.Context, key string) ([]byte, string, error) {
	resp, body, err := b.do(ctx, http.MethodGet, b.objectPath(key), url.Values{"alt": {"media"}}, nil)
	if err != nil {
		return nil, "", err
	}
	return body, resp.Header.Get("X-Goog-Generation"), nil
}

// Put uploads the object at key if its generation is match, or, with an
// empty match, if there is none yet.
func (b *Bucket) Put(ctx context.Context, key string, data []byte, match string) (string, error) {
	if match == "" {
		match = "0"
	}
	// A multipart upload (metadata, then content): emulators honor its
	// preconditions, not always a media upload's.
	var mp bytes.Buffer
	w := multipart.NewWriter(&mp)
	meta, err := json.Marshal(map[string]string{"name": b.Prefix + key, "contentType": "application/json"})
	if err != nil {
		return "", err
	}
	for _, part := range [][]byte{meta, data} {
		pw, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
		if err != nil {
			return "", err
		}
		if _, err := pw.Write(part); err != nil {
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	q := url.Values{"uploadType": {"multipart"}, "ifGenerationMatch": {match}}
	_, body, err := b.do(ctx, http.MethodPost, "/upload/storage/v1/b/"+url.PathEscape(b.Name)+"/o", q,
		mp.Bytes(), "multipart/related; boundary="+w.Boundary())
	if errors.Is(err, jobs.ErrObjectNotFound) {
		return "", jobs.ErrPrecondition
	}
	if err != nil {
		return "", err
	}
	var o object
	if err := json.Unmarshal(body, &o); err != nil {
		return "", fmt.Errorf("gcs: decoding the uploaded object: %w", err)
	}
	if o.Generation == "" {
		return "", errors.New("gcs: the upload returned no generation")
	}
	return o.Generation, nil
}

// Delete removes the object at key, if its generation is match (any, for
// an empty match).
func (b *Bucket) Delete(ctx context.Context, key, match string) error {
	var q url.Values
	if match != "" {
		// The generation is also checked by hand first, as emulators don't
		// all honor a delete's precondition.
		_, body, err := b.do(ctx, http.MethodGet, b.objectPath(key), url.Values{"fields": {"generation"}}, nil)
		if err != nil {
			return err
		}
		var o object
		if err := json.Unmarshal(body, &o); err != nil {
			return fmt.Errorf("gcs: decoding the object's metadata: %w", err)
		}
		if o.Generation != match {
			return jobs.ErrPrecondition
		}
		q = url.Values{"ifGenerationMatch": {match}}
	}
	_, _, err := b.do(ctx, http.MethodDelete, b.objectPath(key), q, nil)
	return err
}

// List returns the keys under prefix, relative to the bucket's prefix.
func (b *Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"prefix": {b.Prefix + prefix}, "fields": {"items(name),nextPageToken"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		_, body, err := b.do(ctx, http.MethodGet, "/storage/v1/b/"+url.PathEscape(b.Name)+"/o", q, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Items         []object `json:"items"`
			NextPageToken string   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("gcs: decoding the object listing: %w", err)
		}
		for _, o := range page.Items {
			keys = append(keys, strings.TrimPrefix(o.Name, b.Prefix))
		}
		if page.NextPageToken == "" {
			return keys, nil
		}
		token = page.NextPageToken
	}
}

func (b *Bucket) objectPath(key string) string {
	return "/storage/v1/b/" + url.PathEscape(b.Name) + "/o/" + url.PathEscape(b.Prefix+key)
}

// Error is a Cloud Storage error response.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("gcs: request failed with status %d: %s", e.StatusCode, e.Message)
}

func (b *Bucket) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: httpx.NewTransport(nil, nil)}
}

// do sends a request and returns the response with its body read. A 404 is
// jobs.ErrObjectNotFound and a 412 jobs.ErrPrecondition.
func (b *Bucket) do(ctx context.Context, method, path string, q url.Values, body []byte, contentType ...string) (*http.Response, []byte, error) {
	u := b.Endpoint + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, nil, err
	}
	if len(contentType) > 0 {
		req.Header.Set("Content-Type", contentType[0])
	}
	if b.Credentials != nil {
		token, err := b.Credentials.Token(ctx, b.client())
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("gcs: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("gcs: reading the response: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp, nil, jobs.ErrObjectNotFound
	case resp.StatusCode == http.StatusPreconditionFailed:
		return resp, nil, jobs.ErrPrecondition
	case resp.StatusCode >= 300:
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := string(respBody)
		if json.Unmarshal(respBody, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Message
		}
		return resp, nil, &Error{StatusCode: resp.StatusCode, Message: msg}
	}
	return resp, respBody, nil
}
