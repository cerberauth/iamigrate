package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/pkg/httpx"
)

// Headers of every webhook request.
const (
	HeaderHook      = "X-Iamigrate-Hook"
	HeaderEventID   = "X-Iamigrate-Event-Id"
	HeaderTimestamp = "X-Iamigrate-Timestamp"
	HeaderSignature = "X-Iamigrate-Signature"
)

// signaturePrefix versions the signature scheme, so it can change without
// receivers mistaking one scheme's signature for another's.
const signaturePrefix = "v1="

// maxResponseBytes caps what is read of a webhook's answer: a batch of
// replaced users is large, but not unbounded.
const maxResponseBytes = 32 << 20

// retryBackoff spaces a webhook's retries.
var retryBackoff = struct{ initial, max time.Duration }{time.Second, 30 * time.Second}

// Webhook is a Handler that POSTs the Envelope as JSON to a URL and reads
// the answer from the response body.
type Webhook struct {
	URL     string
	Secret  []byte
	Timeout time.Duration
	Retries int
	Client  *http.Client
	// Now is the clock the timestamp header is taken from; time.Now if nil.
	Now func() time.Time
}

// NewWebhook returns the Webhook c describes, its secret read and its
// defaults applied.
func NewWebhook(c WebhookConfig) (*Webhook, error) {
	secret, err := c.secret()
	if err != nil {
		return nil, err
	}
	w := &Webhook{URL: c.URL, Secret: secret, Timeout: c.Timeout, Retries: defaultRetries}
	if w.Timeout == 0 {
		w.Timeout = defaultTimeout
	}
	if c.Retries != nil {
		w.Retries = *c.Retries
	}
	w.Client = &http.Client{
		Transport: httpx.NewTransport(nil, nil),
		// A redirect is answered with an error rather than followed, so the
		// signed body is only ever sent to the URL the operator wrote.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return w, nil
}

// StatusError is a webhook answering with a non-2xx status.
type StatusError struct {
	StatusCode int
	Body       string
	retryAfter time.Duration
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("webhook answered %d", e.StatusCode)
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// RetryAfter is the wait the webhook asked for in a Retry-After header.
func (e *StatusError) RetryAfter() time.Duration { return e.retryAfter }

// Call POSTs env, retrying on a 5xx, a 429 or a network error, each try
// bounded by the timeout.
func (w *Webhook) Call(ctx context.Context, env Envelope) (json.RawMessage, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("webhook: encoding envelope: %w", err)
	}
	var out json.RawMessage
	err = httpx.Retry(ctx, httpx.Backoff{Initial: retryBackoff.initial, Max: retryBackoff.max, Retries: w.Retries}, retryable, func() error {
		out, err = w.post(ctx, env, body)
		return err
	})
	return out, err
}

func (w *Webhook) post(ctx context.Context, env Envelope, body []byte) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderHook, env.Hook)
	req.Header.Set(HeaderEventID, env.EventID)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, Sign(w.Secret, ts, body))

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		se := &StatusError{StatusCode: resp.StatusCode, Body: truncate(strings.TrimSpace(string(b)), 200)}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			se.retryAfter = time.Duration(s) * time.Second
		}
		return nil, se
	}
	if len(b) > maxResponseBytes {
		return nil, fmt.Errorf("webhook: answer is over %d bytes", maxResponseBytes)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	if !json.Valid(b) {
		return nil, errors.New("webhook: answer is not JSON")
	}
	return b, nil
}

// retryable reports whether a webhook call's error is worth another try:
// a 429, a 5xx, or a network failure (a timeout included).
func retryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.StatusCode == http.StatusTooManyRequests || se.StatusCode >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded)
}

// Sign returns the X-Iamigrate-Signature of a request: "v1=" and the hex
// HMAC-SHA256, keyed with the secret, of the timestamp header, a dot, and
// the body. Covering the timestamp lets a receiver reject a replayed
// request by its age.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a request's signature and that its timestamp is within
// tolerance of now, for a receiver written in Go.
func Verify(secret []byte, timestamp string, body []byte, signature string, now time.Time, tolerance time.Duration) error {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("hooks: invalid timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
		return errors.New("hooks: timestamp outside tolerance")
	}
	if !hmac.Equal([]byte(Sign(secret, timestamp, body)), []byte(signature)) {
		return errors.New("hooks: signature mismatch")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
