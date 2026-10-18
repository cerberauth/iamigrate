package httpx

import (
	"context"
	"time"
)

// Backoff bounds Retry: the first wait, the cap the doubling waits stop
// at, and how many times fn is retried after its first try.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
	Retries int
}

// RetryAfterer is implemented by an error that knows how long to wait
// before the next try (an HTTP 429 or 503's Retry-After), which Retry
// honors, up to Backoff.Max, over its own doubling delay.
type RetryAfterer interface {
	RetryAfter() time.Duration
}

// Retry runs fn, retrying with exponential backoff while retryable reports
// its error as temporary, so one dropped connection or rate-limited
// response doesn't fail a whole call. It returns fn's last error, or ctx's
// if ctx is done while waiting.
func Retry(ctx context.Context, b Backoff, retryable func(error) bool, fn func() error) error {
	delay := b.Initial
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || attempt >= b.Retries || ctx.Err() != nil || !retryable(err) {
			return err
		}
		wait := delay
		if ra, ok := err.(RetryAfterer); ok && ra.RetryAfter() > 0 {
			wait = min(ra.RetryAfter(), b.Max)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		delay = min(delay*2, b.Max)
	}
}
