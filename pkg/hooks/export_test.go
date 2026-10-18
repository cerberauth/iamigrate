package hooks

import "time"

// SetRetryBackoffForTest shrinks the webhook retry backoff for the
// duration of a test.
func SetRetryBackoffForTest(d time.Duration) func() {
	orig := retryBackoff
	retryBackoff.initial, retryBackoff.max = d, d
	return func() { retryBackoff = orig }
}
