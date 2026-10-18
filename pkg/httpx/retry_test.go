package httpx_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/pkg/httpx"
	"github.com/stretchr/testify/require"
)

var errTemp = errors.New("temporary")

func always(error) bool { return true }

func TestRetryStopsOnSuccess(t *testing.T) {
	calls := 0
	err := httpx.Retry(context.Background(), httpx.Backoff{Initial: time.Millisecond, Max: time.Millisecond, Retries: 5}, always, func() error {
		calls++
		if calls < 3 {
			return errTemp
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, calls)
}

func TestRetryGivesUpAfterRetries(t *testing.T) {
	calls := 0
	err := httpx.Retry(context.Background(), httpx.Backoff{Initial: time.Millisecond, Max: time.Millisecond, Retries: 2}, always, func() error {
		calls++
		return errTemp
	})
	require.ErrorIs(t, err, errTemp)
	require.Equal(t, 3, calls, "one try and two retries")
}

func TestRetryDoesNotRetryPermanentErrors(t *testing.T) {
	calls := 0
	err := httpx.Retry(context.Background(), httpx.Backoff{Initial: time.Millisecond, Max: time.Millisecond, Retries: 5},
		func(error) bool { return false },
		func() error { calls++; return errTemp })
	require.ErrorIs(t, err, errTemp)
	require.Equal(t, 1, calls)
}

type retryAfterErr struct{ d time.Duration }

func (e retryAfterErr) Error() string             { return "slow down" }
func (e retryAfterErr) RetryAfter() time.Duration { return e.d }

func TestRetryHonorsRetryAfterUpToMax(t *testing.T) {
	calls := 0
	start := time.Now()
	err := httpx.Retry(context.Background(), httpx.Backoff{Initial: time.Millisecond, Max: 50 * time.Millisecond, Retries: 1}, always, func() error {
		calls++
		if calls == 1 {
			return retryAfterErr{time.Hour}
		}
		return nil
	})
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "waits the Retry-After, capped")
	require.Less(t, elapsed, 5*time.Second)
}

func TestRetryStopsWhenContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := httpx.Retry(ctx, httpx.Backoff{Initial: time.Hour, Max: time.Hour, Retries: 5}, always, func() error {
		calls++
		cancel()
		return errTemp
	})
	require.Error(t, err)
	require.Equal(t, 1, calls)
}
