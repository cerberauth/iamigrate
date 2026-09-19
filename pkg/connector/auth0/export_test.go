package auth0

import "time"

// SetPollIntervalsForTest overrides pollInterval/pollMaxInterval for the
// duration of a test, returning a restore function.
func SetPollIntervalsForTest(interval, maxInterval time.Duration) func() {
	origInterval, origMax := pollInterval, pollMaxInterval
	pollInterval, pollMaxInterval = interval, maxInterval
	return func() {
		pollInterval, pollMaxInterval = origInterval, origMax
	}
}
