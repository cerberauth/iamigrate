package auth0

import (
	"context"
	"sync"
	"time"

	"github.com/cerberauth/iamigrate/pkg/progress"
)

// defaultConcurrency bounds how many organization/role/membership calls
// run at once during the O(users x memberships) second phase (see
// DESIGN.md, "Organizations, roles, and memberships").
const defaultConcurrency = 8

// rateLimiter is shared across every worker in a pool so a 429 or a
// near-zero X-RateLimit-Remaining response from any one call backs off
// the whole pool, not just the worker that hit it.
type rateLimiter struct {
	mu         sync.Mutex
	pauseUntil time.Time
}

func (rl *rateLimiter) observe(r RateLimit) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if (r.Limited || r.Remaining == 0) && r.ResetAt.After(time.Now()) {
		if r.ResetAt.After(rl.pauseUntil) {
			rl.pauseUntil = r.ResetAt
		}
	}
}

func (rl *rateLimiter) wait(ctx context.Context) error {
	rl.mu.Lock()
	until := rl.pauseUntil
	rl.mu.Unlock()
	if !until.After(time.Now()) {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(until)):
		return nil
	}
}

// poolTask is one unit of work in the org/role/membership phase. It
// returns the rate-limit headers observed (if any) so the pool can back
// off, alongside its error.
type poolTask func(ctx context.Context) (RateLimit, error)

// runPool runs tasks with up to concurrency workers, backing off as a
// group whenever Auth0's rate-limit headers say to. It returns the first
// error from any task that isn't a context cancellation, but still lets
// already-started tasks finish before returning.
func runPool(ctx context.Context, concurrency int, tasks []poolTask) []error {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	rl := &rateLimiter{}
	bar := progress.FromContext(ctx)
	sem := make(chan struct{}, concurrency)
	errs := make([]error, len(tasks))
	var wg sync.WaitGroup

	for i, task := range tasks {
		i, task := i, task
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer bar.Add(1)

			if err := rl.wait(ctx); err != nil {
				errs[i] = err
				return
			}
			r, err := task(ctx)
			rl.observe(r)
			errs[i] = err
		}()
	}
	wg.Wait()
	return errs
}
