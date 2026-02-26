package resilience

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// RetryConfig controls retry behavior for provider calls.
type RetryConfig struct {
	MaxRetries  int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	IsRetryable func(error) bool
}

// RetryWithBackoff retries fn with exponential backoff and jitter.
// It returns the first nil error from fn, or the last error after exhausting retries.
func RetryWithBackoff(ctx context.Context, cfg RetryConfig, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			d := backoffWithJitter(cfg.BaseDelay, attempt-1, cfg.MaxDelay)
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if cfg.IsRetryable != nil && !cfg.IsRetryable(err) {
			return err
		}
	}
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// backoffWithJitter computes exponential backoff with +/-20% jitter, capped at maxDelay.
func backoffWithJitter(base time.Duration, attempt int, maxDelay time.Duration) time.Duration {
	d := base
	for i := 0; i < attempt; i++ {
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}
	// Apply +/-20% jitter
	jitter := float64(d) * 0.2 * (2*rand.Float64() - 1) // range [-20%, +20%]
	d = time.Duration(float64(d) + jitter)
	if d < 0 {
		d = base
	}
	return d
}
