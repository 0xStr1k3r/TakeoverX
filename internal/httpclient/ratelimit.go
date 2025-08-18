package httpclient

import (
	"context"
	"sync"
	"time"
)

// rateLimiter is a token bucket.
//
// The previous implementation seeded a ticker exactly once via sync.Once, so
// a second SetRateLimit call was silently ignored, and it modelled "rps" as a
// ticker period rather than a refill rate. That made low rates (1/s) emit a
// burst of 1000 tokens per refill and made the effective limit wrong for every
// value other than the one configured at startup.
//
// This version refills continuously from elapsed time, so the long-run rate is
// exactly rps regardless of burst behaviour, and the limit is resettable.
type rateLimiter struct {
	mu     sync.Mutex
	rate   int       // requests per second; <= 0 means unlimited
	burst  int       // bucket capacity in tokens
	tokens float64   // tokens currently available
	last   time.Time // when tokens was last refilled
}

func newRateLimiter(rps int) *rateLimiter {
	if rps < 0 {
		rps = 0
	}
	burst := rps
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:   rps,
		burst:  burst,
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// SetRate changes the limit at runtime. A non-positive rate disables limiting.
func (l *rateLimiter) SetRate(rps int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rps < 0 {
		rps = 0
	}
	l.rate = rps
	l.burst = max(rps, 1)
	l.tokens = float64(l.burst)
	l.last = time.Now()
}

// Rate reports the configured requests-per-second limit.
func (l *rateLimiter) Rate() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Wait blocks until a token is available. It returns immediately when limiting
// is disabled, and reports ctx.Err() if the context is cancelled first.
func (l *rateLimiter) Wait(ctx context.Context) error {
	if l.Rate() <= 0 {
		return ctx.Err()
	}
	for {
		l.mu.Lock()
		if l.rate <= 0 {
			l.mu.Unlock()
			return ctx.Err()
		}

		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * float64(l.rate)
		l.last = now
		if l.tokens > float64(l.burst) {
			l.tokens = float64(l.burst)
		}

		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / float64(l.rate) * float64(time.Second))
		l.mu.Unlock()

		wait = min(max(wait, time.Millisecond), time.Second)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
