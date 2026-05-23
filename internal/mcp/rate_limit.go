package mcp

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a tiny token-bucket store keyed by (tool, pid).
// Per Phase-5 Q3: simple in-memory; loses state on restart, which
// is acceptable for the single-user, single-process serve-stdio
// today. Phase 6's daemon model gives us persistence.
//
// Limits are parsed lazily from policy's "20/hour" string the first
// time a tool with a non-empty rate_limit is invoked. The parser
// recognises N/{second,minute,hour,day}.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time // injectable for tests
}

type bucket struct {
	capacity   int
	refillRate float64 // tokens per second
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow returns (true, "") if the call is within budget, or
// (false, "reason") if it should be denied. limitSpec is the
// policy's rate_limit string ("20/hour"); empty disables the
// check. key uniquely identifies the bucket — middleware passes
// (tool || pid) so concurrent Claude Desktop sessions don't share
// a budget.
//
// Tokens refill linearly between calls. A burst of N consecutive
// calls within milliseconds drains the bucket; the (N+1)th waits
// for the next token to accumulate. We don't sleep on the caller's
// side — exceeded budget is a hard deny so the LLM gets a clear
// "rate limit" signal rather than a quiet pause.
func (r *rateLimiter) Allow(key, limitSpec string) (bool, string) {
	if limitSpec == "" {
		return true, ""
	}
	capacity, perSec, ok := parseLimitSpec(limitSpec)
	if !ok {
		// Malformed spec — fail open (allow) but the policy
		// validator should have caught this at load time. Logging
		// is the caller's job via the middleware logger.
		return true, ""
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	b, exists := r.buckets[key]
	if !exists {
		b = &bucket{
			capacity:   capacity,
			refillRate: perSec,
			tokens:     float64(capacity),
			lastRefill: now,
		}
		r.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.lastRefill = now

	if b.tokens < 1.0 {
		return false, "rate limit " + limitSpec + " exceeded"
	}
	b.tokens -= 1.0
	return true, ""
}

// parseLimitSpec parses "20/hour" → (20, 20.0/3600, true). Returns
// false for malformed inputs.
func parseLimitSpec(s string) (capacity int, perSec float64, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	var unit float64
	switch strings.TrimSpace(strings.ToLower(parts[1])) {
	case "second", "sec", "s":
		unit = 1
	case "minute", "min", "m":
		unit = 60
	case "hour", "hr", "h":
		unit = 3600
	case "day", "d":
		unit = 86400
	default:
		return 0, 0, false
	}
	return n, float64(n) / unit, true
}
