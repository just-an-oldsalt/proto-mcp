package mcp

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a token-bucket store keyed by (tool, pid).
//
// Phase 5/D shipped the in-memory version (one bucket per key, lost
// on restart). Phase 6/E adds persistence via a pluggable
// rateLimitPersister so daemon restarts don't grant fresh budgets
// — closes the "restart to bypass mail_send 20/hour" hole.
//
// Limits are parsed lazily from policy's "20/hour" string the first
// time a tool with a non-empty rate_limit is invoked. The parser
// recognises N/{second,minute,hour,day}.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	now       func() time.Time // injectable for tests
	persister RateLimitPersister
}

type bucket struct {
	capacity   int
	refillRate float64 // tokens per second
	tokens     float64
	lastRefill time.Time
	limitSpec  string // raw policy string, persisted alongside the bucket
}

// RateLimitPersister is the seam between the in-memory limiter and
// the SQLite store. internal/serve implements this against
// store.Store. Tests use a no-op or a fake.
//
// The interface and PersistedBucket are exported so external
// implementations (the serve package adapter, tests) can satisfy
// them; the rateLimiter field on Middleware stays unexported.
type RateLimitPersister interface {
	LoadAll(ctx context.Context) (map[string]PersistedBucket, error)
	Save(ctx context.Context, key string, b PersistedBucket) error
}

// PersistedBucket is the wire shape between rateLimiter and the
// persister. Mirrors store.RateLimitState; lives here so internal/
// mcp's interface stays free of store imports.
type PersistedBucket struct {
	LimitSpec  string
	Tokens     float64
	LastRefill time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// setPersister wires the in-memory limiter to a SQLite-backed
// store. Optional — nil persister means in-memory-only (used by
// tests + the no-options Phase-3 mcp.New() path).
//
// On first call, eagerly loads every persisted bucket so the
// in-memory map matches the on-disk state. A subsequent Allow()
// for one of the persisted keys finds the bucket already populated.
func (r *rateLimiter) setPersister(p RateLimitPersister) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.persister = p
	if p == nil {
		return nil
	}
	persisted, err := p.LoadAll(context.Background())
	if err != nil {
		return err
	}
	for key, pb := range persisted {
		capacity, perSec, ok := parseLimitSpec(pb.LimitSpec)
		if !ok {
			continue
		}
		r.buckets[key] = &bucket{
			capacity:   capacity,
			refillRate: perSec,
			tokens:     pb.Tokens,
			lastRefill: pb.LastRefill,
			limitSpec:  pb.LimitSpec,
		}
	}
	return nil
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
			limitSpec:  limitSpec,
		}
		r.buckets[key] = b
	} else if b.limitSpec != limitSpec {
		// Policy reload changed the rate. Reset capacity + refill
		// rate; do NOT reset tokens (would be a free budget on
		// every reload). The next Allow refills against the new
		// rate and the cap clamps if appropriate.
		b.capacity = capacity
		b.refillRate = perSec
		b.limitSpec = limitSpec
		if b.tokens > float64(capacity) {
			b.tokens = float64(capacity)
		}
	}
	// Refill.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.lastRefill = now

	denied := b.tokens < 1.0
	if !denied {
		b.tokens -= 1.0
	}

	// Persist the post-update state. Best-effort: a transient
	// SQLite error doesn't fail the rate-limit decision — the
	// in-memory bucket is the source of truth for the current
	// process, persistence is just so the NEXT daemon-startup
	// inherits the state.
	if r.persister != nil {
		_ = r.persister.Save(context.Background(), key, PersistedBucket{
			LimitSpec:  limitSpec,
			Tokens:     b.tokens,
			LastRefill: b.lastRefill,
		})
	}

	if denied {
		return false, "rate limit " + limitSpec + " exceeded"
	}
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
