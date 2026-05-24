package serve

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// idleTracker holds the most-recent tool-call timestamp (as Unix
// nanoseconds in an atomic int64) and runs a periodic check that
// locks the runtime if the configured idle threshold is exceeded.
//
// Phase 7/A — policy field idle_lock_minutes (default 0 = disabled,
// max 1440 = 24h). The runtime spawns one of these in Setup if the
// engine reports a non-zero idle threshold; on policy reload the
// threshold is re-read from the engine on every tick so a user can
// change the value without restarting the daemon.
//
// Concurrency: the timestamp is a single atomic.Int64; bumpActivity
// is called from the middleware hot path (must be lock-free). The
// poll goroutine reads atomically and may call Runtime.Lock — Lock
// has its own mutex, so the chain is safe.
type idleTracker struct {
	lastActivity atomic.Int64 // unix nanos
	stop         chan struct{}
}

func newIdleTracker() *idleTracker {
	t := &idleTracker{stop: make(chan struct{})}
	t.lastActivity.Store(time.Now().UnixNano())
	return t
}

// bumpActivity records "tool call happened just now." Lock-free.
// Wired into the mcp.Middleware via mcp.WithToolCallObserver.
func (t *idleTracker) bumpActivity() {
	t.lastActivity.Store(time.Now().UnixNano())
}

// run polls every 30 seconds. minutesFn is called on each tick so
// policy reloads pick up new thresholds without restart. lockFn is
// the runtime's Lock method.
//
// 30s tick is the granularity / responsiveness trade-off: a user
// setting idle_lock_minutes=1 sees the lock fire 0–30s after the
// last activity, which is acceptable. A finer tick would burn CPU
// for no real gain.
func (t *idleTracker) run(ctx context.Context, minutesFn func() int, lockFn func(reason string), logger *slog.Logger) {
	const tickInterval = 30 * time.Second
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			minutes := minutesFn()
			if minutes <= 0 {
				continue
			}
			threshold := time.Duration(minutes) * time.Minute
			since := time.Since(time.Unix(0, t.lastActivity.Load()))
			if since >= threshold {
				logger.Info("idle threshold exceeded; locking daemon",
					"idle_minutes", int(since.Minutes()),
					"threshold_minutes", minutes)
				lockFn("idle_timeout")
				// Don't reset lastActivity here. Unlock re-acquires
				// the session and the next tool call will bump it.
				// Locking from already-locked is a no-op so the
				// next tick won't re-fire.
			}
		}
	}
}

// close stops the poll goroutine. Idempotent.
func (t *idleTracker) close() {
	select {
	case <-t.stop:
		// already closed
	default:
		close(t.stop)
	}
}
