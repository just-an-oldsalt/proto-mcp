package serve

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// PROTO-144 — a locked runtime has no session; backgroundSyncOnce must
// skip cleanly rather than dereference a nil/closed session.
func TestBackgroundSyncOnce_SkipsWhenLocked(t *testing.T) {
	rt := &Runtime{locked: true}
	rt.backgroundSyncOnce(context.Background(), discardLogger()) // must not panic
}

// An unlocked runtime with no session yet (e.g. mid-setup) must also be
// a no-op, not a nil dereference.
func TestBackgroundSyncOnce_SkipsWhenNoSession(t *testing.T) {
	rt := &Runtime{}
	rt.backgroundSyncOnce(context.Background(), discardLogger()) // must not panic
}

// The ticker loop must stop promptly when its context is cancelled
// (Close path), so the daemon shuts down cleanly without a leaked
// goroutine.
func TestRunBackgroundSync_StopsOnCtxCancel(t *testing.T) {
	rt := &Runtime{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rt.runBackgroundSync(ctx, discardLogger()); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runBackgroundSync did not return after ctx cancel")
	}
}
