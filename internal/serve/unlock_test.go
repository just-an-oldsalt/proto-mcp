package serve

import (
	"context"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

type fakeBundle struct{ sess *protonclient.Session }

func (b fakeBundle) Close()                            {}
func (b fakeBundle) GetSession() *protonclient.Session { return b.sess }

// PROTO-141 — the Touch-ID-gated acquire must NOT run under the runtime
// write lock, or a pending unlock prompt freezes every tool call
// (r.Locked() → RLock) and blocks an emergency Lock for the prompt's
// whole duration.
func TestUnlock_DoesNotFreezeDuringAcquire(t *testing.T) {
	withTempHome(t) // Lock/Unlock publish the lock-state record under $HOME
	acquireStarted := make(chan struct{})
	releaseAcquire := make(chan struct{})

	rt := &Runtime{locked: true}
	rt.acquireSession = func(ctx context.Context) (SessionBundle, error) {
		close(acquireStarted)
		<-releaseAcquire // simulate a human staring at the Touch ID prompt
		return fakeBundle{sess: &protonclient.Session{}}, nil
	}

	unlockDone := make(chan struct{})
	go func() { _ = rt.Unlock(context.Background()); close(unlockDone) }()
	<-acquireStarted // acquire is now in-flight (prompt "showing")

	// While the prompt is pending, lock-state reads and an emergency
	// Lock must complete promptly — they must not be blocked on r.mu.
	done := make(chan struct{})
	go func() {
		rt.Locked()
		rt.Lock("emergency")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Locked()/Lock() blocked while an unlock prompt was pending (PROTO-141)")
	}

	close(releaseAcquire)
	// Don't let Unlock publish after the test restores $HOME.
	<-unlockDone
}

// PROTO-132 — after a lock/unlock cycle the runtime adopts the freshly
// acquired session AND re-registers the session-backed tools so handlers
// don't keep dereferencing the closed pre-lock session.
func TestUnlock_RebindsSessionAndTools(t *testing.T) {
	withTempHome(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sessA := &protonclient.Session{Email: "a@example.com"}
	sessB := &protonclient.Session{Email: "b@example.com"}

	srv := mcp.New(nil)
	deps := mcptools.Deps{Session: sessA, Store: st}
	tools := mcptools.All(deps)
	for _, tl := range tools {
		srv.Register(tl)
	}

	rt := &Runtime{
		Store:     st,
		Session:   sessA,
		MCPServer: srv,
		locked:    true,
	}
	rt.acquireSession = func(ctx context.Context) (SessionBundle, error) {
		return fakeBundle{sess: sessB}, nil
	}

	if err := rt.Unlock(context.Background()); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if rt.Session != sessB {
		t.Errorf("rt.Session not swapped to the re-acquired session")
	}
	if locked, _ := rt.Locked(); locked {
		t.Errorf("runtime still reports locked after Unlock")
	}
	// Tools were re-registered (full set still present after the swap).
	if got, want := len(srv.Tools()), len(tools); got != want {
		t.Errorf("tool count after unlock = %d, want %d", got, want)
	}
}

// #129 — `protonmcp unlock` must reset the idle clock. Otherwise the
// clock still holds the pre-lock timestamp, and the next idle tick
// relocks the daemon (idle_timeout) seconds after Touch ID approved.
//
// Session acquisition is stubbed: Unlock only ever calls
// rt.acquireSession (nil → error), so this can't reach the Keychain.
func TestUnlock_ResetsIdleClock(t *testing.T) {
	withTempHome(t)

	rt := &Runtime{locked: true, lockReason: "idle_timeout"}
	rt.idleTracker = newIdleTracker()
	rt.idleTracker.lastActivity.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	acquired := false
	rt.acquireSession = func(ctx context.Context) (SessionBundle, error) {
		acquired = true
		return fakeBundle{sess: &protonclient.Session{}}, nil
	}

	if err := rt.Unlock(context.Background()); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !acquired {
		t.Fatal("stub acquireSession was not used")
	}
	if since := time.Since(time.Unix(0, rt.idleTracker.lastActivity.Load())); since > time.Minute {
		t.Errorf("idle clock not reset by Unlock: last activity %v ago; the next idle tick would relock", since)
	}
}
