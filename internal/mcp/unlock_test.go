package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PROTO-152 — a locked daemon may raise a Touch ID prompt on a tool
// call's behalf and proceed on approval, instead of returning an
// instruction only a human at a terminal can follow.

// lockedRuntime is a test double for the runtime's lock state and
// unlock callback.
type lockedRuntime struct {
	mu       sync.Mutex
	locked   bool
	reason   string
	prompts  atomic.Int32
	approve  bool
	failWith error
	// duringUnlock runs inside the unlock callback before the state
	// flips (e.g. to hold the prompt open); afterUnlock runs once it
	// has flipped, which is where a re-lock race lands.
	duringUnlock func()
	afterUnlock  func()
}

func (l *lockedRuntime) state() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locked, l.reason
}

func (l *lockedRuntime) unlock(context.Context) error {
	l.prompts.Add(1)
	if l.duringUnlock != nil {
		l.duringUnlock()
	}
	if l.failWith != nil {
		return l.failWith
	}
	if !l.approve {
		return errors.New("user canceled")
	}
	l.mu.Lock()
	l.locked = false
	l.reason = ""
	l.mu.Unlock()

	if l.afterUnlock != nil {
		l.afterUnlock()
	}
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func okTool(name string, calls *atomic.Int32) Tool {
	return Tool{
		Name: name,
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			calls.Add(1)
			return &ToolResult{Content: []Content{{Type: "text", Text: "ran"}}}, nil
		},
	}
}

func TestLockedCall_WithoutUnlockCallback_RefusesAsBefore(t *testing.T) {
	// The pre-existing behavior must survive for any caller that
	// doesn't opt in.
	rt := &lockedRuntime{locked: true, reason: "screen_locked"}
	var calls atomic.Int32
	m := &Middleware{lockState: rt.state}

	res, jrErr := m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	if jrErr != nil {
		t.Fatalf("unexpected protocol error: %v", jrErr)
	}
	if !res.IsError {
		t.Fatal("locked call should return an error result")
	}
	if got := res.Content[0].Text; !strings.Contains(got, "protonmcp unlock") {
		t.Errorf("refusal should name the CLI fallback, got %q", got)
	}
	if calls.Load() != 0 {
		t.Error("handler ran despite the lock")
	}
	if rt.prompts.Load() != 0 {
		t.Error("prompted without an unlock callback configured")
	}
}

func TestLockedCall_ApprovedUnlockRunsTheTool(t *testing.T) {
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: true}
	var calls atomic.Int32
	m := &Middleware{
		lockState:     rt.state,
		requestUnlock: rt.unlock,
		unlockGate:    newUnlockGate(),
	}

	res, jrErr := m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	if jrErr != nil {
		t.Fatalf("unexpected protocol error: %v", jrErr)
	}
	if res.IsError {
		t.Fatalf("call should have succeeded after unlock, got %q", res.Content[0].Text)
	}
	if calls.Load() != 1 {
		t.Errorf("handler ran %d times, want 1", calls.Load())
	}
	if rt.prompts.Load() != 1 {
		t.Errorf("raised %d prompts, want exactly 1", rt.prompts.Load())
	}
}

func TestLockedCall_DeclinedUnlockRefusesAndSaysSo(t *testing.T) {
	rt := &lockedRuntime{locked: true, reason: "sleep", approve: false}
	var calls atomic.Int32
	m := &Middleware{
		lockState:     rt.state,
		requestUnlock: rt.unlock,
		unlockGate:    newUnlockGate(),
	}

	res, _ := m.runTool(context.Background(), okTool("mail_send", &calls), nil, testLogger())
	if !res.IsError {
		t.Fatal("a declined unlock must not let the call through")
	}
	if calls.Load() != 0 {
		t.Error("handler ran despite the declined unlock")
	}
	if got := res.Content[0].Text; !strings.Contains(got, "not approved") {
		t.Errorf("message should say the prompt was declined, got %q", got)
	}
}

func TestLockedCall_CooldownSuppressesPromptStorm(t *testing.T) {
	// The anti-fatigue property: after a decline, a retry loop can't
	// keep re-raising the dialog.
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: false}
	var calls atomic.Int32
	m := &Middleware{
		lockState:     rt.state,
		requestUnlock: rt.unlock,
		unlockGate:    newUnlockGate(),
	}

	for i := 0; i < 25; i++ {
		m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	}
	if got := rt.prompts.Load(); got != 1 {
		t.Errorf("25 locked calls raised %d prompts, want 1", got)
	}

	res, _ := m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	if got := res.Content[0].Text; !strings.Contains(got, "not asking again") {
		t.Errorf("suppressed call should explain the cooldown, got %q", got)
	}
}

func TestLockedCall_CooldownExpiresAndAllowsAnotherPrompt(t *testing.T) {
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: false}
	var calls atomic.Int32
	gate := newUnlockGate()
	clock := time.Now()
	gate.now = func() time.Time { return clock }
	m := &Middleware{lockState: rt.state, requestUnlock: rt.unlock, unlockGate: gate}

	m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	if got := rt.prompts.Load(); got != 1 {
		t.Fatalf("prompts before expiry = %d, want 1", got)
	}

	clock = clock.Add(defaultUnlockCooldown + time.Second)
	rt.approve = true
	res, _ := m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
	if res.IsError {
		t.Fatalf("call after cooldown expiry should succeed, got %q", res.Content[0].Text)
	}
	if got := rt.prompts.Load(); got != 2 {
		t.Errorf("prompts after expiry = %d, want 2", got)
	}
}

func TestUnlockGate_ApprovalClearsTheCooldown(t *testing.T) {
	// A decline arms the cooldown; a later approval must clear it, so
	// one accidental decline doesn't penalize the rest of the session.
	gate := newUnlockGate()
	if ok, _ := gate.begin(); !ok {
		t.Fatal("first begin should succeed")
	}
	gate.end(errors.New("declined"))
	if ok, _ := gate.begin(); ok {
		t.Fatal("cooldown should be in force right after a decline")
	}

	gate.now = func() time.Time { return time.Now().Add(2 * defaultUnlockCooldown) }
	if ok, _ := gate.begin(); !ok {
		t.Fatal("begin should succeed once the cooldown elapsed")
	}
	gate.end(nil)

	gate.now = time.Now
	if ok, _ := gate.begin(); !ok {
		t.Error("a successful unlock should leave no lingering cooldown")
	}
}

func TestUnlockGate_OnePromptInFlight(t *testing.T) {
	gate := newUnlockGate()
	ok, _ := gate.begin()
	if !ok {
		t.Fatal("first begin should succeed")
	}
	ok, why := gate.begin()
	if ok {
		t.Error("second concurrent begin should be refused")
	}
	if !strings.Contains(why, "already waiting") {
		t.Errorf("reason should mention the pending prompt, got %q", why)
	}
	gate.end(nil)
	if ok, _ := gate.begin(); !ok {
		t.Error("begin should succeed once the prior prompt finished")
	}
}

func TestLockedCall_ConcurrentCallsRaiseOnePrompt(t *testing.T) {
	// Several connected clients hitting a locked daemon at once must
	// produce one dialog, not one per client.
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: true}
	rt.duringUnlock = func() { time.Sleep(20 * time.Millisecond) } // hold the prompt open
	var calls atomic.Int32
	m := &Middleware{
		lockState:     rt.state,
		requestUnlock: rt.unlock,
		unlockGate:    newUnlockGate(),
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runTool(context.Background(), okTool("mail_list", &calls), nil, testLogger())
		}()
	}
	wg.Wait()

	if got := rt.prompts.Load(); got != 1 {
		t.Errorf("8 concurrent locked calls raised %d prompts, want 1", got)
	}
}

func TestLockedCall_ReLockDuringPromptDoesNotRunTheTool(t *testing.T) {
	// The screen re-locking while the prompt is open must not let the
	// call slip through on a stale "unlocked" reading.
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: true}
	// The unlock is approved, then the machine sleeps before the call
	// can run.
	rt.afterUnlock = func() {
		rt.mu.Lock()
		rt.locked = true
		rt.reason = "sleep"
		rt.mu.Unlock()
	}
	var calls atomic.Int32
	m := &Middleware{
		lockState:     rt.state,
		requestUnlock: rt.unlock,
		unlockGate:    newUnlockGate(),
	}

	res, _ := m.runTool(context.Background(), okTool("mail_send", &calls), nil, testLogger())
	if !res.IsError {
		t.Fatal("re-locked daemon must not run the tool")
	}
	if calls.Load() != 0 {
		t.Error("handler ran against a re-locked daemon")
	}
	if got := res.Content[0].Text; !strings.Contains(got, "re-locked") {
		t.Errorf("message should explain the re-lock, got %q", got)
	}
}

// PROTO-132 regression, via the new path. Unlock swaps every
// session-backed handler; a call that unlocked mid-flight captured
// its Tool before that swap, so invoking the captured copy would
// dereference the closed pre-lock session.
func TestLockedCall_UsesRebuiltHandlerAfterUnlock(t *testing.T) {
	rt := &lockedRuntime{locked: true, reason: "screen_locked", approve: true}

	var stale, fresh atomic.Int32
	var srv *Server

	srv = New(testLogger(),
		WithLockState(rt.state),
		WithUnlockRequest(func(ctx context.Context) error {
			if err := rt.unlock(ctx); err != nil {
				return err
			}
			// What Runtime.Unlock does on success: rebind every
			// session-backed handler to the newly acquired session.
			srv.ReplaceTools([]Tool{okTool("mail_list", &fresh)})
			return nil
		}),
	)
	// The "pre-lock" handler — the one bound to the session that
	// Lock() closed.
	srv.Register(okTool("mail_list", &stale))

	raw, _ := json.Marshal(CallToolParams{Name: "mail_list"})
	res, jrErr := srv.handleToolsCall(context.Background(), raw)
	if jrErr != nil {
		t.Fatalf("unexpected protocol error: %v", jrErr)
	}
	if res.IsError {
		t.Fatalf("call should have succeeded, got %q", res.Content[0].Text)
	}
	if stale.Load() != 0 {
		t.Error("ran the pre-lock handler — it holds a Closed session (PROTO-132)")
	}
	if fresh.Load() != 1 {
		t.Errorf("post-unlock handler ran %d times, want 1", fresh.Load())
	}
}
