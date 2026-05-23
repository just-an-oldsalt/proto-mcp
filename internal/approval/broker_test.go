package approval

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// fixtureHelper writes a tiny bash script that exits with whatever
// code the test wants. Lets us exercise the broker's exit-code
// classification without needing a real Touch ID prompt.
func fixtureHelper(t *testing.T, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("posix helper fixture; broker is macOS-only anyway")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "fake-touchid")
	script := "#!/bin/sh\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// itoa avoids importing strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestBrokerExitCodeMapping(t *testing.T) {
	cases := []struct {
		exit int
		want error
	}{
		{0, nil},
		{1, mcperrors.ErrUserCanceled},
		{2, mcperrors.ErrAuthFailed},
		{7, mcperrors.ErrAuthFailed}, // unexpected codes treated as auth fail
	}
	for _, tc := range cases {
		t.Run("exit="+itoa(tc.exit), func(t *testing.T) {
			helper := fixtureHelper(t, tc.exit)
			b, err := New(helper, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = b.Request(context.Background(), Request{
				Tool:   "test_tool",
				Caller: caller.Caller{PID: 1},
				Args:   json.RawMessage(`{}`),
				Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt},
				Title:  "t",
				Body:   "b",
			})
			if tc.want == nil && err != nil {
				t.Errorf("exit 0: got err %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("exit %d: got %v, want errors.Is(%v)", tc.exit, err, tc.want)
			}
		})
	}
}

func TestBrokerCacheHonorsTTL(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mock clock — controls expiry without time.Sleep.
	now := time.Unix(1_000_000, 0)
	b.cache.now = func() time.Time { return now }

	r := Request{
		Tool:   "test_tool",
		Caller: caller.Caller{PID: 1},
		Args:   json.RawMessage(`{"to":"alice@example.com"}`),
		Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt, TTL: "5m"},
		Title:  "t",
		Body:   "b",
	}

	// First call runs the helper.
	src, err := b.Request(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceTouchID {
		t.Errorf("first call: source = %s, want touchid", src)
	}

	// Second call within TTL hits cache.
	src, err = b.Request(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceCached {
		t.Errorf("second call: source = %s, want cached", src)
	}

	// Advance past TTL.
	now = now.Add(6 * time.Minute)
	src, err = b.Request(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceTouchID {
		t.Errorf("after TTL: source = %s, want touchid (cache expired)", src)
	}
}

func TestBrokerCacheKeyChangesWithArgs(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}

	base := Request{
		Tool:   "test_tool",
		Caller: caller.Caller{PID: 1},
		Args:   json.RawMessage(`{"to":"alice@example.com"}`),
		Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt, TTL: "5m"},
	}
	if _, err := b.Request(context.Background(), base); err != nil {
		t.Fatal(err)
	}

	// Change the args: different recipient. Cache key should miss.
	modified := base
	modified.Args = json.RawMessage(`{"to":"mallory@example.com"}`)
	src, err := b.Request(context.Background(), modified)
	if err != nil {
		t.Fatal(err)
	}
	if src == SourceCached {
		t.Error("changing args reused cached approval — security bug")
	}
}

func TestBrokerTTLZeroBypassesCache(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Request{
		Tool:   "test_tool",
		Caller: caller.Caller{PID: 1},
		Args:   json.RawMessage(`{}`),
		Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt, TTL: "0"},
	}
	for i := 0; i < 3; i++ {
		src, err := b.Request(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if src == SourceCached {
			t.Errorf("ttl:0 should always reprompt; got cached on call %d", i+1)
		}
	}
}

func TestResolveHelperPathHonorsEnv(t *testing.T) {
	helper := fixtureHelper(t, 0)
	t.Setenv("PROTONMCP_TOUCHID", helper)
	got, err := ResolveHelperPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != helper {
		t.Errorf("got %q, want %q", got, helper)
	}
}

func TestResolveHelperPathReturnsErrorWhenMissing(t *testing.T) {
	t.Setenv("PROTONMCP_TOUCHID", "")
	_, err := ResolveHelperPath("/nonexistent/bin/protonmcp")
	if err == nil {
		t.Error("expected error when no helper exists")
	}
}

// SECURITY D14 — broker.Invalidate drops every cached approval so
// a policy reload that tightens rules (newly confirm:true, newly
// restricted allowed_recipients) takes effect immediately, instead
// of being shadowed by stale cache entries from the prior policy.
func TestBrokerInvalidateDropsCache(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Request{
		Tool:   "test_tool",
		Caller: caller.Caller{PID: 1},
		Args:   json.RawMessage(`{"to":"alice@example.com"}`),
		Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt, TTL: "5m"},
	}

	// First call runs the helper, populates cache.
	src, err := b.Request(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceTouchID {
		t.Fatalf("first call source = %s, want touchid", src)
	}

	// Second call is a cache hit.
	src, _ = b.Request(context.Background(), r)
	if src != SourceCached {
		t.Fatalf("second call source = %s, want cached", src)
	}

	// Simulate policy reload.
	n := b.Invalidate()
	if n != 1 {
		t.Errorf("Invalidate dropped %d entries, want 1", n)
	}

	// Third call (post-reload) must NOT hit the cache.
	src, err = b.Request(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if src == SourceCached {
		t.Error("post-invalidate request hit the cache — D14 fix not working")
	}
}

func TestBrokerInvalidateNilSafe(t *testing.T) {
	var b *Broker
	if got := b.Invalidate(); got != 0 {
		t.Errorf("nil broker Invalidate = %d, want 0", got)
	}
}
