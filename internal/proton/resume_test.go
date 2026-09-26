package proton

import (
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// Issue #123: session.TryResume defers Zero() on the Secret it passes
// to Resume. The resumed Session must own an independent copy, or the
// live pass becomes 32 zero bytes — non-empty, so it slipped past the
// keystore guard and was persisted on the next token refresh.
func TestNewResumedSession_OwnsSaltedKeyPass(t *testing.T) {
	stored := secret.New([]byte("salted-key-pass-32-bytes-long!!!"))
	sess := newResumedSession(nil, ResumeArgs{UID: "u", RefreshToken: "r", SaltedKeyPass: stored})

	stored.Zero() // what TryResume's deferred Zero does on return

	cp := sess.SaltedKeyPassCopy()
	defer cp.Zero()
	if got := string(cp.Bytes()); got != "salted-key-pass-32-bytes-long!!!" {
		t.Fatalf("session pass after caller Zero() = %q, want the original bytes", got)
	}
}
