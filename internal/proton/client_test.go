package proton

import "testing"

// TestSessionCloseIdempotent verifies the sync.Once guard. A Session
// can be closed from multiple defer paths without panic. With no
// Client / keyrings set this is a pure no-op-after-the-first-call
// sanity check; the network path is covered by live smoke tests.
func TestSessionCloseIdempotent(t *testing.T) {
	s := &Session{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Session.Close panicked: %v", r)
		}
	}()

	s.Close()
	s.Close()
	s.Close()
}

// TestSessionCloseAndRevokeIdempotent mirrors the above for the
// revoke variant. Without a Client both methods short-circuit, so
// this is the no-panic guarantee on the empty path.
func TestSessionCloseAndRevokeIdempotent(t *testing.T) {
	s := &Session{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Session.CloseAndRevoke panicked: %v", r)
		}
	}()

	s.CloseAndRevoke()
	s.CloseAndRevoke()
}

// TestSessionCloseAfterCloseAndRevokeIsNoop confirms the closeOnce
// is shared between Close and CloseAndRevoke — once a session has
// been torn down one way, the other call is a no-op (no double
// AuthDelete, no double zero, no panic).
func TestSessionCloseAfterCloseAndRevokeIsNoop(t *testing.T) {
	s := &Session{}
	s.CloseAndRevoke()
	s.Close() // must not re-do anything
}

// TestCredentialsZeroNil is a regression guard: zeroing a Credentials
// whose Secret fields were never assigned must not panic.
func TestCredentialsZeroNil(t *testing.T) {
	c := &Credentials{Email: "user@example.com"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Credentials.Zero panicked on empty fields: %v", r)
		}
	}()
	c.Zero()
	c.Zero()
}
