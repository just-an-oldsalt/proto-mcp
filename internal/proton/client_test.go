package proton

import "testing"

// TestSessionCloseIdempotent verifies the sync.Once guard added in
// security/signal-cleanup. A Session can be closed from multiple
// defer paths (or future signal-listener goroutines) without panic
// or double-revoke. With no Client / keyrings set this is a pure
// no-op-after-the-first-call sanity check; the actual AuthDelete
// path exercises the same Once and is covered by the live whoami /
// backfill smoke tests against a real account.
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
