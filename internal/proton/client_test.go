package proton

import (
	"bytes"
	"sync"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

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

// TestSaltedKeyPassCopyIsIndependent is the deterministic half of the
// D16 regression: a copy taken via SaltedKeyPassCopy must survive a
// subsequent Session.Close() (which zeroes the live SaltedKeyPass).
// Before the fix, persist paths serialized the live Secret, whose
// backing array Close zeroed out from under them — corrupting the
// stored blob and failing the next resume with "private key checksum
// failure".
func TestSaltedKeyPassCopyIsIndependent(t *testing.T) {
	want := []byte("salted-mailbox-pass-material-32b")
	s := &Session{SaltedKeyPass: secret.New(want)}

	cp := s.SaltedKeyPassCopy()

	s.Close() // zeroes s.SaltedKeyPass

	if !bytes.Equal(cp.Bytes(), want) {
		t.Fatalf("copy corrupted by Close: got %q, want %q", cp.Bytes(), want)
	}
	if !s.SaltedKeyPass.Empty() {
		t.Error("session SaltedKeyPass should be empty after Close")
	}

	cp.Zero() // zeroing the copy must not touch anything shared
}

// TestSaltedKeyPassCopyRaceFreeWithClose is the concurrent half of the
// D16 regression — run under `go test -race`. Many goroutines clone the
// salted pass while one closes the session; the mutex in
// SaltedKeyPassCopy / releaseLocal must make each clone atomic w.r.t.
// the Zero, so every non-empty copy is the *full* pass, never a
// half-zeroed array. Without the fix, -race flags the read/write on the
// shared backing and the partial-copy assertion below can fire.
func TestSaltedKeyPassCopyRaceFreeWithClose(t *testing.T) {
	want := []byte("salted-mailbox-pass-material-32b")

	for round := 0; round < 200; round++ {
		s := &Session{SaltedKeyPass: secret.New(want)}
		var wg sync.WaitGroup

		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cp := s.SaltedKeyPassCopy()
				defer cp.Zero()
				if b := cp.Bytes(); len(b) != 0 && !bytes.Equal(b, want) {
					t.Errorf("partial/corrupt SaltedKeyPass copy: %q", b)
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Close()
		}()

		wg.Wait()
	}
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
