package serve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PROTO-152 — the lock-state record is what lets `protonmcp doctor`
// answer "is the daemon locked?" from another process. Before it,
// doctor reported "All good" against a daemon refusing every call.

// withTempHome points LockStatePath at a scratch directory. The
// record lives under $HOME, and os.UserHomeDir reads $HOME on unix.
func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestLockState_RoundTrip(t *testing.T) {
	withTempHome(t)

	want := LockState{
		PID:    4242,
		Locked: true,
		Reason: "screen_locked",
		Since:  time.Now().Truncate(time.Second),
	}
	if err := WriteLockState(want); err != nil {
		t.Fatalf("WriteLockState: %v", err)
	}

	got, err := ReadLockState()
	if err != nil {
		t.Fatalf("ReadLockState: %v", err)
	}
	if got.PID != want.PID || got.Locked != want.Locked || got.Reason != want.Reason {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.Since.Equal(want.Since) {
		t.Errorf("Since: got %v, want %v", got.Since, want.Since)
	}
}

func TestLockState_AbsentIsATypedError(t *testing.T) {
	withTempHome(t)

	// doctor distinguishes "nothing recorded" (stay quiet) from "the
	// record is unreadable" (report it), so the sentinel matters.
	if _, err := ReadLockState(); !errors.Is(err, ErrNoLockState) {
		t.Errorf("got %v, want ErrNoLockState", err)
	}
}

func TestLockState_UnlockOverwritesLocked(t *testing.T) {
	withTempHome(t)

	if err := WriteLockState(LockState{PID: 1, Locked: true, Reason: "sleep"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLockState(LockState{PID: 1, Locked: false}); err != nil {
		t.Fatal(err)
	}

	got, err := ReadLockState()
	if err != nil {
		t.Fatal(err)
	}
	if got.Locked {
		t.Error("unlock did not clear the locked flag")
	}
	if got.Reason != "" {
		t.Errorf("stale reason survived the unlock: %q", got.Reason)
	}
}

func TestLockState_FileIsOwnerOnly(t *testing.T) {
	withTempHome(t)

	if err := WriteLockState(LockState{PID: 1, Locked: true, Reason: "sleep"}); err != nil {
		t.Fatal(err)
	}
	path, err := LockStatePath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %o, want 600 — the record sits beside the session material", perm)
	}
}

func TestLockState_NoTempFilesLeftBehind(t *testing.T) {
	home := withTempHome(t)

	for i := 0; i < 3; i++ {
		if err := WriteLockState(LockState{PID: i, Locked: true, Reason: "idle"}); err != nil {
			t.Fatal(err)
		}
	}

	dir := filepath.Join(home, "Library", "Application Support", "protonmcp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("write-and-rename left a temp file behind: %s", e.Name())
		}
	}
}

func TestLockState_RemoveClearsTheRecord(t *testing.T) {
	withTempHome(t)

	if err := WriteLockState(LockState{PID: 1, Locked: true, Reason: "sleep"}); err != nil {
		t.Fatal(err)
	}
	removeLockState()

	// A cleanly stopped daemon must not leave a "locked" claim for
	// the next reader to trip over.
	if _, err := ReadLockState(); !errors.Is(err, ErrNoLockState) {
		t.Errorf("got %v, want ErrNoLockState after removal", err)
	}
}

func TestLockState_MalformedRecordReportsAnError(t *testing.T) {
	home := withTempHome(t)

	dir := filepath.Join(home, "Library", "Application Support", "protonmcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lockstate.json"), []byte("{ truncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Must not read as ErrNoLockState — doctor would stay silent
	// about a record it genuinely couldn't parse.
	_, err := ReadLockState()
	if err == nil {
		t.Fatal("malformed record parsed without error")
	}
	if errors.Is(err, ErrNoLockState) {
		t.Error("malformed record reported as absent")
	}
}
