package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// SECURITY D33 — pgrep matches the Claude.app disclaimer wrapper
// (whose argv contains "protonmcp serve-stdio") and would previously
// have received a spurious SIGHUP. hasExecutableNamed filters by the
// process's actual binary so wrappers / editor processes with this
// filename open get dropped.
//
// PROTO-152 — the filter used to compare the candidate against the
// *calling* binary via os.SameFile, which excluded protonmcpd by
// construction (the CLI that signals is a different file from the
// daemon it signals). It now compares against the set of binaries we
// ship, so the two-binary layout works.

func TestHasExecutableNamed_MatchesOwnBasename(t *testing.T) {
	// Best test available without mocking proc_pidpath: our own PID
	// against our own executable's basename must match.
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable failed: %v", err)
	}
	self := os.Getpid()
	if procExeFor(self) == "" {
		t.Skip("proc_pidpath unavailable on this platform")
	}
	base := filepath.Base(exe)

	if !hasExecutableNamed(self, base) {
		t.Errorf("self PID (%d) didn't match own basename %q", self, base)
	}
}

func TestHasExecutableNamed_RejectsUnlistedBinary(t *testing.T) {
	self := os.Getpid()
	if procExeFor(self) == "" {
		t.Skip("proc_pidpath unavailable on this platform")
	}
	// The test binary is never named protonmcpd, so the daemon rule
	// must not match it. This is the check that keeps `unlock` from
	// SIGUSR2-ing (i.e. killing) an unrelated process.
	if hasExecutableNamed(self, DaemonBinary) {
		t.Errorf("test binary matched %q — filtering is too loose", DaemonBinary)
	}
}

func TestHasExecutableNamed_AcceptsAnyOfSeveral(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable failed: %v", err)
	}
	self := os.Getpid()
	if procExeFor(self) == "" {
		t.Skip("proc_pidpath unavailable on this platform")
	}
	// The PID-file source passes both binaries, since the file names
	// whichever runtime wrote it last.
	if !hasExecutableNamed(self, DaemonBinary, filepath.Base(exe)) {
		t.Error("multi-name match failed to accept a listed basename")
	}
}

func TestHasExecutableNamed_UnknownPID(t *testing.T) {
	// PID 1 is launchd; procExeFor returns "/sbin/launchd" on macOS,
	// "" elsewhere. Neither is a binary we ship.
	if hasExecutableNamed(1, DaemonBinary, ServeStdioBinary) {
		t.Error("PID 1 (launchd) matched a product binary — filtering broken")
	}
}

func TestHasExecutableNamed_NoNamesNeverMatches(t *testing.T) {
	// Defensive: an empty allowlist must deny rather than wave
	// everything through. The old code's equivalent edge case
	// ("can't determine our own path") returned true, which was the
	// wrong default for a signal that kills on delivery.
	if hasExecutableNamed(os.Getpid()) {
		t.Error("empty allowlist matched — should never signal on no criteria")
	}
}

func TestReadPIDFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		if got := readPIDFile(filepath.Join(dir, "absent.pid")); got != 0 {
			t.Errorf("absent file: got %d, want 0", got)
		}
	})

	t.Run("valid with trailing newline", func(t *testing.T) {
		// WritePIDFile writes "%d\n" — the trailing newline must not
		// defeat the parse.
		p := filepath.Join(dir, "valid.pid")
		if err := os.WriteFile(p, []byte("4242\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readPIDFile(p); got != 4242 {
			t.Errorf("got %d, want 4242", got)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		p := filepath.Join(dir, "junk.pid")
		if err := os.WriteFile(p, []byte("not-a-pid"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readPIDFile(p); got != 0 {
			t.Errorf("malformed file: got %d, want 0", got)
		}
	})
}

func TestWritePIDFileRoundTrips(t *testing.T) {
	// The PID file is a discovery source now, not just debugging
	// aid — so what WritePIDFile emits must be what readPIDFile
	// accepts.
	path := filepath.Join(t.TempDir(), "nested", "serve-stdio.pid")
	cleanup, err := WritePIDFile(path)
	if err != nil {
		t.Fatalf("WritePIDFile: %v", err)
	}
	defer cleanup()

	if got := readPIDFile(path); got != os.Getpid() {
		t.Errorf("round trip: got %d, want %d", got, os.Getpid())
	}
}

func TestFindRunningPIDs_ExcludesSelf(t *testing.T) {
	// Whatever discovery turns up, it must never include the calling
	// process — `policy reload` from inside a tool handler would
	// otherwise race its own SIGHUP handler.
	pids, err := FindRunningPIDs()
	if err != nil {
		return // ErrNotRunning is a fine outcome in a test environment
	}
	for _, pid := range pids {
		if pid == os.Getpid() {
			t.Errorf("FindRunningPIDs included the calling process (%d)", pid)
		}
	}
}

func TestFindRunningPIDs_NoDuplicates(t *testing.T) {
	// The daemon can legitimately be reported by both the pgrep -x
	// source and the PID-file source; it must be signalled once.
	pids, err := FindRunningPIDs()
	if err != nil {
		return
	}
	seen := map[int]bool{}
	for _, pid := range pids {
		if seen[pid] {
			t.Errorf("PID %d appears more than once", pid)
		}
		seen[pid] = true
	}
}
