package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// SECURITY D33 — pgrep matches the Claude.app disclaimer wrapper
// (whose argv contains "protonmcp serve-stdio") and would
// previously have received a spurious SIGHUP. matchesExecutable
// now filters by actual binary path so wrappers / editor processes
// with this filename open get dropped.

func TestMatchesExecutable_SelfPath(t *testing.T) {
	// Best test we can do without mocking proc_pidpath: matching
	// our own PID against our own executable should always be true.
	self := os.Getpid()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable failed: %v", err)
	}
	exe, _ = filepath.Abs(exe)

	if !matchesExecutable(self, exe) {
		t.Errorf("self PID (%d) didn't match own executable %s", self, exe)
	}
}

func TestMatchesExecutable_UnknownPID(t *testing.T) {
	// PID 1 is launchd; procExeFor returns "/sbin/launchd" on
	// macOS, "" elsewhere. Either way it shouldn't equal our
	// test binary's path.
	exe, err := os.Executable()
	if err != nil {
		t.Skip("os.Executable failed")
	}
	exe, _ = filepath.Abs(exe)
	if matchesExecutable(1, exe) {
		t.Error("PID 1 (launchd) matched the test binary — filtering broken")
	}
}

func TestMatchesExecutable_EmptySelfExe(t *testing.T) {
	// Defensive: if we can't determine our own path, the filter
	// falls back to "trust pgrep" rather than denying everything.
	// Conservative; the alternative (deny-all) would break reload
	// in edge cases where os.Executable fails.
	if !matchesExecutable(1, "") {
		t.Error("empty selfExe should be treated as trust-pgrep fallback (true)")
	}
}
