package serve

import (
	"os"
	"path/filepath"
	"testing"
)

// mkHelper creates an executable stub at path, making parent dirs.
func mkHelper(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestResolveLockwatchPathSourceBuildLayout is the regression guard for
// the source-build miss: `make all` puts the daemon in <repo>/bin/ but
// leaves the Swift helper in <repo>/helpers/lockwatch/, one level ABOVE
// binDir. The resolver previously only looked at <binDir>/helpers/... and
// <binDir>/, so every source build silently came up empty and
// lock-on-screen-lock never armed.
func TestResolveLockwatchPathSourceBuildLayout(t *testing.T) {
	t.Setenv("PROTONMCP_LOCKWATCH", "")

	repo := t.TempDir()
	daemon := filepath.Join(repo, "bin", "protonmcpd")
	mkHelper(t, daemon)

	want := filepath.Join(repo, "helpers", "lockwatch", "protonmcp-lockwatch")
	mkHelper(t, want)

	got, ok := ResolveLockwatchPathFrom(daemon)
	if !ok {
		t.Fatal("no lockwatch helper found for the source-build layout")
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveLockwatchPathFlatLayout covers the Homebrew cask layout,
// where every binary is dropped side by side into the prefix's bin/.
func TestResolveLockwatchPathFlatLayout(t *testing.T) {
	t.Setenv("PROTONMCP_LOCKWATCH", "")

	prefix := t.TempDir()
	daemon := filepath.Join(prefix, "protonmcpd")
	mkHelper(t, daemon)

	want := filepath.Join(prefix, "protonmcp-lockwatch")
	mkHelper(t, want)

	got, ok := ResolveLockwatchPathFrom(daemon)
	if !ok {
		t.Fatal("no lockwatch helper found for the flat cask layout")
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveLockwatchPathPrefersSiblingHelpersDir pins precedence: when
// both the sibling helpers/ dir and the two-up one exist, the sibling
// wins. Keeps the two-up candidate from shadowing a packaged layout.
func TestResolveLockwatchPathPrefersSiblingHelpersDir(t *testing.T) {
	t.Setenv("PROTONMCP_LOCKWATCH", "")

	repo := t.TempDir()
	daemon := filepath.Join(repo, "bin", "protonmcpd")
	mkHelper(t, daemon)

	sibling := filepath.Join(repo, "bin", "helpers", "lockwatch", "protonmcp-lockwatch")
	mkHelper(t, sibling)
	mkHelper(t, filepath.Join(repo, "helpers", "lockwatch", "protonmcp-lockwatch"))

	got, ok := ResolveLockwatchPathFrom(daemon)
	if !ok {
		t.Fatal("no lockwatch helper found")
	}
	if got != sibling {
		t.Errorf("got %q, want the sibling helpers/ dir %q", got, sibling)
	}
}

// TestResolveLockwatchPathMissing confirms a clean "not found" rather
// than a stray match when no helper is installed anywhere reachable.
func TestResolveLockwatchPathMissing(t *testing.T) {
	t.Setenv("PROTONMCP_LOCKWATCH", "")

	repo := t.TempDir()
	daemon := filepath.Join(repo, "bin", "protonmcpd")
	mkHelper(t, daemon)

	// The absolute fallbacks (/opt/homebrew/bin, /usr/local/bin,
	// /Applications) may legitimately hold a helper on a dev machine
	// that also has proto-mcp installed — only assert when they don't.
	for _, p := range []string{
		"/opt/homebrew/bin/protonmcp-lockwatch",
		"/usr/local/bin/protonmcp-lockwatch",
		"/Applications/protonmcp.app/Contents/MacOS/protonmcp-lockwatch",
	} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("system-wide helper present at %s; layout-miss case not observable here", p)
		}
	}

	if got, ok := ResolveLockwatchPathFrom(daemon); ok {
		t.Errorf("expected no helper, got %q", got)
	}
}
