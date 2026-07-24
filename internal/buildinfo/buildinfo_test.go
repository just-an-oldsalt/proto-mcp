package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

// TestStringIncludesVersionAndPlatform pins the shape of the banner
// that `protonmcp version` prints and that bug reports get pasted
// into: the version first, then the toolchain and platform.
func TestStringIncludesVersionAndPlatform(t *testing.T) {
	got := String()

	if !strings.HasPrefix(got, Version()) {
		t.Errorf("String() = %q, want it to start with Version() = %q", got, Version())
	}
	for _, want := range []string{runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
}

// TestVersionNeverEmpty guards the fallback chain. An unstamped `go
// test` build has no -ldflags and (usually) no module version, so this
// exercises the devVersion tail of resolved().
func TestVersionNeverEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() is empty; the devVersion fallback did not fire")
	}
}

// TestStringDoesNotDoubleDirty is a regression guard. `git describe
// --dirty` appends "-dirty" to the stamped version AND the toolchain
// sets vcs.modified=true for the same working tree, so a naive
// concatenation renders "1.0.2-dirty-dirty".
func TestStringDoesNotDoubleDirty(t *testing.T) {
	if n := strings.Count(String(), dirtySuffix); n > 1 {
		t.Errorf("String() = %q contains %d %q suffixes, want at most 1",
			String(), n, dirtySuffix)
	}
}

// TestShortCommitTruncatesFullSHA covers both inputs the resolver sees:
// the toolchain's full 40-char vcs.revision, and the Makefile's
// already-short `git rev-parse --short HEAD`.
func TestShortCommitTruncatesFullSHA(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"full 40-char sha", "272b96e1234567890abcdef1234567890abcdef1", "272b96e"},
		{"already short", "272b96e", "272b96e"},
		{"shorter than 7", "272b", "272b"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shortCommit(tt.in); got != tt.want {
				t.Errorf("shortCommit(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
