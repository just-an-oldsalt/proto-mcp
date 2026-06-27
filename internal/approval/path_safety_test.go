package approval

import (
	"os"
	"path/filepath"
	"testing"
)

// PROTO-127 — a helper (or its directory) that group/other can write is
// a substitution vector and must be rejected.
func TestOwnerWritableOnly(t *testing.T) {
	dir := t.TempDir() // 0700
	f := filepath.Join(dir, "helper")
	if err := os.WriteFile(f, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !ownerWritableOnly(f) {
		t.Fatal("0755 file in a 0700 dir should be owner-writable-only")
	}

	if err := os.Chmod(f, 0o757); err != nil { // other-write on the file
		t.Fatal(err)
	}
	if ownerWritableOnly(f) {
		t.Error("an other-writable helper file must be rejected")
	}
	if err := os.Chmod(f, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o777); err != nil { // world-writable dir
		t.Fatal(err)
	}
	if ownerWritableOnly(f) {
		t.Error("a helper in a world-writable directory must be rejected")
	}
}

// PROTO-127 — resolveHelperPath must not hand back a helper sitting in a
// world-writable directory, even when it's executable.
func TestResolveHelperPath_RejectsWritableHelper(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "protonmcp-touchid")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The test-only env candidate is tried first, so a safe one resolves.
	t.Setenv("PROTONMCP_TOUCHID", helper)
	if got, err := resolveHelperPath(""); err != nil || got != helper {
		t.Fatalf("safe helper should resolve; got %q err=%v", got, err)
	}

	// Make its directory world-writable — it must no longer be returned
	// (resolveHelperPath either errors or falls through to a safe one;
	// either way it must NOT return the now-unsafe helper).
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if got, _ := resolveHelperPath(""); got == helper {
		t.Errorf("resolveHelperPath returned a helper in a world-writable dir: %q", got)
	}
}

// PROTO-127 / Homebrew cask layout — the daemon is launched through a
// symlink in a group-writable directory (`/opt/homebrew/bin`), but the real
// binaries sit beside each other in an owner-writable-only directory (the
// Caskroom). The helper must be discovered by resolving the daemon's own
// symlink to that clean directory, not rejected because the *symlink's*
// directory carries Homebrew's group-write bit.
func TestResolveHelperPath_FollowsDaemonSymlinkToCleanDir(t *testing.T) {
	// "Caskroom": owner-writable-only dir holding the real binaries.
	real := t.TempDir() // 0700
	daemon := filepath.Join(real, "protonmcpd")
	if err := os.WriteFile(daemon, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(real, "protonmcp-touchid")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// "/opt/homebrew/bin": group-writable dir holding only a symlink to the
	// daemon, mirroring a cask `binary` stanza. The helper is NOT reachable
	// here via any lexical candidate — only by following the daemon symlink.
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(bin, 0o775); err != nil { // group-writable, like Homebrew
		t.Fatal(err)
	}
	daemonLink := filepath.Join(bin, "protonmcpd")
	if err := os.Symlink(daemon, daemonLink); err != nil {
		t.Fatal(err)
	}

	got, err := resolveHelperPath(daemonLink)
	if err != nil {
		t.Fatalf("helper should resolve via the daemon symlink; err=%v", err)
	}
	// EvalSymlinks canonicalizes /var → /private/var on macOS; compare
	// resolved forms so the assertion is path-shape-agnostic.
	wantResolved, _ := filepath.EvalSymlinks(helper)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("resolved helper = %q, want %q", gotResolved, wantResolved)
	}
}
