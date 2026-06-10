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
