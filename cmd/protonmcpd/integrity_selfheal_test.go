package main

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the upgrade-survival path added to VerifyBinaryIntegrity:
// a hash mismatch is tolerated only when the running binary still
// carries a valid Developer ID signature from expectedTeamID.

// TestVerifyDeveloperIDSignatureRejectsUnsigned is the security-critical
// direction. An unsigned binary must NOT satisfy the requirement — that
// is exactly the swap the integrity check exists to stop, and it is the
// case that must keep failing now that a passing signature short-
// circuits the hash comparison.
func TestVerifyDeveloperIDSignatureRejectsUnsigned(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeveloperIDSignature(bin); err == nil {
		t.Fatal("unsigned binary passed the Developer ID requirement; " +
			"a swapped binary would now be trusted")
	}
}

// TestVerifyDeveloperIDSignatureRejectsAdHoc closes the more subtle
// hole: ad-hoc signing (`codesign -s -`) produces a structurally valid
// signature with no certificate chain. The requirement's `anchor apple
// generic` clause is what rejects it; a check that merely parsed
// TeamIdentifier out of `codesign -dv` would not.
func TestVerifyDeveloperIDSignatureRejectsAdHoc(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable")
	}
	bin := filepath.Join(t.TempDir(), "adhoc")
	// Copy a real Mach-O; codesign refuses to sign a shell script.
	src, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Skip("no /bin/echo to copy")
	}
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "-s", "-", bin).CombinedOutput(); err != nil {
		t.Skipf("could not ad-hoc sign fixture: %v: %s", err, out)
	}

	if err := verifyDeveloperIDSignature(bin); err == nil {
		t.Fatal("ad-hoc signed binary passed the Developer ID requirement")
	}
}

// TestVerifyDeveloperIDSignatureAcceptsReleaseBinary is the positive
// direction, run only on a machine that has the signed cask installed.
// Without it the two negative tests above would also pass against a
// requirement string that rejects everything.
func TestVerifyDeveloperIDSignatureAcceptsReleaseBinary(t *testing.T) {
	const released = "/opt/homebrew/bin/protonmcpd"
	if _, err := os.Stat(released); err != nil {
		t.Skip("no cask-installed protonmcpd to verify against")
	}
	if err := verifyDeveloperIDSignature(released); err != nil {
		t.Errorf("released binary failed its own Developer ID requirement: %v\n"+
			"if the signing identity changed, expectedTeamID (%s) needs updating",
			err, expectedTeamID)
	}
}

// TestRewriteExpectedSha256RoundTrip checks the re-record path produces
// a file readExpectedSha256 can parse — the two halves have to agree or
// the daemon re-does the signature dance on every launch.
func TestRewriteExpectedSha256RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected_sha256")
	hash := strings.Repeat("a", 64)
	binPath := "/opt/homebrew/bin/protonmcpd"

	if err := rewriteExpectedSha256(path, hash, binPath); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	gotHash, gotPath, err := readExpectedSha256(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotHash != hash {
		t.Errorf("hash = %q, want %q", gotHash, hash)
	}
	if gotPath != binPath {
		t.Errorf("path = %q, want %q", gotPath, binPath)
	}
}

// TestRewriteExpectedSha256ReplacesAndKeepsMode confirms an overwrite
// leaves exactly one record at 0600 — the file holds no secret, but it
// governs whether the daemon starts, so it stays owner-only.
func TestRewriteExpectedSha256ReplacesAndKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected_sha256")
	if err := os.WriteFile(path, []byte(strings.Repeat("b", 64)+"  /old/path\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	newHash := strings.Repeat("c", 64)
	if err := rewriteExpectedSha256(path, newHash, "/new/path"); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte("\n")); n != 1 {
		t.Errorf("file has %d lines, want exactly 1: %q", n, data)
	}
	if !strings.HasPrefix(string(data), newHash) {
		t.Errorf("old record survived: %q", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

// TestRewriteExpectedSha256LeavesNoTempFiles guards the temp-and-rename
// implementation: a leaked .expected_sha256-* sibling would accumulate
// on every upgrade.
func TestRewriteExpectedSha256LeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expected_sha256")

	for range 3 {
		if err := rewriteExpectedSha256(path, strings.Repeat("d", 64), "/bin/x"); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %v, want only expected_sha256", names)
	}
}

// TestVerifyBinaryIntegrityMismatchOnUnsignedStillFails exercises the
// whole wiring, not just the signature helper: with a deliberately
// wrong hash recorded and an unsigned running binary (the test binary
// itself), VerifyBinaryIntegrity must still refuse. This is the
// assertion that would catch a self-heal that accidentally swallowed
// every mismatch.
func TestVerifyBinaryIntegrityMismatchOnUnsignedStillFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, "Library", "Application Support", "protonmcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A hash that cannot match whatever the test binary hashes to.
	wrong := strings.Repeat("e", 64)
	if err := os.WriteFile(filepath.Join(dir, "expected_sha256"),
		[]byte(wrong+"  "+exe+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	err = VerifyBinaryIntegrity(logger)
	if err == nil {
		t.Fatal("hash mismatch on an unsigned binary was accepted; " +
			"the self-heal is swallowing failures it must not")
	}
	if !strings.Contains(err.Error(), "integrity check FAILED") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

// TestVerifyBinaryIntegrityMissingFileStillPasses pins the graceful
// degrade for installs that predate the hash record — the self-heal
// change must not turn a missing file into a startup failure.
func TestVerifyBinaryIntegrityMissingFileStillPasses(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // keep the expected warning out of test output
	}))
	if err := VerifyBinaryIntegrity(logger); err != nil {
		t.Errorf("missing expected_sha256 should degrade gracefully, got: %v", err)
	}
}
