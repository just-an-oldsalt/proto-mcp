package mcptools

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Phase 8/D — small attachments come back inline as base64 with no
// staging file; large ones are written to a staging file and the path
// is returned with no inline base64. sha256 is always the hex digest of
// the plaintext.
func TestStageOrInlineAttachment_SmallInline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	content := []byte("hello world, a small attachment")

	b64, path, sha, err := stageOrInlineAttachment("att-1", "note.txt", content)
	if err != nil {
		t.Fatalf("stageOrInlineAttachment: %v", err)
	}
	if path != "" {
		t.Errorf("path = %q; want empty for small attachment", path)
	}
	if b64 == "" {
		t.Fatal("content_b64 empty; want inline base64 for small attachment")
	}
	got, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("content_b64 not valid base64: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("decoded content_b64 != original")
	}
	wantSha := hex.EncodeToString(sha256Sum(content))
	if sha != wantSha {
		t.Errorf("sha256 = %q; want %q", sha, wantSha)
	}
}

func TestStageOrInlineAttachment_LargeStaged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// 17 KiB — over the 16 KiB inline ceiling.
	content := bytes.Repeat([]byte("A"), inlineAttachmentMaxBytes+1024)

	b64, path, sha, err := stageOrInlineAttachment("att-big", "report.pdf", content)
	if err != nil {
		t.Fatalf("stageOrInlineAttachment: %v", err)
	}
	if b64 != "" {
		t.Errorf("content_b64 set for large attachment; want empty (path mode)")
	}
	if path == "" {
		t.Fatal("path empty; want a staging file path for large attachment")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading staged file %q: %v", path, err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("staged file bytes != original")
	}
	// 0600 perms on the staged plaintext.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("staged file mode = %o; want 600", perm)
	}
	wantSha := hex.EncodeToString(sha256Sum(content))
	if sha != wantSha {
		t.Errorf("sha256 = %q; want %q", sha, wantSha)
	}
}

// Re-staging the same attachment id + filename overwrites rather than
// creating a second file — the staging dir is bounded by distinct
// attachments, not call count.
func TestWriteAttachmentStaging_Idempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	content := bytes.Repeat([]byte("Z"), inlineAttachmentMaxBytes+1)

	p1, err := writeAttachmentStaging("att-x", "a.bin", content)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := writeAttachmentStaging("att-x", "a.bin", content)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Errorf("staging path changed across calls: %q vs %q (want deterministic)", p1, p2)
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// PROTO-135 — a pre-planted symlink at the deterministic staging dest
// must NOT be followed; the decrypted plaintext must not overwrite the
// symlink's target.
func TestWriteAttachmentStaging_RefusesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, "Library", "Application Support", "protonmcp", "attachment-staging")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Deterministic dest for ("attX","a.bin") is "<dir>/attX__a.bin".
	dest := filepath.Join(dir, "attX__a.bin")
	if err := os.Symlink(victim, dest); err != nil {
		t.Fatal(err)
	}

	content := bytes.Repeat([]byte("Z"), inlineAttachmentMaxBytes+1)
	if _, err := writeAttachmentStaging("attX", "a.bin", content); err == nil {
		t.Fatal("expected writeAttachmentStaging to refuse a symlink dest (O_NOFOLLOW)")
	}
	if got, _ := os.ReadFile(victim); string(got) != "original" {
		t.Errorf("symlink target was overwritten through the staging write: %q", got)
	}
}

// PROTO-135 — SweepStagingOlderThan removes files older than the cutoff
// and leaves fresh ones, so on-disk plaintext doesn't outlive retention.
func TestSweepStagingOlderThan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	content := bytes.Repeat([]byte("A"), inlineAttachmentMaxBytes+1)

	old, err := writeAttachmentStaging("attOld", "old.bin", content)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	fresh, err := writeAttachmentStaging("attNew", "new.bin", content)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := SweepStagingOlderThan(time.Now().Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("stale staging file was not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh staging file was wrongly removed: %v", err)
	}
}

// A missing staging dir is a no-op, not an error.
func TestSweepStagingOlderThan_NoDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	removed, err := SweepStagingOlderThan(time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
