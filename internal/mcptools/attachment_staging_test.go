package mcptools

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
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
