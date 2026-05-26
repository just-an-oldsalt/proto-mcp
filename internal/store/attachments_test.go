package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore opens a fresh on-disk SQLite store in a temp dir and
// runs every migration. Tests use this rather than ":memory:" because
// the foreign_keys=on pragma needs the same setup as production.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// seedMessage inserts a stub messages row so attachment_cache FK
// inserts succeed.
func seedMessage(t *testing.T, st *Store, msgID string) {
	t.Helper()
	_, err := st.DB.Exec(
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		msgID, msgID, "test", "x@y", "X",
	)
	if err != nil {
		t.Fatalf("seed message %s: %v", msgID, err)
	}
}

func TestAttachmentCacheRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "msg-1")

	want := AttachmentCacheRow{
		MessageID:    "msg-1",
		AttachmentID: "att-A",
		Filename:     "report.pdf",
		MIMEType:     "application/pdf",
		SizeBytes:    11,
		Content:      []byte("hello world"),
	}
	if err := st.SetAttachmentCache(ctx, want); err != nil {
		t.Fatalf("SetAttachmentCache: %v", err)
	}

	got, err := st.GetCachedAttachment(ctx, "msg-1", "att-A")
	if err != nil {
		t.Fatalf("GetCachedAttachment: %v", err)
	}
	if got.Filename != want.Filename || got.MIMEType != want.MIMEType || got.SizeBytes != want.SizeBytes {
		t.Errorf("metadata round-trip mismatch: got %+v want %+v", got, want)
	}
	if !bytes.Equal(got.Content, want.Content) {
		t.Errorf("content round-trip: got %q want %q", got.Content, want.Content)
	}
	if got.CachedAt.IsZero() {
		t.Errorf("CachedAt was zero — expected server-set timestamp")
	}
}

func TestGetCachedAttachmentNotFound(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_, err := st.GetCachedAttachment(ctx, "nope", "nope")
	if !errors.Is(err, ErrAttachmentNotCached) {
		t.Errorf("missing row should return ErrAttachmentNotCached, got %v", err)
	}
}

func TestAttachmentCacheUpsertOverwrites(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m")

	first := AttachmentCacheRow{MessageID: "m", AttachmentID: "a", Filename: "old", MIMEType: "text/plain", SizeBytes: 3, Content: []byte("aaa")}
	second := AttachmentCacheRow{MessageID: "m", AttachmentID: "a", Filename: "new", MIMEType: "text/plain", SizeBytes: 5, Content: []byte("bbbbb")}
	if err := st.SetAttachmentCache(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAttachmentCache(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetCachedAttachment(ctx, "m", "a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Filename != "new" || got.SizeBytes != 5 || !bytes.Equal(got.Content, []byte("bbbbb")) {
		t.Errorf("upsert didn't overwrite: %+v", got)
	}
}

func TestSumAndCountAttachmentBytes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m1")
	seedMessage(t, st, "m2")

	if sum, _ := st.SumAttachmentBytes(ctx); sum != 0 {
		t.Errorf("empty sum should be 0, got %d", sum)
	}
	if n, _ := st.CountCachedAttachments(ctx); n != 0 {
		t.Errorf("empty count should be 0, got %d", n)
	}

	_ = st.SetAttachmentCache(ctx, AttachmentCacheRow{MessageID: "m1", AttachmentID: "a", Filename: "a", MIMEType: "x", SizeBytes: 100, Content: make([]byte, 100)})
	_ = st.SetAttachmentCache(ctx, AttachmentCacheRow{MessageID: "m1", AttachmentID: "b", Filename: "b", MIMEType: "x", SizeBytes: 250, Content: make([]byte, 250)})
	_ = st.SetAttachmentCache(ctx, AttachmentCacheRow{MessageID: "m2", AttachmentID: "c", Filename: "c", MIMEType: "x", SizeBytes: 50, Content: make([]byte, 50)})

	if sum, _ := st.SumAttachmentBytes(ctx); sum != 400 {
		t.Errorf("sum = %d, want 400", sum)
	}
	if n, _ := st.CountCachedAttachments(ctx); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestEvictAttachmentsToFit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Three rows: oldest (a) is 100b, middle (b) is 200b, newest (c) is 300b. Total 600b.
	rows := []AttachmentCacheRow{
		{MessageID: "m", AttachmentID: "a", Filename: "a", MIMEType: "x", SizeBytes: 100, Content: make([]byte, 100), CachedAt: base},
		{MessageID: "m", AttachmentID: "b", Filename: "b", MIMEType: "x", SizeBytes: 200, Content: make([]byte, 200), CachedAt: base.Add(time.Hour)},
		{MessageID: "m", AttachmentID: "c", Filename: "c", MIMEType: "x", SizeBytes: 300, Content: make([]byte, 300), CachedAt: base.Add(2 * time.Hour)},
	}
	for _, r := range rows {
		if err := st.SetAttachmentCache(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	// Ceiling 500b → should evict the oldest (a, 100b) leaving 500b.
	evicted, err := st.EvictAttachmentsToFit(ctx, 500)
	if err != nil {
		t.Fatalf("EvictAttachmentsToFit: %v", err)
	}
	if evicted != 1 {
		t.Errorf("evicted = %d, want 1", evicted)
	}
	if _, err := st.GetCachedAttachment(ctx, "m", "a"); !errors.Is(err, ErrAttachmentNotCached) {
		t.Errorf("expected `a` to be evicted, got %v", err)
	}
	if _, err := st.GetCachedAttachment(ctx, "m", "b"); err != nil {
		t.Errorf("expected `b` to survive: %v", err)
	}
	if _, err := st.GetCachedAttachment(ctx, "m", "c"); err != nil {
		t.Errorf("expected `c` to survive: %v", err)
	}

	// Ceiling 250b → should now also evict b (200b), leaving just c (300b).
	// Note: ceiling 250 < c.SizeBytes, but eviction can't fix that —
	// once `a` and `b` are gone, sum is 300b which still exceeds 250b
	// but evicting `c` would leave 0 cached. Implementation must
	// stop after freeing enough or after evicting all-but-newest.
	evicted, err = st.EvictAttachmentsToFit(ctx, 250)
	if err != nil {
		t.Fatalf("EvictAttachmentsToFit step 2: %v", err)
	}
	if evicted < 1 {
		t.Errorf("expected at least 1 more eviction at step 2, got %d", evicted)
	}
}

func TestEvictAttachmentsToFitNoOp(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	// Empty cache: no error, zero evicted.
	n, err := st.EvictAttachmentsToFit(ctx, 1000)
	if err != nil {
		t.Fatalf("empty evict: %v", err)
	}
	if n != 0 {
		t.Errorf("empty evict count = %d, want 0", n)
	}
}

func TestPurgeAttachmentsOlderThan(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m")

	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour)
	fresh := now.Add(-1 * time.Hour)

	_ = st.SetAttachmentCache(ctx, AttachmentCacheRow{MessageID: "m", AttachmentID: "stale", Filename: "stale", MIMEType: "x", SizeBytes: 1, Content: []byte("x"), CachedAt: old})
	_ = st.SetAttachmentCache(ctx, AttachmentCacheRow{MessageID: "m", AttachmentID: "fresh", Filename: "fresh", MIMEType: "x", SizeBytes: 1, Content: []byte("y"), CachedAt: fresh})

	cutoff := now.Add(-30 * 24 * time.Hour)
	n, err := st.PurgeAttachmentsOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged = %d, want 1", n)
	}
	if _, err := st.GetCachedAttachment(ctx, "m", "stale"); !errors.Is(err, ErrAttachmentNotCached) {
		t.Errorf("stale should be gone, got %v", err)
	}
	if _, err := st.GetCachedAttachment(ctx, "m", "fresh"); err != nil {
		t.Errorf("fresh should survive: %v", err)
	}
}

// FK cascade verification: deleting a message removes its cached
// attachments. Important for the sync EventDelete + mail_delete_permanent
// flows that drop messages rows.
func TestAttachmentCacheFKCascade(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "doomed")

	if err := st.SetAttachmentCache(ctx, AttachmentCacheRow{
		MessageID: "doomed", AttachmentID: "att", Filename: "f",
		MIMEType: "x", SizeBytes: 1, Content: []byte("x"),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := st.DB.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, "doomed"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.GetCachedAttachment(ctx, "doomed", "att"); !errors.Is(err, ErrAttachmentNotCached) {
		t.Errorf("FK cascade failed: attachment survived parent deletion; got %v", err)
	}
}
