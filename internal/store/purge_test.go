package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Tests for PurgeOlderThan / CountCachedBodies. SECURITY D13 / C-1.
// Uses a temp-file store rather than :memory: because modernc/sqlite
// opens one in-memory DB per connection, and the FTS trigger walk
// after our UPDATE benefits from a stable single-connection store.

func newPurgeStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedBody(t *testing.T, s *Store, id string, cachedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{
		ID:       id,
		ThreadID: id,
		Subject:  "subj-" + id,
		Date:     time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatalf("upsert %s: %v", id, err)
	}
	if err := s.SetCachedBody(ctx, id, CachedBody{
		Text:     "body-" + id,
		HTML:     "<p>body-" + id + "</p>",
		CachedAt: cachedAt,
	}); err != nil {
		t.Fatalf("set body %s: %v", id, err)
	}
}

func TestPurgeOlderThan_DeletesStale(t *testing.T) {
	s := newPurgeStore(t)
	now := time.Now().UTC()
	seedBody(t, s, "old", now.Add(-48*time.Hour))
	seedBody(t, s, "fresh", now.Add(-1*time.Hour))

	n, err := s.PurgeOlderThan(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("rows affected = %d, want 1 (only 'old' is past cutoff)", n)
	}

	// "old" body columns now NULL — GetCachedBody returns ErrNotFound.
	if _, err := s.GetCachedBody(context.Background(), "old"); err == nil {
		t.Error("expected old body to be purged")
	}
	// "fresh" still has its body.
	if _, err := s.GetCachedBody(context.Background(), "fresh"); err != nil {
		t.Errorf("fresh body got purged: %v", err)
	}
}

func TestPurgeOlderThan_HandlesEmptyStore(t *testing.T) {
	s := newPurgeStore(t)
	n, err := s.PurgeOlderThan(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("purge empty: %v", err)
	}
	if n != 0 {
		t.Errorf("empty store rows affected = %d, want 0", n)
	}
}

func TestPurgeOlderThan_SkipsRowsWithoutBody(t *testing.T) {
	// Messages backfilled via runBackfill have envelopes but no
	// body_cached_at. PurgeOlderThan must not match them — body_cached_at
	// IS NOT NULL clause guards.
	s := newPurgeStore(t)
	if err := s.UpsertMessage(context.Background(), Message{
		ID:       "envelope-only",
		ThreadID: "envelope-only",
		Date:     time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgeOlderThan(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("envelope-only row was purged: rows affected = %d", n)
	}
}

func TestPurgeAlsoCleansFTSIndex(t *testing.T) {
	// The messages_fts_update trigger fires on UPDATE — when
	// PurgeOlderThan sets body_text=NULL, the FTS row gets re-
	// inserted with no body content. A subsequent FTS search on
	// the body terms must not match the purged row.
	s := newPurgeStore(t)
	now := time.Now().UTC()
	seedBody(t, s, "stale", now.Add(-48*time.Hour))

	hits, err := s.Search(context.Background(), "body-stale", SearchOpts{Limit: 10})
	if err != nil {
		t.Fatalf("search before purge: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 pre-purge hit, got %d", len(hits))
	}

	if _, err := s.PurgeOlderThan(context.Background(), now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	hits, err = s.Search(context.Background(), "body-stale", SearchOpts{Limit: 10})
	if err != nil {
		t.Fatalf("search after purge: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("FTS still finds purged body: %d hits", len(hits))
	}
}

func TestCountCachedBodies_Stats(t *testing.T) {
	s := newPurgeStore(t)
	now := time.Now().UTC()
	seedBody(t, s, "a", now.Add(-72*time.Hour))
	seedBody(t, s, "b", now.Add(-48*time.Hour))
	seedBody(t, s, "c", now.Add(-1*time.Hour))

	stats, err := s.CountCachedBodies(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalCached != 3 {
		t.Errorf("TotalCached = %d, want 3", stats.TotalCached)
	}
	if stats.WouldPurge != 2 {
		t.Errorf("WouldPurge = %d, want 2", stats.WouldPurge)
	}
	if stats.OldestCached == nil {
		t.Fatal("OldestCached should be populated")
	}
	// Oldest is 'a' at -72h. Tolerance: within ±2s of -72h.
	want := now.Add(-72 * time.Hour)
	delta := stats.OldestCached.Sub(want)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Errorf("OldestCached = %v, want ~%v", stats.OldestCached, want)
	}
}
