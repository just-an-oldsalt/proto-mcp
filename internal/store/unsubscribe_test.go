package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// #102 — List-Unsubscribe values ride with the body cache.

func TestCachedBodyListUnsubscribeRoundTrip(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}

	// Both SetCachedBody statements (with and without ThreadID).
	for _, threadID := range []string{"", "thread-1"} {
		want := CachedBody{
			Text:                "t",
			HTML:                "<p>t</p>",
			ThreadID:            threadID,
			ListUnsubscribe:     "<https://example.com/u?tok=" + threadID + ">",
			ListUnsubscribePost: "List-Unsubscribe=One-Click",
		}
		if err := s.SetCachedBody(ctx, "m1", want); err != nil {
			t.Fatalf("Set (thread %q): %v", threadID, err)
		}
		got, err := s.GetCachedBody(ctx, "m1")
		if err != nil {
			t.Fatalf("Get (thread %q): %v", threadID, err)
		}
		if got.ListUnsubscribe != want.ListUnsubscribe || got.ListUnsubscribePost != want.ListUnsubscribePost {
			t.Errorf("thread %q: got (%q, %q), want (%q, %q)", threadID,
				got.ListUnsubscribe, got.ListUnsubscribePost, want.ListUnsubscribe, want.ListUnsubscribePost)
		}
	}

	// A refetch without the headers clears the previous values.
	if err := s.SetCachedBody(ctx, "m1", CachedBody{Text: "t2"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCachedBody(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ListUnsubscribe != "" || got.ListUnsubscribePost != "" {
		t.Errorf("stale unsubscribe survived refetch: %+v", got)
	}
}

func TestPurgeOlderThanClearsListUnsubscribe(t *testing.T) {
	s := newPurgeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for id, at := range map[string]time.Time{"old": now.Add(-48 * time.Hour), "fresh": now.Add(-time.Hour)} {
		if err := s.UpsertMessage(ctx, Message{ID: id, ThreadID: id, Date: time.Unix(1, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetCachedBody(ctx, id, CachedBody{
			Text:                "body",
			CachedAt:            at,
			ListUnsubscribe:     "<https://example.com/u?tok=" + id + ">",
			ListUnsubscribePost: "List-Unsubscribe=One-Click",
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.PurgeOlderThan(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	read := func(id string) (sql.NullString, sql.NullString) {
		var u, p sql.NullString
		if err := s.DB.QueryRowContext(ctx,
			`SELECT list_unsubscribe, list_unsubscribe_post FROM messages WHERE id = ?`, id,
		).Scan(&u, &p); err != nil {
			t.Fatal(err)
		}
		return u, p
	}
	if u, p := read("old"); u.Valid || p.Valid {
		t.Errorf("purged row still has unsubscribe: (%v, %v)", u, p)
	}
	if u, p := read("fresh"); !u.Valid || !p.Valid {
		t.Errorf("fresh row lost unsubscribe: (%v, %v)", u, p)
	}
}

// TestMigration0006 migrates a v5 database holding a cached body to
// v6: the new columns appear, body_text/body_html survive, and the
// body cache is invalidated so the next read refetches the headers.
func TestMigration0006(t *testing.T) {
	ctx := context.Background()
	dsn, err := buildDSN(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrationFS)
	t.Cleanup(func() { goose.SetBaseFS(nil) })
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatal(err)
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.UpTo(db, "migrations", 5); err != nil {
		t.Fatalf("up to 5: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json, body_text, body_html, body_cached_at)
		 VALUES ('m1', 'm1', 's', 'a@example.com', 'A', '[]', '[]', 0, 0, 0, 0, 'inbox', 0, '{}', 'hello body', '<p>hello body</p>', ?)`,
		time.Now().Unix(),
	); err != nil {
		t.Fatalf("seed v5 row: %v", err)
	}

	if err := goose.UpTo(db, "migrations", 6); err != nil {
		t.Fatalf("up to 6: %v", err)
	}

	var (
		text, html, unsub, post sql.NullString
		cachedAt                sql.NullInt64
	)
	if err := db.QueryRowContext(ctx,
		`SELECT body_text, body_html, body_cached_at, list_unsubscribe, list_unsubscribe_post FROM messages WHERE id = 'm1'`,
	).Scan(&text, &html, &cachedAt, &unsub, &post); err != nil {
		t.Fatalf("select after 0006: %v", err)
	}
	if text.String != "hello body" || html.String != "<p>hello body</p>" {
		t.Errorf("body not preserved: text=%v html=%v", text, html)
	}
	if cachedAt.Valid {
		t.Errorf("body_cached_at = %v, want NULL after 0006", cachedAt)
	}
	if unsub.Valid || post.Valid {
		t.Errorf("new columns not NULL: (%v, %v)", unsub, post)
	}

	// Search still finds the preserved body text.
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'hello'`,
	).Scan(&n); err != nil {
		t.Fatalf("fts: %v", err)
	}
	if n != 1 {
		t.Errorf("fts hits = %d, want 1", n)
	}
}

// #102 x #130: invalidating a cached body must drop the unsubscribe
// values with it (they carry per-recipient tokens), and a row left with
// only unsubscribe values and no cache stamp — e.g. from before this
// fix — must count as purgeable, not linger forever.
func TestInvalidateAndPurgeCoverListUnsubscribe(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	for _, id := range []string{"inval", "orphan"} {
		if err := s.UpsertMessage(ctx, Message{ID: id, ThreadID: id, Date: time.Unix(1, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetCachedBody(ctx, id, CachedBody{
			Text:            "t",
			ListUnsubscribe: "<https://example.com/u?tok=" + id + ">",
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.InvalidateBodyCache(ctx, "inval"); err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-fix orphan: unsubscribe kept, body and stamp gone.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE messages SET body_text = NULL, body_html = NULL, body_cached_at = NULL WHERE id = 'orphan'`); err != nil {
		t.Fatal(err)
	}

	unsub := func(id string) sql.NullString {
		var v sql.NullString
		if err := s.DB.QueryRowContext(ctx, `SELECT list_unsubscribe FROM messages WHERE id = ?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := unsub("inval"); v.Valid {
		t.Errorf("InvalidateBodyCache left list_unsubscribe = %q", v.String)
	}

	// A far-past cutoff: only orphans qualify, whatever their age.
	if _, err := s.PurgeOlderThan(ctx, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if v := unsub("orphan"); v.Valid {
		t.Errorf("purge left an orphaned list_unsubscribe = %q", v.String)
	}
}
