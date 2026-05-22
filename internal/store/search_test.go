package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// seed inserts a small fixture set used by every search test.
func seed(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	rows := []Message{
		{ID: "m1", ThreadID: "m1", Subject: "Portage gear list",
			FromAddress: "alice@example.com", FromName: "Alice",
			ToJSON: `[{"name":"Rich","address":"rdort@proton.me"}]`,
			Date: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			Folder: "inbox"},
		{ID: "m2", ThreadID: "m2", Subject: "Lunch plans",
			FromAddress: "bob@example.com", FromName: "Bob",
			ToJSON: `[{"name":"Rich","address":"rdort@proton.me"}]`,
			Date: time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC),
			Folder: "inbox"},
		{ID: "m3", ThreadID: "m3", Subject: "Rentals confirmation",
			FromAddress: "rentals@example.com", FromName: "Rentals",
			ToJSON: `[{"name":"Rich","address":"rdort@proton.me"}]`,
			Date: time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			Folder: "archive", HasAttachments: true},
	}
	for _, m := range rows {
		if err := s.UpsertMessage(ctx, m); err != nil {
			t.Fatalf("seed %s: %v", m.ID, err)
		}
	}
}

func TestSearchBareTerm(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), "portage", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m1" {
		t.Errorf("got %d hits, want 1 (m1): %+v", len(hits), hits)
	}
}

func TestSearchFromPrefix(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), "from:bob", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m2" {
		t.Errorf("from:bob → %+v", hits)
	}
}

func TestSearchInFolder(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), "in:archive", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m3" {
		t.Errorf("in:archive → %+v", hits)
	}
}

func TestSearchHasAttachment(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), "has:attachment", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m3" {
		t.Errorf("has:attachment → %+v", hits)
	}
}

func TestSearchDateRange(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	// After m1 (2026-03-01), through m2 (2026-03-05), exclude m3.
	hits, err := s.Search(context.Background(), "after:2026-03-02 before:2026-03-09", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m2" {
		t.Errorf("date range → %+v", hits)
	}
}

func TestSearchCombined(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), `from:rentals has:attachment`, SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m3" {
		t.Errorf("from:rentals has:attachment → %+v", hits)
	}
}

func TestSearchPaging(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	first, err := s.Search(context.Background(), "in:inbox", SearchOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("first page len = %d", len(first))
	}
	second, err := s.Search(context.Background(), "in:inbox", SearchOpts{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].MessageID == first[0].MessageID {
		t.Errorf("paging didn't advance: first=%v second=%v", first, second)
	}
}

func TestSearchQuotedSubject(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)

	hits, err := s.Search(context.Background(), `subject:"gear list"`, SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m1" {
		t.Errorf("subject:\"gear list\" → %+v", hits)
	}
}

func TestSearchSnippet(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	if err := s.UpsertMessage(ctx, Message{
		ID:       "m1",
		ThreadID: "m1",
		Subject:  "hello",
		Date:     time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCachedBody(ctx, "m1", CachedBody{
		Text:     "Lots of text " + strings.Repeat("word ", 100),
		HTML:     "",
		CachedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	hits, err := s.Search(ctx, "word", SearchOpts{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if !strings.HasSuffix(hits[0].Snippet, "…") {
		t.Errorf("snippet didn't truncate: %q", hits[0].Snippet)
	}
}

// TestSearchInAllSkipsFolderFilter pins the D1/D2 fix: "in:all" in
// the DSL is a synonym for "no folder filter" rather than a literal
// match. Same intent the LLM has when it asks for folder="all" on
// mail_list. Aliases also include any / all_mail / *.
func TestSearchInAllSkipsFolderFilter(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)
	ctx := context.Background()

	for _, alias := range []string{"all", "any", "all_mail", "*"} {
		hits, err := s.Search(ctx, "in:"+alias, SearchOpts{})
		if err != nil {
			t.Fatalf("in:%s: %v", alias, err)
		}
		// 3 seeded messages span inbox + archive. With folder
		// filter cleared, all three come back.
		if len(hits) != 3 {
			t.Errorf("in:%s returned %d hits, want 3 (all seeded msgs)", alias, len(hits))
		}
	}
}

// TestSearchSinceUntilAliases pins the D3 fix: "since" and "until"
// in the DSL alias to "after" and "before". Previously they fell
// through to the unknown-prefix path and became bare FTS terms that
// matched nothing, so date filters silently no-op'd.
func TestSearchSinceUntilAliases(t *testing.T) {
	s := mustOpen(t)
	seed(t, s)
	ctx := context.Background()

	// since:2026-03-02 → m2 (2026-03-05) and m3 (2026-03-10), not m1 (2026-03-01).
	hits, err := s.Search(ctx, "since:2026-03-02", SearchOpts{})
	if err != nil {
		t.Fatalf("since: %v", err)
	}
	if len(hits) != 2 {
		t.Errorf("since:2026-03-02 → %d hits, want 2", len(hits))
	}

	// until:2026-03-09 (exclusive) → m1 (03-01) and m2 (03-05), not m3 (03-10).
	hits, err = s.Search(ctx, "until:2026-03-09", SearchOpts{})
	if err != nil {
		t.Fatalf("until: %v", err)
	}
	if len(hits) != 2 {
		t.Errorf("until:2026-03-09 → %d hits, want 2", len(hits))
	}

	// Combined.
	hits, err = s.Search(ctx, "since:2026-03-02 until:2026-03-09", SearchOpts{})
	if err != nil {
		t.Fatalf("since+until: %v", err)
	}
	if len(hits) != 1 || hits[0].MessageID != "m2" {
		t.Errorf("since+until → %d hits, want 1 (m2): %+v", len(hits), hits)
	}
}
