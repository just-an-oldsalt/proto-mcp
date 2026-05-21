package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mustOpen returns a fresh in-memory store with migrations applied.
func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAppliesMigrations(t *testing.T) {
	s := mustOpen(t)

	// Walk a few of the tables we expect to exist.
	want := []string{"messages", "message_labels", "labels", "messages_fts", "sync_state", "audit_log"}
	for _, name := range want {
		var found string
		err := s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE name = ?`, name).Scan(&found)
		if err != nil {
			t.Errorf("expected table %q to exist after migrations: %v", name, err)
		}
	}
}

func TestUpsertAndGetMessage(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	body := "Looking forward to the portage trip next weekend."
	m := Message{
		ID:          "msg-1",
		ThreadID:    "thr-1",
		Subject:     "Portage gear list",
		FromAddress: "alice@example.com",
		FromName:    "Alice",
		ToJSON:      `[{"name":"Richard","address":"rdort@proton.me"}]`,
		Date:        time.Unix(1_700_000_000, 0).UTC(),
		Unread:      true,
		Folder:      "inbox",
		SizeBytes:   1234,
		RawJSON:     `{"ID":"msg-1"}`,
	}
	if err := s.UpsertMessage(ctx, m); err != nil {
		t.Fatalf("UpsertMessage: %v", err)
	}

	// Populate the body cache directly so the FTS index includes body text.
	_, err := s.DB.ExecContext(ctx,
		`UPDATE messages SET body_text = ?, body_cached_at = ? WHERE id = ?`,
		body, time.Now().Unix(), m.ID,
	)
	if err != nil {
		t.Fatalf("seed body_text: %v", err)
	}

	got, err := s.GetMessage(ctx, m.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if got.Subject != m.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, m.Subject)
	}
	if !got.Unread {
		t.Errorf("Unread = false, want true")
	}
	if got.BodyText == nil || *got.BodyText != body {
		t.Errorf("BodyText = %v, want %q", got.BodyText, body)
	}

	// Upsert again with different envelope, confirm fields update but body persists.
	m.Subject = "Re: Portage gear list"
	if err := s.UpsertMessage(ctx, m); err != nil {
		t.Fatalf("UpsertMessage (update): %v", err)
	}
	got2, err := s.GetMessage(ctx, m.ID)
	if err != nil {
		t.Fatalf("GetMessage (after update): %v", err)
	}
	if got2.Subject != "Re: Portage gear list" {
		t.Errorf("Subject after update = %q", got2.Subject)
	}
	if got2.BodyText == nil || *got2.BodyText != body {
		t.Errorf("BodyText lost across upsert: got %v", got2.BodyText)
	}
}

func TestSearchMessagesFTS(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	msgs := []Message{
		{ID: "a", ThreadID: "ta", Subject: "Portage gear list", FromAddress: "alice@example.com", FromName: "Alice", Date: time.Unix(1, 0).UTC()},
		{ID: "b", ThreadID: "tb", Subject: "Lunch plans", FromAddress: "bob@example.com", FromName: "Bob", Date: time.Unix(2, 0).UTC()},
		{ID: "c", ThreadID: "tc", Subject: "Portage rentals confirmation", FromAddress: "rentals@example.com", FromName: "Rentals", Date: time.Unix(3, 0).UTC()},
	}
	for _, m := range msgs {
		if err := s.UpsertMessage(ctx, m); err != nil {
			t.Fatalf("UpsertMessage %s: %v", m.ID, err)
		}
	}

	ids, err := s.SearchMessages(ctx, "portage", 10)
	if err != nil {
		t.Fatalf("SearchMessages: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 matches, got %d (%v)", len(ids), ids)
	}

	ids, err = s.SearchMessages(ctx, "alice", 10)
	if err != nil {
		t.Fatalf("SearchMessages from: %v", err)
	}
	if len(ids) != 1 || ids[0] != "a" {
		t.Errorf("expected only msg a to match 'alice', got %v", ids)
	}
}

func TestLabelsCascadeOnDelete(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	m := Message{ID: "m1", ThreadID: "t1", Date: time.Unix(1, 0).UTC()}
	if err := s.UpsertMessage(ctx, m); err != nil {
		t.Fatalf("UpsertMessage: %v", err)
	}
	if err := s.SetMessageLabels(ctx, "m1", []string{"l-inbox", "l-work"}); err != nil {
		t.Fatalf("SetMessageLabels: %v", err)
	}

	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM message_labels WHERE message_id = ?`, "m1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 label rows, got %d", n)
	}

	if _, err := s.DB.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, "m1"); err != nil {
		t.Fatalf("delete message: %v", err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM message_labels WHERE message_id = ?`, "m1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected message_labels rows to cascade-delete, got %d remaining", n)
	}
}

func TestSetMessageLabelsReplaces(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	m := Message{ID: "m2", ThreadID: "t2", Date: time.Unix(1, 0).UTC()}
	if err := s.UpsertMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMessageLabels(ctx, "m2", []string{"l-1", "l-2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMessageLabels(ctx, "m2", []string{"l-3"}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.DB.Query(`SELECT label_id FROM message_labels WHERE message_id = ? ORDER BY label_id`, "m2")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var lid string
		if err := rows.Scan(&lid); err != nil {
			t.Fatal(err)
		}
		got = append(got, lid)
	}
	if len(got) != 1 || got[0] != "l-3" {
		t.Errorf("expected [l-3], got %v", got)
	}
}

func TestSyncState(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	if _, err := s.GetSyncState(ctx, "event_cursor"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unset key, got %v", err)
	}

	if err := s.SetSyncState(ctx, "event_cursor", "abc123"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetSyncState(ctx, "event_cursor")
	if err != nil {
		t.Fatal(err)
	}
	if v != "abc123" {
		t.Errorf("got %q, want abc123", v)
	}

	// Overwrite.
	if err := s.SetSyncState(ctx, "event_cursor", "def456"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetSyncState(ctx, "event_cursor")
	if v != "def456" {
		t.Errorf("got %q, want def456", v)
	}
}
