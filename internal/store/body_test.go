package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBodyCacheRoundtrip(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	// Need a message row to attach the body to.
	if err := s.UpsertMessage(ctx, Message{
		ID:       "m1",
		ThreadID: "m1",
		Date:     time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// First Get → not cached, ErrNotFound.
	if _, err := s.GetCachedBody(ctx, "m1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("uncached Get: err = %v, want ErrNotFound", err)
	}

	// Set + Get round-trips. ThreadID propagates to messages.thread_id.
	now := time.Now().UTC()
	body := CachedBody{
		Text:     "hello world",
		HTML:     "<p>hello world</p>",
		ThreadID: "thread-xyz",
		CachedAt: now,
	}
	if err := s.SetCachedBody(ctx, "m1", body); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.GetCachedBody(ctx, "m1")
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got.Text != "hello world" || got.HTML != "<p>hello world</p>" {
		t.Errorf("body mismatch: %+v", got)
	}

	// ThreadID got written to the message row.
	m, err := s.GetMessage(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreadID != "thread-xyz" {
		t.Errorf("thread_id = %q, want thread-xyz", m.ThreadID)
	}
}

func TestBodyCacheTTL(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}

	// Pretend the cache is from before BodyTTL — Get should ErrNotFound.
	old := time.Now().Add(-BodyTTL - time.Hour).UTC()
	if err := s.SetCachedBody(ctx, "m1", CachedBody{
		Text:     "stale",
		HTML:     "<p>stale</p>",
		CachedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCachedBody(ctx, "m1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale cache: err = %v, want ErrNotFound", err)
	}
}
