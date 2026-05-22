package sync

import (
	"context"
	"net/mail"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// applyEvent is the diff-application core — sync's actual API call
// path needs a real Session, but the per-event store mutations are
// pure-Go and testable with a hand-built Event.

func mustOpen(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestApplyMessageCreate(t *testing.T) {
	st := mustOpen(t)
	ctx := context.Background()

	e := gpa.Event{
		EventID: "ev-1",
		Messages: []gpa.MessageEvent{
			{
				EventItem: gpa.EventItem{ID: "m-new", Action: gpa.EventCreate},
				Message: gpa.MessageMetadata{
					ID:        "m-new",
					AddressID: "a-1",
					LabelIDs:  []string{"0"},
					Subject:   "fresh message",
					Sender:    &mail.Address{Address: "alice@example.com"},
					Time:      1_700_000_000,
				},
			},
		},
	}
	res := &RunResult{}
	if err := applyEvent(ctx, st, e, res); err != nil {
		t.Fatalf("applyEvent: %v", err)
	}
	if res.MessagesUpserted != 1 {
		t.Errorf("MessagesUpserted = %d, want 1", res.MessagesUpserted)
	}

	m, err := st.GetMessage(ctx, "m-new")
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if m.Subject != "fresh message" {
		t.Errorf("Subject = %q", m.Subject)
	}
}

func TestApplyMessageDelete(t *testing.T) {
	st := mustOpen(t)
	ctx := context.Background()

	// Seed an existing row.
	if err := st.UpsertMessage(ctx, store.Message{ID: "m1", ThreadID: "m1"}); err != nil {
		t.Fatal(err)
	}

	e := gpa.Event{
		Messages: []gpa.MessageEvent{
			{EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventDelete}},
		},
	}
	res := &RunResult{}
	if err := applyEvent(ctx, st, e, res); err != nil {
		t.Fatalf("applyEvent: %v", err)
	}
	if res.MessagesDeleted != 1 {
		t.Errorf("MessagesDeleted = %d, want 1", res.MessagesDeleted)
	}

	if _, err := st.GetMessage(ctx, "m1"); err == nil {
		t.Error("expected m1 to be deleted")
	}
}

func TestApplyMessageUpdateInvalidatesBody(t *testing.T) {
	st := mustOpen(t)
	ctx := context.Background()

	if err := st.UpsertMessage(ctx, store.Message{ID: "m1", ThreadID: "m1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCachedBody(ctx, "m1", store.CachedBody{
		Text: "old body",
		HTML: "<p>old</p>",
	}); err != nil {
		t.Fatal(err)
	}

	// Update event should invalidate the body cache.
	e := gpa.Event{
		Messages: []gpa.MessageEvent{
			{
				EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventUpdate},
				Message: gpa.MessageMetadata{
					ID:        "m1",
					AddressID: "a-1",
					Subject:   "updated subject",
					Time:      1,
				},
			},
		},
	}
	if err := applyEvent(ctx, st, e, &RunResult{}); err != nil {
		t.Fatalf("applyEvent: %v", err)
	}

	// GetCachedBody should now be ErrNotFound (body_cached_at zeroed).
	if _, err := st.GetCachedBody(ctx, "m1"); err == nil {
		t.Error("expected body cache to be invalidated after update")
	}
}

func TestApplyLabelCRUD(t *testing.T) {
	st := mustOpen(t)
	ctx := context.Background()

	e := gpa.Event{
		Labels: []gpa.LabelEvent{
			{
				EventItem: gpa.EventItem{ID: "l-1", Action: gpa.EventCreate},
				Label:     gpa.Label{ID: "l-1", Name: "Work", Color: "#aabbcc", Type: 1},
			},
			{
				EventItem: gpa.EventItem{ID: "l-2", Action: gpa.EventCreate},
				Label:     gpa.Label{ID: "l-2", Name: "Personal", Type: 1},
			},
		},
	}
	res := &RunResult{}
	if err := applyEvent(ctx, st, e, res); err != nil {
		t.Fatalf("applyEvent create: %v", err)
	}
	if res.LabelsUpserted != 2 {
		t.Errorf("LabelsUpserted = %d, want 2", res.LabelsUpserted)
	}

	// Delete event.
	e2 := gpa.Event{
		Labels: []gpa.LabelEvent{
			{EventItem: gpa.EventItem{ID: "l-1", Action: gpa.EventDelete}},
		},
	}
	res2 := &RunResult{}
	if err := applyEvent(ctx, st, e2, res2); err != nil {
		t.Fatalf("applyEvent delete: %v", err)
	}
	if res2.LabelsDeleted != 1 {
		t.Errorf("LabelsDeleted = %d, want 1", res2.LabelsDeleted)
	}
}
