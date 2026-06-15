package store

import (
	"context"
	"testing"
	"time"
)

func seedCalendar(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.UpsertCalendar(context.Background(), Calendar{
		ID: id, Name: "Personal", Description: "mine", Color: "#aabbcc", Type: 0, Active: true,
	}); err != nil {
		t.Fatalf("UpsertCalendar: %v", err)
	}
}

func env(id, calID string, start int64) CalendarEventEnvelope {
	return CalendarEventEnvelope{
		ID: id, CalendarID: calID, UID: "uid-" + id,
		StartUnix: start, StartTZ: "Europe/London",
		EndUnix: start + 1800, EndTZ: "Europe/London",
		LastEdit: start,
	}
}

func TestUpsertAndListCalendars(t *testing.T) {
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")

	// Update in place.
	if err := s.UpsertCalendar(context.Background(), Calendar{ID: "cal-1", Name: "Renamed", Active: false}); err != nil {
		t.Fatal(err)
	}
	cals, err := s.ListCalendars(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cals) != 1 {
		t.Fatalf("calendars = %d, want 1", len(cals))
	}
	if cals[0].Name != "Renamed" || cals[0].Active {
		t.Errorf("calendar = %+v, want Renamed/inactive", cals[0])
	}
}

func TestCalendarEventEnvelopeThenDecrypt(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")

	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-1", "cal-1", 1000)); err != nil {
		t.Fatal(err)
	}

	// Before decrypt: envelope present, decrypted flag false.
	got, err := s.GetCalendarEvent(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decrypted {
		t.Error("event should not be marked decrypted yet")
	}
	if got.StartUnix != 1000 || got.StartTZ != "Europe/London" {
		t.Errorf("envelope = %+v", got.CalendarEventEnvelope)
	}
	if got.Summary != "" {
		t.Errorf("summary should be empty pre-decrypt, got %q", got.Summary)
	}

	// Fill decryption.
	if err := s.FillCalendarEventDecrypted(ctx, "ev-1", CalendarEventDecrypted{
		Summary: "Team standup", Location: "Zoom", Description: "daily",
		Organizer: "alice@example.com", Status: "CONFIRMED",
		RRULE: "FREQ=WEEKLY", IsRecurring: true,
		AttendeesJSON: `[{"email":"bob@example.com"}]`, RawICal: "BEGIN:VEVENT...",
	}); err != nil {
		t.Fatal(err)
	}

	got, err = s.GetCalendarEvent(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Decrypted {
		t.Error("event should be marked decrypted")
	}
	if got.Summary != "Team standup" || got.Location != "Zoom" || !got.IsRecurring || got.RRULE != "FREQ=WEEKLY" {
		t.Errorf("decrypted fields = %+v", got.CalendarEventDecrypted)
	}
}

// The core invariant: re-syncing the envelope must NOT drop a cached
// decryption (mirrors UpsertMessage preserving body_text).
func TestEnvelopeReupsertPreservesDecryption(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-1", "cal-1", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.FillCalendarEventDecrypted(ctx, "ev-1", CalendarEventDecrypted{Summary: "Cached"}); err != nil {
		t.Fatal(err)
	}

	// Re-sync the envelope with a moved start time.
	moved := env("ev-1", "cal-1", 2000)
	moved.LastEdit = 2000
	if err := s.UpsertCalendarEventEnvelope(ctx, moved); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCalendarEvent(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.StartUnix != 2000 {
		t.Errorf("start not updated: %d", got.StartUnix)
	}
	if got.Summary != "Cached" || !got.Decrypted {
		t.Errorf("re-upsert dropped the cached decryption: summary=%q decrypted=%v", got.Summary, got.Decrypted)
	}
}

func TestListCalendarEventsFilters(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	seedCalendar(t, s, "cal-2")
	for _, e := range []CalendarEventEnvelope{
		env("ev-1", "cal-1", 1000),
		env("ev-2", "cal-1", 3000),
		env("ev-3", "cal-2", 2000),
	} {
		if err := s.UpsertCalendarEventEnvelope(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// Range filter [1500, 3500) → ev-2, ev-3 ordered by start ASC.
	got, err := s.ListCalendarEvents(ctx, CalendarEventFilter{FromUnix: 1500, ToUnix: 3500})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "ev-3" || got[1].ID != "ev-2" {
		t.Fatalf("range filter = %v", ids(got))
	}

	// Calendar filter.
	got, err = s.ListCalendarEvents(ctx, CalendarEventFilter{CalendarID: "cal-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ev-3" {
		t.Fatalf("calendar filter = %v", ids(got))
	}
}

func TestListCalendarEventsFTS(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-1", "cal-1", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-2", "cal-1", 2000)); err != nil {
		t.Fatal(err)
	}
	if err := s.FillCalendarEventDecrypted(ctx, "ev-1", CalendarEventDecrypted{Summary: "Quarterly planning", Location: "Boardroom"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FillCalendarEventDecrypted(ctx, "ev-2", CalendarEventDecrypted{Summary: "Lunch"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListCalendarEvents(ctx, CalendarEventFilter{Query: "planning"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ev-1" {
		t.Fatalf("FTS planning = %v", ids(got))
	}

	// Special characters must not throw an FTS syntax error.
	if _, err := s.ListCalendarEvents(ctx, CalendarEventFilter{Query: `"quoted (paren)`}); err != nil {
		t.Fatalf("FTS with special chars errored: %v", err)
	}
}

func TestReconcileCalendarEvents(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	for _, id := range []string{"ev-1", "ev-2", "ev-3"} {
		if err := s.UpsertCalendarEventEnvelope(ctx, env(id, "cal-1", 1000)); err != nil {
			t.Fatal(err)
		}
	}

	// Live set drops ev-2.
	deleted, err := s.ReconcileCalendarEvents(ctx, "cal-1", []string{"ev-1", "ev-3"})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	if _, err := s.GetCalendarEvent(ctx, "ev-2"); err != ErrNotFound {
		t.Errorf("ev-2 should be gone, got %v", err)
	}
	if _, err := s.GetCalendarEvent(ctx, "ev-1"); err != nil {
		t.Errorf("ev-1 should remain: %v", err)
	}
}

func TestPurgeCalendarOlderThan(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-1", "cal-1", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.FillCalendarEventDecrypted(ctx, "ev-1", CalendarEventDecrypted{Summary: "secret meeting"}); err != nil {
		t.Fatal(err)
	}

	// Purge everything decrypted before an hour from now (i.e. all).
	n, err := s.PurgeCalendarOlderThan(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("purged = %d, want 1", n)
	}

	got, err := s.GetCalendarEvent(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decrypted || got.Summary != "" {
		t.Errorf("decrypted text should be purged: %+v", got.CalendarEventDecrypted)
	}
	// Envelope must survive the purge.
	if got.StartUnix != 1000 {
		t.Errorf("envelope lost in purge: start=%d", got.StartUnix)
	}
}

func TestDeleteCalendarCascades(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	seedCalendar(t, s, "cal-1")
	if err := s.UpsertCalendarEventEnvelope(ctx, env("ev-1", "cal-1", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCalendar(ctx, "cal-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCalendarEvent(ctx, "ev-1"); err != ErrNotFound {
		t.Errorf("event should cascade-delete with its calendar, got %v", err)
	}
}

func ids(rows []CalendarEventRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}
