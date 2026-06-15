package sync

import (
	"context"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func seedCal(t *testing.T, st *store.Store, id string) {
	t.Helper()
	if err := st.UpsertCalendar(context.Background(), store.Calendar{ID: id, Name: "Cal", Active: true}); err != nil {
		t.Fatalf("seed calendar: %v", err)
	}
}

func calEvent(id, calID string, lastEdit int64) gpa.CalendarEvent {
	return gpa.CalendarEvent{
		ID: id, CalendarID: calID, UID: "uid-" + id,
		StartTime: lastEdit, EndTime: lastEdit + 1800,
		StartTimezone: "UTC", EndTimezone: "UTC",
		LastEditTime: lastEdit, CreateTime: 1,
	}
}

func TestApplyCalendarEvents_FirstPass(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")

	events := []gpa.CalendarEvent{
		calEvent("ev-1", "cal-1", 100),
		calEvent("ev-2", "cal-1", 300),
		calEvent("ev-3", "cal-1", 200),
	}
	newMax, up, del, err := applyCalendarEvents(ctx, st, "cal-1", events, 0)
	if err != nil {
		t.Fatal(err)
	}
	if up != 3 || del != 0 {
		t.Errorf("first pass up=%d del=%d, want 3/0", up, del)
	}
	if newMax != 300 {
		t.Errorf("newMax = %d, want 300", newMax)
	}
}

func TestApplyCalendarEvents_ChangeDetection(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")
	events := []gpa.CalendarEvent{
		calEvent("ev-1", "cal-1", 100),
		calEvent("ev-2", "cal-1", 300),
	}
	if _, _, _, err := applyCalendarEvents(ctx, st, "cal-1", events, 0); err != nil {
		t.Fatal(err)
	}

	// Re-poll with the same events and storedMax=300 → nothing changed.
	_, up, del, err := applyCalendarEvents(ctx, st, "cal-1", events, 300)
	if err != nil {
		t.Fatal(err)
	}
	if up != 0 || del != 0 {
		t.Errorf("unchanged re-poll up=%d del=%d, want 0/0", up, del)
	}

	// Edit ev-1 (LastEditTime bumps past the high-water mark).
	events[0].LastEditTime = 400
	newMax, up, _, err := applyCalendarEvents(ctx, st, "cal-1", events, 300)
	if err != nil {
		t.Fatal(err)
	}
	if up != 1 {
		t.Errorf("after edit up=%d, want 1", up)
	}
	if newMax != 400 {
		t.Errorf("newMax = %d, want 400", newMax)
	}
}

func TestApplyCalendarEvents_Reconcile(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")
	first := []gpa.CalendarEvent{
		calEvent("ev-1", "cal-1", 100),
		calEvent("ev-2", "cal-1", 100),
		calEvent("ev-3", "cal-1", 100),
	}
	if _, _, _, err := applyCalendarEvents(ctx, st, "cal-1", first, 0); err != nil {
		t.Fatal(err)
	}

	// Next poll: ev-2 vanished from the live set → reconcile deletes it.
	second := []gpa.CalendarEvent{
		calEvent("ev-1", "cal-1", 100),
		calEvent("ev-3", "cal-1", 100),
	}
	_, _, del, err := applyCalendarEvents(ctx, st, "cal-1", second, 100)
	if err != nil {
		t.Fatal(err)
	}
	if del != 1 {
		t.Errorf("reconcile del=%d, want 1", del)
	}
	if _, err := st.GetCalendarEvent(ctx, "ev-2"); err != store.ErrNotFound {
		t.Errorf("ev-2 should be deleted, got %v", err)
	}
}

func TestToEnvelopeAndCalendarMapping(t *testing.T) {
	ev := gpa.CalendarEvent{
		ID: "e", CalendarID: "c", UID: "u",
		StartTime: 10, StartTimezone: "Europe/London",
		EndTime: 20, EndTimezone: "Europe/Paris",
		FullDay: true, Author: "a@b.com", CreateTime: 5, LastEditTime: 7,
	}
	env := toEnvelope(ev)
	if env.ID != "e" || env.CalendarID != "c" || env.UID != "u" ||
		env.StartUnix != 10 || env.StartTZ != "Europe/London" ||
		env.EndUnix != 20 || env.EndTZ != "Europe/Paris" ||
		!env.AllDay || env.Author != "a@b.com" || env.CreatedUnix != 5 || env.LastEdit != 7 {
		t.Errorf("toEnvelope = %+v", env)
	}

	active := toStoreCalendar(gpa.Calendar{ID: "c", Name: "n", Flags: gpa.CalendarFlagActive})
	if !active.Active {
		t.Error("calendar with Active flag should map Active=true")
	}
	inactive := toStoreCalendar(gpa.Calendar{ID: "c2", Name: "n2", Flags: 0})
	if inactive.Active {
		t.Error("calendar without Active flag should map Active=false")
	}
}
