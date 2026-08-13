package sync

import (
	"context"
	"errors"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
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

// The listing succeeds even on a session without calendar scope, so the
// calendar rows must be mirrored from it — hydrated from the inline
// member records — independently of whether events are reachable.
func TestSyncCalendarRows_HydratesFromMembers(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)

	// Calendars as the live API sends them: ID and Type, nothing else.
	cals := []gpa.Calendar{{ID: "cal-1"}, {ID: "cal-2"}}
	members := map[string]*protonclient.CalendarMemberFull{
		"cal-1": {CalendarID: "cal-1", Name: "My calendar", Color: "#DB60D6",
			Flags: int64(gpa.CalendarFlagActive)},
		"cal-2": {CalendarID: "cal-2", Name: "work@example.com", Color: "#F78400",
			Flags: int64(gpa.CalendarFlagActive)},
	}

	n, err := syncCalendarRows(ctx, st, cals, func(id string) *protonclient.CalendarMemberFull {
		return members[id]
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("upserted = %d, want 2", n)
	}

	got, err := st.ListCalendars(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("calendars = %d, want 2: %+v", len(got), got)
	}
	byID := map[string]store.Calendar{}
	for _, c := range got {
		byID[c.ID] = c
	}
	if c := byID["cal-1"]; c.Name != "My calendar" || c.Color != "#DB60D6" || !c.Active {
		t.Errorf("cal-1 = %+v, want hydrated from its member", c)
	}
	if c := byID["cal-2"]; c.Name != "work@example.com" || !c.Active {
		t.Errorf("cal-2 = %+v, want hydrated from its member", c)
	}
}

// If the member record is missing there is nothing to hydrate from — the
// calendar object carries no display fields — so the row lands blank. The
// sync must still complete rather than abort, since a listed calendar is
// worth mirroring even unnamed.
func TestSyncCalendarRows_MissingMemberStillMirrors(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)

	n, err := syncCalendarRows(ctx, st, []gpa.Calendar{{ID: "cal-1"}},
		func(string) *protonclient.CalendarMemberFull { return nil })
	if err != nil {
		t.Fatalf("a missing member must not abort the sync: %v", err)
	}
	if n != 1 {
		t.Errorf("upserted = %d, want 1", n)
	}

	got, err := st.ListCalendars(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "cal-1" {
		t.Fatalf("calendars = %+v, want cal-1 mirrored", got)
	}
	if got[0].Name != "" || got[0].Active {
		t.Errorf("calendar = %+v, want the blank fallback when no member is known", got[0])
	}
}

// A failing events fetch (the 403/9100 case) must not half-apply: no
// events, no high-water mark. The calendar row itself is written by phase
// 1 from the listing, which succeeded, so it legitimately survives.
func TestSyncCalendarEvents_FetchFailureWritesNothing(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")

	boom := errors.New("403 insufficient scope (Code=9100)")
	fetch := func(context.Context, string) ([]gpa.CalendarEvent, error) {
		return nil, boom
	}

	_, _, err := syncCalendarEvents(ctx, st, "cal-1", fetch)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}

	if _, err := st.GetSyncState(ctx, calendarMaxEditPrefix+"cal-1"); err != store.ErrNotFound {
		t.Errorf("high-water mark written despite failed fetch: %v", err)
	}
	events, err := st.ListCalendarEvents(ctx, store.CalendarEventFilter{CalendarID: "cal-1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("events written despite failed fetch: %+v", events)
	}
}

func TestSyncCalendarEvents_SuccessWritesEventsAndHighWater(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")

	fetch := func(context.Context, string) ([]gpa.CalendarEvent, error) {
		return []gpa.CalendarEvent{
			calEvent("ev-1", "cal-1", 100),
			calEvent("ev-2", "cal-1", 250),
		}, nil
	}

	upserted, _, err := syncCalendarEvents(ctx, st, "cal-1", fetch)
	if err != nil {
		t.Fatal(err)
	}
	if upserted != 2 {
		t.Errorf("upserted = %d, want 2", upserted)
	}

	// The high-water mark must reflect the newest LastEditTime so the
	// next pass skips these events.
	got, err := st.GetSyncState(ctx, calendarMaxEditPrefix+"cal-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "250" {
		t.Errorf("high-water = %q, want \"250\"", got)
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

	// No member record: fall back to the calendar object's own fields,
	// preserving the pre-existing behaviour.
	active := toStoreCalendar(gpa.Calendar{ID: "c", Name: "n", Flags: gpa.CalendarFlagActive}, nil)
	if !active.Active || active.Name != "n" {
		t.Errorf("nil member should fall back to the calendar object, got %+v", active)
	}
	inactive := toStoreCalendar(gpa.Calendar{ID: "c2", Name: "n2", Flags: 0}, nil)
	if inactive.Active {
		t.Error("calendar without Active flag should map Active=false")
	}
}

// The regression this fixes: the live API sends ID and Type only, so
// every display field on gpa.Calendar decodes to its zero value and the
// mirrored calendar is blank and inactive. The member record carries the
// real values.
func TestToStoreCalendar_MemberIsAuthoritative(t *testing.T) {
	bare := gpa.Calendar{ID: "cal-1", Type: gpa.CalendarTypeNormal}

	if got := toStoreCalendar(bare, nil); got.Name != "" || got.Active {
		t.Fatalf("precondition: bare calendar should map blank/inactive, got %+v", got)
	}

	got := toStoreCalendar(bare, &protonclient.CalendarMemberFull{
		CalendarID: "cal-1", Name: "Personal", Description: "mine",
		Color: "#5a3", Flags: int64(gpa.CalendarFlagActive),
	})
	if got.Name != "Personal" || got.Description != "mine" || got.Color != "#5a3" {
		t.Errorf("member fields not applied: %+v", got)
	}
	if !got.Active {
		t.Error("member Active flag should map Active=true")
	}
	if got.ID != "cal-1" || got.Type != int(gpa.CalendarTypeNormal) {
		t.Errorf("ID/Type must still come from the calendar object: %+v", got)
	}

	// A member without the Active bit means an inactive calendar, even
	// though the (empty) calendar object says nothing either way.
	off := toStoreCalendar(bare, &protonclient.CalendarMemberFull{
		CalendarID: "cal-1", Name: "Archived", Flags: 0,
	})
	if off.Active {
		t.Error("member without the Active flag should map Active=false")
	}
}
