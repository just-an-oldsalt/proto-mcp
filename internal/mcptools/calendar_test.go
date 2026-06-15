package mcptools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func calStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mustCal(t *testing.T, st *store.Store, id, name string) {
	t.Helper()
	if err := st.UpsertCalendar(context.Background(), store.Calendar{ID: id, Name: name, Active: true}); err != nil {
		t.Fatal(err)
	}
}

func mustEnvelope(t *testing.T, st *store.Store, id, calID string, start int64) {
	t.Helper()
	if err := st.UpsertCalendarEventEnvelope(context.Background(), store.CalendarEventEnvelope{
		ID: id, CalendarID: calID, UID: "uid-" + id,
		StartUnix: start, EndUnix: start + 1800, StartTZ: "UTC", EndTZ: "UTC", LastEdit: start,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCalendarListTool(t *testing.T) {
	st := calStore(t)
	mustCal(t, st, "cal-1", "Personal")
	mustCal(t, st, "cal-2", "Work")

	tl := calendarList(Deps{Store: st})
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := res.StructuredContent.(calendarListResult)
	if !ok {
		t.Fatalf("result type = %T", res.StructuredContent)
	}
	if len(out.Calendars) != 2 {
		t.Fatalf("calendars = %d, want 2", len(out.Calendars))
	}
}

func TestCalendarEventsTool_RangeAndDecryptedFields(t *testing.T) {
	st := calStore(t)
	ctx := context.Background()
	mustCal(t, st, "cal-1", "Personal")
	mustEnvelope(t, st, "ev-1", "cal-1", 1000)
	mustEnvelope(t, st, "ev-2", "cal-1", 5000)
	// Decrypt ev-1 only.
	if err := st.FillCalendarEventDecrypted(ctx, "ev-1", store.CalendarEventDecrypted{Summary: "Standup", Location: "Zoom"}); err != nil {
		t.Fatal(err)
	}

	tl := calendarEvents(Deps{Store: st}) // no Session → no on-demand decrypt
	// Range [0, 3600) covers ev-1 (start 1000) but not ev-2 (start 5000).
	raw, _ := json.Marshal(map[string]any{"from": "1970-01-01", "to": "1970-01-01T01:00:00Z"})
	res, err := tl.Handler(mcp.Context{Std: ctx}, raw)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := res.StructuredContent.(calendarEventsResult)
	if !ok {
		t.Fatalf("result type = %T", res.StructuredContent)
	}
	// Range [0, 7200) covers only ev-1 (start 1000); ev-2 (5000) is excluded.
	if len(out.Events) != 1 || out.Events[0].EventID != "ev-1" {
		t.Fatalf("range result = %+v", out.Events)
	}
	if out.Events[0].Summary != "Standup" || out.Events[0].Location != "Zoom" {
		t.Errorf("decrypted summary not surfaced: %+v", out.Events[0])
	}
}

func TestCalendarEventsTool_EnvelopeOnlyWithoutSession(t *testing.T) {
	st := calStore(t)
	mustCal(t, st, "cal-1", "Personal")
	mustEnvelope(t, st, "ev-1", "cal-1", 1000)

	tl := calendarEvents(Deps{Store: st}) // no session: undecrypted stays envelope-only
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	out := res.StructuredContent.(calendarEventsResult)
	if len(out.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(out.Events))
	}
	if out.Events[0].Summary != "" {
		t.Errorf("summary should be empty without decryption, got %q", out.Events[0].Summary)
	}
	if out.Events[0].StartUnix != 1000 {
		t.Errorf("envelope start missing: %d", out.Events[0].StartUnix)
	}
}

func TestCalendarReadEventTool_CacheHit(t *testing.T) {
	st := calStore(t)
	ctx := context.Background()
	mustCal(t, st, "cal-1", "Personal")
	mustEnvelope(t, st, "ev-1", "cal-1", 1000)
	if err := st.FillCalendarEventDecrypted(ctx, "ev-1", store.CalendarEventDecrypted{
		Summary: "Review", Description: "quarterly",
		AttendeesJSON: `[{"email":"bob@example.com","name":"Bob","status":"ACCEPTED"}]`,
	}); err != nil {
		t.Fatal(err)
	}

	tl := calendarReadEvent(Deps{Store: st}) // no session: cache hit must not need one
	res, err := tl.Handler(mcp.Context{Std: ctx}, json.RawMessage(`{"event_id":"ev-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	detail, ok := res.StructuredContent.(*protonclient.CalendarEventDetail)
	if !ok {
		t.Fatalf("result type = %T", res.StructuredContent)
	}
	if detail.Summary != "Review" || detail.Description != "quarterly" {
		t.Errorf("detail = %+v", detail)
	}
	if len(detail.Attendees) != 1 || detail.Attendees[0].Email != "bob@example.com" {
		t.Errorf("attendees not decoded from JSON: %+v", detail.Attendees)
	}
}

func TestCalendarReadEventTool_NotInStoreNeedsCalendarID(t *testing.T) {
	st := calStore(t)
	tl := calendarReadEvent(Deps{Store: st}) // no session, event not mirrored
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(`{"event_id":"missing"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("expected an error result when the event isn't mirrored and no calendar_id is given")
	}
}

func TestCalendarReadEventTool_RequiresEventID(t *testing.T) {
	st := calStore(t)
	tl := calendarReadEvent(Deps{Store: st})
	if _, err := tl.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(`{}`)); err == nil {
		t.Error("expected InvalidParams error for missing event_id")
	}
}
