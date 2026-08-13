package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// calendarMaxEditPrefix + a calendar ID is the sync_state key holding the
// max LastEditTime we've mirrored for that calendar. The global event
// stream carries no calendar delta (gpa.Event has only Messages/Labels/
// Addresses), so calendar sync is a dedicated poll keyed on this
// high-water mark rather than the shared event_cursor.
const calendarMaxEditPrefix = "calendar_max_edit:"

// CalendarRunResult summarizes a RunCalendarOnce / RunCalendarBackfill pass.
type CalendarRunResult struct {
	CalendarsUpserted int
	CalendarsDeleted  int
	EventsUpserted    int
	EventsDeleted     int
	EventsDecrypted   int // populated only by RunCalendarBackfill(decrypt=true)
	Elapsed           time.Duration
}

// RunCalendarOnce polls every calendar and reconciles the local mirror.
// It writes envelope (plaintext metadata) only — decryption is deferred
// to first read (or `protonmcp calendar-backfill --decrypt`) to keep the
// per-tick cost off the PGP path. Change detection is per-calendar
// max(LastEditTime); deletions are handled by a full-set reconcile
// against the live event IDs (the calendar API has no delete cursor).
func RunCalendarOnce(ctx context.Context, sess *protonclient.Session, st *store.Store) (*CalendarRunResult, error) {
	start := time.Now()
	res := &CalendarRunResult{}

	if sess == nil || sess.Client == nil {
		return res, errors.New("calendar sync: session is closed")
	}

	cals, err := sess.Client.GetCalendars(ctx)
	if err != nil {
		return res, fmt.Errorf("get calendars: %w", err)
	}

	// Phase 1 — mirror the calendars themselves. GetCalendars has already
	// succeeded, and its response carried each calendar's member record
	// (the post-request hook stashed them), so every row we write here is
	// backed by a 200. Doing this before events matters: on a session
	// without calendar scope the listing succeeds while /events 403s, and
	// this is then the only calendar data we can get. Writing it is what
	// lets calendar_list show real names on an otherwise blocked account.
	liveCalIDs := make([]string, 0, len(cals))
	for _, c := range cals {
		liveCalIDs = append(liveCalIDs, c.ID)
	}
	upsertedCals, err := syncCalendarRows(ctx, st, cals, sess.OwnCalendarMember)
	if err != nil {
		return res, err
	}
	res.CalendarsUpserted = upsertedCals

	// Reconcile calendars that disappeared server-side (their events
	// cascade-delete via the FK). This belongs with phase 1 — it is driven
	// by the listing, and running it here means a later events failure
	// can't leave a vanished calendar behind.
	deletedCals, err := reconcileCalendars(ctx, st, liveCalIDs)
	if err != nil {
		return res, err
	}
	res.CalendarsDeleted = deletedCals

	// Phase 2 — events, per calendar.
	fetch := func(ctx context.Context, calID string) ([]gpa.CalendarEvent, error) {
		return sess.Client.GetAllCalendarEvents(ctx, calID, nil)
	}
	for _, c := range cals {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		upserted, deleted, err := syncCalendarEvents(ctx, st, c.ID, fetch)
		if err != nil {
			return res, err
		}
		res.EventsUpserted += upserted
		res.EventsDeleted += deleted
	}

	res.Elapsed = time.Since(start)
	slog.Info("calendar sync",
		"calendars", res.CalendarsUpserted,
		"events_upserted", res.EventsUpserted,
		"events_deleted", res.EventsDeleted,
		"elapsed_ms", res.Elapsed.Milliseconds())
	return res, nil
}

// RunCalendarBackfill seeds the mirror from scratch: it runs the normal
// envelope sync, then (if decrypt) eagerly decrypts every event and fills
// the decrypted columns so calendar_events FTS works immediately without
// waiting for lazy per-read warming. Decrypt failures warn and continue —
// one unreadable event must not abort the backfill. The CLI
// `protonmcp calendar-backfill` drives this.
func RunCalendarBackfill(ctx context.Context, sess *protonclient.Session, st *store.Store, decrypt bool) (*CalendarRunResult, error) {
	start := time.Now()
	res, err := RunCalendarOnce(ctx, sess, st)
	if err != nil {
		return res, err
	}
	if !decrypt {
		return res, nil
	}

	cals, err := sess.Client.GetCalendars(ctx)
	if err != nil {
		return res, fmt.Errorf("get calendars: %w", err)
	}
	for _, c := range cals {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		events, err := sess.Client.GetAllCalendarEvents(ctx, c.ID, nil)
		if err != nil {
			return res, fmt.Errorf("get events for calendar %s: %w", c.ID, err)
		}
		cache := protonclient.NewCalendarKeyCache()
		for _, ev := range events {
			detail, derr := sess.DecryptCalendarEvent(ctx, ev, cache)
			if derr != nil {
				slog.Warn("calendar backfill: decrypt failed", "event", ev.ID, "err", derr.Error())
				continue
			}
			if ferr := st.FillCalendarEventDecrypted(ctx, ev.ID, toStoreDecrypted(detail)); ferr != nil {
				slog.Warn("calendar backfill: fill failed", "event", ev.ID, "err", ferr.Error())
				continue
			}
			res.EventsDecrypted++
		}
		cache.Clear()
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// toStoreDecrypted maps a decrypted event detail to the store's decrypted
// column set (attendees flattened to JSON).
func toStoreDecrypted(d *protonclient.CalendarEventDetail) store.CalendarEventDecrypted {
	out := store.CalendarEventDecrypted{
		Summary:     d.Summary,
		Location:    d.Location,
		Description: d.Description,
		Organizer:   d.Organizer,
		Status:      d.Status,
		RRULE:       d.RRULE,
		IsRecurring: d.IsRecurring,
		RawICal:     d.RawICal,
	}
	if len(d.Attendees) > 0 {
		if b, err := json.Marshal(d.Attendees); err == nil {
			out.AttendeesJSON = string(b)
		}
	}
	return out
}

// syncCalendarRows mirrors the calendar rows themselves, hydrating each
// from its member record.
//
// member is looked up rather than fetched: the listing response carries
// every calendar's members inline and the post-request hook has already
// stashed them, so this costs no network.
//
// A missing member record is survivable but not silent. The live API
// sends no display fields on the calendar object itself, so falling back
// to it writes a blank, inactive row — exactly the symptom this whole
// change set exists to fix. If that ever happens we want a breadcrumb
// rather than a mystery, so warn and carry on: a named-but-eventless
// calendar is still better than aborting the sync.
func syncCalendarRows(
	ctx context.Context,
	st *store.Store,
	cals []gpa.Calendar,
	member func(string) *protonclient.CalendarMemberFull,
) (upserted int, err error) {
	for _, c := range cals {
		if err := ctx.Err(); err != nil {
			return upserted, err
		}
		m := member(c.ID)
		if m == nil {
			slog.Warn("calendar sync: no member record for calendar, name/active will be blank",
				"calendar", c.ID)
		}
		if err := st.UpsertCalendar(ctx, toStoreCalendar(c, m)); err != nil {
			return upserted, fmt.Errorf("upsert calendar %s: %w", c.ID, err)
		}
		upserted++
	}
	return upserted, nil
}

// syncCalendarEvents mirrors one calendar's events and advances its
// high-water mark. The calendar row is expected to exist already — phase
// 1 of RunCalendarOnce writes it, and calendar_events.calendar_id is an
// FK onto calendars(id).
//
// The fetch happens before any write, so a failure (the 403 / Code 9100
// case on a session without calendar scope) leaves this calendar's events
// and high-water mark exactly as they were rather than half-applied.
//
// fetch is injected rather than taken from the session so the ordering
// guarantee is testable against an in-memory store, in the same spirit as
// applyCalendarEvents.
func syncCalendarEvents(
	ctx context.Context,
	st *store.Store,
	calID string,
	fetch func(context.Context, string) ([]gpa.CalendarEvent, error),
) (upserted, deleted int, err error) {
	events, err := fetch(ctx, calID)
	if err != nil {
		return 0, 0, fmt.Errorf("get events for calendar %s: %w", calID, err)
	}

	storedMax := readMaxEdit(ctx, st, calID)
	newMax, upserted, deleted, err := applyCalendarEvents(ctx, st, calID, events, storedMax)
	if err != nil {
		return 0, 0, err
	}

	if newMax > storedMax {
		if err := st.SetSyncState(ctx, calendarMaxEditPrefix+calID, strconv.FormatInt(newMax, 10)); err != nil {
			return upserted, deleted, fmt.Errorf("save calendar high-water for %s: %w", calID, err)
		}
	}
	return upserted, deleted, nil
}

// applyCalendarEvents upserts events whose LastEditTime exceeds storedMax,
// reconciles deletions against the live set, and returns the new
// high-water mark plus counts. It is pure with respect to the network
// (takes already-fetched events) so it can be tested against an in-memory
// store, mirroring how applyEvent is tested.
func applyCalendarEvents(ctx context.Context, st *store.Store, calID string, events []gpa.CalendarEvent, storedMax int64) (newMax int64, upserted, deleted int, err error) {
	newMax = storedMax
	liveIDs := make([]string, 0, len(events))
	for _, ev := range events {
		liveIDs = append(liveIDs, ev.ID)
		if ev.LastEditTime > newMax {
			newMax = ev.LastEditTime
		}
		// Skip events we've already mirrored at this edit time.
		if ev.LastEditTime <= storedMax {
			continue
		}
		if err := st.UpsertCalendarEventEnvelope(ctx, toEnvelope(ev)); err != nil {
			return newMax, upserted, deleted, fmt.Errorf("upsert event %s: %w", ev.ID, err)
		}
		upserted++
	}

	n, err := st.ReconcileCalendarEvents(ctx, calID, liveIDs)
	if err != nil {
		return newMax, upserted, deleted, err
	}
	deleted = int(n)
	return newMax, upserted, deleted, nil
}

// reconcileCalendars deletes local calendars no longer present server-side.
func reconcileCalendars(ctx context.Context, st *store.Store, liveIDs []string) (int, error) {
	local, err := st.ListCalendars(ctx)
	if err != nil {
		return 0, fmt.Errorf("list calendars for reconcile: %w", err)
	}
	live := make(map[string]struct{}, len(liveIDs))
	for _, id := range liveIDs {
		live[id] = struct{}{}
	}
	deleted := 0
	for _, c := range local {
		if _, ok := live[c.ID]; ok {
			continue
		}
		if err := st.DeleteCalendar(ctx, c.ID); err != nil {
			return deleted, fmt.Errorf("delete vanished calendar %s: %w", c.ID, err)
		}
		deleted++
	}
	return deleted, nil
}

func readMaxEdit(ctx context.Context, st *store.Store, calID string) int64 {
	v, err := st.GetSyncState(ctx, calendarMaxEditPrefix+calID)
	if err != nil {
		return 0 // ErrNotFound (first run) or transient — treat as cold
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// toStoreCalendar maps a calendar plus our own member record onto the
// mirror row.
//
// The live API returns display metadata on the member, not the calendar —
// `GET /calendar/v1` carries only ID and Type, so gpa.Calendar's Name /
// Description / Color / Flags decode empty and a mirrored calendar ends
// up blank and inactive. When we have the member record it is
// authoritative for those fields, matching what Proton's own web client
// does in getVisualCalendar(). See internal/proton/calendar_members.go.
//
// member may be nil — the members call failed, or a future SDK/API starts
// populating the calendar object again — in which case we fall back to
// the calendar's own fields and behave exactly as before.
func toStoreCalendar(c gpa.Calendar, member *protonclient.CalendarMemberFull) store.Calendar {
	out := store.Calendar{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Color:       c.Color,
		Type:        int(c.Type),
		Active:      c.Flags&gpa.CalendarFlagActive != 0,
	}
	if member == nil {
		return out
	}
	out.Name = member.Name
	out.Description = member.Description
	out.Color = member.Color
	out.Active = gpa.CalendarFlag(member.Flags)&gpa.CalendarFlagActive != 0
	return out
}

func toEnvelope(ev gpa.CalendarEvent) store.CalendarEventEnvelope {
	return store.CalendarEventEnvelope{
		ID:          ev.ID,
		CalendarID:  ev.CalendarID,
		UID:         ev.UID,
		StartUnix:   ev.StartTime,
		StartTZ:     ev.StartTimezone,
		EndUnix:     ev.EndTime,
		EndTZ:       ev.EndTimezone,
		AllDay:      bool(ev.FullDay),
		Author:      ev.Author,
		CreatedUnix: ev.CreateTime,
		LastEdit:    ev.LastEditTime,
	}
}
