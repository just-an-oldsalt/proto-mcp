package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Calendar mirrors a row in the calendars table.
type Calendar struct {
	ID          string
	Name        string
	Description string
	Color       string
	Type        int // 0=normal, 1=subscribed
	Active      bool
}

// CalendarEventEnvelope is the plaintext metadata written on every sync
// pass (the SDK returns these unencrypted). The decrypted text fields
// live in CalendarEventDecrypted and are filled lazily.
type CalendarEventEnvelope struct {
	ID          string
	CalendarID  string
	UID         string
	StartUnix   int64
	StartTZ     string
	EndUnix     int64
	EndTZ       string
	AllDay      bool
	Author      string
	CreatedUnix int64
	LastEdit    int64
}

// CalendarEventDecrypted is the post-decryption text written by
// FillCalendarEventDecrypted on first read (or by calendar-backfill).
type CalendarEventDecrypted struct {
	Summary       string
	Location      string
	Description   string
	Organizer     string
	Status        string
	RRULE         string
	IsRecurring   bool
	AttendeesJSON string
	RawICal       string
}

// CalendarEventRow is a full mirror row: envelope plus whatever decrypted
// fields are present. Decrypted reports whether the row has been
// decrypted yet (decrypted_at IS NOT NULL).
type CalendarEventRow struct {
	CalendarEventEnvelope
	CalendarEventDecrypted
	Decrypted bool
}

// CalendarEventFilter narrows ListCalendarEvents. Zero fields mean "no
// constraint" except Limit, which defaults/clamps.
type CalendarEventFilter struct {
	CalendarID string // optional
	FromUnix   int64  // optional lower bound on start_unix (inclusive)
	ToUnix     int64  // optional upper bound on start_unix (exclusive)
	Query      string // optional FTS over summary/location/description
	Limit      int
	Offset     int
}

// UpsertCalendar inserts or updates a calendar row.
func (s *Store) UpsertCalendar(ctx context.Context, c Calendar) error {
	const q = `
INSERT INTO calendars (id, name, description, color, type, active)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    name        = excluded.name,
    description = excluded.description,
    color       = excluded.color,
    type        = excluded.type,
    active      = excluded.active
`
	_, err := s.DB.ExecContext(ctx, q, c.ID, c.Name, c.Description, c.Color, c.Type, boolToInt(c.Active))
	if err != nil {
		return fmt.Errorf("upsert calendar %s: %w", c.ID, err)
	}
	return nil
}

// ListCalendars returns all mirrored calendars, name-ordered.
func (s *Store) ListCalendars(ctx context.Context) ([]Calendar, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, name, description, color, type, active FROM calendars ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list calendars: %w", err)
	}
	defer rows.Close()

	var out []Calendar
	for rows.Next() {
		var (
			c           Calendar
			description sql.NullString
			color       sql.NullString
			active      int
		)
		if err := rows.Scan(&c.ID, &c.Name, &description, &color, &c.Type, &active); err != nil {
			return nil, fmt.Errorf("scan calendar: %w", err)
		}
		c.Description = description.String
		c.Color = color.String
		c.Active = active != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCalendar removes a calendar; its events cascade-delete via the FK
// and the FTS rows follow via the events delete trigger.
func (s *Store) DeleteCalendar(ctx context.Context, calendarID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM calendars WHERE id = ?`, calendarID)
	if err != nil {
		return fmt.Errorf("delete calendar %s: %w", calendarID, err)
	}
	return nil
}

// UpsertCalendarEventEnvelope writes plaintext metadata only. The
// ON CONFLICT clause deliberately leaves the decrypted columns untouched
// so a re-sync never drops a cached decryption (same trick as
// UpsertMessage with body_text/body_html).
func (s *Store) UpsertCalendarEventEnvelope(ctx context.Context, e CalendarEventEnvelope) error {
	const q = `
INSERT INTO calendar_events (
    id, calendar_id, uid, start_unix, start_tz, end_unix, end_tz,
    all_day, author, created_unix, last_edit
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    calendar_id  = excluded.calendar_id,
    uid          = excluded.uid,
    start_unix   = excluded.start_unix,
    start_tz     = excluded.start_tz,
    end_unix     = excluded.end_unix,
    end_tz       = excluded.end_tz,
    all_day      = excluded.all_day,
    author       = excluded.author,
    created_unix = excluded.created_unix,
    last_edit    = excluded.last_edit
`
	_, err := s.DB.ExecContext(ctx, q,
		e.ID, e.CalendarID, e.UID, e.StartUnix, e.StartTZ, e.EndUnix, e.EndTZ,
		boolToInt(e.AllDay), e.Author, e.CreatedUnix, e.LastEdit,
	)
	if err != nil {
		return fmt.Errorf("upsert calendar event %s: %w", e.ID, err)
	}
	return nil
}

// FillCalendarEventDecrypted writes the decrypted text fields and stamps
// decrypted_at. The FTS update trigger re-indexes summary/location/
// description on the same statement.
func (s *Store) FillCalendarEventDecrypted(ctx context.Context, eventID string, d CalendarEventDecrypted) error {
	const q = `
UPDATE calendar_events SET
    summary        = ?,
    location       = ?,
    description    = ?,
    organizer      = ?,
    status         = ?,
    rrule          = ?,
    is_recurring   = ?,
    attendees_json = ?,
    raw_ical       = ?,
    decrypted_at   = ?
WHERE id = ?
`
	_, err := s.DB.ExecContext(ctx, q,
		d.Summary, d.Location, d.Description, d.Organizer, d.Status, d.RRULE,
		boolToInt(d.IsRecurring), d.AttendeesJSON, d.RawICal, time.Now().Unix(), eventID,
	)
	if err != nil {
		return fmt.Errorf("fill calendar event %s: %w", eventID, err)
	}
	return nil
}

const calendarEventCols = `
    id, calendar_id, uid, start_unix, start_tz, end_unix, end_tz, all_day,
    author, created_unix, last_edit, summary, location, description,
    organizer, status, rrule, is_recurring, attendees_json, raw_ical,
    decrypted_at`

// GetCalendarEvent returns one event by ID, or ErrNotFound.
func (s *Store) GetCalendarEvent(ctx context.Context, eventID string) (CalendarEventRow, error) {
	q := `SELECT` + calendarEventCols + ` FROM calendar_events WHERE id = ?`
	return scanCalendarEventRow(s.DB.QueryRowContext(ctx, q, eventID))
}

// ListCalendarEvents returns events matching the filter, ordered
// chronologically by start time. If Query is set it joins the FTS index.
func (s *Store) ListCalendarEvents(ctx context.Context, f CalendarEventFilter) ([]CalendarEventRow, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var (
		conds []string
		args  []any
	)
	if f.CalendarID != "" {
		conds = append(conds, "calendar_id = ?")
		args = append(args, f.CalendarID)
	}
	if f.FromUnix > 0 {
		conds = append(conds, "start_unix >= ?")
		args = append(args, f.FromUnix)
	}
	if f.ToUnix > 0 {
		conds = append(conds, "start_unix < ?")
		args = append(args, f.ToUnix)
	}
	if m := ftsMatch(f.Query); m != "" {
		conds = append(conds, "id IN (SELECT event_id FROM calendar_events_fts WHERE calendar_events_fts MATCH ?)")
		args = append(args, m)
	}

	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}

	// LIMIT/OFFSET bound as params; ORDER BY is a fixed literal.
	q := `SELECT` + calendarEventCols + ` FROM calendar_events WHERE ` + where +
		` ORDER BY start_unix ASC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)

	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list calendar events: %w", err)
	}
	defer rows.Close()

	var out []CalendarEventRow
	for rows.Next() {
		r, err := scanCalendarEventRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReconcileCalendarEvents deletes mirror rows for a calendar that are no
// longer in the live set returned by the API (handles event deletions —
// the calendar API has no delete cursor). Returns the number deleted.
// Done in Go (load IDs, diff) to sidestep SQLite's bound-parameter cap on
// a large NOT IN (...) list.
func (s *Store) ReconcileCalendarEvents(ctx context.Context, calendarID string, liveIDs []string) (int64, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM calendar_events WHERE calendar_id = ?`, calendarID)
	if err != nil {
		return 0, fmt.Errorf("reconcile list %s: %w", calendarID, err)
	}
	defer rows.Close()

	var existing []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("reconcile scan: %w", err)
		}
		existing = append(existing, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	live := make(map[string]struct{}, len(liveIDs))
	for _, id := range liveIDs {
		live[id] = struct{}{}
	}

	var deleted int64
	for _, id := range existing {
		if _, ok := live[id]; ok {
			continue
		}
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM calendar_events WHERE id = ?`, id); err != nil {
			return deleted, fmt.Errorf("reconcile delete %s: %w", id, err)
		}
		deleted++
	}
	return deleted, nil
}

// PurgeCalendarOlderThan NULLs the decrypted columns on events whose
// decrypted_at < cutoff, keeping the envelope. Parallel to messages
// PurgeOlderThan; the FTS trigger re-indexes the cleared text. Returns
// rows affected.
func (s *Store) PurgeCalendarOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
UPDATE calendar_events
   SET summary        = NULL,
       location       = NULL,
       description    = NULL,
       organizer      = NULL,
       status         = NULL,
       rrule          = NULL,
       is_recurring   = 0,
       attendees_json = NULL,
       raw_ical       = NULL,
       decrypted_at   = NULL
 WHERE decrypted_at IS NOT NULL
   AND decrypted_at  < ?
`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("purge calendar events: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge calendar rows-affected: %w", err)
	}
	return n, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCalendarEventRow(sc rowScanner) (CalendarEventRow, error) {
	var (
		r           CalendarEventRow
		uid         sql.NullString
		startTZ     sql.NullString
		endTZ       sql.NullString
		author      sql.NullString
		createdUnix sql.NullInt64
		summary     sql.NullString
		location    sql.NullString
		description sql.NullString
		organizer   sql.NullString
		status      sql.NullString
		rrule       sql.NullString
		isRecurring int
		attendees   sql.NullString
		rawICal     sql.NullString
		decryptedAt sql.NullInt64
		allDay      int
	)
	err := sc.Scan(
		&r.ID, &r.CalendarID, &uid, &r.StartUnix, &startTZ, &r.EndUnix, &endTZ, &allDay,
		&author, &createdUnix, &r.LastEdit, &summary, &location, &description,
		&organizer, &status, &rrule, &isRecurring, &attendees, &rawICal, &decryptedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CalendarEventRow{}, ErrNotFound
	}
	if err != nil {
		return CalendarEventRow{}, fmt.Errorf("scan calendar event: %w", err)
	}
	r.UID = uid.String
	r.StartTZ = startTZ.String
	r.EndTZ = endTZ.String
	r.AllDay = allDay != 0
	r.Author = author.String
	r.CreatedUnix = createdUnix.Int64
	r.Summary = summary.String
	r.Location = location.String
	r.Description = description.String
	r.Organizer = organizer.String
	r.Status = status.String
	r.RRULE = rrule.String
	r.IsRecurring = isRecurring != 0
	r.AttendeesJSON = attendees.String
	r.RawICal = rawICal.String
	r.Decrypted = decryptedAt.Valid
	return r, nil
}

// ftsMatch turns a free-text query into a safe FTS5 MATCH expression:
// each whitespace-separated term is wrapped as a quoted phrase (internal
// quotes doubled) so user input can't be interpreted as FTS operators or
// throw a syntax error. Empty/whitespace input returns "".
func ftsMatch(query string) string {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(fields))
	for _, f := range fields {
		quoted = append(quoted, `"`+strings.ReplaceAll(f, `"`, `""`)+`"`)
	}
	return strings.Join(quoted, " ")
}
