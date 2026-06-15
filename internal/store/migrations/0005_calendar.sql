-- Phase 9 — read-only Proton Calendar mirror.
--
-- Mirrors calendars + events locally so calendar_list / calendar_events
-- / calendar_read_event serve fast, offline, FTS-searchable results, the
-- same way the messages mirror backs the mail tools.
--
-- Two-tier columns, mirroring messages (envelope vs body_text/body_html):
--   * PLAINTEXT METADATA — start/end/timezone/all-day/uid/author/edit
--     time. These come straight from the SDK's CalendarEvent (Proton
--     returns them unencrypted), so sync writes them on every pass.
--   * DECRYPTED-LAZILY — summary/location/description/organizer/status/
--     rrule/attendees_json/raw_ical. NULL until the first decrypt; filled
--     by FillCalendarEventDecrypted on first read (or eagerly by
--     `protonmcp calendar-backfill --decrypt`). The envelope upsert never
--     overwrites these, so a re-sync doesn't drop a cached decryption —
--     same trick UpsertMessage uses to preserve body_text/body_html.
--
-- Sync model (see internal/sync/calendar.go): the global event stream
-- carries NO calendar delta (gpa.Event has only Messages/Labels/
-- Addresses), so calendar sync is a dedicated poll. Change detection is
-- per-calendar max(last_edit) stored in sync_state under
-- `calendar_max_edit:<calendarID>`; deletes are handled by a full-set
-- reconcile against the live event IDs each pass.
--
-- Threat-model note: summary/location/description/raw_ical hold
-- decrypted (plaintext) event content — the same D13 / C-1
-- plaintext-at-rest posture as body_text/attachment_cache.content. The
-- `secure_delete=on` pragma (store.Open) zeros freed pages on the next
-- write, and PurgeCalendarOlderThan NULLs the decrypted columns past the
-- TTL (parallel to messages PurgeOlderThan). SQLCipher / envelope
-- encryption is the eventual Phase 9+ fix; this matches the existing
-- posture rather than reinventing.

-- +goose Up
CREATE TABLE calendars (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    color       TEXT,
    type        INTEGER NOT NULL DEFAULT 0,  -- 0=normal, 1=subscribed
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE calendar_events (
    id            TEXT PRIMARY KEY,
    calendar_id   TEXT NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    uid           TEXT,                          -- iCal UID (groups recurrence)
    -- plaintext metadata (written every sync pass):
    start_unix    INTEGER NOT NULL,
    start_tz      TEXT,
    end_unix      INTEGER NOT NULL DEFAULT 0,
    end_tz        TEXT,
    all_day       INTEGER NOT NULL DEFAULT 0,
    author        TEXT,
    created_unix  INTEGER,
    last_edit     INTEGER NOT NULL,              -- LastEditTime; sync change-detection
    -- decrypted-lazily (NULL until first decrypt; envelope upsert never clobbers):
    summary        TEXT,
    location       TEXT,
    description    TEXT,
    organizer      TEXT,
    status         TEXT,
    rrule          TEXT,
    is_recurring   INTEGER NOT NULL DEFAULT 0,
    attendees_json TEXT,                          -- JSON array of {email,name,status,role}
    raw_ical       TEXT,
    decrypted_at   INTEGER                        -- unix; NULL until decrypted
);

CREATE INDEX idx_calendar_events_calendar ON calendar_events(calendar_id);
CREATE INDEX idx_calendar_events_start    ON calendar_events(start_unix);
CREATE INDEX idx_calendar_events_uid      ON calendar_events(uid);

CREATE VIRTUAL TABLE calendar_events_fts USING fts5(
    event_id UNINDEXED,
    summary,
    location,
    description,
    tokenize = 'porter unicode61'
);

-- +goose StatementBegin
CREATE TRIGGER calendar_events_fts_insert AFTER INSERT ON calendar_events BEGIN
    INSERT INTO calendar_events_fts(event_id, summary, location, description)
    VALUES (NEW.id, NEW.summary, NEW.location, NEW.description);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER calendar_events_fts_delete AFTER DELETE ON calendar_events BEGIN
    DELETE FROM calendar_events_fts WHERE event_id = OLD.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER calendar_events_fts_update AFTER UPDATE ON calendar_events BEGIN
    DELETE FROM calendar_events_fts WHERE event_id = OLD.id;
    INSERT INTO calendar_events_fts(event_id, summary, location, description)
    VALUES (NEW.id, NEW.summary, NEW.location, NEW.description);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS calendar_events_fts_update;
DROP TRIGGER IF EXISTS calendar_events_fts_delete;
DROP TRIGGER IF EXISTS calendar_events_fts_insert;
DROP TABLE IF EXISTS calendar_events_fts;
DROP INDEX IF EXISTS idx_calendar_events_uid;
DROP INDEX IF EXISTS idx_calendar_events_start;
DROP INDEX IF EXISTS idx_calendar_events_calendar;
DROP TABLE IF EXISTS calendar_events;
DROP TABLE IF EXISTS calendars;
