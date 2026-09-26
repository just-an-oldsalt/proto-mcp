package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SyncKeyCalendarEventsBlocked is the sync_state key recording that
// calendar event access is blocked for this session (Proton Code 9100,
// issue #110). Its value is "missing_scope:<scope>[,<scope>…]" and its
// updated_at is when the block was first seen. Calendar sync sets it,
// clears it after a successful events pass, and the calendar tools and
// doctor read it to explain an empty mirror.
const SyncKeyCalendarEventsBlocked = "calendar_events_blocked"

// CalendarEventsBlock describes a recorded block.
type CalendarEventsBlock struct {
	Value string    // e.g. "missing_scope:calendar"
	Since time.Time // first time the current block was recorded
}

// SetCalendarEventsBlocked records that event access is blocked for the
// given missing scopes. Re-recording the same value keeps the original
// timestamp, so Since means "blocked since", not "last polled".
func (s *Store) SetCalendarEventsBlocked(ctx context.Context, scopes []string) error {
	scope := strings.Join(scopes, ",")
	if scope == "" {
		scope = "unknown"
	}
	const q = `
INSERT INTO sync_state(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
WHERE sync_state.value <> excluded.value
`
	if _, err := s.DB.ExecContext(ctx, q, SyncKeyCalendarEventsBlocked, "missing_scope:"+scope, time.Now().Unix()); err != nil {
		return fmt.Errorf("set sync_state %s: %w", SyncKeyCalendarEventsBlocked, err)
	}
	return nil
}

// ClearCalendarEventsBlocked removes the block record. No-op when unset.
func (s *Store) ClearCalendarEventsBlocked(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM sync_state WHERE key = ?`, SyncKeyCalendarEventsBlocked); err != nil {
		return fmt.Errorf("clear sync_state %s: %w", SyncKeyCalendarEventsBlocked, err)
	}
	return nil
}

// CalendarEventsBlocked returns the recorded block, if any. ok is false
// (with a nil error) when event access isn't known to be blocked.
func (s *Store) CalendarEventsBlocked(ctx context.Context) (blk CalendarEventsBlock, ok bool, err error) {
	var since int64
	err = s.DB.QueryRowContext(ctx,
		`SELECT value, updated_at FROM sync_state WHERE key = ?`, SyncKeyCalendarEventsBlocked,
	).Scan(&blk.Value, &since)
	if errors.Is(err, sql.ErrNoRows) {
		return CalendarEventsBlock{}, false, nil
	}
	if err != nil {
		return CalendarEventsBlock{}, false, fmt.Errorf("get sync_state %s: %w", SyncKeyCalendarEventsBlocked, err)
	}
	blk.Since = time.Unix(since, 0)
	return blk, true, nil
}
