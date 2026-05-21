package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Message is the in-Go representation of a row in the messages table.
// Fields use Go-native zero values; nullable columns map to pointer
// types so callers can distinguish "absent" from "empty".
type Message struct {
	ID             string
	ThreadID       string
	Subject        string
	FromAddress    string
	FromName       string
	ToJSON         string
	CcJSON         string
	Date           time.Time
	Unread         bool
	Starred        bool
	HasAttachments bool
	Folder         string
	SizeBytes      int64
	RawJSON        string

	BodyText     *string
	BodyHTML     *string
	BodyCachedAt *time.Time
}

// UpsertMessage inserts a new row or overwrites an existing one with the
// same ID. Body fields are preserved across upserts (sync updates touch
// only envelope columns), so callers can re-run backfill without losing
// the lazily-decrypted body cache.
func (s *Store) UpsertMessage(ctx context.Context, m Message) error {
	const q = `
INSERT INTO messages (
    id, thread_id, subject, from_address, from_name, to_json, cc_json,
    date, unread, starred, has_attachments, folder, size_bytes, raw_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    thread_id       = excluded.thread_id,
    subject         = excluded.subject,
    from_address    = excluded.from_address,
    from_name       = excluded.from_name,
    to_json         = excluded.to_json,
    cc_json         = excluded.cc_json,
    date            = excluded.date,
    unread          = excluded.unread,
    starred         = excluded.starred,
    has_attachments = excluded.has_attachments,
    folder          = excluded.folder,
    size_bytes      = excluded.size_bytes,
    raw_json        = excluded.raw_json
`
	_, err := s.DB.ExecContext(ctx, q,
		m.ID, m.ThreadID, m.Subject, m.FromAddress, m.FromName,
		m.ToJSON, m.CcJSON, m.Date.Unix(),
		boolToInt(m.Unread), boolToInt(m.Starred), boolToInt(m.HasAttachments),
		m.Folder, m.SizeBytes, m.RawJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert message %s: %w", m.ID, err)
	}
	return nil
}

// GetMessage loads a single message by id. Returns ErrNotFound if absent.
func (s *Store) GetMessage(ctx context.Context, id string) (Message, error) {
	const q = `
SELECT id, thread_id, subject, from_address, from_name, to_json, cc_json,
       date, unread, starred, has_attachments, folder, size_bytes, raw_json,
       body_text, body_html, body_cached_at
FROM messages WHERE id = ?
`
	row := s.DB.QueryRowContext(ctx, q, id)

	var (
		m            Message
		dateUnix     int64
		unread       int
		starred      int
		hasAtt       int
		bodyText     sql.NullString
		bodyHTML     sql.NullString
		bodyCachedAt sql.NullInt64
	)
	err := row.Scan(
		&m.ID, &m.ThreadID, &m.Subject, &m.FromAddress, &m.FromName,
		&m.ToJSON, &m.CcJSON, &dateUnix, &unread, &starred, &hasAtt,
		&m.Folder, &m.SizeBytes, &m.RawJSON,
		&bodyText, &bodyHTML, &bodyCachedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, ErrNotFound
	}
	if err != nil {
		return Message{}, fmt.Errorf("get message %s: %w", id, err)
	}

	m.Date = time.Unix(dateUnix, 0).UTC()
	m.Unread = unread != 0
	m.Starred = starred != 0
	m.HasAttachments = hasAtt != 0
	if bodyText.Valid {
		s := bodyText.String
		m.BodyText = &s
	}
	if bodyHTML.Valid {
		s := bodyHTML.String
		m.BodyHTML = &s
	}
	if bodyCachedAt.Valid {
		t := time.Unix(bodyCachedAt.Int64, 0).UTC()
		m.BodyCachedAt = &t
	}
	return m, nil
}

// SearchMessages runs an FTS5 MATCH against the indexed envelope + body
// columns and returns message IDs ordered by rank (best match first).
// limit caps results; 0 means no limit.
func (s *Store) SearchMessages(ctx context.Context, query string, limit int) ([]string, error) {
	q := `
SELECT message_id FROM messages_fts
WHERE messages_fts MATCH ?
ORDER BY rank
`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.DB.QueryContext(ctx, q, query)
	if err != nil {
		return nil, fmt.Errorf("fts search: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("fts scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetMessageLabels replaces the label associations for a message in a
// single transaction. Pass an empty slice to clear all labels.
func (s *Store) SetMessageLabels(ctx context.Context, messageID string, labelIDs []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM message_labels WHERE message_id = ?`, messageID); err != nil {
		return fmt.Errorf("clear labels: %w", err)
	}
	for _, lid := range labelIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO message_labels(message_id, label_id) VALUES (?, ?)`,
			messageID, lid,
		); err != nil {
			return fmt.Errorf("insert label %s: %w", lid, err)
		}
	}
	return tx.Commit()
}

// SetSyncState records a single key/value pair in the sync_state table.
// Used for the event cursor and any other small per-key state.
func (s *Store) SetSyncState(ctx context.Context, key, value string) error {
	const q = `
INSERT INTO sync_state(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
`
	_, err := s.DB.ExecContext(ctx, q, key, value, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("set sync_state %s: %w", key, err)
	}
	return nil
}

// GetSyncState returns the value for key, or ErrNotFound.
func (s *Store) GetSyncState(ctx context.Context, key string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get sync_state %s: %w", key, err)
	}
	return v, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
