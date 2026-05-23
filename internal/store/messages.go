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

// Label is the in-Go representation of a row in the labels table.
type Label struct {
	ID    string
	Name  string
	Color string
	Type  int // 1=label, 3=folder per Proton schema
}

// UpsertLabel inserts or overwrites a single label row. Used by the
// event-loop sync goroutine on label.create / label.update events.
func (s *Store) UpsertLabel(ctx context.Context, l Label) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO labels (id, name, color, type) VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, color = excluded.color, type = excluded.type
`, l.ID, l.Name, l.Color, l.Type)
	if err != nil {
		return fmt.Errorf("upsert label %s: %w", l.ID, err)
	}
	return nil
}

// GetLabel returns a single label by ID. ErrNotFound when absent —
// the caller (Phase-5 labels_update / folders_update handlers) treats
// that as "the local mirror hasn't synced yet" and proceeds with
// caller-supplied fields only.
func (s *Store) GetLabel(ctx context.Context, labelID string) (Label, error) {
	var l Label
	var color sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, name, color, type FROM labels WHERE id = ?`, labelID).
		Scan(&l.ID, &l.Name, &color, &l.Type)
	if errors.Is(err, sql.ErrNoRows) {
		return Label{}, ErrNotFound
	}
	if err != nil {
		return Label{}, fmt.Errorf("get label %s: %w", labelID, err)
	}
	if color.Valid {
		l.Color = color.String
	}
	return l, nil
}

// DeleteLabel removes a label row. The message_labels rows referencing
// it stay (no FK back from message_labels.label_id → labels.id) so
// per-message label sets stay consistent with the server's view.
func (s *Store) DeleteLabel(ctx context.Context, labelID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM labels WHERE id = ?`, labelID)
	if err != nil {
		return fmt.Errorf("delete label %s: %w", labelID, err)
	}
	return nil
}

// DeleteMessage removes a message row. message_labels rows cascade-
// delete via the FK; messages_fts entries are removed by the trigger
// set up in 0001_initial.sql.
func (s *Store) DeleteMessage(ctx context.Context, messageID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, messageID)
	if err != nil {
		return fmt.Errorf("delete message %s: %w", messageID, err)
	}
	return nil
}

// InvalidateBodyCache zeroes body_cached_at on a single row so the
// next GetCachedBody returns ErrNotFound and triggers a refetch.
// body_text / body_html stay populated (search still works against
// the stale text); only the freshness signal changes.
func (s *Store) InvalidateBodyCache(ctx context.Context, messageID string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE messages SET body_cached_at = NULL WHERE id = ?`, messageID)
	if err != nil {
		return fmt.Errorf("invalidate body cache %s: %w", messageID, err)
	}
	return nil
}

// PurgeOlderThan hard-deletes body_text / body_html / body_cached_at
// on every row whose body_cached_at < cutoff. Returns the number of
// rows updated.
//
// SECURITY D13 / C-1 mitigation. The audit's biggest residual risk
// — three cycles open — is that decrypted message bodies live on
// disk in cleartext until something explicitly removes them. This
// is the explicit-removal helper: serve-stdio calls it at startup,
// `protonmcp purge` calls it on demand.
//
// The FTS update trigger fires on every UPDATE, so messages_fts
// re-indexes with the now-NULL body_text on the same statement.
// Combined with the secure_delete=on pragma (set in store.go via
// the DSN), the cleared cells get zeroed on the next page write
// rather than left as recoverable slack space.
//
// rowsAffected is best-effort: modernc/sqlite returns it correctly
// for our UPDATE; if a driver behind-this-interface ever didn't,
// the count would be -1 and we'd still have purged successfully.
func (s *Store) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
UPDATE messages
   SET body_text       = NULL,
       body_html       = NULL,
       body_cached_at  = NULL
 WHERE body_cached_at IS NOT NULL
   AND body_cached_at  < ?
`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("purge bodies: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge bodies rows-affected: %w", err)
	}
	return n, nil
}

// PurgeStats reports how many rows have cached bodies AND how many
// would be removed by a purge with the given cutoff. Used by
// `protonmcp purge --dry-run` and by the serve-stdio startup
// log so the user has a sense of what got cleaned.
type PurgeStats struct {
	TotalCached   int64
	WouldPurge    int64
	OldestCached  *time.Time
}

// CountCachedBodies returns purge planning info: total rows with
// cached bodies, how many would be purged at the given cutoff, and
// the timestamp of the oldest cached body (or nil if none cached).
func (s *Store) CountCachedBodies(ctx context.Context, cutoff time.Time) (PurgeStats, error) {
	var stats PurgeStats
	err := s.DB.QueryRowContext(ctx, `
SELECT COUNT(*) FROM messages WHERE body_cached_at IS NOT NULL
`).Scan(&stats.TotalCached)
	if err != nil {
		return stats, fmt.Errorf("count cached bodies: %w", err)
	}
	err = s.DB.QueryRowContext(ctx, `
SELECT COUNT(*) FROM messages WHERE body_cached_at IS NOT NULL AND body_cached_at < ?
`, cutoff.Unix()).Scan(&stats.WouldPurge)
	if err != nil {
		return stats, fmt.Errorf("count would-purge bodies: %w", err)
	}
	var oldestUnix sql.NullInt64
	err = s.DB.QueryRowContext(ctx, `
SELECT MIN(body_cached_at) FROM messages WHERE body_cached_at IS NOT NULL
`).Scan(&oldestUnix)
	if err != nil {
		return stats, fmt.Errorf("oldest cached: %w", err)
	}
	if oldestUnix.Valid {
		t := time.Unix(oldestUnix.Int64, 0).UTC()
		stats.OldestCached = &t
	}
	return stats, nil
}

// DefaultBodyRetention is the at-rest TTL applied at serve-stdio
// startup. Bodies older than this get hard-deleted from the local
// mirror. 30 days is a sensible default: long enough that the
// LLM's working set survives a typical idle period, short enough
// that a stolen laptop's exposure is bounded.
//
// SECURITY D13 / C-1: this is the only at-rest mitigation pending
// SQLCipher / envelope encryption (Phase 6+). Tighten by overriding
// via `protonmcp purge --older-than 7d`.
const DefaultBodyRetention = 30 * 24 * time.Hour

// BodyTTL is how long a cached body counts as fresh. After this, the
// row's body_* columns are treated as missing (GetCachedBody returns
// ErrNotFound). Re-fetch will replace them. The sync loop's
// invalidate-on-update is the primary mechanism for staleness; this
// TTL is the defense-in-depth backstop. Per design spec.
const BodyTTL = 24 * time.Hour

// CachedBody holds the post-decryption text + sanitized HTML for a
// single message, plus the cache timestamp.
type CachedBody struct {
	Text     string
	HTML     string
	CachedAt time.Time

	// ThreadID — if set, also persisted to messages.thread_id when
	// passed to SetCachedBody. Phase 2 uses this to reconstruct
	// threading from RFC 2822 In-Reply-To / References headers after
	// the body fetch.
	ThreadID string
}

// SetCachedBody writes the decrypted-and-sanitized body for a message.
// Updates body_text / body_html / body_cached_at on the row. If
// b.ThreadID is non-empty, also overwrites messages.thread_id.
func (s *Store) SetCachedBody(ctx context.Context, msgID string, b CachedBody) error {
	if b.CachedAt.IsZero() {
		b.CachedAt = time.Now().UTC()
	}
	if b.ThreadID == "" {
		_, err := s.DB.ExecContext(ctx,
			`UPDATE messages SET body_text = ?, body_html = ?, body_cached_at = ? WHERE id = ?`,
			b.Text, b.HTML, b.CachedAt.Unix(), msgID,
		)
		if err != nil {
			return fmt.Errorf("set cached body %s: %w", msgID, err)
		}
		return nil
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE messages SET body_text = ?, body_html = ?, body_cached_at = ?, thread_id = ? WHERE id = ?`,
		b.Text, b.HTML, b.CachedAt.Unix(), b.ThreadID, msgID,
	)
	if err != nil {
		return fmt.Errorf("set cached body %s: %w", msgID, err)
	}
	return nil
}

// GetCachedBody returns the cached body for a message, or ErrNotFound
// if the body has never been cached OR the cache is older than
// BodyTTL. A stale cache is silently treated as missing; the caller
// is expected to fall through to a fresh fetch.
func (s *Store) GetCachedBody(ctx context.Context, msgID string) (CachedBody, error) {
	var (
		text     sql.NullString
		html     sql.NullString
		cachedAt sql.NullInt64
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT body_text, body_html, body_cached_at FROM messages WHERE id = ?`,
		msgID,
	).Scan(&text, &html, &cachedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CachedBody{}, ErrNotFound
	}
	if err != nil {
		return CachedBody{}, fmt.Errorf("get cached body %s: %w", msgID, err)
	}
	if !cachedAt.Valid || cachedAt.Int64 == 0 {
		return CachedBody{}, ErrNotFound
	}
	ts := time.Unix(cachedAt.Int64, 0).UTC()
	if time.Since(ts) > BodyTTL {
		return CachedBody{}, ErrNotFound
	}
	return CachedBody{Text: text.String, HTML: html.String, CachedAt: ts}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
