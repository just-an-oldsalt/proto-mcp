package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SearchHit is one row in a search result.
type SearchHit struct {
	MessageID   string
	ThreadID    string
	Subject     string
	FromAddress string
	FromName    string
	Date        time.Time
	Folder      string
	Snippet     string // up to ~200 chars from body_text
}

// SearchOpts narrows the search and pages results.
type SearchOpts struct {
	Limit  int // 0 → default 50, max 200
	Offset int // simple offset paging for now; opaque-cursor paging is a Phase 3 follow-up

	// Optional extra filters layered on top of the query DSL. These
	// are AND-joined with the parsed query, so calling Search with
	// `query=""` and a populated Filter gives you a plain list of
	// envelopes — Phase 3's mail.list tool exercises this path.
	Filter ListFilter
}

// ListFilter is the structured-only subset of search criteria — no
// DSL parsing. mail.list uses this; mail.search uses Search with the
// raw query string and (usually) an empty filter.
type ListFilter struct {
	Folder     string
	LabelID    string // matches if message has this label_id
	UnreadOnly bool
	ThreadID   string
	SinceUnix  int64 // inclusive lower bound (0 → no bound)
	UntilUnix  int64 // exclusive upper bound (0 → no bound)
}

// Search runs a query against the local mirror and returns matching
// rows. The query string uses a small DSL:
//
//	from:alice          → from_address LIKE %alice%
//	to:bob              → to_json LIKE %bob%
//	subject:gear        → subject LIKE %gear%
//	in:inbox            → folder = inbox
//	before:2026-01-01   → date < ts
//	after:2025-12-01    → date >= ts
//	has:attachment      → has_attachments = 1
//	bare terms          → messages_fts MATCH (against subject/from/body)
//
// Prefixed terms translate to structured WHERE clauses; bare terms
// feed into the FTS5 MATCH expression. Combine freely; everything
// AND-joined.
//
// Result ordering: FTS rank if any bare terms were given, otherwise
// date descending.
func (s *Store) Search(ctx context.Context, query string, opts SearchOpts) ([]SearchHit, error) {
	parsed := parseQuery(query)

	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}
	// SECURITY C-8. Limit / Offset are user-controllable once the
	// Phase 3 MCP layer passes them straight through from a tool
	// call. Negative Offset produces a confusing SQLite error
	// rather than the empty result the caller probably wants; clamp.
	if opts.Offset < 0 {
		opts.Offset = 0
	}

	var (
		conds  []string
		args   []any
		fromFTS bool
	)

	if parsed.fts != "" {
		// Join messages → messages_fts on message_id. Adding the FTS
		// table forces SQLite to walk only the matching rows.
		conds = append(conds, "messages.id IN (SELECT message_id FROM messages_fts WHERE messages_fts MATCH ?)")
		args = append(args, parsed.fts)
		fromFTS = true
	}
	for col, like := range parsed.likes {
		conds = append(conds, fmt.Sprintf("messages.%s LIKE ?", col))
		args = append(args, "%"+like+"%")
	}
	if parsed.folder != "" {
		conds = append(conds, "messages.folder = ?")
		args = append(args, parsed.folder)
	}
	if parsed.hasAttachment {
		conds = append(conds, "messages.has_attachments = 1")
	}
	if !parsed.before.IsZero() {
		conds = append(conds, "messages.date < ?")
		args = append(args, parsed.before.Unix())
	}
	if !parsed.after.IsZero() {
		conds = append(conds, "messages.date >= ?")
		args = append(args, parsed.after.Unix())
	}

	// Extra structured filter, layered AND. mail.list uses this with
	// an empty DSL query; mail.search usually leaves Filter zero.
	if opts.Filter.Folder != "" {
		conds = append(conds, "messages.folder = ?")
		args = append(args, opts.Filter.Folder)
	}
	if opts.Filter.LabelID != "" {
		conds = append(conds,
			"messages.id IN (SELECT message_id FROM message_labels WHERE label_id = ?)")
		args = append(args, opts.Filter.LabelID)
	}
	if opts.Filter.UnreadOnly {
		conds = append(conds, "messages.unread = 1")
	}
	if opts.Filter.ThreadID != "" {
		conds = append(conds, "messages.thread_id = ?")
		args = append(args, opts.Filter.ThreadID)
	}
	if opts.Filter.SinceUnix > 0 {
		conds = append(conds, "messages.date >= ?")
		args = append(args, opts.Filter.SinceUnix)
	}
	if opts.Filter.UntilUnix > 0 {
		conds = append(conds, "messages.date < ?")
		args = append(args, opts.Filter.UntilUnix)
	}

	where := "1=1"
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}

	orderBy := "messages.date DESC"
	if fromFTS {
		// FTS5 rank exposed via the rowid->bm25 column. Subselect
		// already filters by MATCH; reorder by joining on rank.
		orderBy = "(SELECT rank FROM messages_fts WHERE message_id = messages.id) ASC, messages.date DESC"
	}

	// SECURITY C-8. LIMIT / OFFSET bound as ? parameters rather than
	// Sprintf'd in — same defense-in-depth as the WHERE clause args.
	// orderBy is one of two hard-coded literals (the FTS-rank or the
	// plain date-DESC variants above), NOT user input.
	q := fmt.Sprintf(`
SELECT id, thread_id, subject, from_address, from_name, date, folder, body_text
  FROM messages
 WHERE %s
 ORDER BY %s
 LIMIT ? OFFSET ?
`, where, orderBy)
	args = append(args, opts.Limit, opts.Offset)

	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer rows.Close()

	var hits []SearchHit
	for rows.Next() {
		var (
			h        SearchHit
			dateUnix int64
			bodyText *string
		)
		if err := rows.Scan(&h.MessageID, &h.ThreadID, &h.Subject,
			&h.FromAddress, &h.FromName, &dateUnix, &h.Folder, &bodyText); err != nil {
			return nil, fmt.Errorf("search scan: %w", err)
		}
		h.Date = time.Unix(dateUnix, 0).UTC()
		if bodyText != nil {
			h.Snippet = snippet(*bodyText, 200)
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// snippet returns up to maxRunes runes of input, collapsing whitespace
// runs to single spaces. Duplicates a small piece of internal/sanitize
// to avoid an internal/store → internal/sanitize import (sanitize is
// already aware of store via the body-fetch path; circulars are
// painful). The actual MCP / CLI consumers should prefer
// sanitize.Snippet, which has stricter handling.
func snippet(input string, maxRunes int) string {
	// Collapse whitespace.
	var b strings.Builder
	prevSpace := true
	for _, r := range input {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	out := strings.TrimSpace(b.String())
	r := []rune(out)
	if len(r) <= maxRunes {
		return out
	}
	return string(r[:maxRunes]) + "…"
}
