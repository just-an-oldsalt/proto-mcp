package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RateLimitState is one bucket's persisted state. Phase 6/E.
// internal/mcp.rateLimiter loads these at startup and writes back
// on every Allow() so daemon restarts (planned or unplanned) don't
// hand a fresh full bucket to the next call.
type RateLimitState struct {
	Key        string
	LimitSpec  string    // "20/hour" etc, copied from the policy at bucket-creation time
	Tokens     float64   // remaining tokens; <1 → next call denied
	LastRefill time.Time // when tokens were last computed
}

// LoadRateLimitState returns every persisted bucket, keyed by the
// composite (tool|pid) string the in-memory limiter uses.
// Returns nil + nil if the table is empty.
func (s *Store) LoadRateLimitState(ctx context.Context) (map[string]RateLimitState, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT key, limit_spec, tokens, last_refill FROM rate_limit_state
`)
	if err != nil {
		return nil, fmt.Errorf("load rate_limit_state: %w", err)
	}
	defer rows.Close()
	out := map[string]RateLimitState{}
	for rows.Next() {
		var (
			st       RateLimitState
			lastUnix int64
		)
		if err := rows.Scan(&st.Key, &st.LimitSpec, &st.Tokens, &lastUnix); err != nil {
			return nil, err
		}
		st.LastRefill = time.Unix(lastUnix, 0).UTC()
		out[st.Key] = st
	}
	return out, rows.Err()
}

// SaveRateLimitBucket upserts a single bucket. Called by the in-
// memory limiter on every Allow() so the persisted view tracks
// the in-memory one.
//
// Cheap: one UPSERT on a 4-column row. SQLite handles thousands
// per second on the WAL-mode DB we already opened.
func (s *Store) SaveRateLimitBucket(ctx context.Context, st RateLimitState) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO rate_limit_state (key, limit_spec, tokens, last_refill, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    limit_spec  = excluded.limit_spec,
    tokens      = excluded.tokens,
    last_refill = excluded.last_refill,
    updated_at  = excluded.updated_at
`,
		st.Key, st.LimitSpec, st.Tokens, st.LastRefill.Unix(), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("save rate_limit bucket %s: %w", st.Key, err)
	}
	return nil
}

// PruneRateLimitOlderThan deletes buckets whose last_refill is older
// than cutoff. Run at startup to avoid carrying around buckets for
// long-dead Claude client PIDs. The in-memory limiter discards
// stale buckets on next-use anyway; this is just disk hygiene.
func (s *Store) PruneRateLimitOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM rate_limit_state WHERE last_refill < ?`,
		cutoff.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("prune rate_limit_state: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Used to surface "no buckets persisted yet" cleanly. Currently
// not returned anywhere — Load returns an empty map for that case —
// kept here for future API consumers.
var ErrNoBuckets = errors.New("store: no persisted rate-limit buckets")

// sql.NullInt64 unused; placeholder so the import stays referenced
// if a future column ends up nullable.
var _ = sql.NullInt64{}
