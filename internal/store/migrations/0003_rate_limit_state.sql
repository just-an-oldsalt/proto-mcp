-- Phase 6/E — persistent rate-limit buckets. Before this, the
-- internal/mcp.rateLimiter held tokens only in memory; a daemon
-- restart (planned via launchctl, or unplanned via crash + KeepAlive)
-- reset every bucket to full. For mail_send rate_limit: 20/hour
-- that meant a misbehaving client could circumvent the cap by
-- triggering daemon restarts. Phase 6/E persists buckets so
-- restarts don't grant fresh budgets.
--
-- Schema:
--   key            unique per-(tool, caller_pid) bucket identifier.
--                  Same string the in-memory rateLimiter map uses
--                  (composed in middleware.go as `tool + "|" +
--                  strconv.Itoa(pid)`).
--   limit_spec     the policy's rate_limit string ("20/hour" etc).
--                  Stored so a policy change that lowers the cap
--                  takes effect on next call rather than holding
--                  the bucket's old capacity until natural refill.
--   tokens         floating-point remaining tokens. <1 = blocks.
--   last_refill    Unix-seconds of the last refill calculation.
--                  The reader computes (now - last_refill) *
--                  refillRate and adds to tokens (capped at the
--                  policy's capacity).
--   updated_at     for debugging — when was the row last touched.

-- +goose Up
CREATE TABLE rate_limit_state (
    key          TEXT PRIMARY KEY,
    limit_spec   TEXT NOT NULL,
    tokens       REAL NOT NULL,
    last_refill  INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS rate_limit_state;
