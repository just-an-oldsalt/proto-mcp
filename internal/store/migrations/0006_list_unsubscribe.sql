-- #102 — cache the List-Unsubscribe / List-Unsubscribe-Post headers
-- alongside the body so mail_read can surface unsubscribe targets on a
-- cache hit.
--
-- Sync only fetches message metadata (no headers); these values arrive
-- with the full GetMessage that mail_read does, so they are stored next
-- to body_text/body_html and share the body cache's lifecycle:
--   * written by SetCachedBody on every fetch,
--   * NULLed by PurgeOlderThan with the body, because the URLs carry
--     per-recipient tokens (same D13 / C-1 plaintext-at-rest posture).
--
-- Values are raw (control-stripped, length-capped) header text; the
-- scheme filter (https / mailto only) runs at read time in
-- internal/mcptools/unsubscribe.go.
--
-- The one-time body_cached_at reset makes every pre-migration cache
-- entry a miss, so the next mail_read refetches and captures the
-- headers instead of reporting "no unsubscribe header" for 24h.
-- body_text/body_html are left intact (search keeps working).

-- +goose Up
ALTER TABLE messages ADD COLUMN list_unsubscribe TEXT;
ALTER TABLE messages ADD COLUMN list_unsubscribe_post TEXT;
UPDATE messages SET body_cached_at = NULL WHERE body_cached_at IS NOT NULL;

-- +goose Down
-- The cache reset is not reversible (and doesn't need to be).
ALTER TABLE messages DROP COLUMN list_unsubscribe_post;
ALTER TABLE messages DROP COLUMN list_unsubscribe;
