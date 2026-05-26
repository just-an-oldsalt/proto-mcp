-- Phase 8/A — on-demand attachment cache.
--
-- proto-mcp's sync loop intentionally does NOT auto-download
-- attachment bytes (a 10k-attachment mailbox would otherwise stall
-- backfill for ~30 minutes and pay for storage that may never be
-- read). Instead the LLM calls mail_download_attachment when it
-- actually needs the content; the first call fetches + decrypts +
-- caches here, subsequent calls hit cache.
--
-- Retention model:
--   * Per-row TTL: 30 days, swept by `protonmcp purge` (same cadence
--     as the body cache; see migration 0001 + internal/store/messages.go
--     PurgeOlderThan for the parallel pattern).
--   * Hard ceiling: 500 MiB total cached bytes. Enforced in
--     internal/store/attachments.go Store.EvictAttachmentsToFit by
--     deleting oldest-cached_at rows until under the cap. Called at
--     the end of every mail_download_attachment cache-miss path.
--   * FK cascade: if the parent messages row is deleted (sync's
--     EventDelete path → store.DeleteMessage → DELETE FROM messages;
--     also mail_delete_permanent's eventual sync round-trip), the
--     cached attachments for that message follow automatically. No
--     orphan cleanup needed.
--
-- Threat-model note: the content column holds plaintext attachment
-- bytes. Same D13 / C-1 plaintext-at-rest risk as body_text /
-- body_html. The `secure_delete=on` pragma set in store.Open zeros
-- freed pages on the next write, so post-purge bytes don't linger
-- in unallocated cells. SQLCipher / envelope encryption is the
-- proper Phase 9+ mitigation; this migration matches the body
-- cache's current posture rather than reinventing.
--
-- Schema:
--   message_id     parent messages.id (FK cascade).
--   attachment_id  Proton's per-attachment identifier from the
--                  message metadata; opaque, unique within a
--                  message.
--   filename       sanitized filename (sanitize.Filename applied
--                  before insert). Display-safe; not used as a
--                  filesystem path directly.
--   mime_type      Proton-reported Content-Type. Trusted for
--                  display; never used to dispatch executable
--                  paths.
--   size_bytes     length of `content` in bytes; cached so we
--                  can SUM() for the eviction sweep without
--                  paying the BLOB-length cost.
--   content        raw plaintext bytes. Decrypted by
--                  Session.FetchAndDecryptAttachment before
--                  insert.
--   cached_at      Unix-seconds insert time. Indexed for the
--                  eviction-by-oldest sweep + the retention
--                  purge.

-- +goose Up
CREATE TABLE attachment_cache (
    message_id    TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    filename      TEXT NOT NULL,
    mime_type     TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    content       BLOB NOT NULL,
    cached_at     INTEGER NOT NULL,
    PRIMARY KEY (message_id, attachment_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachment_cache_cached_at ON attachment_cache(cached_at);

-- +goose Down
DROP INDEX IF EXISTS idx_attachment_cache_cached_at;
DROP TABLE IF EXISTS attachment_cache;
