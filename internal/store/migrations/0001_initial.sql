-- +goose Up

CREATE TABLE messages (
    id              TEXT PRIMARY KEY,
    thread_id       TEXT NOT NULL,
    subject         TEXT,
    from_address    TEXT,
    from_name       TEXT,
    to_json         TEXT,    -- JSON array of {name, address}
    cc_json         TEXT,    -- JSON array of {name, address}
    date            INTEGER NOT NULL, -- unix seconds
    unread          INTEGER NOT NULL DEFAULT 0,
    starred         INTEGER NOT NULL DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    folder          TEXT,
    size_bytes      INTEGER,
    raw_json        TEXT,    -- full proton message metadata JSON
    body_text       TEXT,    -- nullable; populated on first decrypt
    body_html       TEXT,    -- nullable; populated on first decrypt
    body_cached_at  INTEGER  -- unix seconds; null until body is cached
);

CREATE INDEX idx_messages_thread ON messages(thread_id);
CREATE INDEX idx_messages_date   ON messages(date DESC);
CREATE INDEX idx_messages_folder ON messages(folder);
CREATE INDEX idx_messages_unread ON messages(unread) WHERE unread = 1;

CREATE TABLE message_labels (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    label_id   TEXT NOT NULL,
    PRIMARY KEY (message_id, label_id)
);
CREATE INDEX idx_message_labels_label ON message_labels(label_id);

CREATE TABLE labels (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL,
    color TEXT,
    type  INTEGER NOT NULL  -- 1=label, 3=folder per proton schema
);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    message_id UNINDEXED,
    subject,
    from_address,
    from_name,
    to_addresses,
    body_text,
    tokenize = 'porter unicode61'
);

-- +goose StatementBegin
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(message_id, subject, from_address, from_name, to_addresses, body_text)
    VALUES (NEW.id, NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.id;
    INSERT INTO messages_fts(message_id, subject, from_address, from_name, to_addresses, body_text)
    VALUES (NEW.id, NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd

CREATE TABLE sync_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    caller_pid      INTEGER,
    caller_binary   TEXT,
    caller_uid      INTEGER,
    tool            TEXT NOT NULL,
    args_json       TEXT,
    policy_decision TEXT,
    approval_source TEXT,
    outcome         TEXT,
    error_msg       TEXT,
    duration_ms     INTEGER
);
CREATE INDEX idx_audit_ts   ON audit_log(ts);
CREATE INDEX idx_audit_tool ON audit_log(tool);

-- +goose Down
DROP INDEX IF EXISTS idx_audit_tool;
DROP INDEX IF EXISTS idx_audit_ts;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS sync_state;
DROP TRIGGER IF EXISTS messages_fts_update;
DROP TRIGGER IF EXISTS messages_fts_delete;
DROP TRIGGER IF EXISTS messages_fts_insert;
DROP TABLE IF EXISTS messages_fts;
DROP TABLE IF EXISTS labels;
DROP INDEX IF EXISTS idx_message_labels_label;
DROP TABLE IF EXISTS message_labels;
DROP INDEX IF EXISTS idx_messages_unread;
DROP INDEX IF EXISTS idx_messages_folder;
DROP INDEX IF EXISTS idx_messages_date;
DROP INDEX IF EXISTS idx_messages_thread;
DROP TABLE IF EXISTS messages;
