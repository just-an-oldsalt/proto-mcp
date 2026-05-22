// Package audit writes one row per MCP tool invocation to two
// destinations: the SQLite audit_log table (queryable, source of
// truth) and a JSONL mirror file (tailable, best-effort).
//
// Pattern is pre-then-fill: middleware calls Begin BEFORE running
// the tool handler, passing the policy decision and redacted args.
// Begin returns the row's autoincrement ID. The handler runs;
// success or failure, middleware calls Complete with the outcome,
// any error message, and the duration.
//
// A row that begins but never completes (process crash mid-call)
// stays in SQLite with NULL outcome — useful forensic signal. The
// JSONL mirror only receives the line at Complete time, so it
// never carries a partial entry.
//
// Redaction: args_json must be passed through internal/redact.JSON
// BEFORE Begin is called. This package doesn't redact internally
// to keep the contract obvious — caller is responsible.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// Entry is the data the middleware passes into Begin. ID is
// populated by Begin from the SQLite autoincrement; callers don't
// set it.
type Entry struct {
	ID             int64
	Timestamp      time.Time
	Caller         caller.Caller
	Tool           string
	ArgsJSON       json.RawMessage // already redacted
	PolicyDecision string          // "allow" | "prompt" | "deny"
}

// Outcome values the middleware passes to Complete. String-typed for
// the SQLite column; constants here keep callers honest.
const (
	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"
)

// Writer is the dual-destination logger. Construct via New().
// Methods are safe for concurrent use from multiple goroutines.
type Writer struct {
	db     *sql.DB
	jsonl  *jsonlMirror
	logger *slog.Logger
	mu     sync.Mutex // serializes the JSONL writer; SQLite has its own pool lock
}

// New opens (or creates) the JSONL mirror at jsonlPath and returns
// a Writer that writes to both db and jsonl. db must already have
// the audit_log table from Phase 1's migration.
//
// jsonlPath can be "" to disable the mirror entirely (handy for
// tests; production always has it).
func New(db *sql.DB, jsonlPath string, logger *slog.Logger) (*Writer, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: db is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	w := &Writer{db: db, logger: logger}
	if jsonlPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o700); err != nil {
			return nil, fmt.Errorf("audit: create jsonl dir: %w", err)
		}
		m, err := openJSONLMirror(jsonlPath)
		if err != nil {
			return nil, fmt.Errorf("audit: open jsonl: %w", err)
		}
		w.jsonl = m
	}
	return w, nil
}

// Close releases the JSONL file handle. SQLite is owned by the
// caller (store.Store) — we don't close it here.
func (w *Writer) Close() error {
	if w.jsonl == nil {
		return nil
	}
	return w.jsonl.Close()
}

// Begin writes the pre-action row. Returns the SQLite row ID for
// later Complete. Failure to write is logged but doesn't return an
// error — the tool call should still run even if the audit DB is
// transiently unavailable (we'd rather degrade the audit trail than
// brick the daemon).
//
// Caller MUST have already redacted ArgsJSON via internal/redact.JSON.
func (w *Writer) Begin(ctx context.Context, e *Entry) int64 {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	res, err := w.db.ExecContext(ctx, `
INSERT INTO audit_log (ts, caller_pid, caller_binary, caller_uid, tool, args_json, policy_decision)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp.Unix(),
		e.Caller.PID,
		e.Caller.Binary,
		e.Caller.UID,
		e.Tool,
		string(e.ArgsJSON),
		e.PolicyDecision,
	)
	if err != nil {
		w.logger.Warn("audit Begin failed; tool call proceeds without audit row",
			"tool", e.Tool, "err", err.Error())
		return 0
	}
	id, err := res.LastInsertId()
	if err != nil {
		w.logger.Warn("audit Begin: LastInsertId failed", "tool", e.Tool, "err", err.Error())
		return 0
	}
	e.ID = id
	return id
}

// Complete updates the row identified by id with the final outcome
// and appends one line to the JSONL mirror. approvalSource is one
// of "policy", "touchid", "cached", or "" if not gated.
//
// id=0 (Begin failed) → Complete is a no-op; we logged the Begin
// failure already.
func (w *Writer) Complete(ctx context.Context, id int64, outcome, approvalSource, errMsg string, dur time.Duration) {
	if id == 0 {
		return
	}
	_, err := w.db.ExecContext(ctx, `
UPDATE audit_log SET outcome = ?, approval_source = ?, error_msg = ?, duration_ms = ?
WHERE id = ?`,
		outcome, approvalSource, errMsg, dur.Milliseconds(), id,
	)
	if err != nil {
		w.logger.Warn("audit Complete failed; row remains NULL",
			"id", id, "err", err.Error())
		return
	}
	if w.jsonl != nil {
		w.mu.Lock()
		defer w.mu.Unlock()
		if jerr := w.jsonl.WriteCompleted(ctx, id, outcome, approvalSource, errMsg, dur); jerr != nil {
			w.logger.Warn("audit jsonl write failed; SQLite row OK",
				"id", id, "err", jerr.Error())
		}
	}
}

// DefaultJSONLPath is the canonical location of the audit JSONL.
// Phase 4 uses this; Phase 7's log rotation will reuse it.
func DefaultJSONLPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "audit.log"), nil
}
