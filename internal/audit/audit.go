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
// SECURITY D8: the SQL write runs on a DETACHED context with a
// short timeout, not the caller's. The caller's ctx may already be
// cancelled (handler timeout, client disconnect, SIGTERM mid-Touch
// ID); modernc/sqlite would refuse the write and the row would
// never land. We want the audit log to be complete precisely when
// shutdowns get interesting — otherwise the row that documents
// what just happened loses the moment forensic questions get
// asked.
//
// Caller MUST have already redacted ArgsJSON via internal/redact.JSON.
func (w *Writer) Begin(ctx context.Context, e *Entry) int64 {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	detached, cancel := detachedAuditCtx(ctx)
	defer cancel()
	res, err := w.db.ExecContext(detached, `
INSERT INTO audit_log (ts, caller_pid, caller_binary, caller_uid, tool, args_json, policy_decision)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp.Unix(),
		e.Caller.PID,
		e.Caller.Binary,
		e.Caller.UID,
		e.Tool,
		// D26: bind as []byte, not string. modernc/sqlite treats
		// them identically at the wire, but []byte avoids the
		// allocation a string() conversion would do and reads
		// naturally for "this column holds opaque bytes."
		[]byte(e.ArgsJSON),
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
// SECURITY D8: same detached-ctx treatment as Begin. A cancelled
// request ctx mid-handler would otherwise leave the row's outcome
// NULL forever — the exact state the audit row is supposed to
// prevent.
//
// id=0 (Begin failed) → Complete is a no-op; we logged the Begin
// failure already.
func (w *Writer) Complete(ctx context.Context, id int64, outcome, approvalSource, errMsg string, dur time.Duration) {
	if id == 0 {
		return
	}
	detached, cancel := detachedAuditCtx(ctx)
	defer cancel()

	// Caller info comes from the in-flight Entry; the middleware
	// holds it via the closure that built this Complete invocation.
	// For JSONL we need it on the line too (D18), so we fetch the
	// row's metadata as part of the same statement that updates
	// outcome. Cheap UPDATE...RETURNING isn't supported by all
	// drivers; we do a separate SELECT for the JSONL path.
	_, err := w.db.ExecContext(detached, `
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
		// D18: read back the row's identifying fields so the JSONL
		// line is self-contained — operators tailing the file
		// shouldn't need a SQLite query to know what the entry was.
		var row jsonlContext
		_ = w.db.QueryRowContext(detached, `
SELECT tool, caller_pid, caller_binary, policy_decision, args_json
  FROM audit_log WHERE id = ?
`, id).Scan(&row.Tool, &row.CallerPID, &row.CallerBinary, &row.PolicyDecision, &row.ArgsJSON)

		w.mu.Lock()
		defer w.mu.Unlock()
		if jerr := w.jsonl.WriteCompleted(detached, id, outcome, approvalSource, errMsg, dur, row); jerr != nil {
			w.logger.Warn("audit jsonl write failed; SQLite row OK",
				"id", id, "err", jerr.Error())
		}
	}
}

// jsonlContext is the per-row identifying metadata the D18 fix
// pulls back from SQLite so the JSONL mirror line is self-
// contained. Populated via the SELECT inside Complete.
type jsonlContext struct {
	Tool           string
	CallerPID      int64
	CallerBinary   string
	PolicyDecision string
	ArgsJSON       string
}

// detachedAuditCtx returns a fresh context with a short timeout,
// independent of the caller's ctx. Used by Begin / Complete /
// SetDecision so audit writes run to completion even when the
// request context is already cancelled.
//
// 5 seconds is generous for a one-row local SQLite UPDATE. If we
// can't write within that window, the DB is in trouble and the
// daemon has bigger problems than missing one audit row.
func detachedAuditCtx(parent context.Context) (context.Context, context.CancelFunc) {
	// We deliberately ignore the parent — that's the whole point of
	// "detached." But if the parent has a trace/span context, future
	// observability work might want to propagate that; the comment
	// is here so the seam is obvious.
	_ = parent
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// SetDecision backfills the policy_decision column on a row Begin
// created with empty decision. Used by the MCP middleware once the
// policy engine returns — keeps the audit row reflective of the
// decision even if a panic happens between Begin and Complete.
//
// SECURITY D8: detached-ctx, same reasons as Begin / Complete.
//
// No-op if id is 0 (Begin failed).
func (w *Writer) SetDecision(ctx context.Context, id int64, decision string) error {
	if id == 0 {
		return nil
	}
	detached, cancel := detachedAuditCtx(ctx)
	defer cancel()
	_, err := w.db.ExecContext(detached,
		`UPDATE audit_log SET policy_decision = ? WHERE id = ?`,
		decision, id)
	if err != nil {
		w.logger.Warn("audit SetDecision failed", "id", id, "err", err.Error())
		return err
	}
	return nil
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
