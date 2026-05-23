package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// jsonlMirror appends one JSON line per completed audit entry to a
// file the user can `tail -f` for live monitoring of MCP activity.
// Best-effort — failures here log but don't fail the tool call.
type jsonlMirror struct {
	f *os.File
}

// openJSONLMirror opens (or creates) the file with O_APPEND so
// concurrent writes from separate Writer instances would still
// produce a coherent line stream. Mode 0o600 is the right
// confidentiality posture — this file CAN contain recipient
// addresses and tool arg metadata; anyone with read access to the
// home dir would otherwise see it.
func openJSONLMirror(path string) (*jsonlMirror, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &jsonlMirror{f: f}, nil
}

func (m *jsonlMirror) Close() error { return m.f.Close() }

// jsonlEntry is the shape one JSONL line takes.
//
// SECURITY D18: prior versions of this struct held only outcome +
// duration. An operator tailing the file would see lines like
// {"id":42,"outcome":"ok","duration_ms":18} and have no idea what
// tool ran or who called it. That defeated the whole "JSONL for
// live operator monitoring" purpose — every line required a
// separate SQLite query to be useful. Worse, if the SQLite DB was
// locked / corrupted during an incident, the JSONL mirror — the
// durable evidence — was information-poor.
//
// Now each line includes tool / caller_binary / caller_pid /
// policy_decision / args_json (the redactor's output, so it's
// already body-as-sha256 and password-as-[REDACTED]). Same line-
// length budget for `tail -f`.
type jsonlEntry struct {
	ID             int64           `json:"id"`
	CompletedAt    time.Time       `json:"completed_at"`
	Tool           string          `json:"tool"`
	CallerPID      int64           `json:"caller_pid,omitempty"`
	CallerBinary   string          `json:"caller_binary,omitempty"`
	PolicyDecision string          `json:"policy_decision,omitempty"`
	Outcome        string          `json:"outcome"`
	ApprovalSource string          `json:"approval_source,omitempty"`
	ErrorMsg       string          `json:"error_msg,omitempty"`
	DurationMS     int64           `json:"duration_ms"`
	ArgsJSON       json.RawMessage `json:"args,omitempty"`
}

// WriteCompleted serializes one line and appends. The caller holds
// the mutex on the Writer for serialization across concurrent
// Complete calls. ctx is the detached audit ctx from Writer.Complete.
func (m *jsonlMirror) WriteCompleted(_ context.Context, id int64, outcome, approvalSource, errMsg string, dur time.Duration, row jsonlContext) error {
	entry := jsonlEntry{
		ID:             id,
		CompletedAt:    time.Now().UTC(),
		Tool:           row.Tool,
		CallerPID:      row.CallerPID,
		CallerBinary:   row.CallerBinary,
		PolicyDecision: row.PolicyDecision,
		Outcome:        outcome,
		ApprovalSource: approvalSource,
		ErrorMsg:       errMsg,
		DurationMS:     dur.Milliseconds(),
	}
	// ArgsJSON is already a JSON string from SQLite; emit as raw
	// JSON so the entry isn't double-encoded.
	if row.ArgsJSON != "" {
		entry.ArgsJSON = json.RawMessage(row.ArgsJSON)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal jsonl entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := m.f.Write(line); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	return nil
}
