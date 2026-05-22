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

// jsonlEntry is the shape one JSONL line takes. Subset of the
// SQLite row (we leave args_json in the DB, not the mirror — the
// mirror is for ops monitoring, not forensics). If you need full
// detail, query the DB.
type jsonlEntry struct {
	ID             int64     `json:"id"`
	CompletedAt    time.Time `json:"completed_at"`
	Outcome        string    `json:"outcome"`
	ApprovalSource string    `json:"approval_source,omitempty"`
	ErrorMsg       string    `json:"error_msg,omitempty"`
	DurationMS     int64     `json:"duration_ms"`
}

// WriteCompleted serializes one line and appends. The caller holds
// the mutex on the Writer for serialization across concurrent
// Complete calls.
func (m *jsonlMirror) WriteCompleted(_ context.Context, id int64, outcome, approvalSource, errMsg string, dur time.Duration) error {
	line, err := json.Marshal(jsonlEntry{
		ID:             id,
		CompletedAt:    time.Now().UTC(),
		Outcome:        outcome,
		ApprovalSource: approvalSource,
		ErrorMsg:       errMsg,
		DurationMS:     dur.Milliseconds(),
	})
	if err != nil {
		return fmt.Errorf("marshal jsonl entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := m.f.Write(line); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	return nil
}
