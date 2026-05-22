package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// openTestStore returns a fresh on-disk SQLite for the test. We
// CAN'T use ":memory:" here because modernc's sqlite driver opens
// one in-memory DB per connection, and TestConcurrentBeginComplete
// uses 50 goroutines — each goroutine that hits a fresh connection
// would see an empty schema. Temp file shares state across the
// connection pool the way production does.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBeginCompleteRoundTrip(t *testing.T) {
	st := openTestStore(t)
	jpath := filepath.Join(t.TempDir(), "audit.log")
	w, err := New(st.DB, jpath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx := context.Background()
	id := w.Begin(ctx, &Entry{
		Caller:         caller.Caller{PID: 1234, UID: 501, Binary: "/Applications/Claude.app/Contents/MacOS/Claude"},
		Tool:           "mail_list",
		ArgsJSON:       json.RawMessage(`{"folder":"inbox"}`),
		PolicyDecision: "allow",
	})
	if id == 0 {
		t.Fatal("Begin returned 0; row didn't persist")
	}
	w.Complete(ctx, id, OutcomeOK, "policy", "", 42*time.Millisecond)

	// SQLite row populated.
	var (
		outcome, approval, errMsg sql.NullString
		duration                  sql.NullInt64
	)
	row := st.DB.QueryRowContext(ctx,
		`SELECT outcome, approval_source, error_msg, duration_ms FROM audit_log WHERE id = ?`, id)
	if err := row.Scan(&outcome, &approval, &errMsg, &duration); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if outcome.String != "ok" || approval.String != "policy" || duration.Int64 != 42 {
		t.Errorf("row not updated: outcome=%v approval=%v duration=%v", outcome, approval, duration)
	}

	// JSONL line written.
	data, err := os.ReadFile(jpath)
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if !strings.Contains(string(data), `"outcome":"ok"`) {
		t.Errorf("missing outcome in jsonl: %s", data)
	}
}

func TestBeginWithoutCompleteLeavesNullOutcome(t *testing.T) {
	st := openTestStore(t)
	w, err := New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := w.Begin(ctx, &Entry{
		Caller:         caller.Caller{PID: 1},
		Tool:           "mail_read",
		ArgsJSON:       json.RawMessage(`{}`),
		PolicyDecision: "allow",
	})
	if id == 0 {
		t.Fatal("Begin returned 0")
	}
	// Don't Complete.

	var outcome sql.NullString
	if err := st.DB.QueryRowContext(ctx, `SELECT outcome FROM audit_log WHERE id = ?`, id).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.Valid {
		t.Errorf("outcome should be NULL; got %q", outcome.String)
	}
}

func TestConcurrentBeginComplete(t *testing.T) {
	st := openTestStore(t)
	jpath := filepath.Join(t.TempDir(), "audit.log")
	w, err := New(st.DB, jpath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			id := w.Begin(ctx, &Entry{
				Caller:         caller.Caller{PID: i},
				Tool:           "concurrent_tool",
				ArgsJSON:       json.RawMessage(`{}`),
				PolicyDecision: "allow",
			})
			w.Complete(ctx, id, OutcomeOK, "", "", time.Millisecond)
		}(i)
	}
	wg.Wait()

	var count int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE tool = 'concurrent_tool'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != N {
		t.Errorf("got %d rows, want %d", count, N)
	}

	data, _ := os.ReadFile(jpath)
	gotLines := strings.Count(string(data), "\n")
	if gotLines != N {
		t.Errorf("got %d jsonl lines, want %d", gotLines, N)
	}
}

func TestBeginIDIsZeroOnNullDBFails(t *testing.T) {
	// Closed DB → Begin logs Warn, returns 0, Complete is a no-op.
	st := openTestStore(t)
	st.DB.Close()
	w, err := New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := w.Begin(context.Background(), &Entry{
		Tool: "mail_list",
	})
	if id != 0 {
		t.Errorf("Begin should return 0 on closed DB; got %d", id)
	}
	// Complete with id=0 is a no-op; just verifying it doesn't panic.
	w.Complete(context.Background(), 0, OutcomeOK, "", "", time.Millisecond)
}
