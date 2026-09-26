package serve

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// #130 — the startup retention sweep must clear decrypted calendar
// plaintext, not just message bodies. PurgeCalendarOlderThan existed
// but nothing outside tests called it.
func TestSweepStaleBodies_PurgesCalendarPlaintext(t *testing.T) {
	// SweepStaleBodies also sweeps the attachment staging dir, which
	// lives under $HOME.
	withTempHome(t)
	ctx := context.Background()

	st, err := store.Open(filepath.Join(t.TempDir(), "sweep.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertCalendar(ctx, store.Calendar{ID: "cal-1", Name: "Personal"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertCalendarEventEnvelope(ctx, store.CalendarEventEnvelope{
		ID: "ev-1", CalendarID: "cal-1", StartUnix: 1000, LastEdit: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.FillCalendarEventDecrypted(ctx, "ev-1", store.CalendarEventDecrypted{Summary: "secret meeting"}); err != nil {
		t.Fatal(err)
	}
	// Age the decryption past the retention window.
	old := time.Now().Add(-store.DefaultBodyRetention - time.Hour).Unix()
	if _, err := st.DB.ExecContext(ctx, `UPDATE calendar_events SET decrypted_at = ? WHERE id = 'ev-1'`, old); err != nil {
		t.Fatal(err)
	}

	if _, err := SweepStaleBodies(ctx, st); err != nil {
		t.Fatalf("SweepStaleBodies: %v", err)
	}

	got, err := st.GetCalendarEvent(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decrypted || got.Summary != "" {
		t.Errorf("stale calendar plaintext survived the startup sweep: decrypted=%v summary=%q", got.Decrypted, got.Summary)
	}
}
