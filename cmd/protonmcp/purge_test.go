package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// seedOldCalendarPlaintext opens a temp-dir store holding one event
// whose decryption is older than the retention window. HOME is pointed
// at a temp dir too: the purge paths also sweep the attachment
// staging dir, which lives under $HOME.
func seedOldCalendarPlaintext(t *testing.T) (*store.Store, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "purge.db")
	st, err := store.Open(path)
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
	old := time.Now().Add(-store.DefaultBodyRetention - time.Hour).Unix()
	if _, err := st.DB.ExecContext(ctx, `UPDATE calendar_events SET decrypted_at = ? WHERE id = 'ev-1'`, old); err != nil {
		t.Fatal(err)
	}
	return st, path
}

func assertCalendarPurged(t *testing.T, st *store.Store) {
	t.Helper()
	got, err := st.GetCalendarEvent(context.Background(), "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decrypted || got.Summary != "" {
		t.Errorf("stale calendar plaintext survived: decrypted=%v summary=%q", got.Decrypted, got.Summary)
	}
}

// #130 — `protonmcp purge` must clear decrypted calendar text too.
func TestRunPurge_PurgesCalendarPlaintext(t *testing.T) {
	st, path := seedOldCalendarPlaintext(t)
	if err := runPurge(context.Background(), []string{"--db", path}); err != nil {
		t.Fatalf("runPurge: %v", err)
	}
	assertCalendarPurged(t, st)
}

// #130 — as must the serve-stdio startup sweep.
func TestSweepBodiesAtStartup_PurgesCalendarPlaintext(t *testing.T) {
	st, _ := seedOldCalendarPlaintext(t)
	if _, err := sweepBodiesAtStartup(context.Background(), st); err != nil {
		t.Fatalf("sweepBodiesAtStartup: %v", err)
	}
	assertCalendarPurged(t, st)
}

func TestParseDurationFlexible(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30d", 30 * 24 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"90m", 90 * time.Minute, true},
		{"45s", 45 * time.Second, true},
		{"", 0, false},
		{"7days", 0, false}, // not Go's shape
		{"-7d", 0, false},   // our regex anchors to digits only
		{"abc", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseDurationFlexible(tc.in)
			if (err == nil) != tc.ok {
				t.Errorf("ok = %v, want %v (err=%v)", err == nil, tc.ok, err)
				return
			}
			if tc.ok && got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
