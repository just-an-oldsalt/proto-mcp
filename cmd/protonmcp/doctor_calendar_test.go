package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// These tests touch only a temp SQLite file: no keystore, no daemon, and
// HOME pointed at a temp dir so nothing can reach the real one.

func openDoctorStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "mirror.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

func findCheck(r *report, name string) (check, bool) {
	for _, c := range r.checks {
		if c.name == name {
			return c, true
		}
	}
	return check{}, false
}

func TestCheckCalendar_Blocked(t *testing.T) {
	ctx := context.Background()
	st, _ := openDoctorStore(t)
	if err := st.SetCalendarEventsBlocked(ctx, []string{"calendar"}); err != nil {
		t.Fatal(err)
	}

	var r report
	checkCalendar(ctx, &r, st)
	c, ok := findCheck(&r, "calendar")
	if !ok {
		t.Fatal("no calendar line when events are blocked")
	}
	if c.state != stateWarn {
		t.Errorf("state = %v, want warn", c.state)
	}
	if !strings.Contains(c.detail, "calendar scope not granted — events unavailable (issue #110)") {
		t.Errorf("detail = %q", c.detail)
	}
}

// Nothing recorded → no line, so a mail-only user's doctor output is
// unchanged.
func TestCheckCalendar_NotBlockedIsSilent(t *testing.T) {
	st, _ := openDoctorStore(t)
	var r report
	checkCalendar(context.Background(), &r, st)
	if len(r.checks) != 0 {
		t.Errorf("checks = %+v, want none", r.checks)
	}
}

// checkStore wires the calendar check in, after the mirror line, even
// when the mirror check itself fails (an empty mirror returns early).
func TestCheckStore_IncludesCalendarLine(t *testing.T) {
	ctx := context.Background()
	st, path := openDoctorStore(t)
	if err := st.SetCalendarEventsBlocked(ctx, []string{"calendar"}); err != nil {
		t.Fatal(err)
	}

	var r report
	checkStore(ctx, &r, path)
	if len(r.checks) != 2 || r.checks[0].name != "local mirror" || r.checks[1].name != "calendar" {
		t.Fatalf("checks = %+v, want [local mirror, calendar]", r.checks)
	}
}
