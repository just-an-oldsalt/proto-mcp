package store

import (
	"context"
	"testing"
)

func TestCalendarEventsBlocked_SetKeepsSinceAndClears(t *testing.T) {
	ctx := context.Background()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, ok, err := st.CalendarEventsBlocked(ctx); err != nil || ok {
		t.Fatalf("fresh store: ok=%v err=%v, want unset", ok, err)
	}

	if err := st.SetCalendarEventsBlocked(ctx, []string{"calendar"}); err != nil {
		t.Fatal(err)
	}
	// Backdate so a re-set within the same second is distinguishable.
	if _, err := st.DB.ExecContext(ctx, `UPDATE sync_state SET updated_at = 1000 WHERE key = ?`, SyncKeyCalendarEventsBlocked); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCalendarEventsBlocked(ctx, []string{"calendar"}); err != nil {
		t.Fatal(err)
	}
	blk, ok, err := st.CalendarEventsBlocked(ctx)
	if err != nil || !ok {
		t.Fatalf("after set: ok=%v err=%v", ok, err)
	}
	if blk.Value != "missing_scope:calendar" {
		t.Errorf("value = %q", blk.Value)
	}
	if blk.Since.Unix() != 1000 {
		t.Errorf("since = %d, want the original timestamp kept (1000)", blk.Since.Unix())
	}

	if err := st.ClearCalendarEventsBlocked(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.CalendarEventsBlocked(ctx); ok {
		t.Error("still set after clear")
	}
	if err := st.ClearCalendarEventsBlocked(ctx); err != nil {
		t.Errorf("clearing an unset flag: %v", err)
	}
}
