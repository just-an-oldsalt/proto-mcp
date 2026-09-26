package serve

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// The daemon ticks every 2 minutes; a blocked account must produce one
// Warn, not one per tick, and a recovery must re-arm it.
func TestCalendarScopeLog_WarnsOnceThenDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var c calendarScopeLog
	blocked := &syncpkg.CalendarRunResult{EventsBlocked: true, MissingScopes: []string{"calendar"}}

	count := func(level string) int { return strings.Count(buf.String(), "level="+level) }

	c.observe(logger, blocked)
	c.observe(logger, blocked)
	c.observe(logger, blocked)
	if w, d := count("WARN"), count("DEBUG"); w != 1 || d != 2 {
		t.Fatalf("warn=%d debug=%d, want 1/2:\n%s", w, d, buf.String())
	}
	if !strings.Contains(buf.String(), "#110") || !strings.Contains(buf.String(), "missing_scopes=calendar") {
		t.Errorf("warn lacks the actionable text:\n%s", buf.String())
	}

	c.observe(logger, &syncpkg.CalendarRunResult{}) // events reachable again
	c.observe(logger, blocked)
	if w := count("WARN"); w != 2 {
		t.Errorf("warn=%d after recovery + re-block, want 2", w)
	}
	c.observe(logger, nil) // failed run: no result, no change
}
