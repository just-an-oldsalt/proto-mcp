package serve

import (
	"log/slog"
	"strings"
	"sync/atomic"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// calendarScopeLog de-duplicates the daemon's "calendar events are
// blocked" message (issue #110). The block lasts until Proton grants the
// calendar scope, which no restart or re-login changes, so warning on
// every 2-minute tick would bury daemon.log. The first blocked pass in
// this process logs Warn with the actionable text, later ones log Debug,
// and a pass that reaches events re-arms the Warn in case the block
// comes back.
type calendarScopeLog struct {
	warned atomic.Bool
}

func (c *calendarScopeLog) observe(logger *slog.Logger, res *syncpkg.CalendarRunResult) {
	if res == nil {
		return
	}
	if !res.EventsBlocked {
		c.warned.Store(false)
		return
	}
	scopes := strings.Join(res.MissingScopes, ",")
	if c.warned.CompareAndSwap(false, true) {
		logger.Warn("background calendar sync: "+protonclient.CalendarScopeNotice+
			" Calendars are still mirrored; this repeats at debug level while it persists.",
			"missing_scopes", scopes)
		return
	}
	logger.Debug("background calendar sync: events still blocked (issue #110)",
		"missing_scopes", scopes)
}
