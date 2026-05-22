// Package sync drives the event-cursor poll loop that keeps the local
// SQLite mirror in lockstep with the Proton server.
//
// RunOnce is the unit of work: read the stored cursor, call
// client.GetEvent in a loop until the server says it has nothing
// more, apply each diff to the store, and advance the cursor as we
// go (so a crash mid-loop doesn't re-process events on the next run).
//
// Phase 2/C ships RunOnce. Phase 6's daemon will call into this on a
// 30s/5m active/idle cadence from a goroutine; the CLI exposes a
// `protonmcp sync` one-shot for testing and manual nudges.
package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// cursorKey is the sync_state row name that holds the latest applied
// event ID. Matches what cmd/protonmcp/backfill.go writes after the
// initial cold drain.
const cursorKey = "event_cursor"

// RunResult summarizes a RunOnce call so callers (CLI / daemon /
// future audit log) can print or persist meaningful numbers.
type RunResult struct {
	StartCursor   string
	EndCursor     string
	Pages         int           // event pages drained
	MessagesUpserted int
	MessagesDeleted  int
	LabelsUpserted   int
	LabelsDeleted    int
	RefreshRequested bool          // server asked for a full backfill
	Elapsed          time.Duration
}

// ErrRefreshRequested is returned when the server signals the cursor
// is too old to replay events. The caller must drop the mirror and
// re-run `protonmcp backfill`. We don't auto-drop the SQLite store —
// that would silently delete cached bodies + audit log; the user
// should decide.
var ErrRefreshRequested = errors.New("sync: server requested a full refresh — run `protonmcp backfill` again")

// RunOnce drains all pending events from the saved cursor and
// returns. Idempotent: re-running after a successful run is a no-op
// (no events past the cursor → returns immediately).
//
// Errors during page application abort the loop. The cursor is
// already advanced for pages successfully applied, so a re-run picks
// up from the failure point.
func RunOnce(ctx context.Context, sess *protonclient.Session, st *store.Store) (*RunResult, error) {
	start := time.Now()
	res := &RunResult{}

	cursor, err := st.GetSyncState(ctx, cursorKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No cursor → caller hasn't run backfill yet. Capture the
			// latest event ID and store it; equivalent to "start
			// listening from now".
			latest, lerr := sess.LatestEventID(ctx)
			if lerr != nil {
				return res, fmt.Errorf("seed cursor: %w", lerr)
			}
			if serr := st.SetSyncState(ctx, cursorKey, latest); serr != nil {
				return res, fmt.Errorf("save seeded cursor: %w", serr)
			}
			res.StartCursor = latest
			res.EndCursor = latest
			res.Elapsed = time.Since(start)
			slog.Info("sync seeded cursor",
				"cursor", latest, "note", "no prior backfill — listening from now")
			return res, nil
		}
		return res, fmt.Errorf("read cursor: %w", err)
	}
	res.StartCursor = cursor

	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		events, _, err := sess.Client.GetEvent(ctx, cursor)
		if err != nil {
			return res, fmt.Errorf("get event %s: %w", cursor, err)
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			res.Pages++
			if e.Refresh != 0 {
				res.RefreshRequested = true
				return res, ErrRefreshRequested
			}
			if err := applyEvent(ctx, st, e, res); err != nil {
				return res, fmt.Errorf("apply event %s: %w", e.EventID, err)
			}
			cursor = e.EventID
			if err := st.SetSyncState(ctx, cursorKey, cursor); err != nil {
				return res, fmt.Errorf("persist cursor: %w", err)
			}
		}
		// GetEvent already chunked up to its internal limit (50 by
		// default). If we got fewer than that, the server is caught
		// up; stop polling so we don't spin.
		if len(events) < 2 {
			break
		}
	}

	res.EndCursor = cursor
	res.Elapsed = time.Since(start)
	slog.Info("sync drained",
		"pages", res.Pages,
		"messages_upserted", res.MessagesUpserted,
		"messages_deleted", res.MessagesDeleted,
		"elapsed_ms", res.Elapsed.Milliseconds(),
	)
	return res, nil
}

// applyEvent walks a single Event and applies every diff to the
// store. Message bodies are NOT re-fetched here — Update events
// invalidate the cached body by zeroing body_cached_at, so the next
// `protonmcp read` triggers a fresh decrypt.
func applyEvent(ctx context.Context, st *store.Store, e gpa.Event, res *RunResult) error {
	for _, m := range e.Messages {
		switch m.Action {
		case gpa.EventDelete:
			if err := st.DeleteMessage(ctx, m.ID); err != nil {
				return err
			}
			res.MessagesDeleted++
		case gpa.EventCreate, gpa.EventUpdate, gpa.EventUpdateFlags:
			row, err := protonclient.ToStoreMessage(m.Message)
			if err != nil {
				return err
			}
			if err := st.UpsertMessage(ctx, row); err != nil {
				return err
			}
			if err := st.SetMessageLabels(ctx, m.ID, m.Message.LabelIDs); err != nil {
				return err
			}
			// Update events potentially mean the body changed (drafts
			// in particular). Invalidate the body cache so the next
			// read fetches fresh.
			if m.Action != gpa.EventCreate {
				if err := st.InvalidateBodyCache(ctx, m.ID); err != nil {
					return err
				}
			}
			res.MessagesUpserted++
		}
	}

	for _, l := range e.Labels {
		switch l.Action {
		case gpa.EventDelete:
			if err := st.DeleteLabel(ctx, l.ID); err != nil {
				return err
			}
			res.LabelsDeleted++
		case gpa.EventCreate, gpa.EventUpdate, gpa.EventUpdateFlags:
			if err := st.UpsertLabel(ctx, store.Label{
				ID:    l.Label.ID,
				Name:  l.Label.Name,
				Color: l.Label.Color,
				Type:  int(l.Label.Type),
			}); err != nil {
				return err
			}
			res.LabelsUpserted++
		}
	}

	return nil
}
