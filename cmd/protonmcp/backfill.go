package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/cli"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// runBackfill drains the account's message metadata into the local
// SQLite mirror. It does not fetch or decrypt bodies — those are
// populated lazily on first read in Phase 2.
//
// Order of operations is deliberately conservative:
//
//  1. Open the local store (applies migrations).
//  2. Log in to Proton.
//  3. Capture the latest event ID BEFORE backfill, so the future sync
//     loop replays anything that changes during the drain. Storing the
//     cursor after backfill would silently drop events that happen
//     mid-drain.
//  4. Count messages, confirm if large (unless --yes).
//  5. Page through metadata, upsert each row + replace its label set.
//  6. Persist the captured cursor under sync_state.event_cursor.
func runBackfill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt for large mailboxes")
	limit := fs.Int("limit", 0, "stop after writing this many messages (0 = no limit; useful for spot-checks)")
	confirmThreshold := fs.Int("confirm-threshold", 5000, "prompt for confirmation when total message count exceeds this")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := *dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}
	fmt.Printf("Opening store at %s …\n", path)
	st, err := store.Open(path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	bundle, err := acquireSession(acquireCtx)
	if err != nil {
		return err
	}
	defer bundle.Close()
	defer bundle.Session.Close()
	sess := bundle.Session

	cursor, err := sess.LatestEventID(ctx)
	if err != nil {
		return fmt.Errorf("capture event cursor: %w", err)
	}
	fmt.Printf("Captured event cursor: %s\n", cursor)

	// SECURITY D32 — seed the local labels/folders mirror. Before
	// this, the labels table only populated via the sync event loop,
	// so pre-existing labels never landed unless the user changed
	// one. labels_list / folders_list both returned null on a freshly
	// backfilled mirror.
	if err := backfillLabels(ctx, sess, st); err != nil {
		// Non-fatal — messages backfill is the main thing. Print a
		// warning so the user knows labels_list / folders_list will
		// return null until the next label-change event syncs.
		fmt.Fprintf(os.Stderr, "warning: label backfill failed (continuing): %v\n", err)
	}

	total, err := sess.CountMessages(ctx)
	if err != nil {
		return fmt.Errorf("count messages: %w", err)
	}
	fmt.Printf("Account has %d messages.\n", total)
	if total > *confirmThreshold && !*yes {
		ans, err := cli.PromptLine(ctx, fmt.Sprintf("Drain all %d into local store? [y/N]: ", total))
		if err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(ans), "y") {
			return errors.New("aborted")
		}
	}

	start := time.Now()
	written := 0
	lastReport := time.Now()
	reportEvery := 2 * time.Second

	// Pull newest-first so recent mail lands in the local mirror in
	// the first few pages. A user running `protonmcp backfill` against
	// a multi-year mailbox can start using MCP after ~30 seconds even
	// if the long historical tail keeps grinding in the background.
	// (Proton's default sort is by Time; Desc=true reverses it.)
	walkErr := sess.ForEachMessageMetadataPage(ctx, gpa.MessageFilter{Desc: gpa.Bool(true)}, func(batch []gpa.MessageMetadata) error {
		for _, m := range batch {
			row, err := protonclient.ToStoreMessage(m)
			if err != nil {
				return fmt.Errorf("translate %s: %w", m.ID, err)
			}
			if err := st.UpsertMessage(ctx, row); err != nil {
				return err
			}
			if err := st.SetMessageLabels(ctx, m.ID, m.LabelIDs); err != nil {
				return fmt.Errorf("labels for %s: %w", m.ID, err)
			}
			written++
			if *limit > 0 && written >= *limit {
				return errLimitReached
			}
		}
		if time.Since(lastReport) > reportEvery {
			rate := float64(written) / time.Since(start).Seconds()
			fmt.Printf("  ... %d / %d  (%.0f msg/s)\n", written, total, rate)
			lastReport = time.Now()
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errLimitReached) {
		return fmt.Errorf("walk messages: %w", walkErr)
	}

	if err := st.SetSyncState(ctx, "event_cursor", cursor); err != nil {
		return fmt.Errorf("persist cursor: %w", err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	fmt.Printf("Backfill complete: %d messages in %s (avg %.0f msg/s).\n",
		written, elapsed, float64(written)/elapsed.Seconds())
	if errors.Is(walkErr, errLimitReached) {
		fmt.Printf("Stopped early due to --limit %d.\n", *limit)
	}
	return nil
}

// errLimitReached is an internal sentinel used to stop ForEachPage when
// --limit is hit. It's not exposed and not an error condition for the
// command — runBackfill swallows it.
var errLimitReached = errors.New("limit reached")

// backfillLabels fetches every user-defined label and folder from
// Proton and upserts each into the local mirror's `labels` table.
// SECURITY D32: previously the labels table only populated via the
// sync event loop, so a freshly-backfilled mirror returned null
// from labels_list and folders_list until the user changed a label.
//
// We fetch both LabelTypeLabel (user labels) and LabelTypeFolder
// (user folders) — the schema column distinguishes them.
func backfillLabels(ctx context.Context, sess *protonclient.Session, st *store.Store) error {
	labels, err := sess.Client.GetLabels(ctx, gpa.LabelTypeLabel, gpa.LabelTypeFolder)
	if err != nil {
		return fmt.Errorf("fetch labels: %w", err)
	}
	n := 0
	for _, l := range labels {
		if err := st.UpsertLabel(ctx, store.Label{
			ID:    l.ID,
			Name:  l.Name,
			Color: l.Color,
			Type:  int(l.Type),
		}); err != nil {
			return fmt.Errorf("upsert label %s: %w", l.ID, err)
		}
		n++
	}
	fmt.Printf("Seeded %d label(s)/folder(s) into the local mirror.\n", n)
	return nil
}
