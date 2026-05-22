package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// runSync drains pending events into the local mirror. Phase-2 plan
// Q3: yes-CLI for testability + the manual nudge case. Phase 6's
// daemon will call into syncpkg.RunOnce on its own cadence.
func runSync(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sync takes no positional arguments; got %v", fs.Args())
	}

	path := *dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}
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

	res, err := syncpkg.RunOnce(ctx, bundle.Session, st)
	if err != nil {
		if errors.Is(err, syncpkg.ErrRefreshRequested) {
			fmt.Fprintln(os.Stderr,
				"sync: server requested a full refresh — run `protonmcp backfill` to re-seed.")
			return err
		}
		return err
	}

	out := struct {
		StartCursor      string `json:"start_cursor"`
		EndCursor        string `json:"end_cursor"`
		Pages            int    `json:"pages"`
		MessagesUpserted int    `json:"messages_upserted"`
		MessagesDeleted  int    `json:"messages_deleted"`
		LabelsUpserted   int    `json:"labels_upserted"`
		LabelsDeleted    int    `json:"labels_deleted"`
		ElapsedMS        int64  `json:"elapsed_ms"`
	}{
		StartCursor:      res.StartCursor,
		EndCursor:        res.EndCursor,
		Pages:            res.Pages,
		MessagesUpserted: res.MessagesUpserted,
		MessagesDeleted:  res.MessagesDeleted,
		LabelsUpserted:   res.LabelsUpserted,
		LabelsDeleted:    res.LabelsDeleted,
		ElapsedMS:        res.Elapsed.Milliseconds(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
