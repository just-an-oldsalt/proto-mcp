package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// runCalendarBackfill seeds the local mirror with the account's calendars
// and event envelopes. By default it mirrors metadata only (decryption is
// lazy on first read, like message bodies); pass --decrypt to also decrypt
// every event up front so calendar_events full-text search works
// immediately.
func runCalendarBackfill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("calendar-backfill", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	decrypt := fs.Bool("decrypt", false, "also decrypt every event now (warms full-text search; slower)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("calendar-backfill takes no positional arguments; got %v", fs.Args())
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

	if *decrypt {
		fmt.Println("Mirroring calendars + decrypting all events (this can take a moment) …")
	} else {
		fmt.Println("Mirroring calendars + event metadata (run with --decrypt to warm search) …")
	}

	res, err := syncpkg.RunCalendarBackfill(ctx, bundle.Session, st, *decrypt)
	if err != nil {
		return err
	}

	out := struct {
		Calendars       int   `json:"calendars"`
		EventsUpserted  int   `json:"events_upserted"`
		EventsDeleted   int   `json:"events_deleted"`
		EventsDecrypted int   `json:"events_decrypted"`
		ElapsedMS       int64 `json:"elapsed_ms"`
	}{
		Calendars:       res.CalendarsUpserted,
		EventsUpserted:  res.EventsUpserted,
		EventsDeleted:   res.EventsDeleted,
		EventsDecrypted: res.EventsDecrypted,
		ElapsedMS:       res.Elapsed.Milliseconds(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
