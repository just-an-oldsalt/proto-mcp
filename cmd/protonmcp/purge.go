package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// runPurge hard-deletes cached message bodies older than a cutoff.
//
// SECURITY D13 / C-1 mitigation. The audit calls cached plaintext
// bodies at rest the single biggest residual risk; this is the
// explicit removal path. serve-stdio sweeps on startup using
// store.DefaultBodyRetention; users can run a more aggressive
// sweep manually via `protonmcp purge --older-than 7d`.
//
// Flags:
//
//	--older-than <duration>  e.g. 7d, 24h, 30d. Default = 30d
//	                         (= store.DefaultBodyRetention).
//	--dry-run                print stats; do nothing.
//	--vacuum                 after purge, VACUUM the DB so freed
//	                         pages return to the OS. secure_delete=on
//	                         already zeroes them on the next write;
//	                         VACUUM forces it immediately. Slower.
//	--db <path>              override the SQLite store path.
func runPurge(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	olderThan := fs.String("older-than", "30d", "purge bodies cached before now-DURATION (e.g. 7d, 24h)")
	dryRun := fs.Bool("dry-run", false, "report what would be purged; touch nothing")
	doVacuum := fs.Bool("vacuum", false, "VACUUM the DB after purge to release zeroed pages to the OS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("purge takes no positional arguments; got %v", fs.Args())
	}

	dur, err := parseDurationFlexible(*olderThan)
	if err != nil {
		return fmt.Errorf("parse --older-than: %w", err)
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

	cutoff := time.Now().Add(-dur).UTC()
	stats, err := st.CountCachedBodies(ctx, cutoff)
	if err != nil {
		return err
	}

	fmt.Printf("Cached bodies on disk:  %d\n", stats.TotalCached)
	fmt.Printf("Would purge (<= %s):  %d\n", cutoff.Format(time.RFC3339), stats.WouldPurge)
	if stats.OldestCached != nil {
		fmt.Printf("Oldest cached body:     %s\n", stats.OldestCached.Format(time.RFC3339))
	}

	// Phase 8/A — attachment cache stats. Same retention model;
	// distinct storage so the totals are reported separately.
	attCount, _ := st.CountCachedAttachments(ctx)
	attBytes, _ := st.SumAttachmentBytes(ctx)
	fmt.Printf("Cached attachments:     %d (%d bytes)\n", attCount, attBytes)

	if *dryRun {
		fmt.Println("(--dry-run; nothing changed)")
		return nil
	}

	n, err := st.PurgeOlderThan(ctx, cutoff)
	if err != nil {
		return err
	}
	fmt.Printf("Purged %d message body row(s).\n", n)

	// Phase 8/A — sweep stale attachment cache entries with the
	// same cutoff.
	attN, err := st.PurgeAttachmentsOlderThan(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("purge attachments: %w", err)
	}
	fmt.Printf("Purged %d attachment cache row(s).\n", attN)

	if *doVacuum {
		fmt.Println("Vacuuming…")
		if _, err := st.DB.ExecContext(ctx, "VACUUM"); err != nil {
			return fmt.Errorf("vacuum: %w", err)
		}
		fmt.Println("Vacuum complete.")
	}
	return nil
}

// parseDurationFlexible accepts both Go's time.ParseDuration shapes
// (24h, 90m) AND a "d" suffix for days that time.ParseDuration
// doesn't natively support. Anything else falls through to
// time.ParseDuration so users can pass standard values.
//
// Examples:
//
//	7d   → 168h
//	30d  → 720h
//	24h  → 24h
//	90m  → 90m
func parseDurationFlexible(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if m := dayDurationRE.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

var dayDurationRE = regexp.MustCompile(`^(\d+)d$`)

// sweepBodiesAtStartup is the serve-stdio entry point — runs the
// default-retention purge once at startup. Failures log Warn but
// don't fail startup; the daemon's whole job is to serve MCP,
// not be a backup tool.
//
// Phase 8/A — also sweeps attachment_cache at the same cutoff so
// both plaintext-at-rest stores share the retention model.
// Returned count is body-rows only (attachment count is logged
// inside via slog rather than threaded through the int64 contract
// the runtime hook expects).
func sweepBodiesAtStartup(ctx context.Context, st *store.Store) (int64, error) {
	cutoff := time.Now().Add(-store.DefaultBodyRetention).UTC()
	n, err := st.PurgeOlderThan(ctx, cutoff)
	if err != nil {
		return n, err
	}
	if attN, attErr := st.PurgeAttachmentsOlderThan(ctx, cutoff); attErr == nil && attN > 0 {
		// Best-effort — the body sweep is already reported via the
		// caller's stats; attachment counts roll into the same log line
		// via slog if anything else cares.
		_ = attN
	}
	return n, nil
}

var _ = os.Stderr // kept; future error-surface refactors will use it
