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
)

// readOutput is the JSON shape `protonmcp read` prints (Phase-2 plan
// Q5: JSON). Phase 3's MCP `mail.read` tool will eventually marshal
// the same struct, so any debugging done here translates directly.
type readOutput struct {
	MessageID  string    `json:"message_id"`
	ThreadID   string    `json:"thread_id,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	From       string    `json:"from,omitempty"`
	MIMEType   string    `json:"mime_type,omitempty"`
	Text       string    `json:"text,omitempty"`
	HTML       string    `json:"html,omitempty"`
	CachedAt   time.Time `json:"cached_at,omitempty"`
	FromCache  bool      `json:"from_cache"`
	References []string  `json:"references,omitempty"`
}

func runRead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	forceRefresh := fs.Bool("refresh", false, "ignore cached body and re-fetch from Proton")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: protonmcp read [--db <path>] [--refresh] <message-id>")
	}
	msgID := rest[0]

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

	// Cache lookup first — we want to avoid pinging Proton at all
	// when we have a fresh body locally. This is the common case
	// after backfill + a few reads.
	if !*forceRefresh {
		if cached, err := st.GetCachedBody(ctx, msgID); err == nil {
			meta, _ := st.GetMessage(ctx, msgID)
			return printRead(readOutput{
				MessageID: msgID,
				ThreadID:  meta.ThreadID,
				Subject:   meta.Subject,
				From:      meta.FromAddress,
				Text:      cached.Text,
				HTML:      cached.HTML,
				CachedAt:  cached.CachedAt,
				FromCache: true,
			})
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	// Cache miss or --refresh — acquire a session and fetch.
	acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	bundle, err := acquireSession(acquireCtx)
	if err != nil {
		return err
	}
	defer bundle.Close()
	defer bundle.Session.Close()

	body, err := bundle.Session.FetchAndDecryptMessage(ctx, msgID)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	// Reconstruct thread_id from In-Reply-To. If we have a chain,
	// the root (oldest) of References is conventionally the thread
	// anchor; falling back to the immediate parent (In-Reply-To)
	// when References is empty. Simple algorithm per Phase 2 plan
	// Q2 — full RFC 5322 jwz handling is a separate follow-up.
	threadID := body.ThreadHint
	if len(body.References) > 0 {
		threadID = body.References[0]
	}
	if threadID == "" {
		threadID = msgID // no parent → message is its own thread root
	}

	if err := st.SetCachedBody(ctx, msgID, store.CachedBody{
		Text:     body.Text,
		HTML:     body.HTML,
		ThreadID: threadID,
	}); err != nil {
		// Cache failure shouldn't block the user's read — log and continue.
		fmt.Fprintf(os.Stderr, "warning: failed to cache body (%v)\n", err)
	}

	return printRead(readOutput{
		MessageID:  msgID,
		ThreadID:   threadID,
		Subject:    body.Subject,
		From:       body.From,
		MIMEType:   body.MIMEType,
		Text:       body.Text,
		HTML:       body.HTML,
		CachedAt:   time.Now().UTC(),
		FromCache:  false,
		References: body.References,
	})
}

func printRead(o readOutput) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}
