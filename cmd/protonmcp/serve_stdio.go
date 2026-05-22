package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// runServeStdio is the MCP entry point. Claude Desktop spawns this
// subprocess, communicates JSON-RPC over stdin/stdout per the
// 2025-06-18 stdio transport, and tears it down on quit.
//
// SECURITY Foundational #3 — MCP trust model:
//
//   - stdio is the ONLY transport. We never call net.Listen("tcp", …)
//     anywhere in the binary, and there's an init() assertion in
//     internal/mcp/trustguard.go that panics if anyone tries.
//   - No SO_PEERCRED check needed: the trust boundary is "whoever
//     spawned this process," which inherits our UID. That's the
//     accepted threat model from the design spec.
//   - Logs go to stderr exclusively (slog default is configured in
//     internal/logging). Anything written to stdout that isn't a
//     JSON-RPC message corrupts the stream — every code path here
//     must be careful, and a Phase-7 lint guard will enforce.
func runServeStdio(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve-stdio", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve-stdio takes no positional arguments; got %v", fs.Args())
	}

	// Open the local store. mail.list / mail.search / mail.read all
	// read from this; mail.sync writes to it.
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

	// Q4 decision: acquire the session EAGERLY at initialize time —
	// AND in resume-only mode, since Claude Desktop spawns us with
	// no controlling TTY. Any failure here surfaces as "MCP server
	// failed to start" in Claude Desktop with a stderr message
	// telling the user to run `protonmcp login` from a real
	// terminal first.
	acquireCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	bundle, err := acquireSessionResumeOnly(acquireCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("acquire session: %w", err)
	}
	defer bundle.Close()
	defer bundle.Session.Close()

	// Build the MCP server, register every read tool.
	srv := mcp.New(slog.Default())
	for _, tl := range mcptools.All(mcptools.Deps{
		Session: bundle.Session,
		Store:   st,
	}) {
		srv.Register(tl)
	}

	slog.Info("serve-stdio ready",
		"email", bundle.Session.Email,
		"tools", len(srv.Tools()),
		"db", path,
	)

	// Serve runs until stdin closes (client quit) or ctx cancels.
	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
