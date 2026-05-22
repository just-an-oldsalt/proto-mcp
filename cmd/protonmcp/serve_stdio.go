package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
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

	// Phase 4: construct the policy engine BEFORE the MCP server so
	// SIGHUP reload + the PID file land before any tool call. The
	// engine itself is wired into the MCP middleware in 4/D; today
	// it's loaded so `protonmcp policy reload` works against this
	// daemon instance and so the override file is validated at
	// startup (rather than first tool call).
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		return fmt.Errorf("policy override path: %w", err)
	}
	engine, err := policy.New(ctx, overridePath, slog.Default())
	if err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}

	// PID file so `protonmcp policy reload` can find us. Held by an
	// advisory flock so a second serve-stdio fails fast rather than
	// stomping. cleanup removes the file on normal shutdown.
	pidPath, err := policy.DefaultPIDPath()
	if err != nil {
		return fmt.Errorf("pid file path: %w", err)
	}
	pidCleanup, err := policy.WritePIDFile(pidPath)
	if err != nil {
		return fmt.Errorf("pid file: %w", err)
	}
	defer pidCleanup()

	// SIGHUP → policy reload. Installed AFTER main.go drops HUP
	// from its NotifyContext, so the signal arrives here and only
	// here. The handler logs success/failure but never crashes the
	// daemon — a malformed override file keeps the previous policy
	// in place per Engine.Reload semantics.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)
	go func() {
		for range hupCh {
			if rerr := engine.Reload(); rerr != nil {
				slog.Warn("policy reload failed; previous policy retained", "err", rerr.Error())
				continue
			}
			slog.Info("policy reloaded")
		}
	}()

	// Build the MCP server, register every read tool.
	srv := mcp.New(slog.Default())
	_ = engine // policy engine wired into the middleware in PR 4/D
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
