package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/serve"
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

	// SECURITY D5 + D31. The spawning process's environment is
	// untrusted in serve-stdio mode. Two specific vars previously
	// bridged that gap dangerously:
	//
	//   PROTONMCP_DEBUG=1  — enables the redacting HTTP dump
	//     transport. Stderr lands in Claude Desktop's MCP log dir
	//     (~/Library/Logs/Claude/mcp-server-protonmcp.log), so an
	//     inherited shell var sprays Proton API traffic (SRP
	//     exchanges, partially-redacted bodies) into a file users
	//     don't think of as sensitive. Refuse to start.
	//
	//   PROTONMCP_TOUCHID — see internal/approval/path.go (D4); the
	//     resolver itself refuses it outside test mode, but unset
	//     here too so a future code path can't accidentally read it.
	//
	// Anything else under PROTONMCP_* gets dropped defensively. The
	// CLI paths (login/whoami/etc.) still honor these — the policy
	// is "untrusted parent" only for serve-stdio.
	if os.Getenv("PROTONMCP_DEBUG") != "" {
		return fmt.Errorf(
			"refusing to start serve-stdio with PROTONMCP_DEBUG=1 set " +
				"(SECURITY D5 — debug stderr lands in Claude Desktop's MCP " +
				"log directory and contains partially-redacted Proton API " +
				"traffic). Unset PROTONMCP_DEBUG and restart")
	}
	for _, k := range []string{"PROTONMCP_TOUCHID", "PROTONMCP_DEBUG"} {
		_ = os.Unsetenv(k)
	}

	// Setup the shared runtime — store + session + policy + audit +
	// broker + caller + MCP server + SIGHUP handler. Same wiring the
	// protonmcpd daemon uses; only the transport differs.
	rt, err := serve.Setup(ctx, serve.SetupConfig{
		DBPath: *dbPath,
		AcquireSession: func(ctx context.Context) (serve.SessionBundle, error) {
			acquireCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			return acquireSessionResumeOnly(acquireCtx)
		},
		SweepBodiesAtStartup: sweepBodiesAtStartup,
	})
	if err != nil {
		return err
	}
	defer rt.Close()

	slog.Info("serve-stdio ready",
		"email", rt.Session.Email,
		"tools", len(rt.MCPServer.Tools()),
	)

	// Serve runs until stdin closes (client quit) or ctx cancels.
	if err := rt.MCPServer.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
