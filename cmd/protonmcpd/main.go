// protonmcpd is the long-running daemon variant of `protonmcp
// serve-stdio`. Where serve-stdio handles one MCP session per
// process spawned by Claude Desktop, the daemon stays up across
// Claude restarts and serves multiple concurrent connections from
// thin shim processes via a Unix-domain socket.
//
// The transport is the only difference from serve-stdio:
//
//	serve-stdio  — one srv.Serve(ctx, stdin, stdout) call, process exits with stdin EOF
//	protonmcpd   — accept loop, srv.Serve(ctx, conn, conn) per connection in a goroutine
//
// The internal/serve.Runtime is identical between the two so policy
// reload, audit logging, approval brokering, etc. all behave the
// same. See SECURITY.md and TODO.html Phase 6 for the audit /
// architecture context.
//
// Socket path: ~/Library/Application Support/protonmcp/protonmcp.sock
// Mode: 0600. The Application Support directory is 0700, so a
// different-UID process can't reach the socket. Phase 6/D adds an
// explicit SO_PEERCRED check on accept as defense in depth.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/logging"
	"github.com/just-an-oldsalt/proto-mcp/internal/serve"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

func main() {
	// Match the CLI's logging configuration: redacting slog to
	// stderr. Daemon stderr is captured by launchd into
	// ~/Library/Logs/protonmcp/daemon.log per the LaunchAgent plist
	// (added in Phase 6/C).
	logging.Setup(os.Stderr)

	if err := run(); err != nil {
		slog.Error("protonmcpd exited with error", "err", err.Error())
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("protonmcpd", flag.ContinueOnError)
	socketPath := fs.String("socket", "", "Unix socket path (default: ~/Library/Application Support/protonmcp/protonmcp.sock)")
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("protonmcpd takes no positional arguments; got %v", fs.Args())
	}

	// SIGTERM / SIGINT cancel ctx (clean shutdown). SIGHUP is
	// handled inside the Runtime (policy reload). Same split as
	// cmd/protonmcp/main.go uses.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SECURITY D5 — refuse to start with PROTONMCP_DEBUG=1.
	// Daemon stderr lands in the user's Logs/protonmcp directory
	// where partially-redacted Proton API traffic shouldn't end up.
	if os.Getenv("PROTONMCP_DEBUG") != "" {
		return errors.New(
			"refusing to start protonmcpd with PROTONMCP_DEBUG=1 set " +
				"(SECURITY D5 — debug stderr would land in the daemon's launchd log " +
				"directory and contains partially-redacted Proton API traffic). " +
				"Unset PROTONMCP_DEBUG and restart")
	}
	for _, k := range []string{"PROTONMCP_TOUCHID", "PROTONMCP_DEBUG"} {
		_ = os.Unsetenv(k)
	}

	rt, err := serve.Setup(ctx, serve.SetupConfig{
		DBPath: *dbPath,
		AcquireSession: func(ctx context.Context) (serve.SessionBundle, error) {
			acquireCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			return session.AcquireResumeOnly(acquireCtx)
		},
		SweepBodiesAtStartup: serve.SweepStaleBodies,
	})
	if err != nil {
		return err
	}
	defer rt.Close()

	sockPath, err := resolveSocketPath(*socketPath)
	if err != nil {
		return err
	}
	listener, err := openSocket(sockPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", sockPath, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(sockPath)
	}()

	slog.Info("protonmcpd ready",
		"email", rt.Session.Email,
		"tools", len(rt.MCPServer.Tools()),
		"socket", sockPath,
	)

	return acceptLoop(ctx, listener, rt)
}

// resolveSocketPath returns the configured socket path, creating
// the containing directory if it doesn't exist (mode 0700).
func resolveSocketPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, "Library", "Application Support", "protonmcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create socket dir: %w", err)
	}
	return filepath.Join(dir, "protonmcp.sock"), nil
}

// openSocket creates and binds the Unix listener with 0600 perms.
// Removes a stale socket file from a previous crashed daemon — the
// filesystem entry survives a non-graceful exit even though the
// listener is gone.
func openSocket(path string) (*net.UnixListener, error) {
	// Stale socket cleanup. We only remove if we can confirm it's
	// a socket file (not a regular file someone planted) AND a
	// connect attempt fails (so the OWNING daemon — if any — is gone).
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("path exists but is not a socket: %s", path)
		}
		c, derr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("socket %s is already in use by a live daemon", path)
		}
		// Connect failed → previous daemon is gone, remove the stale node.
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	// 0600 — same-UID can connect, nothing else. Application Support
	// directory itself is 0700 so cross-UID is already blocked, but
	// explicit chmod on the socket is defense in depth.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return listener, nil
}

// acceptLoop owns the accept side. One goroutine per accepted
// connection runs srv.Serve(ctx, conn, conn). A WaitGroup tracks
// in-flight connections so the loop can drain them on shutdown
// (up to a grace period — after that we forcibly close).
//
// Phase 6/D will add SO_PEERCRED per-connection on accept.
func acceptLoop(ctx context.Context, l *net.UnixListener, rt *serve.Runtime) error {
	var wg sync.WaitGroup

	// When ctx is cancelled, close the listener so Accept returns
	// immediately with a closed-network error.
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			slog.Warn("accept error; continuing", "err", err.Error())
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			serveConn(ctx, c, rt)
		}(conn)
	}

	// Graceful drain. Bounded so a misbehaving client can't
	// indefinitely block daemon shutdown.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("daemon drained gracefully")
	case <-drainCtx.Done():
		slog.Warn("daemon drain timeout — some connections still open at exit")
	}
	return nil
}

// serveConn runs one NDJSON conversation against a single connection.
// Each call to srv.Serve creates its own per-connection initialized
// state (see the Phase-6 refactor on internal/mcp/server.go), so
// concurrent connections don't share handshake flags.
func serveConn(ctx context.Context, c net.Conn, rt *serve.Runtime) {
	if err := rt.MCPServer.Serve(ctx, c, c); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
			return
		}
		slog.Warn("connection ended with error", "err", err.Error())
	}
}
