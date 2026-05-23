// protonmcp-shim is the thin stdio↔socket forwarder that Claude
// Desktop / Claude Code spawn. It connects to the running
// protonmcpd daemon's Unix socket and pumps NDJSON bytes in both
// directions until either side closes.
//
// Architecture:
//
//	Claude client
//	    │ stdin / stdout  (NDJSON, MCP spec)
//	    ▼
//	protonmcp-shim   (this binary; ~stateless)
//	    │ Unix socket  (same NDJSON framing)
//	    ▼
//	protonmcpd       (long-running daemon; one Runtime, N conns)
//
// What this binary does NOT do: parse JSON-RPC, hold session
// state, enforce policy. All of that lives in the daemon. The
// shim's only job is byte-pumping and a clear error message when
// the daemon isn't running.
//
// Phase 6/B. See TODO.html and SECURITY.md for the broader
// context.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		// stderr only — stdout is reserved for MCP framing.
		fmt.Fprintln(os.Stderr, "protonmcp-shim:", err)
		os.Exit(1)
	}
}

func run() error {
	sockPath, err := defaultSocketPath()
	if err != nil {
		return err
	}
	// Allow override via env (test convenience). Production users
	// shouldn't need this; the daemon's default path matches the
	// shim's default lookup.
	if v := os.Getenv("PROTONMCP_SOCKET"); v != "" {
		sockPath = v
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		// Emit a clean MCP error so Claude shows a real message
		// rather than a silent process crash. Without this, the
		// LLM sees "tool call timed out" without context; with
		// it, the user gets a one-line hint.
		emitDaemonUnavailableError(sockPath, err)
		return fmt.Errorf("connect daemon at %s: %w", sockPath, err)
	}
	defer conn.Close()

	return pump(ctx, conn)
}

// pump runs two io.Copy goroutines: stdin → socket, socket → stdout.
// Returns when EITHER side closes (the other goroutine is unblocked
// by closing the socket from inside this function).
func pump(ctx context.Context, conn net.Conn) error {
	var (
		once  sync.Once
		first error
	)
	done := make(chan struct{})

	// stdin → socket. Daemon close OR stdin EOF ends this side.
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		once.Do(func() {
			first = err
			close(done)
		})
	}()

	// socket → stdout. Daemon close ends this side.
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		once.Do(func() {
			first = err
			close(done)
		})
	}()

	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil
	case <-done:
		// Close the other half so its io.Copy returns and the
		// process exits. If we didn't, a stdin-EOF would leave
		// the socket→stdout copy blocked forever on Read.
		_ = conn.Close()
		_ = os.Stdin.Close()
		if first != nil && !errors.Is(first, io.EOF) && !errors.Is(first, net.ErrClosed) {
			return fmt.Errorf("pump: %w", first)
		}
		return nil
	}
}

// defaultSocketPath mirrors protonmcpd's resolveSocketPath. Kept in
// sync deliberately rather than imported so the shim binary stays
// tiny (no cross-package deps beyond the standard library).
func defaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "protonmcp.sock"), nil
}

// emitDaemonUnavailableError writes a JSON-RPC error response to
// stdout so the Claude client sees a structured message instead of
// a silent crash. id=null per the JSON-RPC spec for errors when no
// request id is in scope.
//
// We do this BEFORE returning so even though the process is about
// to exit non-zero, the client gets one frame describing why.
func emitDaemonUnavailableError(path string, dialErr error) {
	msg := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32099,`+
			`"message":"protonmcpd not running at %s — run `+
			"`"+`protonmcp daemon start`+"`"+` or fall back to `+
			"`"+`protonmcp serve-stdio`+"`"+`",`+
			`"data":{"dial_error":%q}}}`+"\n",
		path, dialErr.Error())
	_, _ = os.Stdout.Write([]byte(msg))
}
