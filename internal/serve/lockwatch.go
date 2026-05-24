package serve

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Phase 7/A — Swift lockwatch helper integration.
//
// The Swift helper at helpers/lockwatch/protonmcp-lockwatch is a
// long-lived subprocess that observes com.apple.screenIsLocked and
// NSWorkspaceWillSleepNotification, emitting "screen_locked" / "sleep"
// lines on stdout. The daemon reads those lines and calls
// Runtime.Lock with the appropriate reason.
//
// If the helper crashes or exits unexpectedly we restart it with a
// short backoff. Hard exits with a clear stderr message (e.g., not
// found, bad signature) cause backoff to lengthen until the operator
// fixes the install.

// startLockwatch launches the helper and returns a cancel function
// that stops it. The cancel cleanly closes the subprocess's stdin
// (the helper exits on EOF) and waits up to 2s for it to shut down.
//
// If the binary path is invalid the function returns a no-op cancel
// and logs a warning — the daemon proceeds without auto-lock
// triggers.
func startLockwatch(binPath string, lockFn func(reason string), logger *slog.Logger) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go runLockwatchLoop(ctx, binPath, lockFn, logger)
	return cancel
}

func runLockwatchLoop(ctx context.Context, binPath string, lockFn func(reason string), logger *slog.Logger) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := runLockwatchOnce(ctx, binPath, lockFn, logger)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Warn("lockwatch helper exited; restarting",
				"err", err.Error(), "backoff", backoff)
		} else {
			logger.Info("lockwatch helper exited cleanly; restarting", "backoff", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func runLockwatchOnce(ctx context.Context, binPath string, lockFn func(reason string), logger *slog.Logger) error {
	cmd := exec.CommandContext(ctx, binPath)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	// Discard stderr; the helper writes ready / EOF lines there
	// and we don't want them mixed into the daemon's slog stream.
	// If diagnostics are needed, swap in cmd.Stderr = os.Stderr
	// during dev.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		// Close stdin → helper hits EOF → exits.
		_ = stdinPipe.Close()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "screen_locked":
			lockFn("screen_locked")
		case "sleep":
			lockFn("sleep")
		case "screen_unlocked", "wake":
			// Informational — daemon stays locked. The user must
			// run `protonmcp unlock` (Touch ID) to resume.
			logger.Debug("lockwatch event (informational)", "event", line)
		default:
			logger.Debug("lockwatch unknown line", "line", line)
		}
	}
	return scanner.Err()
}

// resolveLockwatchPath discovers the helper binary across the
// install layouts proto-mcp supports:
//
//  1. Env override: PROTONMCP_LOCKWATCH (test / dev override).
//  2. Sibling of the running daemon binary:
//     <dir(os.Executable())>/helpers/lockwatch/protonmcp-lockwatch
//     (dev layout: bin/protonmcpd + helpers/lockwatch/...)
//  3. Same directory as the running binary:
//     <dir(os.Executable())>/protonmcp-lockwatch
//     (Phase 7/E Homebrew cask layout: cask `binary` stanzas drop
//     every product directly into <prefix>/bin/).
//  4. /Applications/protonmcp.app/Contents/MacOS/protonmcp-lockwatch
//     (deferred .app-bundle layout; pairs with D37's Phase 7/E
//     re-enable).
//  5. Explicit Homebrew prefix paths in case the running binary
//     was invoked via a PATH symlink and Dir(exe) lands somewhere
//     other than the actual bin directory.
//
// Returns ("", false) if no candidate is executable.
func resolveLockwatchPath() (string, bool) {
	if envPath := os.Getenv("PROTONMCP_LOCKWATCH"); envPath != "" {
		if isExecutable(envPath) {
			return envPath, true
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	binDir := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(binDir, "helpers", "lockwatch", "protonmcp-lockwatch"),
		filepath.Join(binDir, "protonmcp-lockwatch"),
		"/Applications/protonmcp.app/Contents/MacOS/protonmcp-lockwatch",
		"/opt/homebrew/bin/protonmcp-lockwatch",
		"/usr/local/bin/protonmcp-lockwatch",
	} {
		if isExecutable(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}
