package policy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultPIDPath returns the canonical PID file location:
// ~/Library/Application Support/protonmcp/serve-stdio.pid. Created
// by serve-stdio at startup; read by `protonmcp policy reload`.
func DefaultPIDPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "serve-stdio.pid"), nil
}

// WritePIDFile creates path (with the containing dir, mode 0o700)
// and writes os.Getpid() to it (mode 0o600).
//
// **Multi-instance friendly**: as of D9 fix, we no longer take an
// advisory exclusive flock. The PID file is informational — useful
// for `lsof` / debugging — and last-writer-wins. `policy reload`
// uses pgrep to find every live serve-stdio process and signals
// them all, so multiple concurrent clients (Claude Desktop +
// Claude Code, for example) each receive the SIGHUP.
//
// The previous flock-based "only one serve-stdio at a time"
// semantics broke the Claude Desktop + Claude Code coexistence
// use case. The flock was also an unauthenticated lock — any local
// process could plant a PID file with its own PID and either block
// our startup or steal our SIGHUP. Dropping it removes both bugs.
//
// Returns a cleanup func to remove the file on normal shutdown.
// On crash, the file lingers; next startup just overwrites.
func WritePIDFile(path string) (cleanup func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create pid dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open pid file: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pid: %w", err)
	}
	_ = f.Sync()
	_ = f.Close()

	return func() {
		_ = os.Remove(path)
	}, nil
}

// FindRunningPIDs returns the PIDs of every live `protonmcp
// serve-stdio` process. Used by `protonmcp policy reload` to signal
// every running instance — the PID file's last-writer-wins shape
// can't be relied on for "find the running daemon" anymore, and
// pgrep is the natural macOS-side discovery primitive.
//
// Excludes os.Getpid() from the result so a `policy reload` invoked
// from inside an MCP-tool handler doesn't signal itself (which
// would race with the engine.Reload SIGHUP handler).
//
// Returns ErrNotRunning if no matching process exists.
func FindRunningPIDs() ([]int, error) {
	out, err := exec.Command("pgrep", "-f", "protonmcp serve-stdio").Output()
	if err != nil {
		// pgrep exits 1 when no match — that's "not running",
		// not a real error. Distinguish via *exec.ExitError.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("pgrep: %w", err)
	}
	self := os.Getpid()
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid == self {
			continue
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return nil, ErrNotRunning
	}
	return pids, nil
}

// ErrNotRunning is returned when no live serve-stdio is detected.
var ErrNotRunning = errors.New("no protonmcp serve-stdio is running")
