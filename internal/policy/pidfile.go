package policy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	// procExeFor is platform-defined; see pidfile_darwin.go.
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
// SECURITY D33 / D34: pgrep -f matches on the full command line, so
// it picks up wrappers (Claude.app/Contents/Helpers/disclaimer
// invokes protonmcp with serve-stdio in argv) and editor processes
// with this filename open. We post-filter each PID by verifying its
// actual executable path via proc_pidpath equals the running
// protonmcp binary. PIDs whose path can't be resolved (permission
// denied / gone) are dropped from the result — better to miss one
// than to send SIGHUP to a wrapper that ignores it and produce a
// misleading success log.
//
// Returns ErrNotRunning if no matching process exists.
func FindRunningPIDs() ([]int, error) {
	out, err := exec.Command("pgrep", "-f", "protonmcp serve-stdio").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("pgrep: %w", err)
	}
	self := os.Getpid()
	selfExe, _ := os.Executable()
	selfExe, _ = filepath.Abs(selfExe)

	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid == self {
			continue
		}
		// D33/D34: verify the PID's actual executable matches ours.
		// caller.BinaryFor returns "" on can't-determine (permission /
		// non-darwin); drop those rather than SIGHUP a stranger.
		if !matchesExecutable(pid, selfExe) {
			continue
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return nil, ErrNotRunning
	}
	return pids, nil
}

// matchesExecutable returns true if the process at pid is running
// the same executable as us. Lives here rather than in
// internal/caller because it's specifically the SIGHUP-filtering
// rule — a future caller might want a looser match.
//
// Comparison uses os.SameFile (st_dev + st_ino) so symlinks /
// resolved-vs-raw paths between os.Executable() and proc_pidpath
// don't cause false negatives. proc_pidpath returns the
// canonical resolved path; os.Executable on a symlinked install
// may return the symlink. Without SameFile, the strings differ
// and the filter rejects legitimate matches.
func matchesExecutable(pid int, selfExe string) bool {
	if selfExe == "" {
		// We don't know our own path either — fall through to the
		// previous behavior of "trust the pgrep match." Conservative
		// but not strictly wrong.
		return true
	}
	bin := procExeFor(pid)
	if bin == "" {
		return false
	}
	selfInfo, serr := os.Stat(selfExe)
	binInfo, berr := os.Stat(bin)
	if serr != nil || berr != nil {
		return false
	}
	return os.SameFile(selfInfo, binInfo)
}

// ErrNotRunning is returned when no live serve-stdio is detected.
var ErrNotRunning = errors.New("no protonmcp serve-stdio is running")
