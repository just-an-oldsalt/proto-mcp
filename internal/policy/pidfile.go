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
// advisory exclusive flock. The PID file is last-writer-wins, so it
// names only one of the running runtimes; FindRunningPIDs treats it
// as one discovery source among several and signals every instance
// it finds, so multiple concurrent clients (Claude Desktop + Claude
// Code, for example) each receive the SIGHUP.
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

// Executable basenames that host a serve.Runtime and therefore have
// the SIGHUP (policy reload) / SIGUSR1 (lock) / SIGUSR2 (unlock)
// handlers installed.
//
// protonmcp-shim is deliberately absent. It forwards over the Unix
// socket and installs no SIGUSR handler, so signalling it would not
// lock or unlock anything — it would kill it, since SIGUSR1/SIGUSR2
// terminate by default.
const (
	// DaemonBinary is the long-lived background daemon.
	DaemonBinary = "protonmcpd"
	// ServeStdioBinary is the CLI, which hosts a runtime when invoked
	// as `protonmcp serve-stdio`.
	ServeStdioBinary = "protonmcp"
)

// FindRunningPIDs returns the PIDs of every live process hosting a
// signal-handling protonmcp runtime: `protonmcp serve-stdio`
// instances AND the long-lived protonmcpd daemon. Used by `protonmcp
// policy reload`, `protonmcp lock`, and `protonmcp unlock`.
//
// PROTO-152: protonmcpd was previously undiscoverable, so all three
// commands reported "not running" against a perfectly healthy daemon
// — which left a screen-locked daemon with no route back short of a
// restart, and made `policy reload` silently no-op while printing
// success. Two independent bugs caused it, either fatal alone:
//
//  1. Discovery was a lone `pgrep -f "protonmcp serve-stdio"`. The
//     daemon's argv is just its binary path, with no subcommand to
//     match, so pgrep never returned it.
//  2. Survivors were filtered by os.SameFile against the *calling*
//     binary. The CLI that signals is a different file from the
//     daemon it signals, so that test excluded protonmcpd by
//     construction even when pgrep did find it.
//
// Three sources are now unioned, each with its own identity check.
//
// Excludes os.Getpid() so a `policy reload` invoked from inside an
// MCP-tool handler doesn't signal itself (which would race with the
// engine.Reload SIGHUP handler).
//
// SECURITY D33 / D34: pgrep -f matches the full command line, so it
// also picks up wrappers (Claude.app/Contents/Helpers/disclaimer
// invokes protonmcp with serve-stdio in argv) and editor processes
// holding a file of that name open. Every candidate is still post-
// filtered against its real executable via proc_pidpath, and PIDs
// whose path can't be resolved are dropped — better to miss one than
// to signal a stranger, which for SIGUSR1/2 means killing it.
//
// Returns ErrNotRunning if no matching process exists.
func FindRunningPIDs() ([]int, error) {
	found := map[int]struct{}{os.Getpid(): {}}
	var pids []int
	collect := func(pid int, allowed ...string) {
		if pid <= 0 {
			return
		}
		if _, dup := found[pid]; dup {
			return
		}
		if !hasExecutableNamed(pid, allowed...) {
			return
		}
		found[pid] = struct{}{}
		pids = append(pids, pid)
	}

	// Source 1 — serve-stdio instances, one per connected client.
	for _, pid := range pgrepPIDs("-f", ServeStdioBinary+" serve-stdio") {
		collect(pid, ServeStdioBinary)
	}
	// Source 2 — the daemon, matched on exact process name because
	// its argv carries no distinguishing subcommand.
	for _, pid := range pgrepPIDs("-x", DaemonBinary) {
		collect(pid, DaemonBinary)
	}
	// Source 3 — the PID file, written by serve.Setup in whichever
	// process owns the runtime. Last-writer-wins across serve-stdio
	// and the daemon, so it may name either; the executable check
	// sorts that out. Kept as a backstop for the case where pgrep is
	// missing or its output is truncated.
	if path, err := DefaultPIDPath(); err == nil {
		collect(readPIDFile(path), DaemonBinary, ServeStdioBinary)
	}

	if len(pids) == 0 {
		return nil, ErrNotRunning
	}
	return pids, nil
}

// IsRuntimeProcess reports whether pid is a live process running one
// of the binaries that host a protonmcp runtime.
//
// Exported for readers of the records a runtime leaves on disk — the
// PID file and the lock state — so they can tell a live claim from
// one an unclean shutdown left behind. A recorded PID may since have
// been recycled by an unrelated process, which this rejects.
func IsRuntimeProcess(pid int) bool {
	return hasExecutableNamed(pid, DaemonBinary, ServeStdioBinary)
}

// pgrepPIDs runs pgrep with the given arguments and returns the PIDs
// it printed. A non-zero exit (pgrep's "no match") yields nil rather
// than an error: callers union several sources, and one source
// finding nothing is not a failure of the search.
func pgrepPIDs(args ...string) []int {
	out, err := exec.Command("pgrep", args...).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, err := strconv.Atoi(line); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readPIDFile returns the PID recorded at path, or 0 when the file is
// absent or malformed. Liveness isn't checked here — the caller's
// executable check subsumes it, since a dead PID resolves to no
// executable path at all and is dropped.
func readPIDFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

// hasExecutableNamed reports whether the process at pid is running one
// of the named product binaries.
//
// This replaces the old os.SameFile-against-our-own-path check, which
// only ever held for the single-binary serve-stdio topology. The
// daemon is a different executable from the CLI that signals it, so
// "is it the same file as me" was the wrong question — see the
// PROTO-152 note on FindRunningPIDs. Comparing basenames against the
// binaries we ship keeps the property that actually matters (never
// signal a wrapper or an editor) while spanning the two-binary
// layout.
//
// Deliberately does NOT pin the directory: a source-built CLI in
// ./bin is expected to be able to signal a Homebrew-installed daemon,
// which is exactly the mixed layout developers run.
func hasExecutableNamed(pid int, allowed ...string) bool {
	bin := procExeFor(pid)
	if bin == "" {
		// Can't determine: process is gone, permission denied, or a
		// non-darwin build where proc_pidpath has no equivalent.
		return false
	}
	base := filepath.Base(bin)
	for _, name := range allowed {
		if base == name {
			return true
		}
	}
	return false
}

// ErrNotRunning is returned when no live serve-stdio or protonmcpd
// process is detected.
var ErrNotRunning = errors.New("no protonmcp serve-stdio or protonmcpd process is running")
