package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
// and writes os.Getpid() to it (mode 0o600). Acquires an advisory
// flock so a second concurrent serve-stdio would observe the lock
// and either coexist explicitly or bail.
//
// Returns the *os.File holding the lock. Caller MUST keep it alive
// for the life of the daemon — closing the file releases the flock.
// On normal shutdown the file is removed (via the returned cleanup
// func); on crash the OS releases the flock but the file lingers,
// which is fine: the next startup detects the stale PID via
// signal-0 and overwrites.
func WritePIDFile(path string) (cleanup func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create pid dir: %w", err)
	}

	// Check for an already-live previous instance.
	if existing, ok := readExistingPID(path); ok && processAlive(existing) {
		return nil, fmt.Errorf("another protonmcp serve-stdio is already running (pid %d)", existing)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open pid file: %w", err)
	}

	// Advisory exclusive lock (non-blocking). If someone else holds
	// it, we fail loudly rather than racing.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock pid file (another serve-stdio running?): %w", err)
	}

	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pid: %w", err)
	}
	if err := f.Sync(); err != nil {
		// non-fatal — the write went into the page cache
		_ = err
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		_ = os.Remove(path)
	}, nil
}

// ReadPIDFile returns the PID written to path. Returns ErrNotRunning
// if the file doesn't exist OR if the PID it names isn't a live
// process. Distinguishes "no daemon" from "weirdly-formatted file"
// (the latter is a real error).
func ReadPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, ErrNotRunning
		}
		return 0, fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("malformed pid file %q: %w", path, err)
	}
	if !processAlive(pid) {
		return 0, ErrNotRunning
	}
	return pid, nil
}

// ErrNotRunning is returned when no live serve-stdio is detected.
var ErrNotRunning = errors.New("no protonmcp serve-stdio is running")

func readExistingPID(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return pid, true
}

// processAlive returns true if signal 0 succeeds against pid. On
// macOS, kill(pid, 0) returns success if the process exists OR if
// it's a zombie. Good enough for "stale PID file?" detection —
// we'd rather false-positive a zombie than overwrite a live daemon's
// PID file.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
