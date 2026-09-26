package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PROTO-152 — publish lock state to disk.
//
// A locked daemon refuses every tool call, which is the single most
// confusing state the product has: mail tools stop working while the
// process, socket, keychain entry, and local mirror all remain
// perfectly healthy. `protonmcp doctor` used to report "All good"
// straight through it, because nothing outside the daemon process
// could see the flag.
//
// It can't be discovered over the socket either — the lock check
// lives in the tool-call middleware, so the only way to observe it
// via MCP is to make a call and read the refusal, which is a side
// effect no diagnostic command should have. So the runtime publishes
// the flag to a small file on every transition and doctor reads it.
//
// The file is advisory. It records the PID that wrote it so a reader
// can tell live state from a leftover: an unclean shutdown leaves the
// file behind, and the next daemon may not reuse that PID.

// LockState is the on-disk lock record. Written by the runtime on
// every lock/unlock transition and at startup.
type LockState struct {
	// PID is the process that owns this state. Readers must confirm
	// it's still a live protonmcp runtime before trusting Locked.
	PID int `json:"pid"`
	// Locked is the flag the tool-call middleware enforces.
	Locked bool `json:"locked"`
	// Reason is the lock trigger — "screen_locked", "sleep", "idle",
	// "SIGUSR1". Empty when unlocked.
	Reason string `json:"reason,omitempty"`
	// Since is when the process entered this state.
	Since time.Time `json:"since"`
}

// LockStatePath returns the canonical location:
// ~/Library/Application Support/protonmcp/lockstate.json — alongside
// serve-stdio.pid and expected_sha256.
func LockStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "lockstate.json"), nil
}

// WriteLockState publishes st to the canonical path (0600 inside a
// 0700 dir).
//
// Written via a temp file + rename so a reader never observes a
// half-written record. doctor runs at arbitrary times, including
// mid-transition.
func WriteLockState(st LockState) error {
	path, err := LockStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create lock state dir: %w", err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal lock state: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".lockstate-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp lock state: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod lock state: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write lock state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lock state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install lock state: %w", err)
	}
	return nil
}

// ErrNoLockState means no record exists — either no runtime has run
// since this build was installed, or the last one shut down cleanly.
var ErrNoLockState = errors.New("no lock state recorded")

// ReadLockState returns the published record. Returns ErrNoLockState
// if the file is absent.
//
// Callers MUST validate st.PID against a live runtime process (see
// policy.IsRuntimeProcess) before acting on Locked — a stale file
// from a crashed daemon otherwise reads as authoritative.
func ReadLockState() (LockState, error) {
	var st LockState
	path, err := LockStatePath()
	if err != nil {
		return st, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, ErrNoLockState
		}
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parse lock state: %w", err)
	}
	return st, nil
}

// removeLockState deletes the record on clean shutdown, so a stopped
// daemon doesn't leave a "locked" claim behind for the next reader.
func removeLockState() {
	if path, err := LockStatePath(); err == nil {
		_ = os.Remove(path)
	}
}
