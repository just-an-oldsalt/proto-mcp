package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultRotateBytes is the default size threshold at which a log
// file rotates. 50 MiB matches typical macOS launchd log expectations
// and balances "useful retention" against "file the user can grep
// without paging."
const DefaultRotateBytes int64 = 50 << 20

// DefaultMaxGenerations is the number of rotated copies kept around.
// We keep <name>.1 (most recent) through <name>.N (oldest) so the
// directory naming is grep-stable. 10 generations × 50 MiB = 500 MiB
// per log channel ceiling.
const DefaultMaxGenerations = 10

// Rotator wraps an *os.File-like target with a "rotate when size
// exceeds threshold" behavior. Implements io.Writer + io.Closer so
// it slots in wherever a writer is expected — audit.log, daemon
// stderr, etc.
//
// Rotation is synchronous on the Write that crosses the threshold:
// the in-flight write goes to the new file. This is intentional —
// asynchronous rotation needs coordination with consumers that may
// be open()'d to the old fd, and we don't have any. Synchronous is
// also why we keep MaxBytes generous (50 MiB) — rotation pauses
// less often.
//
// Concurrency: a single mu guards the whole writer. Logging from
// multiple goroutines through the same Rotator serializes, which
// is the same behavior as a plain os.File on most platforms.
type Rotator struct {
	path           string
	maxBytes       int64
	maxGenerations int

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
}

// NewRotator opens path for append (creating if needed) and returns
// a Rotator. maxBytes ≤ 0 → DefaultRotateBytes. maxGenerations ≤ 0 →
// DefaultMaxGenerations.
//
// The directory must already exist. Permissions on the file mirror
// what os.OpenFile would set (umask applies); the daemon's main()
// installs a 0o077 umask early so log files land at 0o600.
func NewRotator(path string, maxBytes int64, maxGenerations int) (*Rotator, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultRotateBytes
	}
	if maxGenerations <= 0 {
		maxGenerations = DefaultMaxGenerations
	}
	r := &Rotator{
		path:           path,
		maxBytes:       maxBytes,
		maxGenerations: maxGenerations,
	}
	if err := r.openCurrent(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) openCurrent() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("rotator: open %s: %w", r.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("rotator: stat %s: %w", r.path, err)
	}
	r.f = f
	r.size = info.Size()
	return nil
}

// Write writes p to the current file. If the post-write size would
// cross maxBytes, the file is closed, rotated, and a new current
// file opened BEFORE the write — so a single record never spans
// two generations.
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close flushes and closes the current file. After Close, further
// Writes return os.ErrClosed. Idempotent.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Rotate forces rotation immediately, regardless of current size.
// Useful for SIGHUP-driven log rotation triggered from outside the
// writer (e.g. by a separate logrotate-style cron job). Mostly here
// so the daemon can respond to a "rotate now" admin signal in a
// future phase; not wired into any signal handler today.
func (r *Rotator) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	return r.rotateLocked()
}

// rotateLocked performs the rename chain + reopens. Caller must hold
// r.mu.
//
//	<path>.<N-1> → <path>.<N>   (drops the oldest)
//	<path>.<N-2> → <path>.<N-1>
//	...
//	<path>.1     → <path>.2
//	<path>       → <path>.1
//	new <path>   opened fresh
//
// Each rename is best-effort: a missing source (because the file
// hasn't accumulated that many generations yet) is silently skipped.
// A failed rename of the current file fails the whole rotation —
// without that move we'd append to the same file we just decided was
// full.
func (r *Rotator) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("rotator: close current: %w", err)
	}
	r.f = nil

	// Drop the oldest if it exists.
	oldest := r.generationPath(r.maxGenerations)
	_ = os.Remove(oldest) // ignore "not exists"

	// Shift everything down: <path>.{i} → <path>.{i+1}.
	for i := r.maxGenerations - 1; i >= 1; i-- {
		src := r.generationPath(i)
		dst := r.generationPath(i + 1)
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rotator: rename %s → %s: %w", src, dst, err)
		}
	}

	// Move current → <path>.1.
	if err := os.Rename(r.path, r.generationPath(1)); err != nil {
		return fmt.Errorf("rotator: rename current %s: %w", r.path, err)
	}

	return r.openCurrent()
}

func (r *Rotator) generationPath(i int) string {
	dir, name := filepath.Split(r.path)
	return filepath.Join(dir, fmt.Sprintf("%s.%d", name, i))
}
