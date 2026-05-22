// Package store is the local SQLite mirror of the Proton mailbox.
//
// The store holds message envelopes (always), full-text-search indexes
// (built from envelopes + decrypted bodies), sync-cursor state for the
// event-id polling loop, and the audit log of tool invocations. Bodies
// are populated lazily on first read.
//
// Migrations live in migrations/*.sql and are embedded into the binary.
// goose handles versioning; calling Open() always brings the schema to
// the latest version.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DefaultPath returns the path the daemon uses in production:
// $XDG_DATA_HOME/protonmcp/store.db, falling back to
// ~/Library/Application Support/protonmcp/store.db on macOS.
func DefaultPath() (string, error) {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "protonmcp", "store.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "store.db"), nil
}

// Store wraps a *sql.DB whose schema is guaranteed to be at the latest
// migration. Concurrent use is safe — *sql.DB handles its own connection
// pool — but callers should treat reads and writes as serialized at the
// app level if they care about FTS5 trigger semantics.
type Store struct {
	DB   *sql.DB
	Path string
}

// Open opens or creates the SQLite database at path, applies all
// migrations, and returns a ready-to-use Store. Pass ":memory:" for an
// ephemeral test database.
//
// The parent directory is created if missing. WAL mode and foreign-key
// enforcement are enabled.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	dsn, err := buildDSN(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	// Tighten perms on the on-disk SQLite files. The umask the process
	// runs under should already make this 0o600, but be explicit —
	// process umask can be unset by callers, and the -wal / -shm
	// sidecar files may have been created with default modes by an
	// older version of the binary. SECURITY M-2.
	if path != ":memory:" {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			p := path + suffix
			if _, statErr := os.Stat(p); statErr == nil {
				_ = os.Chmod(p, 0o600)
			}
		}
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{DB: db, Path: path}, nil
}

// buildDSN constructs a modernc.org/sqlite DSN for the given path with
// the pragmas we want. Built via net/url rather than string concat
// (SECURITY L-4) so a path with unusual characters can't accidentally
// inject extra _pragma=... fragments. The "?_pragma=..." form is
// modernc-specific; the driver name is "sqlite", which is also why
// goose's dialect arg is "sqlite3" (the name and the dialect are
// independent concepts in our setup — see the gotchas list in TODO).
func buildDSN(path string) (string, error) {
	if path == ":memory:" {
		v := url.Values{}
		v.Add("_pragma", "busy_timeout(5000)")
		v.Add("_pragma", "foreign_keys(on)")
		// secure_delete is no-op for in-memory but keep it on so the
		// test code path mirrors production.
		v.Add("_pragma", "secure_delete(on)")
		return path + "?" + v.Encode(), nil
	}
	v := url.Values{}
	v.Add("_pragma", "busy_timeout(5000)")
	v.Add("_pragma", "foreign_keys(on)")
	v.Add("_pragma", "journal_mode(WAL)")
	v.Add("_pragma", "synchronous(normal)")
	// SECURITY B-10. With Phase 2 about to start caching plaintext
	// message bodies, deleted rows must be zeroed in SQLite free
	// pages rather than just marked unused. secure_delete is on a
	// per-table basis when set via PRAGMA but applies to ALL writes
	// when set as a DB-level pragma here.
	v.Add("_pragma", "secure_delete(on)")
	return path + "?" + v.Encode(), nil
}

// Close closes the underlying database. Safe to call on a nil receiver.
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

func migrate(db *sql.DB) error {
	goose.SetBaseFS(migrationFS)
	defer goose.SetBaseFS(nil)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	// Goose logs to stdout by default; the daemon logs structured, so
	// silence goose unless something goes wrong.
	goose.SetLogger(goose.NopLogger())

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// ErrNotFound is returned by lookup helpers when no row matches.
var ErrNotFound = errors.New("store: not found")
