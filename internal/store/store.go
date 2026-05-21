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

	// modernc.org/sqlite registers itself as "sqlite". The DSN options
	// turn on busy_timeout and ensure pragmas survive across connections
	// in the pool.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	if path != ":memory:" {
		dsn += "&_pragma=journal_mode(WAL)&_pragma=synchronous(normal)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{DB: db, Path: path}, nil
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
