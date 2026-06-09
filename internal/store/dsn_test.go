package store

import (
	"strings"
	"testing"
)

// SECURITY D12 — buildDSN must not let a caller-supplied path inject
// extra "?_pragma=..." fragments that override the pragmas we set
// (WAL durability, secure_delete). The driver parses everything after
// the first "?" as connection pragmas, so a path containing "?" is
// rejected outright.
func TestBuildDSN_RejectsPragmaInjection(t *testing.T) {
	bad := []string{
		"/tmp/x.db?_pragma=journal_mode(off)",
		"/tmp/x.db?_pragma=secure_delete(off)",
		"relative.db?foo=bar",
		"/tmp/has?question.db",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			if _, err := buildDSN(p); err == nil {
				t.Fatalf("buildDSN(%q) = nil error; want rejection of '?' in path", p)
			}
		})
	}
}

func TestBuildDSN_AcceptsNormalPaths(t *testing.T) {
	good := []string{
		"/tmp/store.db",
		"relative.db",
		"/Users/x/Library/Application Support/protonmcp/store.db", // spaces are fine
		":memory:",
	}
	for _, p := range good {
		t.Run(p, func(t *testing.T) {
			dsn, err := buildDSN(p)
			if err != nil {
				t.Fatalf("buildDSN(%q) returned error: %v", p, err)
			}
			// Our own pragmas must survive and the path prefix must be intact.
			if !strings.HasPrefix(dsn, p+"?") {
				t.Errorf("buildDSN(%q) = %q; want it to start with the path + '?'", p, dsn)
			}
			if !strings.Contains(dsn, "secure_delete") {
				t.Errorf("buildDSN(%q) = %q; expected secure_delete pragma present", p, dsn)
			}
		})
	}
}
