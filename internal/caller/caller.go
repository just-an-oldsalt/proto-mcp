// Package caller resolves the identity of the process that spawned
// this binary. Phase 4 needs this for the audit log's
// caller_pid / caller_uid / caller_binary columns and for the policy
// engine's per-caller decisioning (Phase 5 may want "only Claude
// Desktop can call mail_send", for example).
//
// On macOS we resolve the binary path via libproc's proc_pidpath.
// The Resolve() call is cached for the life of the process because
// our parent PID can't legitimately change after startup — if it
// does, that's because our parent died and we got reparented to
// launchd, which is a session we should refuse to honor anyway.
// (Phase 6's daemon will reconsider this.)
package caller

import (
	"fmt"
	"os"
	"sync"
)

// Caller is the resolved identity of whoever spawned us.
type Caller struct {
	PID    int
	UID    int
	Binary string // absolute path, empty if resolution failed
}

// String formats for log / audit display: "Claude Desktop (pid 1234)".
// Falls back to the binary basename + pid if the full path is
// unhelpful, or just "pid 1234" if we couldn't resolve a path.
func (c Caller) String() string {
	if c.Binary == "" {
		return fmt.Sprintf("pid %d", c.PID)
	}
	return fmt.Sprintf("%s (pid %d)", basenameOf(c.Binary), c.PID)
}

// Resolver caches a single Caller for the life of the process.
// Construct via New; call Resolve() on every tool-call to get the
// cached value at O(1) cost.
type Resolver struct {
	once   sync.Once
	cached Caller
}

// New returns a fresh Resolver. The actual resolution happens lazily
// on the first Resolve() call so package init doesn't make syscalls.
func New() *Resolver {
	return &Resolver{}
}

// Resolve returns the cached Caller, computing it on first call.
// Never returns an error — partial resolution (PID only, no binary)
// is acceptable; consumers handle empty Binary as "unknown."
func (r *Resolver) Resolve() Caller {
	r.once.Do(func() {
		pid := os.Getppid()
		uid := os.Getuid()
		bin, _ := resolveBinary(pid) // platform-specific; nil error tolerated
		r.cached = Caller{PID: pid, UID: uid, Binary: bin}
	})
	return r.cached
}

// basenameOf returns the last path element of p, stripping any
// trailing slash. Used for display only — not for security
// decisions; an attacker who controls argv[0] could forge this.
func basenameOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
