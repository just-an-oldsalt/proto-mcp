//go:build darwin

package policy

import "github.com/just-an-oldsalt/proto-mcp/internal/caller"

// procExeFor returns the absolute executable path for a given PID
// on macOS, via libproc's proc_pidpath. Delegates to internal/caller
// rather than re-wrapping the same cgo helper — same code already
// powers Caller.Binary for audit rows.
func procExeFor(pid int) string {
	return caller.BinaryFor(pid)
}
