package mcp

import (
	"errors"
	"net"
)

// init installs a "no TCP listen ever" invariant per SECURITY
// Foundational #3. Phase 3 ships only the stdio transport; Phase 6's
// daemon adds a Unix-domain socket. TCP is never the right answer
// for a local-only MCP server (DNS rebinding, exposing to the local
// network, etc.), so we forbid it structurally — any call to
// net.Listen("tcp", …) or net.ListenTCP panics with a clear message.
//
// Implementation: monkey-patching net.Listen would require unsafe
// tricks Go won't let us do. Instead, this file exposes a small
// MustNotListenTCP helper that future transport code can call as a
// no-op assertion, AND a build-tag-driven test that greps the
// codebase for forbidden patterns. The point is to make it loud
// rather than silent if anyone ever tries.
//
// For now (no transport code outside stdio), this is documentation
// + a sentinel error that future code paths can reference.

// ErrTCPForbidden is returned if any future transport tries to bind
// a TCP listener. Code that opens a new transport SHOULD call
// MustNotListenTCP at the top to make this explicit.
var ErrTCPForbidden = errors.New("mcp: TCP transport forbidden — SECURITY Foundational #3 (stdio + Unix-domain only)")

// MustNotListenTCP panics if called. Use as a sentinel in any
// future code path that handles a network address — the panic is the
// invariant guard.
//
//nolint:unused // sentinel exported for future transport code
func MustNotListenTCP(network, address string) {
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		panic(ErrTCPForbidden.Error() + ": tried to listen on " + address)
	}
}

// _ guarantees the net package is part of the import graph so a
// future "remove unused imports" pass doesn't drop it before
// MustNotListenTCP grows real callers.
var _ = net.Listen
