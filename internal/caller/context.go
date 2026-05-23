package caller

import "context"

// callerKey is the unexported context key under which a
// per-connection Caller is stashed by the daemon's accept loop.
// The MCP middleware reads it via FromContext; if absent (the
// serve-stdio path where one process == one caller), the
// middleware falls back to the cached process-wide Resolver.
type ctxKey struct{}

var callerKey ctxKey

// WithCaller returns a copy of ctx that carries the given Caller.
// Used by the daemon's accept loop (Phase 6/D) to associate the
// peer's identity with every tool call on that connection.
//
// SECURITY D20: before this, the audit row's caller_pid was the
// daemon's own PID because Resolver.Resolve() walks os.Getppid().
// That was correct for serve-stdio (the parent IS the Claude
// client) but wrong for the daemon model where multiple clients
// connect to one server. WithCaller + peer-cred lookup at accept
// time fix it.
func WithCaller(parent context.Context, c Caller) context.Context {
	return context.WithValue(parent, callerKey, c)
}

// FromContext returns the Caller stashed by WithCaller, or the
// zero Caller if absent. Callers detect "no per-conn caller set"
// by comparing the result against the zero value.
func FromContext(ctx context.Context) Caller {
	if c, ok := ctx.Value(callerKey).(Caller); ok {
		return c
	}
	return Caller{}
}
