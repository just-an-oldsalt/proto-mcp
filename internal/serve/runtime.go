// Package serve assembles the long-running MCP-server runtime: the
// session, policy engine, audit writer, approval broker, caller
// resolver, and configured mcp.Server. Shared by serve-stdio (one
// transport, stdin/stdout) and protonmcpd (one transport, Unix
// socket accept loop).
//
// The split is for code reuse, not for hiding the wiring. The setup
// is intentionally explicit — callers pass Deps with their own
// session-acquire callback so the daemon can choose resume-only
// behavior while a future interactive command could prompt.
package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Runtime is the bundle of state every long-running MCP-serving
// process holds. Construct via Setup(). The MCPServer field is
// what transport code (stdio / Unix socket) calls Serve on.
//
// Concurrency: every field is independently safe for concurrent
// use. The daemon model (one Runtime, N connections) shares this
// instance across goroutines without additional locking.
type Runtime struct {
	Store     *store.Store
	Session   *protonclient.Session
	Bundle    SessionBundle // close + revoke surface from the cmd package
	Policy    *policy.Engine
	Audit     *audit.Writer
	Broker    *approval.Broker
	Resolver  *caller.Resolver
	MCPServer *mcp.Server

	hupStop   chan struct{}
	pidUnlink func()
}

// SessionBundle is the cmd-side wrapper around a Proton session.
// We refer to it via an interface here so internal/serve doesn't
// import cmd/protonmcp (which would be a cycle anyway). The
// underlying type lives in cmd/protonmcp's session.go.
type SessionBundle interface {
	Close()
	GetSession() *protonclient.Session
}

// SweepStaleBodies hard-deletes cached body rows older than
// store.DefaultBodyRetention. The default SetupConfig hook for the
// SECURITY D13 / C-1 startup sweep — both serve-stdio and
// protonmcpd pass this in.
func SweepStaleBodies(ctx context.Context, st *store.Store) (int64, error) {
	cutoff := time.Now().Add(-store.DefaultBodyRetention).UTC()
	return st.PurgeOlderThan(ctx, cutoff)
}

// SetupConfig is the input to Setup. Callers fill it in based on
// which transport they're building.
type SetupConfig struct {
	// DBPath overrides the SQLite store path. "" → DefaultPath().
	DBPath string

	// AcquireSession is how this runtime should obtain a logged-in
	// Proton session. serve-stdio passes acquireSessionResumeOnly;
	// the daemon does too. Future interactive commands could pass
	// a prompt-allowed variant.
	AcquireSession func(ctx context.Context) (SessionBundle, error)

	// SweepBodiesAtStartup — optional D13/C-1 retention sweep.
	// Pass cmd/protonmcp's sweepBodiesAtStartup wrapper or nil.
	SweepBodiesAtStartup func(ctx context.Context, st *store.Store) (int64, error)

	// Logger overrides slog.Default for runtime-level diagnostics.
	// Tool handlers and middleware still use slog.Default; this
	// is just for Setup / Close / HUP messages.
	Logger *slog.Logger
}

// Setup assembles every dependency a long-running MCP server needs.
// Returns a Runtime + an error. On error any partially-initialized
// resources are torn down before returning so callers don't have
// to special-case half-built runtimes.
//
// Lifecycle: the SIGHUP handler is installed by Setup and torn
// down by Close. Same for the PID file (so `protonmcp policy
// reload` can find a running daemon).
func Setup(ctx context.Context, cfg SetupConfig) (*Runtime, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Store.
	path := cfg.DBPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return nil, fmt.Errorf("default db path: %w", err)
		}
		path = p
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// 2. Retention sweep (D13/C-1).
	if cfg.SweepBodiesAtStartup != nil {
		if n, err := cfg.SweepBodiesAtStartup(ctx, st); err != nil {
			logger.Warn("body purge sweep failed at startup", "err", err.Error())
		} else if n > 0 {
			logger.Info("purged stale cached bodies at startup", "rows", n)
		}
	}

	// 3. Session (eager-acquire).
	if cfg.AcquireSession == nil {
		_ = st.Close()
		return nil, errors.New("serve.Setup: AcquireSession is required")
	}
	bundle, err := cfg.AcquireSession(ctx)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	sess := bundle.GetSession()

	// 4. Policy engine.
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("policy override path: %w", err)
	}
	engine, err := policy.New(ctx, overridePath, logger)
	if err != nil {
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("policy engine: %w", err)
	}

	// 5. PID file (so `policy reload` can pgrep us).
	pidPath, err := policy.DefaultPIDPath()
	if err != nil {
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("pid file path: %w", err)
	}
	pidCleanup, err := policy.WritePIDFile(pidPath)
	if err != nil {
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("pid file: %w", err)
	}

	// 6. Audit writer.
	jsonlPath, err := audit.DefaultJSONLPath()
	if err != nil {
		pidCleanup()
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("audit path: %w", err)
	}
	auditWriter, err := audit.New(st.DB, jsonlPath, logger)
	if err != nil {
		pidCleanup()
		bundle.Close()
		sess.Close()
		_ = st.Close()
		return nil, fmt.Errorf("audit writer: %w", err)
	}

	// 7. Approval broker — missing helper is non-fatal.
	helperPath, herr := approval.ResolveHelperPath(os.Args[0])
	var broker *approval.Broker
	if herr != nil {
		logger.Warn("touchid helper not found; prompted tools will be denied",
			"hint", "run `make touchid` from the repo root",
			"err", herr.Error())
	} else {
		broker, err = approval.New(helperPath, logger)
		if err != nil {
			_ = auditWriter.Close()
			pidCleanup()
			bundle.Close()
			sess.Close()
			_ = st.Close()
			return nil, fmt.Errorf("approval broker: %w", err)
		}
	}

	// 8. Caller resolver.
	resolver := caller.New()

	// 9. SIGHUP handler — policy reload + approval cache drop.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	hupStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-hupCh:
				if rerr := engine.Reload(); rerr != nil {
					logger.Warn("policy reload failed; previous policy retained", "err", rerr.Error())
					continue
				}
				n := 0
				if broker != nil {
					n = broker.Invalidate()
				}
				logger.Info("policy reloaded", "approvals_dropped", n)
			case <-hupStop:
				signal.Stop(hupCh)
				return
			}
		}
	}()

	// 10. MCP server with full middleware stack.
	opts := []mcp.Option{
		mcp.WithPolicy(engine),
		mcp.WithAudit(auditWriter),
		mcp.WithCallerResolver(resolver),
	}
	if broker != nil {
		opts = append(opts, mcp.WithApproval(broker))
	}
	srv := mcp.New(logger, opts...)
	for _, tl := range mcptools.All(mcptools.Deps{
		Session: sess,
		Store:   st,
		Policy:  engine,
	}) {
		srv.Register(tl)
	}

	return &Runtime{
		Store:     st,
		Session:   sess,
		Bundle:    bundle,
		Policy:    engine,
		Audit:     auditWriter,
		Broker:    broker,
		Resolver:  resolver,
		MCPServer: srv,
		hupStop:   hupStop,
		pidUnlink: pidCleanup,
	}, nil
}

// Close tears down the runtime in reverse setup order. Safe to call
// once; idempotency past the first call is not guaranteed.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.hupStop != nil {
		close(r.hupStop)
	}
	if r.Audit != nil {
		_ = r.Audit.Close()
	}
	if r.pidUnlink != nil {
		r.pidUnlink()
	}
	if r.Bundle != nil {
		r.Bundle.Close()
	}
	if r.Session != nil {
		r.Session.Close()
	}
	if r.Store != nil {
		_ = r.Store.Close()
	}
}
