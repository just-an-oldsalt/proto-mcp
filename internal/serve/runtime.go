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
	"sync"
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

	// Phase 6/E — lock/unlock state. The lock signal (SIGUSR1 or
	// `protonmcp lock`) zeroes Session and flips Locked=true; the
	// MCP middleware checks Locked before running any tool and
	// returns a structured "daemon_locked" error. Unlock (SIGUSR2
	// or `protonmcp unlock`) prompts Touch ID via the existing
	// approval broker, then re-runs the session-acquire callback.
	//
	// The Locked flag is intentionally readable without a lock
	// (via Locked() method). Concurrent reads from middleware vs
	// writes from the signal handler are race-safe via the mu
	// mutex on the write path; the worst-case race lets one
	// in-flight tool call get through during the lock signal,
	// which is acceptable (lock is best-effort hygiene, not a
	// hard wall).
	mu             sync.RWMutex
	locked         bool
	lockReason     string
	acquireSession func(context.Context) (SessionBundle, error)

	// Phase 7/A — auto-lock infrastructure. idleTracker bumps on
	// every tool call via the mcp.WithToolCallObserver hook.
	// lockwatchCancel terminates the Swift lockwatch helper on
	// runtime Close (the helper inherits our SIGTERM via its own
	// process group but we cancel explicitly for cleanliness).
	idleTracker     *idleTracker
	lockwatchCancel func()

	hupStop   chan struct{}
	pidUnlink func()
}

// Locked reports whether the runtime is currently in the locked
// state. Middleware checks this on every tool call.
func (r *Runtime) Locked() (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.locked, r.lockReason
}

// Lock zeroes the in-memory session and flips Locked=true. Idempotent
// (re-lock from an already-locked state is a no-op). Reason is shown
// to the LLM in the structured error response so it knows whether
// the lock was manual, idle, or signal-driven.
func (r *Runtime) Lock(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return
	}
	r.locked = true
	r.lockReason = reason
	if r.Session != nil {
		// Session.Close() zeros the in-memory keyring + drops
		// the access/refresh tokens from the wrapped client. The
		// Keychain blob is untouched; unlock re-loads from there.
		r.Session.Close()
	}
	// Drop every cached approval — a locked-then-unlocked daemon
	// shouldn't honor pre-lock prompts (the user may have wanted
	// to revoke them by locking).
	if r.Broker != nil {
		r.Broker.Invalidate()
	}
	slog.Info("daemon locked", "reason", reason)
}

// Unlock re-acquires the session by calling the same callback that
// Setup used at startup. Caller-supplied (typically Touch ID gated
// via the approval broker). Returns the error from session acquire
// so the CLI / signal handler can report it.
func (r *Runtime) Unlock(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.locked {
		return nil
	}
	if r.acquireSession == nil {
		return errors.New("runtime: no acquireSession callback registered for unlock")
	}
	bundle, err := r.acquireSession(ctx)
	if err != nil {
		return err
	}
	r.Bundle = bundle
	r.Session = bundle.GetSession()
	r.locked = false
	r.lockReason = ""
	slog.Info("daemon unlocked")
	return nil
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

	// 3. Session (eager-acquire). Phase 6/E — wrapped in a
	// Touch-ID-at-startup gate via the approval broker if one is
	// available. This is the application-layer substitute for the
	// Keychain ACL we deferred: even though the keychain blob is
	// readable without biometric (keybase/go-keychain doesn't
	// expose SecAccessControl), every session-acquire — both
	// initial startup and SIGUSR2-driven unlock — prompts Touch
	// ID before the keychain is touched. Same net UX.
	if cfg.AcquireSession == nil {
		_ = st.Close()
		return nil, errors.New("serve.Setup: AcquireSession is required")
	}

	// Resolve helper now so we know up-front whether to install
	// the startup gate. Missing helper is non-fatal: we degrade
	// to the Phase-5 behavior (acquire-without-prompt at startup),
	// and the same warning fires later when the broker construction
	// would have happened.
	startupHelperPath, helperResolveErr := approval.ResolveHelperPath(os.Args[0])
	gatedAcquire := cfg.AcquireSession
	if helperResolveErr == nil {
		gatedAcquire = newStartupGatedAcquire(startupHelperPath, cfg.AcquireSession, logger)
	}

	bundle, err := gatedAcquire(ctx)
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
	// Reuse the path resolution result from the Touch-ID-at-startup
	// gate above so we only pgrep + stat once.
	var broker *approval.Broker
	if helperResolveErr != nil {
		logger.Warn("touchid helper not found; prompted tools will be denied",
			"hint", "run `make touchid` from the repo root",
			"err", helperResolveErr.Error())
	} else {
		broker, err = approval.New(startupHelperPath, logger)
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
	//
	// rt is built post-srv so the lock-state callback closes over
	// it. Done in two steps so the closure has a stable target.
	rt := &Runtime{}
	rt.idleTracker = newIdleTracker()
	opts := []mcp.Option{
		mcp.WithPolicy(engine),
		mcp.WithAudit(auditWriter),
		mcp.WithCallerResolver(resolver),
		mcp.WithRateLimitPersister(newRateLimitStoreAdapter(st)),
		mcp.WithLockState(rt.Locked),
		mcp.WithToolCallObserver(rt.idleTracker.bumpActivity),
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

	rt.Store = st
	rt.Session = sess
	rt.Bundle = bundle
	rt.Policy = engine
	rt.Audit = auditWriter
	rt.Broker = broker
	rt.Resolver = resolver
	rt.MCPServer = srv
	rt.hupStop = hupStop
	rt.pidUnlink = pidCleanup
	rt.acquireSession = gatedAcquire

	// Phase 6/E — install SIGUSR1 / SIGUSR2 handlers for lock /
	// unlock. The signals are documented in the protonmcp lock /
	// unlock CLI subcommands; the daemon binary's main signal
	// loop is separate (SIGTERM-as-shutdown), so these two are
	// handled here.
	usrCh := make(chan os.Signal, 2)
	signal.Notify(usrCh, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range usrCh {
			switch sig {
			case syscall.SIGUSR1:
				rt.Lock("SIGUSR1")
			case syscall.SIGUSR2:
				if err := rt.Unlock(context.Background()); err != nil {
					logger.Warn("unlock failed", "err", err.Error())
				}
			}
		}
	}()

	// Phase 7/A — idle-lock + lockwatch helper.
	//
	// Idle lock: goroutine ticks every 30s, checks the engine's
	// IdleLockMinutes() (policy reload picks up new values), locks
	// the runtime when threshold exceeded.
	//
	// Lockwatch: spawn the Swift helper as a managed subprocess if
	// the binary is on disk. The helper writes "screen_locked" /
	// "sleep" lines to stdout when macOS broadcasts the
	// corresponding distributed notifications; we read those and
	// call Lock with the reason. If the helper isn't built, fall
	// through silently — the daemon still works, just without the
	// auto-lock triggers.
	go rt.idleTracker.run(context.Background(), engine.IdleLockMinutes, rt.Lock, logger)
	if lockwatchPath, found := resolveLockwatchPath(); found {
		rt.lockwatchCancel = startLockwatch(lockwatchPath, rt.Lock, logger)
	} else {
		logger.Info("lockwatch helper not found; screen-lock and sleep auto-lock disabled",
			"hint", "run `make lockwatch` from the repo root")
	}

	return rt, nil
}

// Close tears down the runtime in reverse setup order. Safe to call
// once; idempotency past the first call is not guaranteed.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.lockwatchCancel != nil {
		r.lockwatchCancel()
	}
	if r.idleTracker != nil {
		r.idleTracker.close()
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
