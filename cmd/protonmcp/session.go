package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

// sessionBundle is an alias of the shared session.Bundle. Kept under
// this local name to avoid a churn-y rename across the CLI
// subcommands (whoami / backfill / sync / etc all reference
// sessionBundle today). Phase 6's `internal/session` extraction
// keeps the type, just relocates the implementation so the daemon
// can use it without duplicating ~150 LOC.
type sessionBundle = session.Bundle

// acquireSessionResumeOnly delegates to internal/session for the
// resume-from-Keychain path. Same exported error messages.
func acquireSessionResumeOnly(ctx context.Context) (*sessionBundle, error) {
	return session.AcquireResumeOnly(ctx)
}

// acquireSession is the unified login-or-resume helper. Flow:
//
//  1. If the Keychain holds a session, preload its cookies into a
//     fresh jar, build the Manager around that jar, and call Resume.
//
//  2. On Resume success, wire OnAuthUpdate so rotated tokens AND
//     refreshed cookies get written back to the Keychain. Returns.
//
//  3. On ErrSessionExpired: wipe the Keychain entry (so we don't loop
//     on the dead token), print a loud message that we're falling
//     through, then continue to step 4.
//
//  4. First-run / no-stored / re-auth path: empty jar, full
//     interactive SRP + TOTP, save session + cookies on success.
//
// Interactive — stays in cmd/protonmcp because it depends on
// internal/cli's /dev/tty prompts.
func acquireSession(ctx context.Context) (*sessionBundle, error) {
	if b, err := session.TryResume(ctx); err == nil {
		return b, nil
	} else if !errors.Is(err, keystore.ErrNotFound) {
		slog.Warn("stored session unusable; re-authenticating", "err", err.Error())
	}

	jar := protonclient.NewCookieJar()
	mgr := protonclient.NewManager(jar)

	creds, err := collectCredentials(ctx)
	if err != nil {
		mgr.Close()
		return nil, err
	}
	defer creds.Zero()

	sess, err := protonclient.Login(ctx, mgr, creds)
	if err != nil {
		mgr.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	bundle := &session.Bundle{Session: sess, Manager: mgr, Jar: jar}
	if err := session.Persist(bundle); err != nil {
		slog.Warn("failed to save session to Keychain; subsequent runs will need to log in again", "err", err.Error())
	}
	session.WireKeystoreSync(bundle)
	return bundle, nil
}
