package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// sessionBundle is everything a subcommand needs to talk to Proton
// and clean up afterward. The cookie jar lives in the bundle because
// every save-back to the Keychain (initial, on rotation, on logout)
// needs to extract the current cookies from it — without persisting
// cookies, a future process's refresh request hits 422.
type sessionBundle struct {
	Session *protonclient.Session
	Manager *gpa.Manager
	Jar     http.CookieJar
}

// Close releases the Manager. Use bundle.Session.Close() (no server
// revoke) for normal exit; call bundle.Session.CloseAndRevoke() before
// this only when explicitly logging out.
func (b *sessionBundle) Close() {
	if b.Manager != nil {
		b.Manager.Close()
	}
}

// acquireSessionResumeOnly tries to rebuild a session from the
// Keychain blob alone. If that fails — for any reason — it returns
// a clear error instead of falling through to interactive prompts.
//
// Used by `protonmcp serve-stdio`, which is spawned by Claude
// Desktop with no controlling TTY. Falling through to PromptLine in
// that environment fails opaquely ("no controlling tty available")
// in the middle of MCP initialization; better to refuse early with
// a message that points at the fix.
func acquireSessionResumeOnly(ctx context.Context) (*sessionBundle, error) {
	bundle, err := tryResume(ctx)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, fmt.Errorf(
				"no stored Proton session — run `protonmcp login` from a terminal " +
					"before launching the MCP server (MCP can't prompt for credentials)")
		}
		return nil, fmt.Errorf(
			"stored session unusable (%v) — run `protonmcp logout && protonmcp login` "+
				"from a terminal to refresh credentials", err)
	}
	return bundle, nil
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
func acquireSession(ctx context.Context) (*sessionBundle, error) {
	if b, err := tryResume(ctx); err == nil {
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
		return nil, err
	}

	bundle := &sessionBundle{Session: sess, Manager: mgr, Jar: jar}
	if err := persistSession(bundle); err != nil {
		slog.Warn("failed to save session to Keychain; subsequent runs will need to log in again", "err", err.Error())
	}
	wireKeystoreSync(bundle)
	return bundle, nil
}

// tryResume opens an existing Keychain entry, rebuilds the jar +
// Manager, and calls Resume. Returns keystore.ErrNotFound when there's
// nothing to resume so the caller can fall through to interactive
// login.
func tryResume(ctx context.Context) (*sessionBundle, error) {
	stored, err := keystore.Load()
	if err != nil {
		return nil, err
	}

	jar := protonclient.NewCookieJar()
	protonclient.PreloadJar(jar, stored.Cookies)
	mgr := protonclient.NewManager(jar)

	sess, err := protonclient.Resume(ctx, mgr, protonclient.ResumeArgs{
		Email:         stored.Email,
		UID:           stored.UID,
		AccessToken:   stored.AccessToken,
		RefreshToken:  stored.RefreshToken,
		SaltedKeyPass: stored.SaltedKeyPass,
	})
	if err != nil {
		mgr.Close()
		if errors.Is(err, protonclient.ErrSessionExpired) {
			_ = keystore.Delete()
		}
		return nil, err
	}

	bundle := &sessionBundle{Session: sess, Manager: mgr, Jar: jar}

	// Important: NewClientWithRefresh hands back rotated tokens but
	// does NOT fire the SDK's AuthHandler — that hook only triggers
	// on the auto-refresh-on-401 path inside the Client. Without an
	// explicit save here, the Keychain still holds the OLD refresh
	// token and the next process hits 400 / 422 on its own resume.
	if err := persistSession(bundle); err != nil {
		slog.Warn("failed to update Keychain with rotated tokens", "err", err.Error())
	}

	wireKeystoreSync(bundle)
	return bundle, nil
}

// persistSession writes the session's resumable fields (tokens, salted
// pass, cookies) to the Keychain. Called both at first-login time and
// immediately after a successful Resume — Resume's refresh response
// carries rotated tokens that must replace the stored ones.
func persistSession(b *sessionBundle) error {
	access, refresh := b.Session.Tokens()
	return keystore.Save(keystore.Live{
		Email:         b.Session.Email,
		UID:           b.Session.UID,
		AccessToken:   access,
		RefreshToken:  refresh,
		SaltedKeyPass: b.Session.SaltedKeyPass,
		Cookies:       protonclient.JarCookies(b.Jar),
	})
}

// wireKeystoreSync installs OnAuthUpdate so any SDK-driven token
// rotation also re-saves the Keychain blob (including refreshed
// cookies). Without this, a long-running backfill that triggers a
// refresh would leave the Keychain holding a now-invalidated refresh
// token.
func wireKeystoreSync(b *sessionBundle) {
	b.Session.OnAuthUpdate = func(uid, accessToken, refreshToken string) {
		err := keystore.Save(keystore.Live{
			Email:         b.Session.Email,
			UID:           uid,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			SaltedKeyPass: b.Session.SaltedKeyPass,
			Cookies:       protonclient.JarCookies(b.Jar),
		})
		if err != nil {
			slog.Warn("token rotation not persisted", "err", err.Error())
		}
	}
}
