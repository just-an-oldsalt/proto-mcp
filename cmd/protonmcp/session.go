package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

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
		fmt.Fprintf(os.Stderr, "stored session unusable (%v); re-authenticating ...\n", err)
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
		fmt.Fprintf(os.Stderr, "warning: failed to save session to Keychain (%v); subsequent runs will need to log in again.\n", err)
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
	wireKeystoreSync(bundle)
	return bundle, nil
}

// persistSession writes the session's resumable fields (tokens, salted
// pass, cookies) to the Keychain. Called once at first-login time;
// subsequent rotations go through wireKeystoreSync's hook.
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
			fmt.Fprintf(os.Stderr, "warning: token rotation not persisted (%v)\n", err)
		}
	}
}
