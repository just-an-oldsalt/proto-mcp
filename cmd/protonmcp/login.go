package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

// runLogin does the full SRP + TOTP + key-unlock flow interactively
// and saves the resulting session (tokens + cookies) to the Keychain.
// Unlike whoami, `login` does not try to resume from an existing
// entry — the explicit subcommand is for "I want to re-auth from
// scratch", so any existing entry is replaced.
func runLogin(ctx context.Context, _ []string) error {
	// Drop any existing entry up front so a failed re-login leaves
	// a clean slate rather than the old + potentially-stale tokens.
	if err := keystore.Delete(); err != nil {
		return fmt.Errorf("clear existing session: %w", err)
	}

	jar := protonclient.NewCookieJar()
	mgr := protonclient.NewManager(jar)
	defer mgr.Close()

	creds, err := collectCredentials(ctx)
	if err != nil {
		return err
	}
	defer creds.Zero()

	sess, err := protonclient.Login(ctx, mgr, creds)
	if err != nil {
		return err
	}
	defer sess.Close()

	bundle := &sessionBundle{Session: sess, Manager: mgr, Jar: jar}
	if err := session.Persist(bundle); err != nil {
		return fmt.Errorf("save session to Keychain: %w", err)
	}

	primary, _ := sess.PrimaryAddress()
	fmt.Printf("Logged in as %s (%s). Session stored in Keychain.\n",
		sess.Email, coalesce(primary.Email, "no primary address"))
	// SECURITY B-7 (residual). Phase 7/C ships Developer-ID signing
	// and notarization, which closes the "any binary at this path
	// can launch and impersonate us" half of the threat. Phase 7/D's
	// SecAccessControl path would close the "any same-UID process can
	// read the saved blob" half but is blocked on a provisioning
	// profile (D37, deferred to Phase 7/E .app-bundle work). Until
	// then, the application-layer Touch ID gate (Phase 6/E + 7/A)
	// is the practical guarantee: every session-acquire prompts the
	// user before the keychain is touched.
	fmt.Println("Note: a same-UID process with the login keychain unlocked can still read this")
	fmt.Println("session blob directly. The Touch ID startup gate is the active mitigation;")
	fmt.Println("OS-level keychain ACL hardening is tracked as D37 (Phase 7/E packaging).")
	return nil
}

// runLogout revokes the server-side session (best effort) and deletes
// the Keychain entry.
func runLogout(ctx context.Context, _ []string) error {
	stored, loadErr := keystore.Load()
	if loadErr != nil && !errors.Is(loadErr, keystore.ErrNotFound) {
		slog.Warn("couldn't load stored session for server-side revoke", "err", loadErr.Error())
	}
	// SECURITY D10 / B-3: zero salted material on return regardless
	// of whether we proceed to Resume — heap-resident keys for a
	// logout call are exactly the kind of leak the defense exists for.
	if loadErr == nil {
		defer stored.Zero()
	}

	if loadErr == nil {
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
		if err == nil {
			sess.CloseAndRevoke() // explicit revoke: this is logout
		} else {
			// SECURITY B-8. Resume failed → AuthDelete never ran → the
			// session is still alive on Proton's side. We're about to
			// delete the local Keychain entry; tell the user how to
			// finish the revocation manually rather than leaving them
			// thinking they're fully logged out.
			fmt.Fprintf(os.Stderr,
				"warning: couldn't reach Proton to revoke the server-side session (%v).\n"+
					"  The local Keychain entry will still be deleted, but the session\n"+
					"  remains active on Proton until you visit\n"+
					"    https://account.proton.me/u/0/mail/security\n"+
					"  and revoke it under \"Active sessions\".\n", err)
		}
		mgr.Close()
	}

	if err := keystore.Delete(); err != nil {
		return fmt.Errorf("delete Keychain entry: %w", err)
	}
	fmt.Println("Logged out.")
	return nil
}
