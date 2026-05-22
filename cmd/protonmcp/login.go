package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
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
	if err := persistSession(bundle); err != nil {
		return fmt.Errorf("save session to Keychain: %w", err)
	}

	primary, _ := sess.PrimaryAddress()
	fmt.Printf("Logged in as %s (%s). Session stored in Keychain.\n",
		sess.Email, coalesce(primary.Email, "no primary address"))
	return nil
}

// runLogout revokes the server-side session (best effort) and deletes
// the Keychain entry.
func runLogout(ctx context.Context, _ []string) error {
	stored, loadErr := keystore.Load()
	if loadErr != nil && !errors.Is(loadErr, keystore.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "warning: couldn't load stored session for server-side revoke (%v)\n", loadErr)
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
		}
		mgr.Close()
	}

	if err := keystore.Delete(); err != nil {
		return fmt.Errorf("delete Keychain entry: %w", err)
	}
	fmt.Println("Logged out.")
	return nil
}
