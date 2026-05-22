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
// and saves the resulting session to the Keychain. Unlike whoami,
// `login` does not try to resume from an existing Keychain entry —
// the explicit subcommand is for "I want to re-auth from scratch",
// so any existing entry is replaced.
func runLogin(ctx context.Context, _ []string) error {
	// Drop any existing entry up front so a failed re-login leaves
	// a clean slate rather than the old + potentially-stale tokens.
	if err := keystore.Delete(); err != nil {
		return fmt.Errorf("clear existing session: %w", err)
	}

	creds, err := collectCredentials()
	if err != nil {
		return err
	}
	defer creds.Zero()

	mgr := protonclient.NewManager("")
	defer mgr.Close()

	sess, err := protonclient.Login(ctx, mgr, creds)
	if err != nil {
		return err
	}
	defer sess.Close()

	if err := persistSession(sess); err != nil {
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
		// Surface but don't bail — we still want to attempt the
		// Keychain delete below.
		fmt.Fprintf(os.Stderr, "warning: couldn't load stored session for server-side revoke (%v)\n", loadErr)
	}

	if loadErr == nil {
		mgr := protonclient.NewManager("")
		sess, err := protonclient.Resume(ctx, mgr, protonclient.ResumeArgs{
			Email:         stored.Email,
			UID:           stored.UID,
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
