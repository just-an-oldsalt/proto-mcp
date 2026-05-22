package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// acquireSession is the unified login-or-resume helper every read /
// write subcommand uses. The flow:
//
//  1. Look in the Keychain. If a session blob is present, try Resume.
//     Success returns immediately; Resume installs the AuthHandler that
//     keeps the Keychain blob in sync with rotated tokens.
//
//  2. If the stored session is expired (refresh token revoked), wipe
//     the Keychain entry and fall through to the full interactive
//     login. Tell the user out loud that we're re-authing — surprises
//     about extra prompts are worse than the prompt itself.
//
//  3. If the Keychain has nothing (first run on this machine), do the
//     full SRP+TOTP+unlock login, then save to Keychain so the next
//     invocation doesn't ask again.
//
// The returned Session has OnAuthUpdate wired to write rotated tokens
// back to the Keychain, so long-running operations like backfill
// survive token rotation cleanly.
func acquireSession(ctx context.Context, mgr *gpa.Manager) (*protonclient.Session, error) {
	if sess, err := tryResume(ctx, mgr); err == nil {
		return sess, nil
	} else if !errors.Is(err, keystore.ErrNotFound) {
		// Surface the reason we fell through so the user knows we're
		// about to prompt them.
		fmt.Fprintf(os.Stderr, "stored session unusable (%v); re-authenticating ...\n", err)
	}

	creds, err := collectCredentials()
	if err != nil {
		return nil, err
	}
	defer creds.Zero()

	sess, err := protonclient.Login(ctx, mgr, creds)
	if err != nil {
		return nil, err
	}

	if err := persistSession(sess); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save session to Keychain (%v); subsequent runs will need to log in again.\n", err)
	}
	wireKeystoreSync(sess)

	return sess, nil
}

// tryResume reads the Keychain blob and attempts Resume. Returns
// keystore.ErrNotFound when there's nothing to resume so the caller
// can distinguish "first run" from "stored session is dead".
func tryResume(ctx context.Context, mgr *gpa.Manager) (*protonclient.Session, error) {
	stored, err := keystore.Load()
	if err != nil {
		return nil, err
	}

	sess, err := protonclient.Resume(ctx, mgr, protonclient.ResumeArgs{
		Email:         stored.Email,
		UID:           stored.UID,
		RefreshToken:  stored.RefreshToken,
		SaltedKeyPass: stored.SaltedKeyPass,
	})
	if err != nil {
		// Stored token is dead — wipe the Keychain entry so we don't
		// hammer Proton on the next run. Best-effort; if the delete
		// fails the next run will just retry the same dead token,
		// which is wasteful but not unsafe.
		if errors.Is(err, protonclient.ErrSessionExpired) {
			_ = keystore.Delete()
		}
		return nil, err
	}
	wireKeystoreSync(sess)
	return sess, nil
}

// persistSession writes the session's resumable fields to the Keychain.
func persistSession(sess *protonclient.Session) error {
	access, refresh := sess.Tokens()
	return keystore.Save(keystore.Live{
		Email:         sess.Email,
		UID:           sess.UID,
		AccessToken:   access,
		RefreshToken:  refresh,
		SaltedKeyPass: sess.SaltedKeyPass,
	})
}

// wireKeystoreSync installs an OnAuthUpdate hook that re-saves the
// session to Keychain whenever the SDK rotates tokens. Without this,
// a long-running operation that triggers a refresh mid-flight would
// leave the Keychain holding a now-invalid refresh token.
func wireKeystoreSync(sess *protonclient.Session) {
	sess.OnAuthUpdate = func(uid, accessToken, refreshToken string) {
		err := keystore.Save(keystore.Live{
			Email:         sess.Email,
			UID:           uid,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			SaltedKeyPass: sess.SaltedKeyPass,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: token rotation not persisted (%v)\n", err)
		}
	}
}
