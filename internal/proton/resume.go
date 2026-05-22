package proton

import (
	"context"
	"errors"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// ErrSessionExpired wraps the family of errors that mean "the stored
// refresh token is no longer valid — the user must re-authenticate".
// Callers detect this with errors.Is and respond by wiping the
// Keychain entry and falling back to a full Login.
var ErrSessionExpired = errors.New("proton: stored session expired or revoked")

// ResumeArgs is the minimum state needed to rebuild a Session without
// running the full SRP + 2FA + salt-fetch flow. All fields are
// populated from a Keychain blob.
type ResumeArgs struct {
	Email         string
	UID           string
	RefreshToken  string
	SaltedKeyPass secret.Secret
}

// Resume rebuilds a Session from a previously-stored refresh token and
// salted mailbox password. It calls NewClientWithRefresh (which rotates
// the token), fetches user + addresses, and unlocks the keyring with
// the supplied saltedPass.
//
// Resume does NOT retry on network errors — a single attempt is the
// right policy for two reasons. First, the caller (the CLI shell) is
// the natural retry boundary; a failed resume should simply prompt
// the user. Second, a buggy MCP client that loops on auth failure
// could otherwise hammer Proton's anti-abuse — Phase 7 will add
// proper rate limiting at the daemon level, but for now "one shot,
// fail-clean" is the bounded behavior we want.
//
// On expiry (the SDK returns a 401-class error from authRefresh),
// Resume returns ErrSessionExpired so the caller can distinguish "the
// stored token is dead" from "the network is flaky".
func Resume(ctx context.Context, mgr *gpa.Manager, args ResumeArgs) (*Session, error) {
	if args.UID == "" || args.RefreshToken == "" {
		return nil, errors.New("proton: resume requires UID + RefreshToken")
	}
	if args.SaltedKeyPass.Empty() {
		return nil, errors.New("proton: resume requires saltedKeyPass — re-login required")
	}

	client, auth, err := mgr.NewClientWithRefresh(ctx, args.UID, args.RefreshToken)
	if err != nil {
		if isAuthExpired(err) {
			return nil, fmt.Errorf("%w: %v", ErrSessionExpired, err)
		}
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	closeAndWrap := func(format string, vals ...any) error {
		// Best-effort revoke. If the refresh succeeded but a follow-up
		// call failed, the access token we just got is still good and
		// we should revoke it server-side rather than leak it.
		revokeCtx, cancel := detachedShutdownCtx()
		defer cancel()
		_ = client.AuthDelete(revokeCtx)
		client.Close()
		return fmt.Errorf(format, vals...)
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		return nil, closeAndWrap("resume get user: %w", err)
	}
	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		return nil, closeAndWrap("resume get addresses: %w", err)
	}

	userKR, addrKRs, err := gpa.Unlock(user, addrs, args.SaltedKeyPass.Bytes(), nil)
	if err != nil {
		return nil, closeAndWrap("resume unlock: %w — keystore blob may be stale, run `protonmcp login` again", err)
	}

	// SDK didn't expose PasswordMode / 2FA on refresh; we don't need
	// those fields for downstream Session users (they're informational
	// in whoami). Leave them at zero values — whoami's labels handle
	// unknown(0) gracefully.
	sess := &Session{
		Client:        client,
		User:          user,
		Addresses:     addrs,
		UserKR:        userKR,
		AddrKRs:       addrKRs,
		Email:         args.Email,
		UID:           args.UID,
		AccessToken:   auth.AccessToken,
		RefreshToken:  auth.RefreshToken,
		SaltedKeyPass: args.SaltedKeyPass,
	}
	sess.installAuthHandler()
	return sess, nil
}

// isAuthExpired distinguishes "token dead" from other failure modes
// (network down, server 500, etc.) so callers know whether to wipe the
// keystore or retry later.
//
// The Proton API returns HTTP 401 with a JSON body for invalid refresh
// tokens; go-proton-api wraps these as gpa.APIError values. We check
// for status code 401 conservatively — anything else falls through to
// the generic "refresh failed" path.
func isAuthExpired(err error) bool {
	var apiErr *gpa.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == 401
	}
	return false
}
