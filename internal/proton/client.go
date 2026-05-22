// Package proton wraps github.com/ProtonMail/go-proton-api with the login,
// 2FA, and key-unlock flow protonmcp needs at startup.
//
// At this stage the wrapper only supports an interactive setup path
// (env-var driven). Keychain storage, token refresh, and the LOCKED state
// machine described in the design doc land in later phases.
package proton

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// shutdownTimeout caps how long the session-revoke + close path is
// willing to wait. Five seconds is generous for a single HTTPS round-
// trip; anything longer than that and we'd rather walk away than block
// the caller's shutdown indefinitely.
const shutdownTimeout = 5 * time.Second

// detachedShutdownCtx returns a fresh context with shutdownTimeout. Use
// this for revoke paths that must run *even when the caller's context
// is already cancelled* (Ctrl-C during login, SIGTERM during a long
// backfill). Using the caller's cancelled context would silently skip
// the server-side AuthDelete and leave the session alive on Proton.
func detachedShutdownCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), shutdownTimeout)
}

// HostURL is the production Proton Mail API endpoint, matching what
// proton-bridge ships with.
const HostURL = "https://mail-api.proton.me"

// AppVersion intentionally impersonates Proton Bridge. The Proton API
// validates this header against a known allowlist; an unknown value gets
// rejected. The design spec calls for "same envelope the official client
// uses" — we hold to that here.
//
// TODO(v1.1): apply for a Proton-issued client identifier so we can stop
// pretending to be Bridge.
const AppVersion = "macos-bridge@3.24.2"

// Credentials is everything needed to bring the daemon from cold start
// to a fully-unlocked session. MailboxPassword only applies when the
// account uses the legacy two-password mode; for one-password accounts
// (the common case) leave it empty and Password is reused.
//
// All credential fields are secret.Secret values. Callers are expected
// to call Zero() (or the Credentials.Zero helper) once login completes
// so the byte material doesn't linger on the heap. The Email field is
// plain string — it identifies but isn't a credential.
//
// AskTOTP and AskMailboxPassword are optional callbacks invoked mid-
// login, after the server reveals whether 2FA and a separate mailbox
// password are required. Returning a Secret keeps the lifecycle
// promise end-to-end.
type Credentials struct {
	Email           string
	Password        secret.Secret
	MailboxPassword secret.Secret // empty falls back to Password
	TOTP            secret.Secret // required if account has TOTP 2FA

	AskTOTP            func() (secret.Secret, error)
	AskMailboxPassword func() (secret.Secret, error)
}

// Zero wipes every secret field. Idempotent.
func (c *Credentials) Zero() {
	c.Password.Zero()
	c.MailboxPassword.Zero()
	c.TOTP.Zero()
}

// Session is the unlocked-state bundle returned by Login or Resume.
// The caller owns the client and is responsible for calling Close
// when done; the keyrings hold decrypted PGP material and should be
// cleared as soon as feasible.
//
// Close is idempotent (guarded by sync.Once), so it's safe to wire
// from multiple defer / signal paths without risking double-revoke or
// panic.
//
// Email / UID / AccessToken / RefreshToken / SaltedKeyPass let callers
// persist the session to the OS Keychain after Login and use Resume
// on a later run. AccessToken / RefreshToken are rotated in place by
// the SDK's AuthHandler when Proton hands back a fresh pair; callers
// that persist these to disk subscribe via OnAuthUpdate to write the
// rotated values back.
type Session struct {
	Client       *gpa.Client
	User         gpa.User
	Addresses    []gpa.Address
	UserKR       *crypto.KeyRing
	AddrKRs      map[string]*crypto.KeyRing
	PasswordMode gpa.PasswordMode
	TwoFA        gpa.TwoFAStatus

	Email         string
	UID           string
	SaltedKeyPass secret.Secret

	authMu       sync.Mutex
	AccessToken  string
	RefreshToken string

	// OnAuthUpdate, if set, fires whenever the SDK hands us a rotated
	// auth bundle. Session.AccessToken / RefreshToken have already been
	// updated by the time this is called. Callers wire this to persist
	// the rotated tokens so the next process can resume.
	OnAuthUpdate func(uid, accessToken, refreshToken string)

	closeOnce sync.Once
}

// Tokens returns the current (rotating) access + refresh tokens under
// the auth mutex.
func (s *Session) Tokens() (access, refresh string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	return s.AccessToken, s.RefreshToken
}

// installAuthHandler wires the SDK's AuthHandler into the session so
// rotated tokens are captured and (optionally) forwarded to
// OnAuthUpdate. Called by both Login and Resume after they construct
// a Client.
func (s *Session) installAuthHandler() {
	if s.Client == nil {
		return
	}
	s.Client.AddAuthHandler(func(auth gpa.Auth) {
		s.authMu.Lock()
		s.AccessToken = auth.AccessToken
		s.RefreshToken = auth.RefreshToken
		cb := s.OnAuthUpdate
		uid := s.UID
		s.authMu.Unlock()
		if cb != nil {
			cb(uid, auth.AccessToken, auth.RefreshToken)
		}
	})
}

// PrimaryAddress returns the user's primary (Order == 1) enabled address,
// falling back to the first enabled address if no Order==1 exists.
func (s *Session) PrimaryAddress() (gpa.Address, bool) {
	var fallback gpa.Address
	haveFallback := false
	for _, a := range s.Addresses {
		if a.Status != gpa.AddressStatusEnabled {
			continue
		}
		if a.Order == 1 {
			return a, true
		}
		if !haveFallback {
			fallback = a
			haveFallback = true
		}
	}
	return fallback, haveFallback
}

// Close releases local crypto + HTTP state for the session. It does
// NOT revoke the session on the Proton server — doing so would kill
// the refresh token we just stored in the Keychain and force a fresh
// SRP login on every subcommand. For explicit revoke (logout, or
// abandoning a partial login), call CloseAndRevoke instead.
//
// Idempotent via sync.Once.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.releaseLocal()
		if s.Client != nil {
			s.Client.Close()
			s.Client = nil
		}
	})
}

// CloseAndRevoke is Close plus a server-side AuthDelete. Use from the
// logout subcommand or error-recovery paths that explicitly want the
// session destroyed on Proton's side. The AuthDelete runs against a
// fresh 5-second context so a cancelled parent ctx (Ctrl-C) cannot
// smuggle through and skip the revoke step.
//
// Idempotent via sync.Once.
func (s *Session) CloseAndRevoke() {
	s.closeOnce.Do(func() {
		s.releaseLocal()
		if s.Client != nil {
			ctx, cancel := detachedShutdownCtx()
			defer cancel()
			_ = s.Client.AuthDelete(ctx)
			s.Client.Close()
			s.Client = nil
		}
	})
}

// releaseLocal zeroes keyring material and the salted mailbox pass.
// Not protected by closeOnce — callers (Close, CloseAndRevoke) own
// the Once guard.
func (s *Session) releaseLocal() {
	if s.UserKR != nil {
		s.UserKR.ClearPrivateParams()
		s.UserKR = nil
	}
	for id, kr := range s.AddrKRs {
		kr.ClearPrivateParams()
		delete(s.AddrKRs, id)
	}
	s.SaltedKeyPass.Zero()
}

// NewManager constructs a Manager pre-configured for production Proton
// Mail. Tests can swap in a different host via the host arg (pass "" for
// the default).
func NewManager(host string) *gpa.Manager {
	if host == "" {
		host = HostURL
	}
	return gpa.New(
		gpa.WithHostURL(host),
		gpa.WithAppVersion(AppVersion),
	)
}

func doTOTP(ctx context.Context, client *gpa.Client, creds *Credentials) error {
	if creds.TOTP.Empty() && creds.AskTOTP != nil {
		v, err := creds.AskTOTP()
		if err != nil {
			return fmt.Errorf("prompt totp: %w", err)
		}
		creds.TOTP = v
	}
	if creds.TOTP.Empty() {
		return errors.New("proton: account requires TOTP code")
	}
	// Auth2FA takes a string; the SDK doesn't accept []byte for the TOTP
	// field. The string copy lives until GC, which is a small leak but
	// the TOTP code itself is short-lived (30s validity) and one-shot.
	if err := client.Auth2FA(ctx, gpa.Auth2FAReq{TwoFactorCode: string(creds.TOTP.Bytes())}); err != nil {
		return fmt.Errorf("2fa: %w", err)
	}
	return nil
}

// Login performs SRP login, submits the TOTP code if the server requires
// one, fetches user/addresses/salts, and unlocks the PGP keyring. On any
// failure the partially-built client is closed before returning.
//
// Login mutates creds via the AskTOTP / AskMailboxPassword callbacks (the
// prompts may populate the corresponding Secret fields). After Login
// returns — success or failure — the caller should call creds.Zero() to
// wipe the credential material.
func Login(ctx context.Context, mgr *gpa.Manager, creds *Credentials) (*Session, error) {
	if creds.Email == "" || creds.Password.Empty() {
		return nil, errors.New("proton: email and password are required")
	}

	client, auth, err := mgr.NewClientWithLogin(ctx, creds.Email, creds.Password.Bytes())
	if err != nil {
		return nil, fmt.Errorf("srp login: %w", err)
	}

	// Use a detached context for revoke. The caller's ctx may be cancelled
	// (Ctrl-C mid-login), and AuthDelete on a cancelled context would
	// silently fail, leaving an authenticated session alive on Proton.
	// SECURITY H-3.
	cleanup := func() {
		revokeCtx, cancel := detachedShutdownCtx()
		defer cancel()
		_ = client.AuthDelete(revokeCtx)
		client.Close()
	}

	// 2FA. We only implement TOTP today. FIDO2 (security keys / passkeys)
	// is tracked in TODO.html; if the account has FIDO2+TOTP we
	// transparently use TOTP, if it's FIDO2-only the user gets a pointer
	// to add TOTP in Proton settings as a workaround.
	switch auth.TwoFA.Enabled {
	case 0:
		// no 2FA
	case gpa.HasTOTP, gpa.HasFIDO2AndTOTP:
		if err := doTOTP(ctx, client, creds); err != nil {
			cleanup()
			return nil, err
		}
	case gpa.HasFIDO2:
		cleanup()
		return nil, errors.New("proton: this account uses FIDO2 (security key / passkey) as its only 2FA method, which protonmcp does not support yet. Workaround: in the Proton web app go to Settings → All settings → Account → Two-factor authentication and add an Authenticator-app (TOTP) method alongside your security key. Native FIDO2 support is tracked in TODO.html.")
	default:
		cleanup()
		return nil, fmt.Errorf("proton: unknown 2FA mode %d", auth.TwoFA.Enabled)
	}

	// Resolve the mailbox password. For one-password accounts the login
	// password is reused. For two-password accounts we need a separate
	// secret (from env, or prompted via the callback).
	if auth.PasswordMode == gpa.TwoPasswordMode && creds.MailboxPassword.Empty() {
		if creds.AskMailboxPassword == nil {
			cleanup()
			return nil, errors.New("proton: account uses two-password mode; mailbox password required")
		}
		v, err := creds.AskMailboxPassword()
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("prompt mailbox password: %w", err)
		}
		if v.Empty() {
			cleanup()
			return nil, errors.New("proton: mailbox password is empty")
		}
		creds.MailboxPassword = v
	}
	mailboxBytes := creds.MailboxPassword.Bytes()
	if len(mailboxBytes) == 0 {
		mailboxBytes = creds.Password.Bytes()
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("get user: %w", err)
	}

	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	salts, err := client.GetSalts(ctx)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("get salts: %w", err)
	}

	if len(user.Keys) == 0 {
		cleanup()
		return nil, errors.New("proton: user has no keys")
	}
	primaryKey := user.Keys.Primary()

	saltedRaw, err := salts.SaltForKey(mailboxBytes, primaryKey.ID)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("salt for primary key: %w", err)
	}
	// Wrap and zero the raw buffer right away. saltedKeyPass is just as
	// sensitive as the mailbox password (it derives the user PGP key);
	// we keep it on the Session so callers can persist it to the
	// Keychain for resume, but the raw buffer goes away.
	saltedPass := secret.New(saltedRaw)
	for i := range saltedRaw {
		saltedRaw[i] = 0
	}

	userKR, addrKRs, err := gpa.Unlock(user, addrs, saltedPass.Bytes(), nil)
	if err != nil {
		saltedPass.Zero()
		cleanup()
		return nil, fmt.Errorf("unlock keyring: %w (wrong mailbox password?)", err)
	}

	sess := &Session{
		Client:        client,
		User:          user,
		Addresses:     addrs,
		UserKR:        userKR,
		AddrKRs:       addrKRs,
		PasswordMode:  auth.PasswordMode,
		TwoFA:         auth.TwoFA.Enabled,
		Email:         creds.Email,
		UID:           auth.UID,
		AccessToken:   auth.AccessToken,
		RefreshToken:  auth.RefreshToken,
		SaltedKeyPass: saltedPass,
	}
	sess.installAuthHandler()
	return sess, nil
}
