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

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

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

// Credentials is everything needed to bring the daemon from cold start to
// a fully-unlocked session. MailboxPassword only applies when the account
// uses the legacy two-password mode; for one-password accounts (the common
// case) leave it empty and Password is reused.
//
// AskTOTP and AskMailboxPassword are optional callbacks invoked mid-login,
// after the server reveals whether 2FA and a separate mailbox password are
// required. This avoids forcing the caller to pre-collect credentials the
// account may not need. If a credential is required, the matching string
// field is empty, and the callback is nil, Login returns a clear error.
type Credentials struct {
	Email           string
	Password        string
	MailboxPassword string // optional; empty falls back to Password
	TOTP            string // optional; required if account has TOTP 2FA

	AskTOTP            func() (string, error)
	AskMailboxPassword func() (string, error)
}

// Session is the unlocked-state bundle returned by Login. The caller owns
// the client and is responsible for calling Close when done; the keyrings
// hold decrypted PGP material and should be cleared as soon as feasible.
type Session struct {
	Client       *gpa.Client
	User         gpa.User
	Addresses    []gpa.Address
	UserKR       *crypto.KeyRing
	AddrKRs      map[string]*crypto.KeyRing
	PasswordMode gpa.PasswordMode
	TwoFA        gpa.TwoFAStatus
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

// Close revokes the session on the server and zeroes local keyring state.
// Safe to call multiple times.
func (s *Session) Close(ctx context.Context) {
	if s.UserKR != nil {
		s.UserKR.ClearPrivateParams()
		s.UserKR = nil
	}
	for id, kr := range s.AddrKRs {
		kr.ClearPrivateParams()
		delete(s.AddrKRs, id)
	}
	if s.Client != nil {
		_ = s.Client.AuthDelete(ctx)
		s.Client.Close()
		s.Client = nil
	}
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

func doTOTP(ctx context.Context, client *gpa.Client, creds Credentials) error {
	totp := creds.TOTP
	if totp == "" && creds.AskTOTP != nil {
		v, err := creds.AskTOTP()
		if err != nil {
			return fmt.Errorf("prompt totp: %w", err)
		}
		totp = v
	}
	if totp == "" {
		return errors.New("proton: account requires TOTP code")
	}
	if err := client.Auth2FA(ctx, gpa.Auth2FAReq{TwoFactorCode: totp}); err != nil {
		return fmt.Errorf("2fa: %w", err)
	}
	return nil
}

// Login performs SRP login, submits the TOTP code if the server requires
// one, fetches user/addresses/salts, and unlocks the PGP keyring. On any
// failure the partially-built client is closed before returning.
func Login(ctx context.Context, mgr *gpa.Manager, creds Credentials) (*Session, error) {
	if creds.Email == "" || creds.Password == "" {
		return nil, errors.New("proton: email and password are required")
	}

	client, auth, err := mgr.NewClientWithLogin(ctx, creds.Email, []byte(creds.Password))
	if err != nil {
		return nil, fmt.Errorf("srp login: %w", err)
	}

	cleanup := func() {
		_ = client.AuthDelete(ctx)
		client.Close()
	}

	// 2FA. We only implement TOTP today. FIDO2 (security keys / passkeys)
	// is tracked in TODO.md; if the account has FIDO2+TOTP we transparently
	// use TOTP, if it's FIDO2-only the user gets a pointer to add TOTP in
	// Proton settings as a workaround.
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
		return nil, errors.New("proton: this account uses FIDO2 (security key / passkey) as its only 2FA method, which protonmcp does not support yet. Workaround: in the Proton web app go to Settings → All settings → Account → Two-factor authentication and add an Authenticator-app (TOTP) method alongside your security key. Native FIDO2 support is tracked in TODO.md.")
	default:
		cleanup()
		return nil, fmt.Errorf("proton: unknown 2FA mode %d", auth.TwoFA.Enabled)
	}

	mailboxPass := creds.MailboxPassword
	if auth.PasswordMode == gpa.TwoPasswordMode && mailboxPass == "" {
		if creds.AskMailboxPassword == nil {
			cleanup()
			return nil, errors.New("proton: account uses two-password mode; mailbox password required")
		}
		v, err := creds.AskMailboxPassword()
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("prompt mailbox password: %w", err)
		}
		if v == "" {
			cleanup()
			return nil, errors.New("proton: mailbox password is empty")
		}
		mailboxPass = v
	}
	if mailboxPass == "" {
		mailboxPass = creds.Password
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

	saltedPass, err := salts.SaltForKey([]byte(mailboxPass), primaryKey.ID)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("salt for primary key: %w", err)
	}

	userKR, addrKRs, err := gpa.Unlock(user, addrs, saltedPass, nil)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("unlock keyring: %w (wrong mailbox password?)", err)
	}

	return &Session{
		Client:       client,
		User:         user,
		Addresses:    addrs,
		UserKR:       userKR,
		AddrKRs:      addrKRs,
		PasswordMode: auth.PasswordMode,
		TwoFA:        auth.TwoFA.Enabled,
	}, nil
}

