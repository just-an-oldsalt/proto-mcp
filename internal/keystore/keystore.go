// Package keystore persists Proton session state to the macOS Keychain
// so a fresh process can resume work without re-running the full SRP +
// 2FA + keyring-unlock flow.
//
// One Keychain item per machine, identified by Service + Account below.
// The item's secret payload is a JSON blob containing the email, the
// session UID, the rotating access / refresh tokens, and the SRP-derived
// salted mailbox-password (base64'd). The Keychain handles encryption
// at rest; this package just brokers the in/out conversion.
//
// Multi-account support is deliberately out of scope for now — there's
// one slot, and `protonmcp login` overwrites whatever was there.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	keychain "github.com/keybase/go-keychain"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

const (
	// Service is the macOS Keychain service identifier under which the
	// session blob is filed. Matches the launchd label placeholder used
	// throughout the design spec; will become a real bundle identifier
	// once the daemon is signed.
	Service = "zone.dort.protonmcp"

	// Account is the single per-machine slot the v1 keystore uses.
	// Multi-account would put the email here instead.
	Account = "session"

	// Label is what shows up in Keychain Access.app for humans.
	Label = "Proton MCP session"
)

// ErrNotFound is returned by Load and Delete when no session is stored.
var ErrNotFound = errors.New("keystore: no stored session")

// Live is the in-memory shape of a stored session. SaltedKeyPass is a
// secret.Secret because it's the binary used to re-unlock the user's
// PGP keyring — just as sensitive as the mailbox password.
//
// Cookies carries the http.Cookie values set by /auth/v4 during the
// initial SRP login. Proton's refresh endpoint is cookie-bound: a
// cold-process resume with the right UID + refresh token still hits
// 422 "Invalid refresh token" unless the same session cookies are
// sent. We persist them alongside the tokens so a fresh process can
// rebuild the jar exactly as the SDK left it.
type Live struct {
	Email         string
	UID           string
	AccessToken   string
	RefreshToken  string
	SaltedKeyPass secret.Secret
	Cookies       []*http.Cookie
}

// Zero wipes secret material on the Live value.
func (l *Live) Zero() {
	l.SaltedKeyPass.Zero()
	// Tokens are still string-valued — Go strings can't be zeroed, so
	// the best we can do is drop the reference and let GC reclaim.
	l.AccessToken = ""
	l.RefreshToken = ""
}

// savedBlob is the on-disk shape (in the Keychain blob). Kept private
// so callers can't accidentally hand a json.Marshal-able struct around
// the codebase. All fields are strings / JSON-safe types because
// Keychain stores bytes and we want a stable schema independent of
// secret.Secret internals.
type savedBlob struct {
	Email            string         `json:"email"`
	UID              string         `json:"uid"`
	AccessToken      string         `json:"access_token"`
	RefreshToken     string         `json:"refresh_token"`
	SaltedKeyPassB64 string         `json:"salted_key_pass_b64"`
	Cookies          []*http.Cookie `json:"cookies,omitempty"`
	Version          int            `json:"v"` // schema version, for future migrations
}

// blobVersion gets bumped when the JSON shape changes incompatibly.
// Old blobs from a previous version are rejected (forcing the user to
// re-login) rather than silently misinterpreted.
//
// History:
//
//	v1: original {email, uid, access_token, refresh_token, salted_key_pass_b64}
//	v2: added cookies (required for cold-start refresh — see Live doc)
const blobVersion = 2

// Save writes (or overwrites) the single session slot.
func Save(l Live) error {
	if l.Email == "" || l.UID == "" || l.RefreshToken == "" {
		return errors.New("keystore: refusing to save incomplete session (need email, uid, refresh_token)")
	}
	blob := savedBlob{
		Email:            l.Email,
		UID:              l.UID,
		AccessToken:      l.AccessToken,
		RefreshToken:     l.RefreshToken,
		SaltedKeyPassB64: base64.StdEncoding.EncodeToString(l.SaltedKeyPass.Bytes()),
		Cookies:          l.Cookies,
		Version:          blobVersion,
	}
	data, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("marshal blob: %w", err)
	}
	defer zero(data)

	// AccessibleWhenUnlocked means the Keychain item is readable only
	// while the user is logged in and the Keychain is unlocked. This is
	// the strictest setting that still lets `protonmcp whoami` run
	// without an extra Touch ID prompt every invocation. Tightening to
	// AccessibleWhenPasscodeSetThisDeviceOnly would require user passcode
	// input and is overkill until we add explicit Touch ID gating.
	item := keychain.NewGenericPassword(Service, Account, Label, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err = keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		// Item exists — update it. UpdateItem needs a query item (search
		// criteria) and an update item (new values).
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(Service)
		query.SetAccount(Account)

		update := keychain.NewItem()
		update.SetData(data)
		update.SetLabel(Label)
		return keychain.UpdateItem(query, update)
	}
	return err
}

// Load reads the stored session. Returns ErrNotFound if absent.
func Load() (Live, error) {
	data, err := keychain.GetGenericPassword(Service, Account, "", "")
	if err != nil {
		return Live{}, fmt.Errorf("keychain get: %w", err)
	}
	if data == nil {
		return Live{}, ErrNotFound
	}
	defer zero(data)

	var blob savedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return Live{}, fmt.Errorf("decode blob: %w", err)
	}
	if blob.Version != blobVersion {
		return Live{}, fmt.Errorf("keystore: unknown blob version %d (expected %d) — delete & re-login",
			blob.Version, blobVersion)
	}

	saltedRaw, err := base64.StdEncoding.DecodeString(blob.SaltedKeyPassB64)
	if err != nil {
		return Live{}, fmt.Errorf("decode salted_key_pass: %w", err)
	}
	live := Live{
		Email:         blob.Email,
		UID:           blob.UID,
		AccessToken:   blob.AccessToken,
		RefreshToken:  blob.RefreshToken,
		SaltedKeyPass: secret.New(saltedRaw),
		Cookies:       blob.Cookies,
	}
	zero(saltedRaw)
	return live, nil
}

// Delete removes the stored session. Returns nil if no entry exists
// (idempotent — useful for logout flows that don't want to fail when
// the user was never logged in).
func Delete() error {
	err := keychain.DeleteGenericPasswordItem(Service, Account)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return nil
	}
	return err
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
