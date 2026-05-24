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
// the codebase.
//
// SaltedKeyPass is []byte rather than a base64'd string deliberately
// (SECURITY B-1): encoding/json natively marshals []byte → base64 on
// write and base64 → []byte on read, so the raw key material goes
// through json.Marshal as a slice we can zero (defer zero(data) below),
// not as a Go string that lives in the GC heap until reclaimed.
type savedBlob struct {
	Email         string         `json:"email"`
	UID           string         `json:"uid"`
	AccessToken   string         `json:"access_token"`
	RefreshToken  string         `json:"refresh_token"`
	SaltedKeyPass []byte         `json:"salted_key_pass"`
	Cookies       []*http.Cookie `json:"cookies,omitempty"`
	Version       int            `json:"v"`
}

// blobVersion gets bumped when the JSON shape changes incompatibly.
// Old blobs from a previous version are rejected (forcing the user to
// re-login) rather than silently misinterpreted.
//
// History:
//
//	v1: original {email, uid, access_token, refresh_token, salted_key_pass_b64}
//	v2: added cookies (required for cold-start refresh — see Live doc)
//	v3: SaltedKeyPass migrated from base64 string to []byte (SECURITY B-1)
//
// v4 was briefly introduced for Phase 7/D's SecAccessControl-based
// keychain ACL hardening but rolled back: the cgo path required a
// `keychain-access-groups` entitlement, which is a "restricted
// entitlement" on macOS — Developer ID Application signing alone is
// not authorized for it; you need an Apple-provisioned profile
// embedded in the binary (Phase 7/E .app-bundle work). Without the
// profile, the kernel SIGKILLs the binary at launch. D37 is reopened
// and deferred to Phase 7/E. The cgo wrapper in
// access_control_darwin.{h,c,go} stays in tree, dormant, ready to
// re-enable once the bundle work lands.
const blobVersion = 3

// Save writes (or overwrites) the single session slot.
//
// Uses the keybase/go-keychain path with AccessibleWhenUnlocked. The
// Phase-7/D SecAccessControl path is intentionally NOT called here
// — see the blobVersion comment for why (restricted-entitlement wall).
func Save(l Live) error {
	if l.Email == "" || l.UID == "" || l.RefreshToken == "" {
		return errors.New("keystore: refusing to save incomplete session (need email, uid, refresh_token)")
	}
	// SECURITY D16 / B-14: refuse to write a blob whose
	// SaltedKeyPass got zeroed mid-flight. Without this guard, a
	// Close-vs-OnAuthUpdate race silently corrupts the Keychain
	// entry — next Resume fails at the key-unlock step with no
	// diagnostic clue. Pair with C-4 (OnAuthUpdate guard).
	if len(l.SaltedKeyPass.Bytes()) == 0 {
		return errors.New("keystore: refusing to save empty SaltedKeyPass (D16: likely Close/OnAuthUpdate race)")
	}
	blob := savedBlob{
		Email:         l.Email,
		UID:           l.UID,
		AccessToken:   l.AccessToken,
		RefreshToken:  l.RefreshToken,
		SaltedKeyPass: l.SaltedKeyPass.Bytes(),
		Cookies:       l.Cookies,
		Version:       blobVersion,
	}
	data, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("marshal blob: %w", err)
	}
	defer zero(data)

	item := keychain.NewGenericPassword(Service, Account, Label, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err = keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
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

	// Version migrations. v3 is current; older versions read with a
	// compat decoder + are silently rewritten as v3 on the next Save
	// (the caller of Load is typically about to call Resume → which
	// triggers a token rotation → which fires OnAuthUpdate → which
	// re-Saves). No user action required.
	switch blob.Version {
	case blobVersion:
		// happy path
	case 4:
		// Briefly-shipped v4 (Phase 7/D SecAccessControl). Same JSON
		// shape, just a different version marker. Treat as v3 — the
		// next Save will write a v3-flagged blob. No data lost.
	case 2:
		// v2 stored the salted key pass as a base64 STRING under the
		// "salted_key_pass_b64" field. Decode it here, populate the
		// v3-shaped slice in `blob` so the rest of Load doesn't care.
		raw, err := loadV2Salt(data)
		if err != nil {
			return Live{}, fmt.Errorf("migrate v2 blob: %w", err)
		}
		blob.SaltedKeyPass = raw
	default:
		return Live{}, fmt.Errorf("keystore: unknown blob version %d (expected %d) — run `protonmcp logout && protonmcp login`",
			blob.Version, blobVersion)
	}

	live := Live{
		Email:         blob.Email,
		UID:           blob.UID,
		AccessToken:   blob.AccessToken,
		RefreshToken:  blob.RefreshToken,
		SaltedKeyPass: secret.New(blob.SaltedKeyPass),
		Cookies:       blob.Cookies,
	}
	// Zero the unmarshaled bytes so the only copy of the salted key
	// material now lives inside the Secret. The data buffer at the
	// top of this function will also be zeroed by its defer.
	zero(blob.SaltedKeyPass)
	return live, nil
}

// v2 used a base64-encoded string for the salted key pass. The bytes
// it encodes are identical to what v3 ships as a []byte (Go's json
// happens to encode []byte to base64 too), so the migration is just
// "decode the string, install it in the new field."
func loadV2Salt(data []byte) ([]byte, error) {
	var legacy struct {
		B64 string `json:"salted_key_pass_b64"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("decode legacy field: %w", err)
	}
	if legacy.B64 == "" {
		return nil, errors.New("v2 blob missing salted_key_pass_b64 field")
	}
	raw, err := base64.StdEncoding.DecodeString(legacy.B64)
	if err != nil {
		return nil, fmt.Errorf("decode legacy base64: %w", err)
	}
	return raw, nil
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
