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
	"os"

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
//	v4: same JSON shape as v3; signals the keychain item was written
//	    with SecAccessControl + kSecAccessControlUserPresence (Phase
//	    7/D, D37 fix). Reads of v4 items trigger Touch ID at the OS
//	    level. v3 blobs are upgraded in place by Load.
const blobVersion = 4

// Save writes (or overwrites) the single session slot.
//
// Phase 7/D — on darwin the write routes through saveProtected
// (cgo wrapper around SecItemAdd / SecItemUpdate) which attaches a
// SecAccessControl requiring user-presence for subsequent reads.
// The save itself does NOT prompt; the prompt fires on every Load
// of the resulting v4 item. On non-darwin (test only — proto-mcp
// is macOS-only at runtime) Save falls back to the plain
// keybase/go-keychain path with AccessibleWhenUnlocked.
//
// D37 closed by this change: any same-UID process that previously
// could read the v3 item via the plain Keychain API will now hit
// the OS-level Touch ID prompt instead.
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

	if saveProtectedSupported {
		return saveProtected(Service, Account, Label, data)
	}

	// Non-darwin fallback. The original keybase/go-keychain path,
	// kept so tests build on Linux CI. Runtime on macOS always
	// takes the saveProtected branch above.
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

	// Version migrations. v4 is current; older versions read with a
	// compat decoder + are silently rewritten on the next Save
	// (typically triggered by the post-Load Resume → token rotation
	// → OnAuthUpdate → Save chain).
	//
	// Phase 7/D — v3→v4 specifically signals "this blob predates
	// the SecAccessControl hardening; the next Save will upgrade
	// it." We trigger that Save eagerly below so the upgrade
	// completes on the first daemon launch after rollout rather
	// than waiting for a token rotation (which can take days).
	needsACLUpgrade := false
	switch blob.Version {
	case blobVersion:
		// happy path — already v4
	case 3:
		// Same JSON shape; bump the version so the eager re-Save
		// writes a v4-flagged blob with SecAccessControl.
		needsACLUpgrade = true
	case 2:
		// v2 stored the salted key pass as a base64 STRING under the
		// "salted_key_pass_b64" field. Decode it here, populate the
		// v3-shaped slice in `blob` so the rest of Load doesn't care.
		// The eager re-Save below carries the upgrade through to v4.
		raw, err := loadV2Salt(data)
		if err != nil {
			return Live{}, fmt.Errorf("migrate v2 blob: %w", err)
		}
		blob.SaltedKeyPass = raw
		needsACLUpgrade = true
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

	// Phase 7/D — eager ACL upgrade. The write doesn't prompt; the
	// new ACL takes effect on the NEXT Load. Failure to upgrade is
	// non-fatal (Load already returned a valid Live); we log via
	// the package-level logger if one's installed, otherwise stay
	// silent and the next Save attempt retries.
	if needsACLUpgrade && saveProtectedSupported {
		if err := Save(live); err != nil {
			migrationLogf("keystore: ACL upgrade from v%d to v%d failed: %v (will retry on next save)",
				blob.Version, blobVersion, err)
		} else {
			migrationLogf("keystore: upgraded blob from v%d to v%d (SecAccessControl now requires Touch ID on next load)",
				blob.Version, blobVersion)
		}
	}

	return live, nil
}

// migrationLogf is a deliberately tiny logger seam — the keystore
// package historically doesn't take a logger, and we don't want to
// force one through every call site for a single diagnostic line.
// Defaults to writing to os.Stderr; tests / dev builds can swap.
var migrationLogf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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
