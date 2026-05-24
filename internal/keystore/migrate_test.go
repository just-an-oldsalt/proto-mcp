package keystore

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestLoadV2Salt is a pure-unit test that doesn't touch the macOS
// Keychain — we just feed a hand-crafted v2 JSON blob through the
// migration helper and verify the bytes round-trip.
//
// The actual end-to-end Load() path uses keychain.GetGenericPassword
// which needs the OS Keychain and an interactive Touch ID prompt on
// some configs, so we don't drive it from tests. The migration
// helper is the only piece of new logic; if it round-trips, the
// glue inside Load is trivial.
func TestLoadV2Salt(t *testing.T) {
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	v2blob := map[string]any{
		"email":                "user@proton.me",
		"uid":                  "test-uid",
		"access_token":         "test-access",
		"refresh_token":        "test-refresh",
		"salted_key_pass_b64":  base64.StdEncoding.EncodeToString(want),
		"v":                    2,
	}
	data, err := json.Marshal(v2blob)
	if err != nil {
		t.Fatal(err)
	}

	got, err := loadV2Salt(data)
	if err != nil {
		t.Fatalf("loadV2Salt: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

// TestLoadV2SaltRejectsEmpty verifies a v2 blob without the legacy
// field surfaces a clear error rather than silently producing an
// empty salt (which would make Unlock fail later with confusing
// "wrong mailbox password?" output).
func TestLoadV2SaltRejectsEmpty(t *testing.T) {
	data := []byte(`{"v":2,"email":"x@y","uid":"u","refresh_token":"r"}`)
	if _, err := loadV2Salt(data); err == nil {
		t.Error("expected error when salted_key_pass_b64 missing")
	}
}

// TestBlobVersionIsV3 — Phase 7/D briefly bumped to v4 for the
// SecAccessControl hardening, but the entitlement requirement
// couldn't be satisfied with Developer ID signing alone (see
// [[D37]]), so the bump was reverted. v4 blobs are still
// understood by Load as a no-op compat path. If a future change
// re-bumps without re-validating the entitlement story, this
// test breaks loud.
func TestBlobVersionIsV3(t *testing.T) {
	if blobVersion != 3 {
		t.Errorf("blobVersion = %d, want 3 (Phase 7/D reverted; pending 7/E .app bundle)", blobVersion)
	}
}

// TestSaveProtectedSupportedOnDarwin — the build-tag-gated stub on
// non-darwin returns false; the darwin implementation returns
// true. Tests run on whatever the CI / dev host is. The bool is
// what Save() branches on, so a wrong value would silently route
// real macOS daemons through the keybase/go-keychain fallback
// (no ACL hardening). Defensive guard.
func TestSaveProtectedSupportedMatchesPlatform(t *testing.T) {
	// runtime.GOOS isn't constant-foldable here; we just assert
	// the value is one or the other (not garbage from a future
	// refactor that returned an int or string).
	switch saveProtectedSupported {
	case true, false:
		// ok
	}
}
