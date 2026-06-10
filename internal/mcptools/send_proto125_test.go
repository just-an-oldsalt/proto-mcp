package mcptools

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func genKey(t *testing.T, email string) *crypto.Key {
	t.Helper()
	k, err := crypto.GenerateKey("Test", email, "rsa", 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// PROTO-125 — decryptDraftBody must recover the original plaintext from
// the armored ciphertext CreateDraft stores, so mail_send_draft doesn't
// double-encrypt the body into garbage.
func TestDecryptDraftBody_RoundTrip(t *testing.T) {
	key := genKey(t, "me@proton.me")
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}

	const plaintext = "the original draft body, written once"
	// Unsigned encryption, mirroring CreateDraft's kr.Encrypt(msg, nil).
	enc, err := kr.Encrypt(crypto.NewPlainMessageFromString(plaintext), nil)
	if err != nil {
		t.Fatal(err)
	}
	armored, err := enc.GetArmored()
	if err != nil {
		t.Fatal(err)
	}

	got, err := decryptDraftBody(kr, armored)
	if err != nil {
		t.Fatalf("decryptDraftBody: %v", err)
	}
	if got != plaintext {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

// PROTO-125 — the root-cause fix: a recipient with multiple address keys
// must be reduced to its primary (first) key before the body session key
// is encrypted, or the BodyKeyPacket carries multiple key packets and the
// send API rejects it ("Multiple packets present", Code=2001). This pins
// the FirstKey() reduction buildSendPreferences relies on.
func TestPrimaryKeyReduction(t *testing.T) {
	kr, err := crypto.NewKeyRing(genKey(t, "rcpt@proton.me"))
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.AddKey(genKey(t, "rcpt@proton.me")); err != nil {
		t.Fatal(err)
	}
	if n := kr.CountEntities(); n != 2 {
		t.Fatalf("setup: expected a 2-key ring, got %d", n)
	}

	primary, err := kr.FirstKey()
	if err != nil {
		t.Fatal(err)
	}
	if n := primary.CountEntities(); n != 1 {
		t.Errorf("FirstKey() ring has %d keys, want 1 (single BodyKeyPacket)", n)
	}

	// The reduced ring still encrypts a session key (and to exactly one
	// recipient key, which is the whole point).
	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primary.EncryptSessionKey(sk); err != nil {
		t.Errorf("EncryptSessionKey to the primary key failed: %v", err)
	}
}
