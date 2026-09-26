package keystore

import (
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// Issue #123: a zeroed-but-not-detached pass keeps its length, so the
// empty check alone let an all-zero pass reach the Keychain. Save must
// refuse it. Tests call validate(), never Save(): Save writes the one
// real per-machine Keychain item, so a regression in a guard would
// otherwise clobber the developer's stored session.
func TestValidateRefusesAllZeroSaltedKeyPass(t *testing.T) {
	err := Live{
		Email:         "a@b.c",
		UID:           "uid",
		RefreshToken:  "refresh",
		SaltedKeyPass: secret.New(make([]byte, 32)),
	}.validate()
	if err == nil || !strings.Contains(err.Error(), "all-zero") {
		t.Fatalf("validate with an all-zero pass = %v, want an all-zero refusal", err)
	}
}
