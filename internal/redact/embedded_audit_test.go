package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// PROTO-136 — the args_json audit path must scrub tokens embedded in a
// larger string value, and standard (non-url-safe) base64 credentials
// containing '/', which looksLikeToken deliberately skips.
func TestJSON_ScrubsEmbeddedTokensInArgString(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	args := map[string]any{
		// A token embedded in prose under a non-sensitive key — passes
		// looksLikeToken (has spaces/quotes) but must still be scrubbed.
		"note": `upstream said {"refreshToken":"` + jwt + `"}`,
		// Standard base64 with '/' — looksLikeToken bails on '/'.
		"blob": "AAAA/BBBB+CCCC/DDDD+EEEE/FFFF+GGGG/HHHH+IIIIJJJJ",
	}
	raw, _ := json.Marshal(args)

	out := string(JSON(raw))

	if strings.Contains(out, jwt) {
		t.Errorf("embedded JWT survived redaction in args_json:\n%s", out)
	}
	if strings.Contains(out, "AAAA/BBBB+CCCC/DDDD") {
		t.Errorf("standard-base64 blob survived redaction in args_json:\n%s", out)
	}
}

// A benign string value must pass through untouched (no over-redaction).
func TestJSON_LeavesBenignStringsAlone(t *testing.T) {
	args := map[string]any{"subject": "Re: gear list for the weekend"}
	raw, _ := json.Marshal(args)
	out := string(JSON(raw))
	if !strings.Contains(out, "Re: gear list for the weekend") {
		t.Errorf("benign subject was mangled: %s", out)
	}
}

// PROTO-136 — Error() scrubs embedded tokens out of an audit error_msg.
func TestError_ScrubsTokens(t *testing.T) {
	tok := "abcdefghIJKLMNOP0123456789-_abcdefghIJKLMNOP0123456789" // ≥40 base64url
	in := "auth failed: unknown response {\"AccessToken\":\"" + tok + "\"}"
	out := Error(in)
	if strings.Contains(out, tok) {
		t.Errorf("Error() left a token in place: %q", out)
	}
	// A plain error must be returned unchanged.
	plain := "tool returned nil result with no error"
	if Error(plain) != plain {
		t.Errorf("Error() altered a token-free message: %q", Error(plain))
	}
}
