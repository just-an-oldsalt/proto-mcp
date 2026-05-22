package proton

import (
	"strings"
	"testing"
)

// SECURITY B-2 / B-12 guard: PROTONMCP_DEBUG output must not leak
// credentials in HTTP headers or JSON bodies even though the
// transport itself dumps raw bytes.

func TestRedactDumpHeaders(t *testing.T) {
	dump := []byte(
		"POST /auth/v4 HTTP/1.1\r\n" +
			"Host: mail-api.proton.me\r\n" +
			"Authorization: Bearer sk_live_abc123\r\n" +
			"Cookie: Session-Id=verysecret; Tag=default\r\n" +
			"X-Pm-Uid: kyt2bhaj27dzjofd\r\n" +
			"Content-Type: application/json\r\n\r\n" +
			"{}")
	got := string(redactDump(dump))
	for _, leak := range []string{"sk_live_abc123", "verysecret", "kyt2bhaj27dzjofd"} {
		if strings.Contains(got, leak) {
			t.Errorf("leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "Authorization: [REDACTED]") {
		t.Errorf("Authorization header not redacted: %q", got)
	}
	if !strings.Contains(got, "Content-Type:") {
		t.Errorf("non-sensitive headers should pass through: %q", got)
	}
}

func TestRedactDumpJSONBody(t *testing.T) {
	dump := []byte(`POST /auth/v4 HTTP/1.1
Host: mail-api.proton.me
Content-Type: application/json

{"Username":"alice","ClientProof":"abc","ClientEphemeral":"def","SRPSession":"opaque"}`)
	got := string(redactDump(dump))
	for _, leak := range []string{`"abc"`, `"def"`} {
		if strings.Contains(got, leak) {
			t.Errorf("body leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, `"Username":"alice"`) {
		t.Errorf("non-sensitive fields should pass through: %q", got)
	}
	if !strings.Contains(got, `"ClientProof": "[REDACTED]"`) {
		t.Errorf("ClientProof not redacted: %q", got)
	}
}

func TestRedactDumpResponseBody(t *testing.T) {
	// A /auth/v4 response shape.
	dump := []byte(`HTTP/1.1 200 OK
Set-Cookie: Session-Id=abc; HttpOnly
Content-Type: application/json

{"UID":"kyt2bhaj","AccessToken":"uozazbvw","RefreshToken":"k2fkzwv4","TwoFA":{"Enabled":3}}`)
	got := string(redactDump(dump))
	for _, leak := range []string{"abc", "kyt2bhaj", "uozazbvw", "k2fkzwv4"} {
		if strings.Contains(got, leak) {
			t.Errorf("response leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, `"Enabled":3`) {
		t.Errorf("nested non-sensitive value lost: %q", got)
	}
}
