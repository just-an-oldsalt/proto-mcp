package redact

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// captureLogger returns a slog.Logger that writes through Attr into
// the caller's buffer instead of stderr. Same wiring internal/logging
// uses; lets the test cases inspect what would have been logged.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			return Attr(a)
		},
	}))
}

func TestRedactsSensitiveKeys(t *testing.T) {
	cases := []string{
		"password", "Password", "PASSWORD",
		"mailbox_password", "MailboxPassword",
		"totp",
		"access_token", "AccessToken",
		"refresh_token", "RefreshToken",
		"salted_key_pass",
		"cookie", "Set-Cookie",
		"authorization", "Authorization",
		"client_proof", "ClientProof",
		"srp_session",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			l := captureLogger(&buf)
			l.Info("sensitive log", slog.String(key, "hunter2"))
			out := buf.String()
			if strings.Contains(out, "hunter2") {
				t.Errorf("value leaked for key %q: %s", key, out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("missing REDACTED marker for key %q: %s", key, out)
			}
		})
	}
}

func TestBodyShapedKeysGetSHA256Form(t *testing.T) {
	// Body / text / html in slog attrs become a {sha256, bytes}
	// string representation — keeps the row diagnostically useful
	// (length + correlation hash) without persisting the content.
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Info("draft", slog.String("body", "hello world"))
	out := buf.String()
	if strings.Contains(out, "hello world") {
		t.Errorf("body value leaked: %s", out)
	}
	if !strings.Contains(out, "sha256") || !strings.Contains(out, "bytes") {
		t.Errorf("body should be replaced with sha256+bytes form: %s", out)
	}
}

func TestPassThroughKeys(t *testing.T) {
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Info("benign log",
		slog.String("email", "user@example.com"),
		slog.String("tool", "mail_list"),
		slog.Int("count", 42),
	)
	out := buf.String()
	if !strings.Contains(out, "user@example.com") {
		t.Errorf("email shouldn't be redacted: %s", out)
	}
	if !strings.Contains(out, "mail_list") {
		t.Errorf("tool shouldn't be redacted: %s", out)
	}
	if !strings.Contains(out, "count=42") {
		t.Errorf("count shouldn't be redacted: %s", out)
	}
	if strings.Contains(out, "REDACTED") {
		t.Errorf("nothing should have been redacted: %s", out)
	}
}

func TestLooksLikeToken(t *testing.T) {
	cases := map[string]bool{
		// Token-shaped → redact.
		"k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzh":            true,
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghij": true,
		"ag-7forKApckinVnXyZxxxXyZxxXyZxxXyZxxX":          true,
		"hunter2hunter2hunter2hunter2hunter2":             true,
		// Free-text / URLs / paths → keep.
		"https://example.com/path?q=hello-world&y=1":          false,
		"user@example.com login flow":                         false,
		"/Users/richarddort/Documents/GIT/proto-mcp/store.db": false,
		"this is a normal sentence about something or other.": false,
		"short":                         false,
		"abcdefghijklmnopqrstuvwxyzABC": false,
	}
	for in, want := range cases {
		if got := LooksLikeToken(in); got != want {
			t.Errorf("LooksLikeToken(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValueHeuristicBackstop(t *testing.T) {
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Warn("token rotated", "new_token_value", "k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzh")
	out := buf.String()
	if strings.Contains(out, "k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzh") {
		t.Errorf("value-heuristic missed pure token under benign key: %q", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Errorf("REDACTED marker missing: %q", out)
	}
}

func TestNestedGroups(t *testing.T) {
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Info("nested",
		slog.Group("creds",
			slog.String("email", "user@example.com"),
			slog.String("password", "hunter2"),
		),
	)
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Errorf("nested password leaked: %s", out)
	}
	if !strings.Contains(out, "user@example.com") {
		t.Errorf("nested email shouldn't be redacted: %s", out)
	}
}

// ============================================================
// JSON() coverage — the audit-log path.
// ============================================================

func TestJSONRedactsSensitiveKey(t *testing.T) {
	in := json.RawMessage(`{"password":"hunter2","subject":"hello"}`)
	out := JSON(in)
	s := string(out)
	if strings.Contains(s, "hunter2") {
		t.Errorf("password leaked: %s", s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("missing REDACTED marker: %s", s)
	}
	if !strings.Contains(s, "hello") {
		t.Errorf("non-sensitive subject got eaten: %s", s)
	}
}

func TestJSONBodyShapedField(t *testing.T) {
	in := json.RawMessage(`{"body":"hello world","subject":"hi"}`)
	out := JSON(in)
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	body, ok := decoded["body"].(map[string]any)
	if !ok {
		t.Fatalf("body should be {sha256, bytes}; got %T %v", decoded["body"], decoded["body"])
	}
	if _, ok := body["sha256"].(string); !ok {
		t.Errorf("missing sha256: %v", body)
	}
	if n, ok := body["bytes"].(float64); !ok || int(n) != len("hello world") {
		t.Errorf("bytes wrong: %v", body)
	}
}

func TestJSONRecipientAddressesSurvive(t *testing.T) {
	// SECURITY invariant from the design spec: recipient addresses
	// MUST stay literal in the audit row. This locks it in — if
	// someone ever adds "to" / "cc" / "bcc" to sensitiveKeys, this
	// test breaks loudly.
	in := json.RawMessage(`{"to":["alice@example.com","bob@example.com"],"cc":["c@example.com"],"bcc":["b@example.com"],"subject":"hi"}`)
	out := JSON(in)
	s := string(out)
	for _, want := range []string{"alice@example.com", "bob@example.com", "c@example.com", "b@example.com"} {
		if !strings.Contains(s, want) {
			t.Errorf("recipient %q got eaten by redactor: %s", want, s)
		}
	}
}

func TestJSONNestedSensitiveKey(t *testing.T) {
	in := json.RawMessage(`{"outer":{"inner":{"password":"hunter2","email":"user@example.com"}}}`)
	out := JSON(in)
	s := string(out)
	if strings.Contains(s, "hunter2") {
		t.Errorf("nested password leaked: %s", s)
	}
	if !strings.Contains(s, "user@example.com") {
		t.Errorf("nested email got eaten: %s", s)
	}
}

func TestJSONTokenShapedValue(t *testing.T) {
	in := json.RawMessage(`{"err":"k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzh"}`)
	out := JSON(in)
	if strings.Contains(string(out), "k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzh") {
		t.Errorf("token-shaped value got through under benign key: %s", out)
	}
}

func TestJSONInvalidPassesThrough(t *testing.T) {
	// If we can't parse, we return as-is rather than dropping the row.
	in := json.RawMessage(`{not valid json`)
	out := JSON(in)
	if string(out) != string(in) {
		t.Errorf("invalid JSON should pass through; got %s", out)
	}
}

// ============================================================
// Body() direct API.
// ============================================================

func TestBodyReturnsHexAndBytes(t *testing.T) {
	sha, n := Body("hello world")
	if n != 11 {
		t.Errorf("bytes = %d, want 11", n)
	}
	// sha256 of "hello world" — pinned.
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if sha != want {
		t.Errorf("sha mismatch:\ngot  %s\nwant %s", sha, want)
	}
}

// SECURITY D19 — embedded-token scrubber catches credentials hidden
// in surrounding prose (library error messages, quoted JSON
// snippets) that looksLikeToken intentionally rejects.

func TestAttr_ScrubsJWTEmbeddedInError(t *testing.T) {
	var buf bytes.Buffer
	l := captureLogger(&buf)
	// JWT-shaped value embedded in an error message — the kind of
	// thing go-proton-api can produce.
	l.Warn("auth refused", "err",
		"POST /auth/v4/refresh: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature_part_abc invalid")
	out := buf.String()
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature_part_abc") {
		t.Errorf("JWT leaked through value heuristic: %s", out)
	}
	if !strings.Contains(out, "REDACTED-JWT") {
		t.Errorf("missing REDACTED-JWT marker: %s", out)
	}
}

func TestAttr_ScrubsLongBase64InError(t *testing.T) {
	var buf bytes.Buffer
	l := captureLogger(&buf)
	// 40+ base64url chars embedded in a quoted JSON snippet.
	l.Warn("upstream error",
		"err", `unknown auth response: {"refreshToken":"k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzhDEADBEEF"}`)
	out := buf.String()
	if strings.Contains(out, "k2fkzwv4sczy2zp7uozazbvwi3xiaabvkkzhDEADBEEF") {
		t.Errorf("long base64 token leaked: %s", out)
	}
	if !strings.Contains(out, "REDACTED-TOKEN") {
		t.Errorf("missing REDACTED-TOKEN marker: %s", out)
	}
}

func TestAttr_PreservesBenignProse(t *testing.T) {
	// Defensive check: don't over-redact ordinary error messages.
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Warn("benign", "msg", "connection refused: read tcp 192.168.1.5:443: i/o timeout")
	out := buf.String()
	if strings.Contains(out, "REDACTED") {
		t.Errorf("over-redacted a benign error: %s", out)
	}
}
