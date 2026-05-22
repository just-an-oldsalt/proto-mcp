package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureLogger returns a slog.Logger that writes through the same
// redaction filter Setup() installs, but into the caller's buffer
// instead of stderr. Lets the test cases inspect what would have
// been logged.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: redactSensitive,
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
		"body", "body_text", "body_html",
		"cookie", "Set-Cookie",
		"authorization", "Authorization",
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

func TestPassThroughKeys(t *testing.T) {
	// Keys that aren't on the sensitive list must pass through.
	var buf bytes.Buffer
	l := captureLogger(&buf)
	l.Info("benign log",
		slog.String("email", "user@example.com"),
		slog.String("tool", "mail.list"),
		slog.Int("count", 42),
	)
	out := buf.String()
	if !strings.Contains(out, "user@example.com") {
		t.Errorf("email shouldn't be redacted: %s", out)
	}
	if !strings.Contains(out, "mail.list") {
		t.Errorf("tool shouldn't be redacted: %s", out)
	}
	if !strings.Contains(out, "count=42") {
		t.Errorf("count shouldn't be redacted: %s", out)
	}
	if strings.Contains(out, "REDACTED") {
		t.Errorf("nothing should have been redacted: %s", out)
	}
}

func TestNestedGroups(t *testing.T) {
	// ReplaceAttr is called for attrs inside slog.Group; verify a
	// nested sensitive key is still caught.
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
