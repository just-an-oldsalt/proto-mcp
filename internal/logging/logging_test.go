package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestSetupInstallsRedactor smoke-tests that Setup wires the
// internal/redact filter into the default slog logger. The detailed
// behavior is covered by internal/redact's tests; this just confirms
// the wiring stays in place after the Phase-4 extraction.
func TestSetupInstallsRedactor(t *testing.T) {
	var buf bytes.Buffer
	Setup(&buf)
	slog.Info("test", "password", "hunter2", "email", "user@example.com")
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Errorf("password leaked through default logger: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("REDACTED marker missing: %s", out)
	}
	if !strings.Contains(out, "user@example.com") {
		t.Errorf("non-sensitive email got eaten: %s", out)
	}
}
