// Package logging configures the slog default logger with a
// redacting ReplaceAttr hook so we can never accidentally write
// secret material into log records.
//
// The audit log Phase 4 builds on top of this — by the time we
// start persisting log records to SQLite + a JSONL mirror, every
// log call has already been routed through the redaction filter.
// SECURITY Foundational #2.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// sensitiveKeys is the set of attribute keys we treat as secret. Any
// slog.Attr with one of these keys (case-insensitive) is replaced
// with the literal string "[REDACTED]" — its value never reaches the
// underlying handler.
//
// Keep this list narrow on purpose. Over-redacting is annoying but
// not dangerous; under-redacting is the actual risk. New sensitive
// keys should be added here as the codebase grows.
var sensitiveKeys = map[string]struct{}{
	"password":          {},
	"mailbox_password":  {},
	"mailboxpassword":   {},
	"totp":              {},
	"access_token":      {},
	"accesstoken":       {},
	"refresh_token":     {},
	"refreshtoken":      {},
	"salted_key_pass":   {},
	"saltedkeypass":     {},
	"body":              {},
	"body_text":         {},
	"body_html":         {},
	"cookie":            {},
	"set-cookie":        {},
	"authorization":     {},
}

// Setup installs a default slog logger writing to stderr in text
// format, with the redacting ReplaceAttr hook applied. Call once
// from main(); subsequent slog package-level calls go through it.
//
// w can be nil; defaults to os.Stderr.
func Setup(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: redactSensitive,
	})
	slog.SetDefault(slog.New(handler))
}

// redactSensitive is the slog.HandlerOptions.ReplaceAttr hook. It
// only mutates Attrs whose Key matches sensitiveKeys; everything
// else passes through unchanged.
func redactSensitive(_ []string, a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[strings.ToLower(a.Key)]; hit {
		return slog.String(a.Key, "[REDACTED]")
	}
	return a
}
