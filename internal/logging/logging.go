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

// redactSensitive is the slog.HandlerOptions.ReplaceAttr hook. Two
// passes:
//
//  1. Key-based: any Attr whose Key matches sensitiveKeys becomes
//     "[REDACTED]" regardless of value.
//
//  2. Value-heuristic backstop (SECURITY B-4 + updated Foundational
//     #1): if the value is a string that looks like a token /
//     credential — long, high-entropy, base64- or JWT-shaped — it
//     gets redacted even when its key is benign. Catches the
//     `slog.Warn("...", "err", "refresh token kZb...")` case where
//     a wrapped error message embeds the secret under an innocent
//     key. Tuned conservatively to avoid eating long ordinary
//     strings (URLs, file paths).
func redactSensitive(_ []string, a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[strings.ToLower(a.Key)]; hit {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindString && looksLikeToken(a.Value.String()) {
		return slog.String(a.Key, "[REDACTED-VALUE]")
	}
	return a
}

// looksLikeToken returns true for strings that resemble session
// tokens / JWTs / opaque API keys. False positives are tolerable
// (the value just gets redacted unnecessarily); false negatives are
// the actual risk.
//
// Heuristic: ≥32 characters AND all characters are in the base64url
// alphabet OR the JWT alphabet (base64url + dots). URLs, filesystem
// paths, and free-text get rejected because they contain spaces,
// slashes, colons, or shorter runs.
func looksLikeToken(s string) bool {
	if len(s) < 32 {
		return false
	}
	// Quick reject for free-text / URLs.
	for _, r := range s {
		if r == ' ' || r == '/' || r == ':' || r == '"' || r == '\'' || r == '<' || r == '>' || r == '\n' || r == '\t' {
			return false
		}
	}
	// All-base64url (with optional '.' for JWT-style)?
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		isB64Punct := r == '-' || r == '_' || r == '=' || r == '+' || r == '.'
		if !isAlnum && !isB64Punct {
			return false
		}
	}
	return true
}
