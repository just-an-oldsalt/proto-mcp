// Package redact is the shared secret-scrubber used by both
// internal/logging (slog ReplaceAttr) and internal/audit (args_json
// column in the audit log).
//
// Originally embedded in internal/logging; extracted in Phase 4 so
// the audit writer can apply the same value-heuristic backstop
// (SECURITY B-4) without forcing audit to import logging (cycle
// risk; semantic mismatch).
//
// Three public surfaces:
//
//	Attr(slog.Attr)         — used by logging.Setup's ReplaceAttr.
//	JSON(json.RawMessage)   — used by audit; walks parsed JSON and
//	                          redacts sensitive keys + token-shaped
//	                          values, and replaces body fields with
//	                          {sha256, bytes} per design spec.
//	Body(string)            — exposed for callers that want the
//	                          sha256+bytes shape directly.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
)

// sensitiveKeys is the set of attribute keys we treat as secret. Any
// Attr or JSON field whose KEY (case-insensitive) matches becomes
// "[REDACTED]" regardless of value.
//
// Keep this list narrow. Over-redacting is annoying but not
// dangerous; under-redacting is the actual risk. New sensitive keys
// should be added here as the codebase grows.
//
// Body-shaped keys (body, body_text, body_html, text, html,
// plaintext) are NOT in this set — they get the sha256+bytes
// treatment in JSON() so the audit row records WHAT was sent
// (length, content hash) without keeping the literal content.
var sensitiveKeys = map[string]struct{}{
	"password":         {},
	"mailbox_password": {},
	"mailboxpassword":  {},
	"totp":             {},
	"access_token":     {},
	"accesstoken":      {},
	"refresh_token":    {},
	"refreshtoken":     {},
	"salted_key_pass":  {},
	"saltedkeypass":    {},
	"cookie":           {},
	"set-cookie":       {},
	"authorization":    {},
	"client_proof":     {},
	"clientproof":      {},
	"client_ephemeral": {},
	"clientephemeral":  {},
	"server_proof":     {},
	"serverproof":      {},
	"srp_session":      {},
	"srpsession":       {},
	"uid":              {},
}

// bodyKeys are JSON fields we replace with {sha256, bytes} rather
// than the [REDACTED] string. The audit log needs to know HOW MUCH
// was sent (a 50-line message vs a 5MiB blast) and a stable hash
// (correlate identical drafts) without keeping the content.
//
// Recipient address fields (to, cc, bcc, recipients) are deliberately
// NOT in this set — they stay literal per design spec. Locked in
// with a test.
var bodyKeys = map[string]struct{}{
	"body":      {},
	"body_text": {},
	"body_html": {},
	"text":      {},
	"html":      {},
	"plaintext": {},
}

// Attr is the slog.HandlerOptions.ReplaceAttr hook. Two passes:
//
//  1. Key-based: any Attr whose Key matches sensitiveKeys becomes
//     "[REDACTED]" regardless of value.
//
//  2. Value-heuristic backstop (SECURITY B-4): if the value is a
//     string that looks like a token / credential — long,
//     high-entropy, base64- or JWT-shaped — it gets redacted even
//     when its key is benign. Catches the
//     `slog.Warn("...", "err", "refresh token kZb...")` case where
//     a wrapped error message embeds the secret under an innocent
//     key.
//
// Body-shaped values are NOT replaced with sha256+bytes here —
// slog usage is verbose-by-key, so a 50KB body string in a log
// would be the bug; we punt to JSON() for the structured-args path.
func Attr(a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[strings.ToLower(a.Key)]; hit {
		return slog.String(a.Key, "[REDACTED]")
	}
	if _, hit := bodyKeys[strings.ToLower(a.Key)]; hit && a.Value.Kind() == slog.KindString {
		sha, n := Body(a.Value.String())
		return slog.String(a.Key, formatBody(sha, n))
	}
	if a.Value.Kind() == slog.KindString && looksLikeToken(a.Value.String()) {
		return slog.String(a.Key, "[REDACTED-VALUE]")
	}
	return a
}

// JSON walks a parsed JSON payload and applies redaction. Used by
// internal/audit on the args_json column.
//
// Behavior per key:
//   - sensitiveKeys → string "[REDACTED]"
//   - bodyKeys      → object {"sha256": "<hex>", "bytes": <int>}
//   - other         → unchanged, but string VALUES still go through
//                     looksLikeToken
//
// If the input isn't valid JSON we return it unchanged with a
// best-effort string redaction — better to log the row imperfectly
// than to lose the audit trail entirely.
func JSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out := redactValue(v)
	b, err := json.Marshal(out)
	if err != nil {
		return raw
	}
	return b
}

// Body returns (sha256_hex, byte_len). Used by JSON() internally and
// exposed for callers that want the same shape directly (e.g., audit
// log entries for tools whose args are NOT JSON).
func Body(text string) (sha256hex string, byteLen int) {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]), len(text)
}

// LooksLikeToken is exported so tests in other packages can pin the
// heuristic. Same threshold as the inline version in old logging.go:
// ≥32 chars, all base64url + optional dots, no whitespace/slashes.
func LooksLikeToken(s string) bool { return looksLikeToken(s) }

func looksLikeToken(s string) bool {
	if len(s) < 32 {
		return false
	}
	for _, r := range s {
		if r == ' ' || r == '/' || r == ':' || r == '"' || r == '\'' || r == '<' || r == '>' || r == '\n' || r == '\t' {
			return false
		}
	}
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		isB64Punct := r == '-' || r == '_' || r == '=' || r == '+' || r == '.'
		if !isAlnum && !isB64Punct {
			return false
		}
	}
	return true
}

func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			lower := strings.ToLower(k)
			if _, hit := sensitiveKeys[lower]; hit {
				out[k] = "[REDACTED]"
				continue
			}
			if _, hit := bodyKeys[lower]; hit {
				switch s := val.(type) {
				case string:
					sha, n := Body(s)
					out[k] = bodyRef{SHA256: sha, Bytes: n}
				default:
					// Body field present but not a string — leave
					// it alone and let the recursive walk handle it.
					out[k] = redactValue(val)
				}
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactValue(e)
		}
		return out
	case string:
		if looksLikeToken(x) {
			return "[REDACTED-VALUE]"
		}
		return x
	default:
		return v
	}
}

// bodyRef is the JSON shape for redacted body content. Stable across
// versions because callers (audit consumers, log analyzers) key off
// the sha256 to correlate.
type bodyRef struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// formatBody produces the string the slog handler prints for body-
// shaped fields. JSON-y format on purpose so a future log-aggregator
// can re-parse it.
func formatBody(sha string, n int) string {
	return `{"sha256":"` + sha + `","bytes":` + intToStr(n) + `}`
}

func intToStr(n int) string {
	// strconv.Itoa via the slim builder dance — avoids importing
	// strconv for this single use site.
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
