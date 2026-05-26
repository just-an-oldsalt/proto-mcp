package sanitize

import (
	"strings"
)

// Filename normalizes an attachment filename for safe display + safe
// filesystem use. Phase 8/A. Called at three points:
//
//   1. Inbound: by Session.FetchAndDecryptAttachment before the
//      filename hits attachment_cache / the MCP response / the audit
//      log. Defends the audit + LLM context against RTL-spoofed names
//      ("repor‮.exe.txt" rendering as "report.txt.exe").
//   2. Outbound: by mail_send's attachment validation before
//      Client.UploadAttachment. Defends downstream Proton recipients
//      against the same spoofing if an LLM is fed an adversarial
//      filename.
//   3. mail_save_attachment: as the first transform on the input
//      filename, before the path-traversal defense (filepath.Base +
//      Clean + ~/Downloads root check). Defense-in-depth: this step
//      strips the obvious; the path resolver catches anything missed.
//
// Strips applied in order:
//   - C0 / C1 control bytes (reuses stripControlChars).
//   - RTL / LRO / bidi-isolate codepoints (U+202D, U+202E,
//     U+2066–U+2069). Same set internal/mcp/middleware.go's
//     SanitizePromptText drops.
//   - Path separators (/, \, NUL) replaced with '_'.
//   - Leading '.' (defeats Unix dot-hidden trick when saved).
//   - Trailing whitespace + dots (Windows refuses these; macOS just
//     finds them confusing).
//   - Length capped at 255 bytes (POSIX NAME_MAX). Truncates from
//     the end while preserving the file extension where possible.
//
// Empty post-strip falls back to "attachment.bin". The caller can
// override with a more informative default (e.g.
// "attachment-<id>.bin") if it has an attachment id handy.
const filenameMaxBytes = 255
const filenameFallback = "attachment.bin"

// bidiControl is the set of bidi-control codepoints that can flip
// visual rendering. Same list as internal/mcp/middleware.go's
// SanitizePromptText — keeping the two in sync matters because the
// filename ends up in the Touch ID prompt body for both
// mail_save_attachment and the send-family's attachment summary.
var bidiControl = map[rune]struct{}{
	0x202d: {}, // LRO
	0x202e: {}, // RLO
	0x2066: {}, // LRI
	0x2067: {}, // RLI
	0x2068: {}, // FSI
	0x2069: {}, // PDI
}

// Filename returns the sanitized form of s. See package-level doc
// for the transforms applied. Idempotent: Filename(Filename(s)) ==
// Filename(s).
func Filename(s string) string {
	// Single-pass: bidi-drop, path-sep-replace, control-strip.
	// Done in one loop so NUL (a control char AND a C-string
	// terminator) gets replaced with '_' for visibility instead of
	// silently disappearing.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if _, isBidi := bidiControl[r]; isBidi {
			continue
		}
		switch r {
		case '/', '\\', 0:
			b.WriteRune('_')
			continue
		case '\n', '\t':
			// Newlines + tabs in filenames are absurd but not
			// strictly dangerous. Strip silently.
			continue
		}
		// C0 + C1 control range.
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()

	// 3. Strip leading dots (Unix dot-hidden defense).
	out = strings.TrimLeft(out, ".")

	// 4. Trim trailing whitespace + dots (Windows-incompat + ugly).
	out = strings.TrimRight(out, " \t.")

	// 5. Length cap. Truncate from the end, try to preserve extension.
	if len(out) > filenameMaxBytes {
		out = truncatePreservingExt(out, filenameMaxBytes)
	}

	if out == "" {
		return filenameFallback
	}
	return out
}

// truncatePreservingExt shortens s to at most maxBytes, trying to
// keep the last "." extension intact if doing so leaves at least
// one base byte. Falls back to a straight byte-truncation if the
// extension itself is longer than maxBytes.
func truncatePreservingExt(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	idx := strings.LastIndex(s, ".")
	if idx <= 0 || idx >= len(s)-1 {
		// No extension, or filename starts with '.' (defensive;
		// shouldn't happen post-TrimLeft), or extension at very
		// end with no following bytes.
		return s[:maxBytes]
	}
	ext := s[idx:]
	if len(ext) >= maxBytes {
		// Extension alone exceeds the cap; can't preserve it.
		return s[:maxBytes]
	}
	baseRoom := maxBytes - len(ext)
	if baseRoom <= 0 {
		return s[:maxBytes]
	}
	return s[:baseRoom] + ext
}
