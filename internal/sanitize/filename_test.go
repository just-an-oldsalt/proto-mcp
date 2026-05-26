package sanitize

import (
	"strings"
	"testing"
)

func TestFilenameStripsControlChars(t *testing.T) {
	// \x07 (bell), \x1b (escape) — terminal-corruption material.
	got := Filename("report\x07\x1b.pdf")
	if got != "report.pdf" {
		t.Errorf("Filename = %q, want %q", got, "report.pdf")
	}
}

// D21-class RTL-override defense. "repor‮3pm.exe" visually
// renders as "reporexe.mp3" in many terminals. Strip it.
func TestFilenameStripsBidiControls(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"repor‮3pm.exe", "repor3pm.exe"},
		{"‭left-to-right-override.pdf", "left-to-right-override.pdf"},
		{"isolate⁦test⁩.txt", "isolatetest.txt"},
	} {
		got := Filename(tc.in)
		if got != tc.want {
			t.Errorf("Filename(%q) = %q, want %q", tc.in, got, tc.want)
		}
		// Ensure no bidi codepoint survives.
		for _, r := range got {
			if _, isBidi := bidiControl[r]; isBidi {
				t.Errorf("Filename(%q) leaked bidi codepoint U+%04X", tc.in, r)
			}
		}
	}
}

func TestFilenameRejectsPathSeparators(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		// Forward slash traversal attempt. The leading `..` gets
		// stripped by TrimLeft-dots (dot-hidden defense), the
		// slashes become underscores. Real path-traversal defense
		// lives in mail_save_attachment (filepath.Base + Clean +
		// root check); this sanitizer just neutralizes structural
		// separators.
		{"../../etc/passwd", "_.._etc_passwd"},
		// Backslash (Windows-style traversal).
		{"..\\..\\windows\\system32\\cmd.exe", "_.._windows_system32_cmd.exe"},
		// NUL byte — substituted, not stripped, so it's visible
		// in the sanitized name.
		{"report\x00malicious.exe", "report_malicious.exe"},
		// Mixed.
		{"a/b\\c\x00d", "a_b_c_d"},
	} {
		got := Filename(tc.in)
		if got != tc.want {
			t.Errorf("Filename(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.ContainsAny(got, "/\\\x00") {
			t.Errorf("Filename(%q) leaked a path separator: %q", tc.in, got)
		}
	}
}

func TestFilenameStripsLeadingDots(t *testing.T) {
	// ".env" → "env" so saving doesn't create a Unix dot-hidden file.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{".env", "env"},
		{"..env", "env"},
		{"...secret", "secret"},
		{".gitignore", "gitignore"},
	} {
		got := Filename(tc.in)
		if got != tc.want {
			t.Errorf("Filename(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.HasPrefix(got, ".") {
			t.Errorf("Filename(%q) still starts with dot: %q", tc.in, got)
		}
	}
}

func TestFilenameTrimsTrailingWhitespaceAndDots(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"report.pdf.", "report.pdf"},
		{"report.pdf  ", "report.pdf"},
		{"report.pdf...   ", "report.pdf"},
		{"trailing\t", "trailing"},
	} {
		got := Filename(tc.in)
		if got != tc.want {
			t.Errorf("Filename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFilenameCapsAtMaxBytes(t *testing.T) {
	// A 300-byte name with a 4-byte extension. Should truncate
	// to <= 255 and preserve the extension.
	in := strings.Repeat("a", 300) + ".pdf"
	got := Filename(in)
	if len(got) > filenameMaxBytes {
		t.Errorf("Filename returned %d bytes, want <= %d", len(got), filenameMaxBytes)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Errorf("extension lost in truncation: %q", got)
	}
}

func TestFilenameCapWithoutExtension(t *testing.T) {
	in := strings.Repeat("b", 300)
	got := Filename(in)
	if len(got) != filenameMaxBytes {
		t.Errorf("no-extension truncate: got %d bytes, want %d", len(got), filenameMaxBytes)
	}
}

func TestFilenameEmptyFallback(t *testing.T) {
	// Only inputs that sanitize to ZERO bytes get the fallback.
	// A single substituted '_' (from a NUL or '/') is a valid
	// filename and stays.
	for _, tc := range []string{
		"",
		"   ",
		"...",
		"\x01\x02\x03",  // C0 controls only — all stripped
		"‮‭⁦",          // bidi controls only — all stripped
	} {
		got := Filename(tc)
		if got != filenameFallback {
			t.Errorf("Filename(%q) = %q, want fallback %q", tc, got, filenameFallback)
		}
	}
}

// "_" alone is a legitimate (if odd) filename — substitutions from
// path separators or NULs shouldn't trigger the fallback.
func TestFilenameSingleUnderscoreNotFallback(t *testing.T) {
	for _, tc := range []string{
		"/",
		"\\",
		"\x00",
	} {
		got := Filename(tc)
		if got != "_" {
			t.Errorf("Filename(%q) = %q, want %q", tc, got, "_")
		}
	}
}

func TestFilenameIdempotent(t *testing.T) {
	for _, tc := range []string{
		"report.pdf",
		"../../etc/passwd",
		".env",
		"repor‮3pm.exe",
		strings.Repeat("a", 300) + ".pdf",
		"",
	} {
		once := Filename(tc)
		twice := Filename(once)
		if once != twice {
			t.Errorf("Filename not idempotent on %q: once=%q twice=%q", tc, once, twice)
		}
	}
}

func TestFilenamePreservesNormalNames(t *testing.T) {
	for _, tc := range []string{
		"report.pdf",
		"My Document (final).docx",
		"image-2026-05-25.jpg",
		"data.tar.gz",
		"unicode-名前.txt",
	} {
		got := Filename(tc)
		if got != tc {
			t.Errorf("Filename(%q) mangled normal name: %q", tc, got)
		}
	}
}
