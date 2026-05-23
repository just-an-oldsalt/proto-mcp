package mcp

import (
	"strings"
	"testing"
)

// SECURITY D21 / D23 — NSAlert prompt content sanitization.

func TestSanitizePromptText_StripsControlChars(t *testing.T) {
	// \x07 BEL, \x1b ESC (terminal escape),  APC (C1 range).
	//  is intentionally written as a Unicode escape so the
	// string is valid UTF-8; raw \x9f would be an invalid byte
	// that NFKC replaces with U+FFFD before we get to it.
	in := "alice@example.com\x07\x1bevil"
	got := SanitizePromptText(in, 1000)
	for _, bad := range []rune{0x07, 0x1b, 0x9f} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("control char %U not stripped: %q", bad, got)
		}
	}
}

func TestSanitizePromptText_StripsBidiOverride(t *testing.T) {
	// U+202E RIGHT-TO-LEFT OVERRIDE — used to spoof email addresses
	// by flipping rendering ("alice@example.com" ←→ "moc.elpmaxe@ecila").
	in := "alice@‮example.com"
	got := SanitizePromptText(in, 1000)
	if strings.ContainsRune(got, '‮') {
		t.Errorf("RLO not stripped: %q (codepoints: %v)", got, []rune(got))
	}
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("visible content damaged: %q", got)
	}
}

func TestSanitizePromptText_StripsZeroWidth(t *testing.T) {
	// U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM. The BOM
	// must be source-encoded as a Go rune literal — embedding the
	// raw codepoint at the top of the file would be parsed as a
	// byte-order mark by the Go scanner.
	for _, zw := range []rune{'​', '‌', '‍', '\ufeff'} {
		in := "a" + string(zw) + "b"
		got := SanitizePromptText(in, 1000)
		if strings.ContainsRune(got, zw) {
			t.Errorf("zero-width %U not stripped: %q", zw, got)
		}
		if got != "ab" {
			t.Errorf("expected \"ab\", got %q", got)
		}
	}
}

func TestSanitizePromptText_PreservesNewlineTab(t *testing.T) {
	in := "line one\nline two\tcol b"
	got := SanitizePromptText(in, 1000)
	if !strings.Contains(got, "\n") || !strings.Contains(got, "\t") {
		t.Errorf("newline/tab lost: %q", got)
	}
}

func TestSanitizePromptText_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 10_000)
	got := SanitizePromptText(in, 200)
	r := []rune(got)
	if len(r) > 200+len([]rune("…[truncated]"))+1 {
		t.Errorf("not truncated; len = %d", len(r))
	}
	if !strings.HasSuffix(got, "…[truncated]") {
		t.Errorf("truncation marker missing: %q", got[len(got)-30:])
	}
}

func TestSanitizePromptText_NFKCNormalization(t *testing.T) {
	// Fullwidth Latin "ＡＢＣ" (U+FF21..) normalizes to "ABC" under NFKC.
	in := "ＡＢＣ"
	got := SanitizePromptText(in, 1000)
	if got != "ABC" {
		t.Errorf("NFKC didn't fold fullwidth: %q", got)
	}
}
