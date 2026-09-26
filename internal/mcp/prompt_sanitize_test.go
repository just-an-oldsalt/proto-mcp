package mcp

import (
	"errors"
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

// Issue #125 — codepoints that render as a line break, or invisibly,
// in the Touch ID dialog. A line break inside a field (a subject taken
// from an attacker's email, say) could fake a "To:" line.
func TestSanitizePromptText_StripsLineSeparatorsAndInvisibles(t *testing.T) {
	for _, r := range []rune{
		0x0085, // NEL
		0x2028, // LINE SEPARATOR
		0x2029, // PARAGRAPH SEPARATOR
		0x061c, // ARABIC LETTER MARK
		0x2060, // WORD JOINER
		0x2061, // FUNCTION APPLICATION
		0x2062, // INVISIBLE TIMES
		0x2063, // INVISIBLE SEPARATOR
		0x2064, // INVISIBLE PLUS
	} {
		in := "Q3 notes" + string(r) + "To: fake@x"
		got := SanitizePromptText(in, 1000)
		if strings.ContainsRune(got, r) {
			t.Errorf("%U not stripped: %q", r, got)
		}
		if got != "Q3 notesTo: fake@x" {
			t.Errorf("%U: got %q", r, got)
		}
		strict, err := SanitizePromptTextStrict(in, 1000)
		if err != nil || strict != got {
			t.Errorf("%U: strict = %q, %v; want %q", r, strict, err, got)
		}
	}
}

// Issue #125 — the strict variant refuses rather than truncates, and
// measures the text after normalization and stripping.
func TestSanitizePromptTextStrict_RefusesOverCap(t *testing.T) {
	if _, err := SanitizePromptTextStrict(strings.Repeat("a", 201), 200); !errors.Is(err, ErrPromptTooLong) {
		t.Errorf("201 runes at cap 200: err = %v, want ErrPromptTooLong", err)
	}
	got, err := SanitizePromptTextStrict(strings.Repeat("a", 200), 200)
	if err != nil || got != strings.Repeat("a", 200) {
		t.Errorf("200 runes at cap 200: %q, %v", got, err)
	}
	// Stripped characters don't count toward the cap.
	if _, err := SanitizePromptTextStrict(strings.Repeat("a​", 200), 200); err != nil {
		t.Errorf("zero-width padding counted toward the cap: %v", err)
	}
}
