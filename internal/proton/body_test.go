package proton

import (
	"strings"
	"testing"
	"unicode/utf8"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestListUnsubscribeHeaders_FromParsedHeaders(t *testing.T) {
	parsed := gpa.Headers{Values: map[string][]string{
		// Non-canonical casing: the lookup is case-insensitive.
		"list-unsubscribe":      {"<https://example.com/u?t=abc>,\r\n <mailto:u@example.com>"},
		"List-Unsubscribe-Post": {"List-Unsubscribe=One-Click"},
	}}
	// The raw block disagrees; ParsedHeaders must win.
	raw := "List-Unsubscribe: <https://raw.example/u>\r\n"

	unsub, post := listUnsubscribeHeaders(parsed, raw)
	// CR, LF and the folding space each flatten to one space.
	if want := "<https://example.com/u?t=abc>,   <mailto:u@example.com>"; unsub != want {
		t.Errorf("unsub = %q, want %q", unsub, want)
	}
	if post != "List-Unsubscribe=One-Click" {
		t.Errorf("post = %q", post)
	}
}

func TestListUnsubscribeHeaders_RawHeaderFallback(t *testing.T) {
	parsed := gpa.Headers{Values: map[string][]string{
		"Subject": {"hi"},
	}}
	raw := "Subject: hi\r\n" +
		"List-Unsubscribe: <mailto:u@example.com>,\r\n <https://example.com/u>\r\n" +
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" +
		"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"

	unsub, post := listUnsubscribeHeaders(parsed, raw)
	if want := "<mailto:u@example.com>, <https://example.com/u>"; unsub != want {
		t.Errorf("unsub = %q, want %q", unsub, want)
	}
	if post != "List-Unsubscribe=One-Click" {
		t.Errorf("post = %q", post)
	}
}

func TestListUnsubscribeHeaders_Absent(t *testing.T) {
	unsub, post := listUnsubscribeHeaders(gpa.Headers{}, "Subject: hi\r\nFrom: a@example.com\r\n")
	if unsub != "" || post != "" {
		t.Errorf("got (%q, %q), want empty", unsub, post)
	}
	unsub, post = listUnsubscribeHeaders(gpa.Headers{}, "")
	if unsub != "" || post != "" {
		t.Errorf("empty raw: got (%q, %q), want empty", unsub, post)
	}
}

func TestListUnsubscribeHeaders_StripsControlsAndCaps(t *testing.T) {
	parsed := gpa.Headers{Values: map[string][]string{
		"List-Unsubscribe": {"<https://example.com/\x1b[31mu\x00>\r\n\t<mailto:u@example.com>"},
	}}
	unsub, _ := listUnsubscribeHeaders(parsed, "")
	if strings.ContainsAny(unsub, "\x1b\x00\r\n\t") {
		t.Errorf("control characters survived: %q", unsub)
	}

	// A multi-byte rune straddling the cap must not be split.
	big := strings.Repeat("a", maxListHeaderBytes-1) + "é" + strings.Repeat("b", 100)
	parsed = gpa.Headers{Values: map[string][]string{"List-Unsubscribe": {big}}}
	unsub, _ = listUnsubscribeHeaders(parsed, "")
	if len(unsub) > maxListHeaderBytes {
		t.Errorf("len = %d, want <= %d", len(unsub), maxListHeaderBytes)
	}
	if !utf8.ValidString(unsub) {
		t.Error("truncation split a rune")
	}
}
