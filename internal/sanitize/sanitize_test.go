package sanitize

import (
	"strings"
	"testing"
)

func TestHTMLStripsScripts(t *testing.T) {
	in := `<p>Hello</p><script>alert("xss")</script>`
	got := HTML(in)
	if strings.Contains(got, "<script") || strings.Contains(got, "alert") {
		t.Errorf("script not stripped: %q", got)
	}
	if !strings.Contains(got, "<p>Hello</p>") {
		t.Errorf("paragraph lost: %q", got)
	}
}

func TestHTMLStripsIframes(t *testing.T) {
	in := `<p>Body</p><iframe src="https://evil/"></iframe>`
	got := HTML(in)
	if strings.Contains(got, "iframe") {
		t.Errorf("iframe not stripped: %q", got)
	}
}

func TestHTMLDropsAnchorsKeepsText(t *testing.T) {
	// bluemonday strips the whole <a> element when no attrs are
	// allowed on it, but the link TEXT survives as the surrounding
	// content. The LLM sees "Click here to reset." with no URL
	// anywhere — exactly the prompt-injection-via-href mitigation
	// we want. (Allowing href would just give the LLM a string to
	// be tricked by; better to drop it entirely.)
	in := `<p>Click <a href="https://reset.example/?id=123">here</a> to reset.</p>`
	got := HTML(in)
	if strings.Contains(got, "href") || strings.Contains(got, "reset.example") {
		t.Errorf("href survived: %q", got)
	}
	if !strings.Contains(got, "here") {
		t.Errorf("link text lost: %q", got)
	}
	if !strings.Contains(got, "Click") {
		t.Errorf("surrounding text lost: %q", got)
	}
}

func TestHTMLStripsRemoteImages(t *testing.T) {
	in := `<p>Hi</p><img src="https://tracker/pixel.gif">`
	got := HTML(in)
	if strings.Contains(got, "img") || strings.Contains(got, "tracker") {
		t.Errorf("remote image survived: %q", got)
	}
}

func TestHTMLKeepsAllowlist(t *testing.T) {
	in := "<p>Para</p>" +
		"<h1>H1</h1><h2>H2</h2>" +
		"<ul><li>one</li><li>two</li></ul>" +
		"<blockquote>quoted</blockquote>" +
		"<b>bold</b> <strong>strong</strong> <i>italic</i> <em>em</em>"
	got := HTML(in)
	for _, want := range []string{"<p>", "<h1>", "<h2>", "<ul>", "<li>",
		"<blockquote>", "<b>", "<strong>", "<i>", "<em>"} {
		if !strings.Contains(got, want) {
			t.Errorf("allowlist tag %s lost: %q", want, got)
		}
	}
}

func TestHTMLStripsUnknownTags(t *testing.T) {
	// Anything outside the allowlist (style, form, object, embed, ...)
	// is stripped wholesale.
	in := `<style>body{display:none}</style><form><input name="creds"></form>`
	got := HTML(in)
	for _, bad := range []string{"<style", "<form", "<input", "display:none", "creds"} {
		if strings.Contains(got, bad) {
			t.Errorf("disallowed content %q survived: %q", bad, got)
		}
	}
}

func TestHTMLEmpty(t *testing.T) {
	if got := HTML(""); got != "" {
		t.Errorf("HTML(\"\") = %q, want \"\"", got)
	}
}

func TestTextStripsHTML(t *testing.T) {
	in := `<p>Hello <b>world</b></p>`
	got := Text(in)
	if got != "Hello world" {
		t.Errorf("Text = %q, want \"Hello world\"", got)
	}
}

func TestTextStripsQuotedReplies(t *testing.T) {
	in := "On Tuesday Alice wrote:\n> Original message\n> > Nested\nMy actual reply"
	got := Text(in)
	if strings.Contains(got, "Original message") || strings.Contains(got, "Nested") {
		t.Errorf("quoted lines kept: %q", got)
	}
	if !strings.Contains(got, "actual reply") {
		t.Errorf("real reply lost: %q", got)
	}
}

func TestTextCollapsesWhitespace(t *testing.T) {
	in := "Hello\n\n\n   world\t\tagain"
	got := Text(in)
	if got != "Hello world again" {
		t.Errorf("Text = %q, want \"Hello world again\"", got)
	}
}

func TestSnippetTruncates(t *testing.T) {
	long := strings.Repeat("abc ", 100) // 400 chars
	s := Snippet(long, 50)
	// 50 runes + ellipsis
	if !strings.HasSuffix(s, "…") {
		t.Errorf("missing ellipsis: %q", s)
	}
	// Count runes, not bytes — the ellipsis is a multibyte rune.
	if got := len([]rune(s)); got != 51 {
		t.Errorf("Snippet rune len = %d, want 51 (50 + …)", got)
	}
}

func TestSnippetShortInputUnchanged(t *testing.T) {
	in := "short"
	if got := Snippet(in, 100); got != "short" {
		t.Errorf("Snippet = %q, want \"short\"", got)
	}
}

func TestSnippetDefaultMaxRunes(t *testing.T) {
	// maxRunes <= 0 → 200
	long := strings.Repeat("x", 500)
	got := Snippet(long, 0)
	if r := []rune(got); len(r) != 201 { // 200 + ellipsis
		t.Errorf("default snippet rune len = %d, want 201", len(r))
	}
}

func TestSnippetUnicodeSafe(t *testing.T) {
	// Verify we don't slice a multibyte rune in half.
	in := strings.Repeat("✓ ", 100)
	got := Snippet(in, 10)
	if len([]rune(got)) != 11 {
		t.Errorf("unicode snippet rune len = %d, want 11", len([]rune(got)))
	}
}

// Phase 5/C — outbound HTML sanitization for LLM-supplied drafts.
// Same allowlist as HTML(); script tags, iframes, and remote-resource
// refs must be stripped before the body is encrypted and sent.

func TestOutboundStripsScript(t *testing.T) {
	got := Outbound(`<p>hello</p><script>alert(1)</script>`)
	if strings.Contains(got, "<script>") || strings.Contains(got, "alert") {
		t.Errorf("script not stripped: %q", got)
	}
	if !strings.Contains(got, "<p>hello</p>") {
		t.Errorf("legitimate <p> markup lost: %q", got)
	}
}

func TestOutboundKeepsBasicMarkup(t *testing.T) {
	cases := []string{
		`<p><b>bold</b> and <em>emphasis</em></p>`,
		`<ul><li>one</li><li>two</li></ul>`,
		`<blockquote>quoted text</blockquote>`,
		`<h2>heading</h2>`,
	}
	for _, in := range cases {
		got := Outbound(in)
		if got == "" {
			t.Errorf("Outbound(%q) returned empty", in)
		}
	}
}

func TestOutboundStripsRemoteImageAndIframe(t *testing.T) {
	in := `<p>hi</p><img src="https://attacker.example/track.gif"><iframe src="evil"></iframe>`
	got := Outbound(in)
	if strings.Contains(got, "<img") || strings.Contains(got, "<iframe") {
		t.Errorf("img/iframe not stripped: %q", got)
	}
	if strings.Contains(got, "attacker.example") {
		t.Errorf("remote URL survived: %q", got)
	}
}

// Phase 5/C — C-2 fold. sanitize.Text now strips C0 control chars
// (except \n / \t) and the C1 range. Hardens the LLM-output path
// against terminal-escape injection in mail bodies.

func TestTextStripsC0ControlChars(t *testing.T) {
	in := "hi\x07world\x1bextra"
	got := Text(in)
	if strings.ContainsAny(got, "\x07\x1b") {
		t.Errorf("control chars not stripped: %q", got)
	}
	if !strings.Contains(got, "hiworldextra") {
		t.Errorf("visible content lost: %q", got)
	}
}

func TestTextPreservesNewlineAndTab(t *testing.T) {
	// Whitespace collapse turns \n/\t into single spaces in the
	// final output (whitespaceRun), but the strip pass before
	// that must not eat them. Verify the result still contains
	// the words separated.
	in := "line one\nline two\tcol b"
	got := Text(in)
	for _, want := range []string{"line one", "line two", "col b"} {
		if !strings.Contains(got, want) {
			t.Errorf("piece %q lost: %q", want, got)
		}
	}
}

func TestTextStripsC1ControlChars(t *testing.T) {
	// 0x80-0x9f is the C1 range.  is NEL (next line) — a
	// common one in adversarial payloads.
	in := "hiworldextra"
	got := Text(in)
	if strings.Contains(got, "") || strings.Contains(got, "") {
		t.Errorf("C1 control chars not stripped: %q", got)
	}
}
