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
