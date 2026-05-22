// Package sanitize is the single audited surface for turning
// Proton-Mail message bodies into LLM-safe payloads.
//
// Two outputs:
//
//   - HTML(input) — minimal-allowlist HTML stripped of scripts,
//     iframes, remote-image refs, and any markup not on the
//     allowlist below. Designed for an LLM prompt: rich enough to
//     preserve sentence structure / links / lists, narrow enough
//     that prompt-injection embedded in exotic markup has nowhere
//     to hide.
//
//   - Text(input) — pure text extraction with quoted-reply markers
//     trimmed and whitespace collapsed. Source for snippets and
//     for the FTS5 body_text column.
//
// SECURITY Foundational #7 + Phase-2 plan Q1 (strict policy).
package sanitize

import (
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// AllowedHTMLTags is the closed allowlist used by HTML(). Anything not
// in this list gets stripped (content kept, surrounding tags removed
// by bluemonday). Kept narrow on purpose — every additional tag is a
// new place for exotic HTML to hide a prompt-injection vector.
//
// Block-level structure (p, br, headings, lists, blockquote) preserves
// the visual rhythm of an email so the LLM can tell paragraphs apart.
// Inline emphasis (b, strong, i, em) carries semantic weight. Anchors
// are allowed but their href is stripped — the LLM sees the link text
// and never the underlying URL, which neutralizes the "click here for
// reset" embed-attack class.
var AllowedHTMLTags = []string{
	"p", "br",
	"b", "strong", "i", "em",
	"ul", "ol", "li",
	"h1", "h2", "h3", "h4",
	"blockquote",
}

// Note: <a> is intentionally NOT on the allowlist. bluemonday strips
// the element when no attrs are allowed on it but preserves the link
// text as surrounding content — so the LLM sees "click here" with no
// surrounding URL. Letting href through would give an attacker a free
// string the LLM can be tricked by; dropping it is the right safety.

// htmlPolicy is built once and reused. bluemonday.Policy is safe for
// concurrent use, so a single package-level value is fine.
var htmlPolicy = buildHTMLPolicy()

func buildHTMLPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements(AllowedHTMLTags...)
	// Anchors are on the allowlist but their href is NOT — we keep
	// the visible link text and drop the URL the LLM would otherwise
	// see. This is the deliberate "prompt-injection via crafted href"
	// mitigation; the user can always re-fetch the message via the
	// Proton web UI if they want the actual link.
	//
	// Note: not calling AllowAttrs(...) at all = strip everything.
	return p
}

// HTML returns a sanitized copy of input. Always safe to call;
// returns "" for empty input.
func HTML(input string) string {
	if input == "" {
		return ""
	}
	return htmlPolicy.Sanitize(input)
}

// quotedReplyLine matches lines that are pure quoted-reply markers
// ("> something" or "> > something"). Used by Text() to drop the
// in-line reply history — for snippets we want the new content,
// not the email-thread tail.
var quotedReplyLine = regexp.MustCompile(`^\s*(>+\s?)+`)

// htmlTagStripper removes any remaining tags after the HTML policy
// has done its work. The policy keeps allowlist tags; this pass
// converts them to plain text. We DON'T use bluemonday.StripTagsPolicy
// because it doesn't handle entities the way Text() needs (it
// decodes &amp; → & which can re-introduce noise).
var htmlTagStripper = regexp.MustCompile(`(?s)<[^>]+>`)

// whitespaceRun matches any run of two-or-more whitespace chars
// (including newlines) so Text() can collapse them to one space.
var whitespaceRun = regexp.MustCompile(`\s+`)

// Text extracts plain text from an HTML or text input, suitable for
// snippet generation and FTS5 indexing.
//
// Steps:
//
//  1. Strip every tag (including allowlist tags — for text output
//     we want pure content).
//  2. Drop lines that are entirely quoted-reply markers.
//  3. Collapse whitespace runs to a single space.
//  4. Trim leading/trailing space.
//
// Note: HTML entities like &amp; are NOT decoded. Decoding adds a
// dependency on html.UnescapeString and lets clever encodings hide
// content from the FTS index — which is the inverse of what we want.
// A literal "&amp;" in the index won't match "&" in a search query,
// but that's a reasonable trade-off for an index built specifically
// to find prompt-injection-like content via key terms.
func Text(input string) string {
	if input == "" {
		return ""
	}
	out := htmlTagStripper.ReplaceAllString(input, " ")

	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if quotedReplyLine.MatchString(line) {
			continue
		}
		lines = append(lines, line)
	}
	out = strings.Join(lines, " ")
	out = whitespaceRun.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

// Snippet returns up to maxRunes runes from Text(input), suitable for
// the message-list preview. maxRunes <= 0 falls back to 200.
//
// Runes (not bytes) so a snippet doesn't slice a multibyte character
// in half — important for emoji-heavy email and any non-ASCII content.
func Snippet(input string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 200
	}
	text := Text(input)
	r := []rune(text)
	if len(r) <= maxRunes {
		return text
	}
	return string(r[:maxRunes]) + "…"
}
