package store

import (
	"strings"
	"time"
)

// parsedQuery is the structured form of a user's search input.
// parseQuery splits a query on whitespace and routes each token to
// the right field; unknown prefixes (`foo:bar`) and bare terms
// accumulate into the FTS5 MATCH expression.
type parsedQuery struct {
	// likes is a small map of column → LIKE substring. Avoids the
	// FTS5 path for trivial prefix queries (from:alice) so we don't
	// pay tokenizer setup cost for what's effectively a substring scan.
	// Only structured fields go in here: from_address, from_name,
	// to_json (for to:), subject.
	likes map[string]string

	folder        string
	hasAttachment bool
	before        time.Time
	after         time.Time
	fts           string // FTS5 MATCH expression, "" if none
}

func parseQuery(input string) parsedQuery {
	p := parsedQuery{likes: map[string]string{}}
	var ftsTerms []string

	for _, tok := range tokenizeQuery(input) {
		key, val, hasColon := splitPrefix(tok)
		if !hasColon {
			ftsTerms = append(ftsTerms, tok)
			continue
		}
		switch strings.ToLower(key) {
		case "from":
			// Match either the address or the display name — users
			// usually type "alice" without remembering which.
			p.likes["from_address"] = val
		case "to":
			// to_json is a JSON array of {name, address}; LIKE
			// substring matches both the address and the name in
			// the same pass.
			p.likes["to_json"] = val
		case "subject":
			p.likes["subject"] = val
		case "in":
			lower := strings.ToLower(val)
			// D1/D2: "in:all" is the DSL form of folder="all". Same
			// LLM intent — list across every folder. Treat as no
			// folder filter rather than a literal match.
			switch lower {
			case "all", "any", "all_mail", "*":
				// leave p.folder empty → no folder filter
			default:
				p.folder = lower
			}
		case "has":
			if strings.EqualFold(val, "attachment") || strings.EqualFold(val, "attachments") {
				p.hasAttachment = true
			}
		case "before", "until":
			// Defect D3: "until" as an alias for "before". The LLM
			// reaches for since/until naturally; was previously
			// falling through to the unknown-prefix path and
			// becoming a bare FTS term that matched nothing.
			if t, ok := parseSearchDate(val); ok {
				p.before = t
			}
		case "after", "since":
			// Defect D3: "since" alias for "after".
			if t, ok := parseSearchDate(val); ok {
				p.after = t
			}
		default:
			// Unknown prefix → treat the whole token as a bare FTS5
			// term so it still counts toward the match. Better UX
			// than silently dropping; we accept the risk that a
			// typo'd prefix produces a weird match instead of zero
			// results.
			ftsTerms = append(ftsTerms, tok)
		}
	}

	if len(ftsTerms) > 0 {
		// SECURITY C-9. Phrase-wrap every term so FTS5 metachars
		// (NEAR, ^, *, parentheses, etc.) lose their operator
		// meaning. Users who write a bare term get a phrase-match
		// against that token; users who try to write an FTS5
		// expression get the literal string matched as a phrase.
		// Defense-in-depth against query-injection-class DoS like
		// `NEAR/0 "a" "b"` against a large corpus.
		quoted := make([]string, 0, len(ftsTerms))
		for _, t := range ftsTerms {
			quoted = append(quoted, ftsQuote(t))
		}
		// Default to AND across terms (FTS5 implicit).
		p.fts = strings.Join(quoted, " ")
	}
	return p
}

// ftsQuote wraps a term in FTS5 phrase-form, escaping embedded
// double-quotes per the FTS5 syntax (a literal " inside a phrase
// is doubled: "" → ").
func ftsQuote(term string) string {
	return `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
}

// tokenizeQuery splits the input on whitespace, respecting double-
// quoted phrases as single tokens (`subject:"gear list"` is one
// token, value `gear list`).
func tokenizeQuery(input string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range input {
		switch {
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t' || r == '\n'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// splitPrefix returns (key, value, hasColon). For "from:alice"
// → ("from", "alice", true). For "alice" → ("", "alice", false).
// The split only happens on the FIRST colon so `before:2026-01-01`
// keeps the rest of the date intact.
func splitPrefix(tok string) (string, string, bool) {
	idx := strings.IndexByte(tok, ':')
	if idx <= 0 {
		return "", tok, false
	}
	return tok[:idx], tok[idx+1:], true
}

// parseSearchDate accepts YYYY-MM-DD and a few common alternatives.
// Returns midnight UTC of the given day. Anything unparsable returns
// (zero, false).
func parseSearchDate(s string) (time.Time, bool) {
	for _, layout := range []string{
		"2006-01-02",
		"2006/01/02",
		"2006-1-2",
	} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
