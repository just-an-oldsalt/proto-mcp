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
			p.folder = strings.ToLower(val)
		case "has":
			if strings.EqualFold(val, "attachment") || strings.EqualFold(val, "attachments") {
				p.hasAttachment = true
			}
		case "before":
			if t, ok := parseSearchDate(val); ok {
				p.before = t
			}
		case "after":
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
		// Default to AND across terms (FTS5 implicit).
		p.fts = strings.Join(ftsTerms, " ")
	}
	return p
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
