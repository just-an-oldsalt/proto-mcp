package mcptools

import (
	"net/mail"
	"net/url"
	"strings"
	"unicode"
)

// unsubscribeInfo is mail_read's `unsubscribe` field (#102): the
// sender's RFC 2369 List-Unsubscribe targets, filtered to https and
// mailto, plus whether the sender advertises RFC 8058 one-click.
//
// Every value here is sender-controlled. proto-mcp only exposes the
// targets; it never visits a URL or sends to an address on its own.
type unsubscribeInfo struct {
	HTTPS    []string `json:"https"`
	Mailto   []string `json:"mailto"`
	OneClick bool     `json:"one_click"`
}

const (
	// maxUnsubscribeEntries bounds how many <uri> entries of the
	// header are examined. Real senders list one or two.
	maxUnsubscribeEntries = 4
	// maxUnsubscribeURILen caps a single URI; longer ones are dropped.
	maxUnsubscribeURILen = 2048
	// oneClickPostValue is the only RFC 8058 List-Unsubscribe-Post body.
	oneClickPostValue = "List-Unsubscribe=One-Click"
)

// parseUnsubscribe turns raw List-Unsubscribe / List-Unsubscribe-Post
// header values into the filtered exposure shape, or nil if no entry
// survives the filter.
//
// Parsing is deliberately strict: only angle-bracketed entries count
// (text between them is ignored), at most maxUnsubscribeEntries are
// examined, and an entry is kept only if it is
//   - https with a non-empty host and no userinfo, or
//   - mailto whose address parses as a single bare RFC 5322 address,
//
// is at most maxUnsubscribeURILen bytes, and contains no control
// characters or non-ASCII whitespace. Spaces and tabs inside the angle
// brackets are ignored, as RFC 2369 section 2 requires: senders wrap
// long URLs across folded header lines, and unfolding leaves them
// there. A bare CR or LF still present is not folding, so it rejects
// the entry. http, javascript, data and every other scheme are
// dropped. one_click requires at least one kept https entry AND a
// List-Unsubscribe-Post of exactly "List-Unsubscribe=One-Click"
// (case-insensitive, surrounding whitespace ignored).
func parseUnsubscribe(listUnsub, listUnsubPost string) *unsubscribeInfo {
	info := &unsubscribeInfo{HTTPS: []string{}, Mailto: []string{}}
	seen := map[string]bool{}

	rest := listUnsub
	for examined := 0; examined < maxUnsubscribeEntries; examined++ {
		start := strings.IndexByte(rest, '<')
		if start < 0 {
			break
		}
		end := strings.IndexByte(rest[start+1:], '>')
		if end < 0 {
			break
		}
		uri := strings.Map(dropFoldingSpace, rest[start+1:start+1+end])
		rest = rest[start+1+end+1:]

		scheme, ok := validUnsubscribeURI(uri)
		if !ok || seen[uri] {
			continue
		}
		seen[uri] = true
		switch scheme {
		case "https":
			info.HTTPS = append(info.HTTPS, uri)
		case "mailto":
			info.Mailto = append(info.Mailto, uri)
		}
	}

	if len(info.HTTPS) == 0 && len(info.Mailto) == 0 {
		return nil
	}
	info.OneClick = len(info.HTTPS) > 0 &&
		strings.EqualFold(strings.TrimSpace(listUnsubPost), oneClickPostValue)
	return info
}

// validUnsubscribeURI reports whether uri is an acceptable unsubscribe
// target and, if so, its lower-cased scheme ("https" or "mailto").
func validUnsubscribeURI(uri string) (string, bool) {
	if uri == "" || len(uri) > maxUnsubscribeURILen {
		return "", false
	}
	for _, r := range uri {
		if r <= 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.IsSpace(r) || r == '<' {
			return "", false
		}
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Opaque != "" || u.User != nil || u.Hostname() == "" {
			return "", false
		}
		return "https", true
	case "mailto":
		// mailto:addr?subject=... → Opaque is the (percent-encoded)
		// address. An empty address (mailto:?to=...) is rejected.
		addr, err := url.PathUnescape(u.Opaque)
		if err != nil || addr == "" {
			return "", false
		}
		parsed, err := mail.ParseAddress(addr)
		if err != nil || parsed.Name != "" || parsed.Address != addr {
			return "", false
		}
		return "mailto", true
	default:
		return "", false
	}
}

// dropFoldingSpace removes the spaces and tabs RFC 2369 says to ignore
// inside a List-Unsubscribe <uri>; every other rune is kept.
func dropFoldingSpace(r rune) rune {
	if r == ' ' || r == '\t' {
		return -1
	}
	return r
}
