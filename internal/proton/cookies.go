package proton

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// protonAPIURL is parsed once for cookie extraction / insertion.
// Cookies set by /auth/v4 are scoped to mail-api.proton.me; persisting
// them lets a future process resume a refresh token that the server
// considers bound to the same session.
var protonAPIURL = mustParseURL(HostURL)

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic("proton: invalid HostURL " + s + ": " + err.Error())
	}
	return u
}

// NewCookieJar returns a fresh in-memory cookie jar. Pass it to
// NewManager so the SDK's HTTP client tracks cookies across requests.
//
// Proton's /auth/v4/refresh endpoint validates cookies set by the
// original /auth/v4 login response — without a persistent jar, a
// cold-start refresh hits 422 "Invalid refresh token" even with the
// correct UID + refresh-token pair. See JarCookies / PreloadJar for
// the persistence helpers.
func NewCookieJar() http.CookieJar {
	j, err := cookiejar.New(nil)
	if err != nil {
		// cookiejar.New(nil) only errors if it can't init the public-
		// suffix list, which the stdlib gracefully handles. Treat as
		// programmer error.
		panic("proton: cookiejar.New failed: " + err.Error())
	}
	return j
}

// JarCookies returns the cookies the jar currently holds for the
// Proton API host, deduplicated by Name. Used to serialize a jar for
// the Keychain blob after a successful login or token rotation.
//
// Dedup is needed because Proton occasionally sets the same cookie
// (e.g. Session-Id) on multiple paths, which the stdlib cookiejar
// stores as separate entries. Without this, the blob grows by one
// entry per invocation. We keep the LAST occurrence under the
// assumption that the most recent server write is the canonical one.
func JarCookies(jar http.CookieJar) []*http.Cookie {
	if jar == nil {
		return nil
	}
	raw := jar.Cookies(protonAPIURL)
	if len(raw) <= 1 {
		return raw
	}
	byName := make(map[string]*http.Cookie, len(raw))
	order := make([]string, 0, len(raw))
	for _, c := range raw {
		if _, seen := byName[c.Name]; !seen {
			order = append(order, c.Name)
		}
		byName[c.Name] = c // overwrite — last write wins
	}
	out := make([]*http.Cookie, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// PreloadJar populates a fresh jar with cookies previously extracted
// via JarCookies. Used at resume time so the SDK's outgoing refresh
// request carries the same session cookies the server originally set.
func PreloadJar(jar http.CookieJar, cookies []*http.Cookie) {
	if jar == nil || len(cookies) == 0 {
		return
	}
	jar.SetCookies(protonAPIURL, cookies)
}
