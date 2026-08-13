package proton

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
)

// Proton returns a calendar's display metadata — name, description,
// colour, and the flags that say whether it's active — on the calendar's
// *member* records, not on the calendar object itself. Confirmed against
// the live API: GET /calendar/v1 responds with
//
//	{"Calendars":[{"ID":…,"Type":0,"Owner":{…},"CreateTime":…,
//	  "Members":[{"Name":"My calendar","Flags":1,"Color":"#DB60D6",…}]}]}
//
// so the members arrive inline with the listing (Proton's
// CalendarWithOwnMembers) and no per-calendar round trip is needed. Their
// own web client does the same thing in getVisualCalendar(), copying
// Name/Description/Color/Display/Email/Flags/Permissions/Priority off the
// member (WebClients, packages/shared/lib/calendar/calendar.ts).
//
// go-proton-api hasn't kept up, and fails silently in two directions:
// gpa.Calendar declares Name / Description / Color / Display / Flags —
// none of which the API sends any more, so they decode to zero values —
// and declares no Members field at all, so the data that *is* there is
// discarded. gpa.CalendarMember (used by the separate members endpoint)
// likewise omits Name and Flags. That is why a mirrored calendar shows up
// with a blank name and active=false.
//
// The SDK gives us no way to widen its own decode (Client.do is
// unexported and both GetCalendars and GetCalendarMembers hardcode their
// result types), so we re-decode these responses out of a post-request
// hook and keep the full records alongside the session.

// CalendarMemberFull is the members-endpoint payload as the live API
// sends it. Field set mirrors Proton's CalendarMember interface in
// WebClients (packages/shared/lib/interfaces/calendar/CalendarMember.ts).
// Name and Description are plaintext — calendar names are not part of the
// E2EE envelope the way event contents are.
type CalendarMemberFull struct {
	ID          string
	CalendarID  string
	AddressID   string
	Email       string
	Name        string
	Description string
	Color       string
	Display     int
	Flags       int64
	Permissions int64
	Priority    int64
}

// installCalendarMemberHook wires the post-request hook that captures
// full member records. Safe to call once per session; Login and Resume
// both do so as soon as the Session shell exists.
func (s *Session) installCalendarMemberHook() {
	if s == nil || s.Client == nil {
		return
	}
	s.Client.AddPostRequestHook(func(_ *resty.Client, res *resty.Response) error {
		s.captureCalendarMembers(res)
		// Never fail the request over a capture problem — this is a
		// side-channel for display metadata, not the caller's payload.
		return nil
	})
}

// captureCalendarMembers decodes a /calendar/v1/{id}/members response and
// stashes the full records under the calendar ID taken from the request
// path. Using the request URL (rather than a CalendarID inside the body)
// keeps the association exact: res.Request is by definition the request
// that produced this response.
func (s *Session) captureCalendarMembers(res *resty.Response) {
	if res == nil || res.Request == nil {
		return
	}
	raw, body := res.Request.URL, res.Body()

	// The calendar listing embeds each calendar's own members inline.
	// This is the path calendar sync actually exercises, and it answers
	// for every calendar in one response.
	if byCal := parseCalendarListMembers(raw, body); len(byCal) > 0 {
		for calID, members := range byCal {
			s.stashCalendarMembers(calID, members)
		}
		return
	}

	// The dedicated members endpoint, reached via the decrypt path
	// (calendarKeyRing → GetCalendarMembers).
	if calID, members := parseCalendarMembers(raw, body); calID != "" && len(members) > 0 {
		s.stashCalendarMembers(calID, members)
	}
}

// parseCalendarListMembers decodes a GET /calendar/v1 response and
// returns each calendar's member records keyed by calendar ID.
//
// The listing embeds members inline — Proton's CalendarWithOwnMembers —
// so a single response carries the display metadata for every calendar
// and no per-calendar round trip is needed. gpa.Calendar declares no
// Members field at all, so the SDK drops the whole thing on the floor.
func parseCalendarListMembers(rawURL string, body []byte) map[string][]CalendarMemberFull {
	if !strings.Contains(rawURL, "/calendar/v1") || !isCalendarListURL(rawURL) {
		return nil
	}
	var payload struct {
		Calendars []struct {
			ID      string
			Members []CalendarMemberFull
		}
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	out := make(map[string][]CalendarMemberFull, len(payload.Calendars))
	for _, c := range payload.Calendars {
		if c.ID == "" || len(c.Members) == 0 {
			continue
		}
		out[c.ID] = c.Members
	}
	return out
}

// isCalendarListURL reports whether raw is the bare /calendar/v1 listing
// (as opposed to any /calendar/v1/{id}/... sub-resource).
func isCalendarListURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(parts) == 2 && parts[0] == "calendar" && parts[1] == "v1"
}

// parseCalendarMembers decodes a members response body, returning the
// calendar ID from the URL and the member records. Returns a zero calID
// for any URL that isn't a members endpoint, so unrelated traffic (all of
// mail) falls straight through. Split out from captureCalendarMembers so
// the wire decode is testable without a live response.
func parseCalendarMembers(rawURL string, body []byte) (string, []CalendarMemberFull) {
	// Cheap reject before parsing — most traffic is mail.
	if !strings.Contains(rawURL, "/members") {
		return "", nil
	}
	calID := calendarIDFromMembersURL(rawURL)
	if calID == "" {
		return "", nil
	}
	var payload struct{ Members []CalendarMemberFull }
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil
	}
	return calID, payload.Members
}

// calendarIDFromMembersURL returns the calendar ID from a
// /calendar/v1/{id}/members URL, or "" if the path isn't that shape.
func calendarIDFromMembersURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 {
		return ""
	}
	if parts[0] != "calendar" || parts[1] != "v1" || parts[3] != "members" {
		return ""
	}
	return parts[2]
}

func (s *Session) stashCalendarMembers(calID string, members []CalendarMemberFull) {
	s.calMu.Lock()
	defer s.calMu.Unlock()
	if s.calMembers == nil {
		s.calMembers = make(map[string][]CalendarMemberFull)
	}
	s.calMembers[calID] = members
}

// CalendarMembers returns the captured member records for a calendar, or
// nil if none have been seen. The caller owns the returned slice.
func (s *Session) CalendarMembers(calID string) []CalendarMemberFull {
	s.calMu.Lock()
	defer s.calMu.Unlock()
	m, ok := s.calMembers[calID]
	if !ok {
		return nil
	}
	return append([]CalendarMemberFull(nil), m...)
}

// OwnCalendarMember returns the captured member whose email matches one
// of this session's addresses — the record carrying *our* view of the
// calendar's name and flags. A shared calendar lists every participant,
// so picking the first member would show someone else's name for it.
// Mirrors the address-matching in memberKeyring. Returns nil if no
// members were captured or none match.
func (s *Session) OwnCalendarMember(calID string) *CalendarMemberFull {
	members := s.CalendarMembers(calID)
	for i := range members {
		for _, a := range s.Addresses {
			if strings.EqualFold(a.Email, members[i].Email) {
				return &members[i]
			}
		}
	}
	return nil
}
