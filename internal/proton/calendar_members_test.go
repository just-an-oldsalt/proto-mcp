package proton

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"
)

// membersJSON is a /calendar/v1/{id}/members response shaped after
// Proton's own CalendarMember interface (WebClients,
// packages/shared/lib/interfaces/calendar/CalendarMember.ts). The fields
// that matter here — Name and Flags — are the ones go-proton-api's
// CalendarMember omits, so they never survive its decode.
const membersJSON = `{
  "Code": 1000,
  "Members": [
    {
      "ID": "member-1",
      "CalendarID": "cal-1",
      "AddressID": "addr-1",
      "Email": "me@proton.me",
      "Name": "Personal",
      "Description": "my calendar",
      "Color": "#5a3fc0",
      "Display": 1,
      "Flags": 1,
      "Permissions": 127,
      "Priority": 1
    },
    {
      "ID": "member-2",
      "CalendarID": "cal-1",
      "AddressID": "addr-9",
      "Email": "someone.else@proton.me",
      "Name": "Shared with me",
      "Color": "#c04040",
      "Display": 1,
      "Flags": 1,
      "Permissions": 1,
      "Priority": 2
    }
  ]
}`

// calendarListJSON mirrors a real GET /calendar/v1 response: members are
// embedded inline on each calendar, and the calendar object itself
// carries only ID / Type / Owner / CreateTime — no Name, Color or Flags.
// Two calendars, because the listing answers for all of them at once.
const calendarListJSON = `{
  "Calendars": [
    {
      "Members": [
        {
          "Flags": 1,
          "ID": "member-1",
          "Permissions": 127,
          "Email": "me@proton.me",
          "AddressID": "addr-1",
          "CalendarID": "cal-1",
          "Name": "My calendar",
          "Description": "",
          "Color": "#DB60D6",
          "Display": 1,
          "Priority": 1
        }
      ],
      "ID": "cal-1",
      "Type": 0,
      "Owner": {"Email": "me@proton.me"},
      "CreateTime": 1659662303
    },
    {
      "Members": [
        {
          "Flags": 1,
          "ID": "member-2",
          "Permissions": 127,
          "Email": "me@proton.me",
          "AddressID": "addr-1",
          "CalendarID": "cal-2",
          "Name": "work@example.com",
          "Description": "",
          "Color": "#F78400",
          "Display": 1,
          "Priority": 2
        }
      ],
      "ID": "cal-2",
      "Type": 0,
      "Owner": {"Email": "me@proton.me"},
      "CreateTime": 1663384800
    }
  ],
  "Code": 1000
}`

// The listing is the response calendar sync actually sees, and it is the
// one that still returns 200 on a session without calendar scope — so
// this is the path that has to work.
func TestParseCalendarListMembers(t *testing.T) {
	byCal := parseCalendarListMembers(
		"https://mail-api.proton.me/calendar/v1", []byte(calendarListJSON))
	if len(byCal) != 2 {
		t.Fatalf("calendars = %d, want 2", len(byCal))
	}

	first := byCal["cal-1"]
	if len(first) != 1 {
		t.Fatalf("cal-1 members = %d, want 1", len(first))
	}
	if first[0].Name != "My calendar" || first[0].Color != "#DB60D6" {
		t.Errorf("cal-1 member = %+v, want name/colour decoded", first[0])
	}
	if first[0].Flags != int64(gpa.CalendarFlagActive) {
		t.Errorf("cal-1 Flags = %d, want %d", first[0].Flags, gpa.CalendarFlagActive)
	}
	if got := byCal["cal-2"]; len(got) != 1 || got[0].Name != "work@example.com" {
		t.Errorf("cal-2 members = %+v, want the second calendar decoded too", got)
	}
}

// Only the bare listing carries inline members; sub-resources must not be
// mistaken for it.
func TestParseCalendarListMembers_OnlyMatchesTheListing(t *testing.T) {
	for _, u := range []string{
		"https://mail-api.proton.me/calendar/v1/cal-1/events",
		"https://mail-api.proton.me/calendar/v1/cal-1/members",
		"https://mail-api.proton.me/calendar/v1/cal-1",
		"https://mail-api.proton.me/mail/v4/messages",
	} {
		if got := parseCalendarListMembers(u, []byte(calendarListJSON)); len(got) != 0 {
			t.Errorf("%s: captured as a listing, want ignored", u)
		}
	}
}

// End-to-end through the hook: the listing populates every calendar's
// member record in one response, with no per-calendar round trip.
func TestCaptureCalendarMembers_FromListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(calendarListJSON))
	}))
	defer srv.Close()

	s := &Session{Addresses: []gpa.Address{{ID: "addr-1", Email: "me@proton.me"}}}
	c := resty.New()
	c.OnAfterResponse(func(_ *resty.Client, res *resty.Response) error {
		s.captureCalendarMembers(res)
		return nil
	})

	// The SDK's own result type has no Members field at all, so it
	// discards the metadata entirely — the reason for this hook.
	var sdkResult struct{ Calendars []gpa.Calendar }
	if _, err := c.R().SetResult(&sdkResult).Get(srv.URL + "/calendar/v1"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(sdkResult.Calendars) != 2 {
		t.Fatalf("SDK decoded %d calendars, want 2", len(sdkResult.Calendars))
	}
	if sdkResult.Calendars[0].Name != "" {
		t.Errorf("precondition failed: gpa.Calendar.Name = %q, expected the SDK to decode it empty",
			sdkResult.Calendars[0].Name)
	}

	for calID, want := range map[string]string{"cal-1": "My calendar", "cal-2": "work@example.com"} {
		got := s.OwnCalendarMember(calID)
		if got == nil {
			t.Errorf("%s: nothing captured", calID)
			continue
		}
		if got.Name != want {
			t.Errorf("%s: Name = %q, want %q", calID, got.Name, want)
		}
	}
}

func TestParseCalendarMembers(t *testing.T) {
	calID, members := parseCalendarMembers(
		"https://mail-api.proton.me/calendar/v1/cal-1/members", []byte(membersJSON))
	if calID != "cal-1" {
		t.Fatalf("calID = %q, want cal-1", calID)
	}
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}

	m := members[0]
	if m.Name != "Personal" || m.Description != "my calendar" || m.Color != "#5a3fc0" {
		t.Errorf("display fields not decoded: %+v", m)
	}
	if m.Flags != int64(gpa.CalendarFlagActive) {
		t.Errorf("Flags = %d, want %d", m.Flags, gpa.CalendarFlagActive)
	}
	if m.Email != "me@proton.me" || m.AddressID != "addr-1" {
		t.Errorf("identity fields not decoded: %+v", m)
	}
}

func TestParseCalendarMembers_IgnoresUnrelatedTraffic(t *testing.T) {
	for _, u := range []string{
		"https://mail-api.proton.me/mail/v4/messages",
		"https://mail-api.proton.me/calendar/v1",
		"https://mail-api.proton.me/calendar/v1/cal-1/events",
		"https://mail-api.proton.me/calendar/v1/cal-1/keys",
		"https://mail-api.proton.me/core/v4/members", // core members, not calendar
	} {
		if calID, _ := parseCalendarMembers(u, []byte(membersJSON)); calID != "" {
			t.Errorf("%s: captured as calendar members (calID=%q), want ignored", u, calID)
		}
	}
}

func TestParseCalendarMembers_MalformedBodyIsNotFatal(t *testing.T) {
	calID, members := parseCalendarMembers(
		"https://mail-api.proton.me/calendar/v1/cal-1/members", []byte("<html>gateway error</html>"))
	if calID != "" || members != nil {
		t.Errorf("malformed body should yield nothing, got %q / %+v", calID, members)
	}
}

// A shared calendar lists every participant. We must pick the member
// matching one of our own addresses, not simply the first — otherwise the
// calendar shows up under whatever name its owner gave it.
func TestOwnCalendarMember_PicksOurAddress(t *testing.T) {
	s := &Session{
		Addresses: []gpa.Address{{ID: "addr-9", Email: "someone.else@proton.me"}},
	}
	_, members := parseCalendarMembers(
		"https://mail-api.proton.me/calendar/v1/cal-1/members", []byte(membersJSON))
	s.stashCalendarMembers("cal-1", members)

	got := s.OwnCalendarMember("cal-1")
	if got == nil {
		t.Fatal("no member matched our address")
	}
	if got.Name != "Shared with me" {
		t.Errorf("Name = %q, want the member matching our address", got.Name)
	}
}

func TestOwnCalendarMember_NoMatchOrNoCapture(t *testing.T) {
	s := &Session{Addresses: []gpa.Address{{ID: "a", Email: "nobody@proton.me"}}}

	if got := s.OwnCalendarMember("cal-1"); got != nil {
		t.Errorf("uncaptured calendar should yield nil, got %+v", got)
	}

	_, members := parseCalendarMembers(
		"https://mail-api.proton.me/calendar/v1/cal-1/members", []byte(membersJSON))
	s.stashCalendarMembers("cal-1", members)
	if got := s.OwnCalendarMember("cal-1"); got != nil {
		t.Errorf("no address match should yield nil, got %+v", got)
	}
}

// The capture hangs off resty's post-response hook, and the SDK decodes
// the same response into its own struct via SetResult. This asserts the
// raw body is still readable from that hook — if resty ever consumed the
// body during SetResult, the capture would silently return nothing.
func TestCaptureCalendarMembers_BodyReadableFromPostResponseHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(membersJSON))
	}))
	defer srv.Close()

	s := &Session{Addresses: []gpa.Address{{ID: "addr-1", Email: "me@proton.me"}}}

	c := resty.New()
	c.OnAfterResponse(func(_ *resty.Client, res *resty.Response) error {
		s.captureCalendarMembers(res)
		return nil
	})

	// Mirror what the SDK does: decode into its own (lossy) result type.
	var sdkResult struct{ Members []gpa.CalendarMember }
	if _, err := c.R().SetResult(&sdkResult).Get(srv.URL + "/calendar/v1/cal-1/members"); err != nil {
		t.Fatalf("request: %v", err)
	}

	// The SDK's own decode drops Name — that is the bug being worked around.
	if len(sdkResult.Members) != 2 {
		t.Fatalf("SDK decoded %d members, want 2", len(sdkResult.Members))
	}

	got := s.OwnCalendarMember("cal-1")
	if got == nil {
		t.Fatal("hook captured nothing — the raw body was not readable after SetResult")
	}
	if got.Name != "Personal" || got.Flags != int64(gpa.CalendarFlagActive) {
		t.Errorf("captured member = %+v, want Name/Flags preserved", got)
	}
}
