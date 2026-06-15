package proton

import (
	"fmt"
	"strings"

	ical "github.com/emersion/go-ical"
)

// This file is the ONLY place go-ical is used. Calendar event payloads
// decrypt to iCalendar (RFC 5545) VEVENT text; everything downstream
// works with the structured icalFields below, so the dependency stays
// swappable and the RFC-5545 quirks (line folding, escaping, parameter
// quoting) are handled in one well-tested library rather than by hand.

// icalAttendee is one ATTENDEE line, flattened.
type icalAttendee struct {
	Email  string // mailto: prefix stripped
	Name   string // CN param, if present
	Status string // PARTSTAT param (NEEDS-ACTION/ACCEPTED/DECLINED/TENTATIVE)
	Role   string // ROLE param (REQ-PARTICIPANT/OPT-PARTICIPANT/CHAIR)
}

// icalFields is the subset of VEVENT properties we surface. Times are
// deliberately NOT parsed here — proto-mcp takes start/end/timezone from
// the SDK's plaintext CalendarEvent metadata, which is authoritative and
// avoids re-deriving TZID/DST edges from the text.
type icalFields struct {
	UID         string
	Summary     string
	Description string
	Location    string
	Organizer   string
	Status      string
	RRULE       string
	IsRecurring bool
	Attendees   []icalAttendee
}

// parseICalEvent decodes a decrypted VEVENT blob and extracts the text
// fields we expose. It reads the first VEVENT component (the master);
// recurrence overrides (additional VEVENTs with RECURRENCE-ID) are
// ignored in v1 — see the recurrence limitation in docs.
func parseICalEvent(text string) (icalFields, error) {
	var f icalFields

	cal, err := ical.NewDecoder(strings.NewReader(text)).Decode()
	if err != nil {
		return f, fmt.Errorf("parse ical: %w", err)
	}

	events := cal.Events()
	if len(events) == 0 {
		return f, fmt.Errorf("ical payload has no VEVENT")
	}
	ev := events[0]

	f.UID = propText(ev.Props, "UID")
	f.Summary = propText(ev.Props, "SUMMARY")
	f.Description = propText(ev.Props, "DESCRIPTION")
	f.Location = propText(ev.Props, "LOCATION")
	f.Status = propText(ev.Props, "STATUS")

	if p := ev.Props.Get("ORGANIZER"); p != nil {
		f.Organizer = stripMailto(p.Value)
		if cn := paramFirst(p, "CN"); cn != "" && f.Organizer == "" {
			f.Organizer = cn
		}
	}

	if p := ev.Props.Get("RRULE"); p != nil && strings.TrimSpace(p.Value) != "" {
		f.RRULE = strings.TrimSpace(p.Value)
		f.IsRecurring = true
	}

	for _, p := range ev.Props.Values("ATTENDEE") {
		email := stripMailto(p.Value)
		if email == "" {
			continue
		}
		f.Attendees = append(f.Attendees, icalAttendee{
			Email:  email,
			Name:   paramFirst(&p, "CN"),
			Status: paramFirst(&p, "PARTSTAT"),
			Role:   paramFirst(&p, "ROLE"),
		})
	}

	return f, nil
}

// propText returns a property's text value, or "" if absent. Props.Text
// resolves go-ical's value escaping (\n, \, , \;).
func propText(props ical.Props, name string) string {
	v, err := props.Text(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// paramFirst returns the first value of a property parameter (e.g. CN,
// PARTSTAT, ROLE), or "".
func paramFirst(p *ical.Prop, name string) string {
	if p == nil {
		return ""
	}
	if vals, ok := p.Params[name]; ok && len(vals) > 0 {
		return strings.TrimSpace(vals[0])
	}
	return ""
}

// stripMailto removes a leading "mailto:" (case-insensitive) from a
// CAL-ADDRESS value and trims it.
func stripMailto(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 7 && strings.EqualFold(v[:7], "mailto:") {
		return strings.TrimSpace(v[7:])
	}
	return v
}
