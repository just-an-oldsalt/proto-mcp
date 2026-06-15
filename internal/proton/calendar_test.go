package proton

import (
	"encoding/base64"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// A realistic Proton-style VEVENT (CRLF-folded per RFC 5545). Covers the
// fields the parser must surface, including an escaped comma in
// DESCRIPTION and two attendees with differing params.
var sampleVEVENT = strings.Join([]string{
	"BEGIN:VCALENDAR",
	"VERSION:2.0",
	"PRODID:-//proto-mcp//test//EN",
	"BEGIN:VEVENT",
	"UID:event-uid-123",
	"DTSTAMP:20260614T120000Z",
	"DTSTART:20260615T090000Z",
	"DTEND:20260615T091500Z",
	"SUMMARY:Team standup",
	"LOCATION:Zoom",
	"DESCRIPTION:Daily sync\\, bring updates",
	"ORGANIZER;CN=Alice:mailto:alice@example.com",
	"ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:bob@example.com",
	"ATTENDEE;PARTSTAT=NEEDS-ACTION:MAILTO:carol@example.com",
	"RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR",
	"STATUS:CONFIRMED",
	"END:VEVENT",
	"END:VCALENDAR",
}, "\r\n") + "\r\n"

func TestParseICalEvent(t *testing.T) {
	f, err := parseICalEvent(sampleVEVENT)
	if err != nil {
		t.Fatalf("parseICalEvent: %v", err)
	}

	if f.UID != "event-uid-123" {
		t.Errorf("UID = %q, want event-uid-123", f.UID)
	}
	if f.Summary != "Team standup" {
		t.Errorf("Summary = %q", f.Summary)
	}
	if f.Location != "Zoom" {
		t.Errorf("Location = %q", f.Location)
	}
	// The escaped comma must be unescaped by the parser.
	if f.Description != "Daily sync, bring updates" {
		t.Errorf("Description = %q, want unescaped comma", f.Description)
	}
	if f.Organizer != "alice@example.com" {
		t.Errorf("Organizer = %q, want alice@example.com (mailto stripped)", f.Organizer)
	}
	if f.Status != "CONFIRMED" {
		t.Errorf("Status = %q", f.Status)
	}
	if !f.IsRecurring || f.RRULE != "FREQ=WEEKLY;BYDAY=MO,WE,FR" {
		t.Errorf("recurrence = (%v, %q)", f.IsRecurring, f.RRULE)
	}

	if len(f.Attendees) != 2 {
		t.Fatalf("attendees = %d, want 2", len(f.Attendees))
	}
	bob := f.Attendees[0]
	if bob.Email != "bob@example.com" || bob.Name != "Bob" || bob.Status != "ACCEPTED" || bob.Role != "REQ-PARTICIPANT" {
		t.Errorf("attendee[0] = %+v", bob)
	}
	carol := f.Attendees[1]
	// Upper-case MAILTO: must also be stripped.
	if carol.Email != "carol@example.com" || carol.Status != "NEEDS-ACTION" {
		t.Errorf("attendee[1] = %+v", carol)
	}
}

func TestParseICalEvent_NoVEvent(t *testing.T) {
	_, err := parseICalEvent("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n")
	if err == nil {
		t.Fatal("expected error for payload with no VEVENT")
	}
}

// TestDecryptSharedPart_RoundTrip encrypts a VEVENT exactly the way
// Proton does — a session key wrapped to the calendar key (the key
// packet) plus a symmetric data packet, both base64 — and confirms
// decryptSharedPart recovers the plaintext. This also pins that we do
// NOT rely on the SDK's broken CalendarEventPart.Decode.
func TestDecryptSharedPart_RoundTrip(t *testing.T) {
	calKR := newTestKeyRing(t, "calendar@proton.me")

	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPacket, err := calKR.EncryptSessionKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	dataPacket, err := sk.Encrypt(crypto.NewPlainMessageFromString(sampleVEVENT))
	if err != nil {
		t.Fatal(err)
	}

	parts := []gpa.CalendarEventPart{{
		Type: gpa.CalendarEventTypeEncrypted,
		Data: base64.StdEncoding.EncodeToString(dataPacket),
	}}
	got, err := decryptSharedPart(calKR, base64.StdEncoding.EncodeToString(keyPacket), parts)
	if err != nil {
		t.Fatalf("decryptSharedPart: %v", err)
	}
	// PGP text mode canonicalizes line endings to LF on decrypt, so
	// compare with CRLF normalized away — the content must be identical.
	if norm(got) != norm(sampleVEVENT) {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, sampleVEVENT)
	}

	// End-to-end: the recovered text parses to the expected summary.
	f, err := parseICalEvent(got)
	if err != nil {
		t.Fatalf("parse round-tripped ical: %v", err)
	}
	if f.Summary != "Team standup" {
		t.Errorf("round-tripped summary = %q", f.Summary)
	}
}

func TestDecryptSharedPart_ClearPart(t *testing.T) {
	calKR := newTestKeyRing(t, "calendar@proton.me")
	parts := []gpa.CalendarEventPart{{
		Type: gpa.CalendarEventTypeClear,
		Data: sampleVEVENT,
	}}
	got, err := decryptSharedPart(calKR, "", parts)
	if err != nil {
		t.Fatalf("decryptSharedPart (clear): %v", err)
	}
	if got != sampleVEVENT {
		t.Errorf("clear part = %q", got)
	}
}

func TestDecryptSharedPart_NoParts(t *testing.T) {
	calKR := newTestKeyRing(t, "calendar@proton.me")
	if _, err := decryptSharedPart(calKR, "", nil); err == nil {
		t.Fatal("expected error for event with no parts")
	}
}

// TestMemberKeyring matches a calendar member to the session's address
// (case-insensitively) and returns its keyring; and errors when none of
// the members map to an unlocked address.
func TestMemberKeyring(t *testing.T) {
	kr := newTestKeyRing(t, "me@proton.me")
	s := &Session{
		Addresses: []gpa.Address{{ID: "addr-1", Email: "Me@Proton.me"}},
		AddrKRs:   map[string]*crypto.KeyRing{"addr-1": kr},
	}

	members := []gpa.CalendarMember{
		{ID: "member-x", Email: "someone-else@proton.me"},
		{ID: "member-1", Email: "me@proton.me"},
	}
	memberID, gotKR, err := s.memberKeyring(members)
	if err != nil {
		t.Fatalf("memberKeyring: %v", err)
	}
	if memberID != "member-1" {
		t.Errorf("memberID = %q, want member-1", memberID)
	}
	if gotKR != kr {
		t.Error("returned keyring is not the address keyring")
	}

	// No member matches any address keyring → error.
	if _, _, err := s.memberKeyring([]gpa.CalendarMember{{ID: "m", Email: "nobody@proton.me"}}); err == nil {
		t.Fatal("expected error when no member matches an address")
	}
}

func norm(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

func newTestKeyRing(t *testing.T, email string) *crypto.KeyRing {
	t.Helper()
	k, err := crypto.GenerateKey("Test", email, "rsa", 2048)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.NewKeyRing(k)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}
