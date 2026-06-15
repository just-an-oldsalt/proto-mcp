package proton

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Proton Calendar is end-to-end encrypted. Reading an event means
// walking a key hierarchy — address key → member passphrase → calendar
// key — then decrypting the event's "shared" part (the iCalendar text)
// with the calendar key. Every primitive lives in go-proton-api +
// gopenpgp; this file orchestrates them and reuses the per-address
// keyrings Resume/Login already unlocked into Session.AddrKRs.
//
// NOTE: we do NOT call CalendarEventPart.Decode — that SDK method has a
// value receiver and assigns the decrypted plaintext to a copy
// (`part.Data = ...`), so the result is discarded and it returns only an
// error. It is also unused upstream. decryptSharedPart below replicates
// its body and actually returns the plaintext.

// CalendarAttendeeDetail is a flattened attendee from the decrypted
// VEVENT. Attendee emails are NOT in the plaintext event metadata
// (which carries only opaque tokens) — they come from the iCal payload.
type CalendarAttendeeDetail struct {
	Email  string `json:"email"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	Role   string `json:"role,omitempty"`
}

// CalendarEventDetail is a fully-resolved event: plaintext metadata from
// the SDK (times, timezones, all-day) plus the decrypted text fields.
type CalendarEventDetail struct {
	EventID    string `json:"event_id"`
	CalendarID string `json:"calendar_id"`
	UID        string `json:"uid,omitempty"`

	Summary     string `json:"summary,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
	Organizer   string `json:"organizer,omitempty"`
	Status      string `json:"status,omitempty"`

	StartUnix int64  `json:"start_unix"`
	StartTZ   string `json:"start_tz,omitempty"`
	EndUnix   int64  `json:"end_unix"`
	EndTZ     string `json:"end_tz,omitempty"`
	AllDay    bool   `json:"all_day"`

	IsRecurring bool   `json:"recurring"`
	RRULE       string `json:"rrule,omitempty"`

	Attendees []CalendarAttendeeDetail `json:"attendees,omitempty"`

	RawICal string `json:"raw_ical,omitempty"`
}

// CalendarKeyCache holds unlocked per-calendar keyrings for the duration
// of a single sync/backfill pass so each calendar's passphrase→key
// unlock happens once, not once per event. Unlocked calendar keys are
// sensitive; keep the cache short-lived and call Clear() when the pass
// ends.
type CalendarKeyCache struct {
	rings map[string]*crypto.KeyRing
}

// NewCalendarKeyCache returns an empty cache. Pass it through a sync pass
// to amortize key unlocks; pass a fresh one (or nil) for a one-off read.
func NewCalendarKeyCache() *CalendarKeyCache {
	return &CalendarKeyCache{rings: make(map[string]*crypto.KeyRing)}
}

// Clear wipes the private key material in every cached keyring. Call it
// when a sync/backfill pass finishes.
func (c *CalendarKeyCache) Clear() {
	if c == nil {
		return
	}
	for id, kr := range c.rings {
		if kr != nil {
			kr.ClearPrivateParams()
		}
		delete(c.rings, id)
	}
}

// calendarKeyRing returns (and caches) the unlocked keyring for a
// calendar. It finds the calendar member whose email matches one of the
// session's addresses, decrypts that member's passphrase with the
// address keyring, then unlocks the calendar keys with the passphrase.
func (s *Session) calendarKeyRing(ctx context.Context, calID string, cache *CalendarKeyCache) (*crypto.KeyRing, error) {
	if s == nil || s.Client == nil {
		return nil, errors.New("proton: session is closed")
	}
	if cache != nil {
		if kr, ok := cache.rings[calID]; ok {
			return kr, nil
		}
	}

	members, err := s.Client.GetCalendarMembers(ctx, calID)
	if err != nil {
		return nil, fmt.Errorf("get calendar members: %w", err)
	}

	memberID, addrKR, err := s.memberKeyring(members)
	if err != nil {
		return nil, err
	}

	passphrase, err := s.Client.GetCalendarPassphrase(ctx, calID)
	if err != nil {
		return nil, fmt.Errorf("get calendar passphrase: %w", err)
	}
	passBytes, err := passphrase.Decrypt(memberID, addrKR)
	if err != nil {
		return nil, fmt.Errorf("decrypt calendar passphrase: %w", err)
	}

	keys, err := s.Client.GetCalendarKeys(ctx, calID)
	if err != nil {
		return nil, fmt.Errorf("get calendar keys: %w", err)
	}
	calKR, err := keys.Unlock(passBytes)
	if err != nil {
		return nil, fmt.Errorf("unlock calendar keys: %w", err)
	}
	if calKR == nil || calKR.CountEntities() == 0 {
		return nil, fmt.Errorf("no calendar keys unlocked for %s", calID)
	}

	if cache != nil {
		cache.rings[calID] = calKR
	}
	return calKR, nil
}

// memberKeyring matches a calendar member to one of the session's
// addresses and returns that member's ID plus the address keyring used
// to decrypt its passphrase.
func (s *Session) memberKeyring(members []gpa.CalendarMember) (string, *crypto.KeyRing, error) {
	for _, m := range members {
		for _, a := range s.Addresses {
			if !strings.EqualFold(a.Email, m.Email) {
				continue
			}
			if kr, ok := s.AddrKRs[a.ID]; ok && kr != nil {
				return m.ID, kr, nil
			}
		}
	}
	return "", nil, errors.New("proton: no calendar member matches an unlocked address keyring — re-login may be required")
}

// DecryptCalendarEvent resolves a single event into structured detail:
// plaintext metadata from ev plus the decrypted SharedEvents iCalendar
// text, parsed into fields. Pass a per-pass cache during sync; pass nil
// (or a fresh cache) for a one-off read.
func (s *Session) DecryptCalendarEvent(ctx context.Context, ev gpa.CalendarEvent, cache *CalendarKeyCache) (*CalendarEventDetail, error) {
	calKR, err := s.calendarKeyRing(ctx, ev.CalendarID, cache)
	if err != nil {
		return nil, err
	}

	raw, err := decryptSharedPart(calKR, ev.SharedKeyPacket, ev.SharedEvents)
	if err != nil {
		return nil, fmt.Errorf("decrypt event %s: %w", ev.ID, err)
	}

	fields, err := parseICalEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("event %s: %w", ev.ID, err)
	}

	detail := &CalendarEventDetail{
		EventID:     ev.ID,
		CalendarID:  ev.CalendarID,
		UID:         firstNonEmpty(ev.UID, fields.UID),
		Summary:     fields.Summary,
		Location:    fields.Location,
		Description: fields.Description,
		Organizer:   fields.Organizer,
		Status:      fields.Status,
		StartUnix:   ev.StartTime,
		StartTZ:     ev.StartTimezone,
		EndUnix:     ev.EndTime,
		EndTZ:       ev.EndTimezone,
		AllDay:      bool(ev.FullDay),
		IsRecurring: fields.IsRecurring,
		RRULE:       fields.RRULE,
		RawICal:     raw,
	}
	for _, a := range fields.Attendees {
		detail.Attendees = append(detail.Attendees, CalendarAttendeeDetail(a))
	}
	return detail, nil
}

// decryptSharedPart decrypts the SharedEvents iCalendar payload using the
// calendar keyring and the event's SharedKeyPacket. This replicates
// CalendarEventPart.Decode's working logic (see the note at the top of
// the file). Signature verification is intentionally not performed: for
// shared/invited events the author is a third party whose public key we
// don't hold, and confidentiality is already guaranteed by decrypting
// with the calendar key.
func decryptSharedPart(calKR *crypto.KeyRing, keyPacketB64 string, parts []gpa.CalendarEventPart) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("event has no shared parts")
	}

	var kp []byte
	if keyPacketB64 != "" {
		var err error
		kp, err = base64.StdEncoding.DecodeString(keyPacketB64)
		if err != nil {
			return "", fmt.Errorf("decode shared key packet: %w", err)
		}
	}

	for _, part := range parts {
		// Clear (unencrypted) part — the data is already plaintext.
		if part.Type&gpa.CalendarEventTypeEncrypted == 0 {
			if strings.TrimSpace(part.Data) != "" {
				return part.Data, nil
			}
			continue
		}

		var msg *crypto.PGPMessage
		if kp != nil {
			data, err := base64.StdEncoding.DecodeString(part.Data)
			if err != nil {
				return "", fmt.Errorf("decode event data: %w", err)
			}
			msg = crypto.NewPGPSplitMessage(kp, data).GetPGPMessage()
		} else {
			var err error
			if msg, err = crypto.NewPGPMessageFromArmored(part.Data); err != nil {
				return "", fmt.Errorf("parse armored event data: %w", err)
			}
		}

		dec, err := calKR.Decrypt(msg, nil, crypto.GetUnixTime())
		if err != nil {
			return "", fmt.Errorf("decrypt event part: %w", err)
		}
		return dec.GetString(), nil
	}

	return "", errors.New("no decryptable shared event part")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
