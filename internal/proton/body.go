package proton

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// MessageBody is the post-decryption + post-sanitization payload of a
// single message. HTML is bluemonday-cleaned; Text is the LLM-snippet-
// ready plaintext extraction. References + InReplyTo are the threading
// headers needed for thread_id reconstruction.
type MessageBody struct {
	MessageID  string
	ThreadHint string   // In-Reply-To (or References tail) — root of the thread
	References []string // Full References chain, oldest → newest
	Subject    string
	From       string
	Text       string // plaintext (snippet-ready, no HTML)
	HTML       string // sanitized HTML (no scripts/iframes/anchors)
	MIMEType   string // "text/html", "text/plain", "multipart/*"
}

// FetchAndDecryptMessage pulls a single full message from the API,
// decrypts the body using the correct address keyring, sanitizes the
// HTML, and returns a MessageBody ready to be cached + returned to
// MCP clients.
//
// The keyring choice depends on the message's AddressID — Proton
// keys are per-address, and a session may have multiple. Resume /
// Login already populated Session.AddrKRs[addressID] for every
// enabled address.
func (s *Session) FetchAndDecryptMessage(ctx context.Context, msgID string) (*MessageBody, error) {
	if s == nil || s.Client == nil {
		return nil, errors.New("proton: session is closed")
	}

	m, err := s.Client.GetMessage(ctx, msgID)
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}

	kr, ok := s.AddrKRs[m.AddressID]
	if !ok {
		return nil, fmt.Errorf("proton: no unlocked keyring for address %s — re-login may be required", m.AddressID)
	}

	plaintext, err := m.Decrypt(kr)
	if err != nil {
		return nil, fmt.Errorf("decrypt body: %w", err)
	}

	mimeType := string(m.MIMEType)
	body := string(plaintext)
	out := &MessageBody{
		MessageID:  m.ID,
		Subject:    m.Subject,
		MIMEType:   mimeType,
		References: parseReferences(m.ParsedHeaders),
		ThreadHint: parseInReplyTo(m.ParsedHeaders),
	}
	if m.Sender != nil {
		out.From = m.Sender.Address
	}

	switch {
	case strings.HasPrefix(mimeType, "text/html"):
		out.HTML = sanitize.HTML(body)
		out.Text = sanitize.Text(body)
	case strings.HasPrefix(mimeType, "text/plain"):
		out.Text = sanitize.Text(body)
		// Leave HTML empty for plaintext-only messages.
	default:
		// multipart/* or unknown — for v1 just treat the whole body
		// as a HTML-ish blob; sanitize.Text strips tags either way.
		// Phase 2-followup: real MIME parsing for multipart/alternative
		// so we can pick the text part vs the HTML part explicitly.
		out.HTML = sanitize.HTML(body)
		out.Text = sanitize.Text(body)
	}

	return out, nil
}

// parseInReplyTo returns the In-Reply-To message-id (RFC 2822 angle
// brackets stripped), or "" if absent. The first <id> in the header
// wins if multiple are present.
func parseInReplyTo(h gpa.Headers) string {
	for _, raw := range headerValues(h, "In-Reply-To") {
		if id := firstMessageID(raw); id != "" {
			return id
		}
	}
	return ""
}

// parseReferences returns the References header parsed into individual
// message-id values, oldest → newest.
func parseReferences(h gpa.Headers) []string {
	var out []string
	for _, raw := range headerValues(h, "References") {
		out = append(out, extractMessageIDs(raw)...)
	}
	return out
}

// headerValues is a case-insensitive lookup over the Headers map.
// Email header names are RFC-defined to be case-insensitive, but the
// SDK's map preserves the casing the server sent — usually the
// canonical form, occasionally not.
func headerValues(h gpa.Headers, name string) []string {
	if v, ok := h.Values[name]; ok {
		return v
	}
	lower := strings.ToLower(name)
	for k, v := range h.Values {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return nil
}

// firstMessageID extracts the first <message-id> from a header value.
// Returns "" if no angle-bracket-delimited id is found.
func firstMessageID(s string) string {
	start := strings.IndexByte(s, '<')
	end := strings.IndexByte(s, '>')
	if start < 0 || end < 0 || end <= start+1 {
		return ""
	}
	return strings.TrimSpace(s[start+1 : end])
}

// extractMessageIDs walks a header value and returns every
// <message-id> found. The References header is space-separated angle-
// bracket-delimited ids.
func extractMessageIDs(s string) []string {
	var ids []string
	for {
		start := strings.IndexByte(s, '<')
		if start < 0 {
			break
		}
		end := strings.IndexByte(s[start:], '>')
		if end < 0 {
			break
		}
		id := strings.TrimSpace(s[start+1 : start+end])
		if id != "" {
			ids = append(ids, id)
		}
		s = s[start+end+1:]
	}
	return ids
}
