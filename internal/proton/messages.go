package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// MessagePageSize is the max page size the Proton API accepts for
// /mail/v4/messages. Larger requests are silently clamped.
const MessagePageSize = 150

// ForEachMessageMetadataPage walks every page of message metadata for
// the authenticated account, calling fn for each batch in API order.
// Pagination is API-side; the helper just drives it until a short page.
//
// fn returning an error aborts the walk and returns that error.
func (s *Session) ForEachMessageMetadataPage(
	ctx context.Context,
	filter gpa.MessageFilter,
	fn func(batch []gpa.MessageMetadata) error,
) error {
	if s == nil || s.Client == nil {
		return fmt.Errorf("proton: session is closed")
	}

	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, err := s.Client.GetMessageMetadataPage(ctx, page, MessagePageSize, filter)
		if err != nil {
			return fmt.Errorf("page %d: %w", page, err)
		}
		if len(batch) == 0 {
			return nil
		}
		if err := fn(batch); err != nil {
			return err
		}
		if len(batch) < MessagePageSize {
			return nil
		}
	}
}

// CountMessages returns the total number of messages in the account,
// across all labels. Used by the backfill command to size progress
// reporting.
func (s *Session) CountMessages(ctx context.Context) (int, error) {
	if s == nil || s.Client == nil {
		return 0, fmt.Errorf("proton: session is closed")
	}
	return s.Client.CountMessages(ctx)
}

// LatestEventID returns the current head of the event log, used as the
// resumption cursor for the future sync loop.
func (s *Session) LatestEventID(ctx context.Context) (string, error) {
	if s == nil || s.Client == nil {
		return "", fmt.Errorf("proton: session is closed")
	}
	return s.Client.GetLatestEventID(ctx)
}

// ToStoreMessage flattens a go-proton-api MessageMetadata into the row
// shape internal/store wants. ThreadID is set to the message ID for now
// — Bridge's SDK doesn't expose Proton's ConversationID, and Phase 2
// will reconstruct threading from RFC 2822 In-Reply-To / References
// headers once we start decoding full messages.
func ToStoreMessage(m gpa.MessageMetadata) (store.Message, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return store.Message{}, fmt.Errorf("marshal raw metadata: %w", err)
	}

	toJSON, err := marshalAddressList(m.ToList)
	if err != nil {
		return store.Message{}, fmt.Errorf("marshal to list: %w", err)
	}
	ccJSON, err := marshalAddressList(m.CCList)
	if err != nil {
		return store.Message{}, fmt.Errorf("marshal cc list: %w", err)
	}

	var fromName, fromAddress string
	if m.Sender != nil {
		fromName = m.Sender.Name
		fromAddress = m.Sender.Address
	}

	return store.Message{
		ID:             m.ID,
		ThreadID:       m.ID, // see doc comment
		Subject:        m.Subject,
		FromAddress:    fromAddress,
		FromName:       fromName,
		ToJSON:         toJSON,
		CcJSON:         ccJSON,
		Date:           time.Unix(m.Time, 0).UTC(),
		Unread:         bool(m.Unread),
		Starred:        m.Starred(),
		HasAttachments: m.NumAttachments > 0,
		Folder:         primaryFolder(m.LabelIDs),
		SizeBytes:      int64(m.Size),
		RawJSON:        string(raw),
	}, nil
}

// primaryFolder picks the canonical folder location for a message from
// its label IDs. Proton stores virtual folders (AllMail/AllDrafts/AllSent)
// alongside the real one; we prefer the concrete folder. Returns "all"
// when no system folder is present (rare — usually only for custom
// folders, which we'll wire through label.type=3 in a later phase).
func primaryFolder(labelIDs []string) string {
	priority := []struct {
		id, name string
	}{
		{gpa.InboxLabel, "inbox"},
		{gpa.SentLabel, "sent"},
		{gpa.DraftsLabel, "drafts"},
		{gpa.ArchiveLabel, "archive"},
		{gpa.TrashLabel, "trash"},
		{gpa.SpamLabel, "spam"},
	}
	have := make(map[string]struct{}, len(labelIDs))
	for _, id := range labelIDs {
		have[id] = struct{}{}
	}
	for _, p := range priority {
		if _, ok := have[p.id]; ok {
			return p.name
		}
	}
	return "all"
}

// marshalAddressList renders a Proton address list into the
// `[{"name":"...","address":"..."}]` JSON shape stored on the row.
func marshalAddressList(addrs []*mail.Address) (string, error) {
	if len(addrs) == 0 {
		return "[]", nil
	}
	out := make([]map[string]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, map[string]string{
			"name":    a.Name,
			"address": a.Address,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
