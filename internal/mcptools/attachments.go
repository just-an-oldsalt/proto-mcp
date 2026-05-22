package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// headerFirst returns the first value for the given header (case-
// insensitive lookup over Headers.Values). RFC 2822 header names
// are case-insensitive; the SDK preserves whatever casing the server
// sent.
func headerFirst(h gpa.Headers, name string) string {
	if v, ok := h.Values[name]; ok && len(v) > 0 {
		return v[0]
	}
	lower := strings.ToLower(name)
	for k, v := range h.Values {
		if strings.ToLower(k) == lower && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// attachmentMeta is what we report per attachment. Fields chosen to
// match the design-spec AttachmentMeta type. inline / content_id are
// the bits you'd need to render inline images later; size_bytes lets
// the caller decide whether downloading is worth the bandwidth.
type attachmentMeta struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	MIMEType  string `json:"mime_type,omitempty"`
	SizeBytes int    `json:"size_bytes"`
	Inline    bool   `json:"inline,omitempty"`
	ContentID string `json:"content_id,omitempty"`
}

// rawJSONShape is the subset of MessageMetadata's raw_json we
// actually need to extract. Mirrors the proton.Attachment shape but
// avoids importing the SDK here.
type rawJSONShape struct {
	NumAttachments int `json:"NumAttachments"`
	// The metadata response doesn't actually include the Attachments
	// array — it's only on the full message. So if the row was
	// populated from a backfill, NumAttachments is what we have. We
	// fall back to fetching the full message when the caller wants
	// real attachment metadata.
}

func mailListAttachments(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
	}
	type result struct {
		MessageID   string           `json:"message_id"`
		Attachments []attachmentMeta `json:"attachments"`
	}

	return mcp.Tool{
		Name: "mail.list_attachments",
		Description: "List attachment metadata for a message (id / filename / mime_type / size / inline). " +
			"Does NOT download attachment bytes — that's a separate tool. " +
			"Triggers a single API call to fetch the full message if it's not already cached locally.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id": {"type": "string"}
			},
			"required": ["message_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id": {"type": "string"},
				"attachments": {
					"type": "array",
					"items": {
						"type": "object",
						"properties": {
							"id":         {"type": "string"},
							"filename":   {"type": "string"},
							"mime_type":  {"type": "string"},
							"size_bytes": {"type": "integer"},
							"inline":     {"type": "boolean"},
							"content_id": {"type": "string"}
						},
						"required": ["id", "filename", "size_bytes"]
					}
				}
			},
			"required": ["message_id", "attachments"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail.list_attachments: "+err.Error())
			}
			if in.MessageID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail.list_attachments: message_id is required")
			}

			// The backfilled raw_json (B-9 truncated to 1 MiB) only
			// carries NumAttachments, not the attachment array — the
			// MessageMetadata API response doesn't include it. To get
			// real attachment metadata we need the full message,
			// which we cache anyway via mail.read. So: hit the
			// local body cache first (FetchAndDecryptMessage
			// populates attachments on the proton-side struct, but
			// we don't currently persist the attachment list — Phase
			// 2 only kept text + html). For v1 we always fetch.
			if deps.Session == nil {
				return nil, errors.New("session not available")
			}

			// Use the SDK's GetMessage directly — it returns the
			// full Message with .Attachments populated. We don't
			// need decrypt for attachment metadata.
			m, err := deps.Session.Client.GetMessage(ctx.Std, in.MessageID)
			if err != nil {
				return mcp.ErrorResult("mail.list_attachments: fetch failed: %v", err), nil
			}

			out := result{MessageID: in.MessageID}
			for _, a := range m.Attachments {
				meta := attachmentMeta{
					ID:        a.ID,
					Filename:  a.Name,
					MIMEType:  string(a.MIMEType),
					SizeBytes: int(a.Size),
					Inline:    a.Disposition == "inline",
				}
				// ContentID isn't a top-level field on Attachment;
				// it lives in the RFC 822 headers when present.
				if cid := headerFirst(a.Headers, "Content-Id"); cid != "" {
					meta.ContentID = cid
				}
				out.Attachments = append(out.Attachments, meta)
			}
			return mcp.StructuredResult(out)
		},
	}
}

// _ unused-but-kept references so a Go vet / unused-import sweep
// doesn't trip on transitive helpers as we keep iterating.
var (
	_ = store.SearchOpts{}
	_ = fmt.Sprintf
)
