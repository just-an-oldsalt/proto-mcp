package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// listInput is the shared input shape for mail_list and (with extra
// fields) mail_search. The cursor field is opaque per Q3 — clients
// pass back the next_cursor value they received from a prior call;
// we encode {offset, query_hash} into it so we can invalidate stale
// cursors when the underlying query changes.
type listInput struct {
	Folder     string `json:"folder,omitempty"`
	LabelID    string `json:"label_id,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Cursor     string `json:"cursor,omitempty"`
	UnreadOnly bool   `json:"unread_only,omitempty"`
	Since      string `json:"since,omitempty"` // RFC 3339 or YYYY-MM-DD
	Until      string `json:"until,omitempty"`
}

type messageSummary struct {
	MessageID      string    `json:"message_id"`
	ThreadID       string    `json:"thread_id,omitempty"`
	Subject        string    `json:"subject,omitempty"`
	FromAddress    string    `json:"from_address,omitempty"`
	FromName       string    `json:"from_name,omitempty"`
	Date           time.Time `json:"date"`
	Folder         string    `json:"folder,omitempty"`
	Unread         bool      `json:"unread,omitempty"`
	HasAttachments bool      `json:"has_attachments,omitempty"`
	Snippet        string    `json:"snippet,omitempty"`
}

type listResult struct {
	Messages   []messageSummary `json:"messages"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func mailList(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_list",
		Description: "List message envelopes from the local mirror, filtered by folder / label / unread / date range. " +
			"Read-only — does NOT pull fresh data from Proton. " +
			"Call mail_sync first if the user implies they're looking for recent activity (\"just got\", \"today\", \"latest\"); " +
			"skip the sync for historical or open-ended queries.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"folder":      {"type": "string", "description": "One of: inbox, sent, drafts, archive, trash, spam, all"},
				"label_id":    {"type": "string"},
				"limit":       {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
				"cursor":      {"type": "string", "description": "Opaque pagination cursor from a previous response"},
				"unread_only": {"type": "boolean"},
				"since":       {"type": "string", "description": "Lower bound on message date. RFC3339 or YYYY-MM-DD."},
				"until":       {"type": "string", "description": "Exclusive upper bound on message date."}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(messageListSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in listInput
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_list: "+err.Error())
				}
			}
			opts := store.SearchOpts{
				Limit: in.Limit,
				Filter: store.ListFilter{
					Folder:     in.Folder,
					LabelID:    in.LabelID,
					UnreadOnly: in.UnreadOnly,
				},
			}
			if in.Since != "" {
				t, err := parseListDate(in.Since)
				if err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						fmt.Sprintf("mail_list since: %v", err))
				}
				opts.Filter.SinceUnix = t.Unix()
			}
			if in.Until != "" {
				t, err := parseListDate(in.Until)
				if err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						fmt.Sprintf("mail_list until: %v", err))
				}
				opts.Filter.UntilUnix = t.Unix()
			}

			// Build the query hash from the filter values so a cursor
			// from one filter set can't be replayed against a
			// different one. The cursor encoder + decoder validate
			// this; mismatch returns a CodeInvalidParams.
			qhash := filterHash(opts.Filter)
			if in.Cursor != "" {
				off, ok := decodeCursor(in.Cursor, qhash)
				if !ok {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						"mail_list: cursor is stale or belongs to a different query")
				}
				opts.Offset = off
			}

			hits, err := deps.Store.Search(ctx.Std, "", opts)
			if err != nil {
				return nil, err
			}

			summaries := make([]messageSummary, 0, len(hits))
			for _, h := range hits {
				summaries = append(summaries, hitToSummary(h))
			}

			res := listResult{Messages: summaries}
			if len(hits) == opts.Limit || (len(hits) > 0 && opts.Limit > 0 && len(hits) >= opts.Limit) {
				res.NextCursor = encodeCursor(opts.Offset+len(hits), qhash)
			}
			return mcp.StructuredResult(res)
		},
	}
}

// parseListDate accepts RFC 3339 timestamps and YYYY-MM-DD dates.
// Returns the parsed time in UTC.
func parseListDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.UTC); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("expected RFC3339 timestamp or YYYY-MM-DD date")
}

func hitToSummary(h store.SearchHit) messageSummary {
	return messageSummary{
		MessageID:   h.MessageID,
		ThreadID:    h.ThreadID,
		Subject:     h.Subject,
		FromAddress: h.FromAddress,
		FromName:    h.FromName,
		Date:        h.Date,
		Folder:      h.Folder,
		Snippet:     h.Snippet,
	}
}

const messageListSchema = `{
	"type": "object",
	"properties": {
		"messages": {
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"message_id":      {"type": "string"},
					"thread_id":       {"type": "string"},
					"subject":         {"type": "string"},
					"from_address":    {"type": "string"},
					"from_name":       {"type": "string"},
					"date":            {"type": "string"},
					"folder":          {"type": "string"},
					"unread":          {"type": "boolean"},
					"has_attachments": {"type": "boolean"},
					"snippet":         {"type": "string"}
				},
				"required": ["message_id", "date"]
			}
		},
		"next_cursor": {"type": "string"}
	},
	"required": ["messages"]
}`
