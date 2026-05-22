package mcptools

import (
	"encoding/json"
	"errors"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// mail_sync is the model-driven freshness primitive from Phase-3
// plan Q7. The description is the lever — clear contextual guidance
// is what makes "call sync when recency matters, skip when it
// doesn't" work without us hard-coding heuristics on the server side.

func mailSync(deps Deps) mcp.Tool {
	type result struct {
		StartCursor      string `json:"start_cursor"`
		EndCursor        string `json:"end_cursor"`
		MessagesUpserted int    `json:"messages_upserted"`
		MessagesDeleted  int    `json:"messages_deleted"`
		LabelsUpserted   int    `json:"labels_upserted"`
		LabelsDeleted    int    `json:"labels_deleted"`
		Pages            int    `json:"pages"`
		ElapsedMS        int64  `json:"elapsed_ms"`
	}

	return mcp.Tool{
		Name: "mail_sync",
		Description: "Pull recent changes from Proton into the local mirror. " +
			"Call this BEFORE mail_list or mail_search when the user's question implies " +
			"they're looking for recent activity: \"just got\", \"today\", \"this morning\", " +
			"\"latest from X\", anything time-anchored to now. " +
			"Skip it for historical or open-ended queries: \"any emails about X\", \"from last year\", " +
			"\"what did Alice say about gear in 2024\". The local mirror has everything ever backfilled " +
			"— only sync when newness matters. " +
			"Typical sync is ≤200ms when nothing has changed.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"start_cursor":      {"type": "string"},
				"end_cursor":        {"type": "string"},
				"messages_upserted": {"type": "integer"},
				"messages_deleted":  {"type": "integer"},
				"labels_upserted":   {"type": "integer"},
				"labels_deleted":    {"type": "integer"},
				"pages":             {"type": "integer"},
				"elapsed_ms":        {"type": "integer"}
			}
		}`),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			if deps.Session == nil {
				return nil, errors.New("session not available")
			}
			res, err := syncpkg.RunOnce(ctx.Std, deps.Session, deps.Store)
			if err != nil {
				if errors.Is(err, syncpkg.ErrRefreshRequested) {
					return mcp.ErrorResult(
						"sync requested a full refresh — the local mirror's event cursor is too old. " +
							"Run `protonmcp backfill` from the command line to re-seed.",
					), nil
				}
				return mcp.ErrorResult("mail_sync failed: %v", err), nil
			}
			return mcp.StructuredResult(result{
				StartCursor:      res.StartCursor,
				EndCursor:        res.EndCursor,
				MessagesUpserted: res.MessagesUpserted,
				MessagesDeleted:  res.MessagesDeleted,
				LabelsUpserted:   res.LabelsUpserted,
				LabelsDeleted:    res.LabelsDeleted,
				Pages:            res.Pages,
				ElapsedMS:        res.Elapsed.Milliseconds(),
			})
		},
	}
}
