package mcptools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func mailSearch(deps Deps) mcp.Tool {
	type input struct {
		Query  string `json:"query"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}

	return mcp.Tool{
		Name: "mail_search",
		Description: "Full-text + structured search over the local mirror. Query DSL: " +
			"from:alice  to:bob  subject:\"gear list\"  in:inbox  " +
			"before:2026-01-01  after:2025-12-01  has:attachment  " +
			"plus bare full-text terms (subject + body + sender). " +
			"All criteria are AND-joined. Read-only — does NOT pull fresh data from Proton; " +
			"call mail_sync first if the user implies they want recent activity.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query":  {"type": "string", "description": "Search query in the DSL described in the tool description."},
				"limit":  {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
				"cursor": {"type": "string", "description": "Opaque pagination cursor from a previous response"}
			},
			"required": ["query"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(messageListSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_search: "+err.Error())
			}
			if in.Query == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_search: query is required")
			}

			opts := store.SearchOpts{Limit: in.Limit}
			qhash := queryStringHash(in.Query)
			if in.Cursor != "" {
				off, ok := decodeCursor(in.Cursor, qhash)
				if !ok {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						"mail_search: cursor is stale or belongs to a different query")
				}
				opts.Offset = off
			}

			hits, err := deps.Store.Search(ctx.Std, in.Query, opts)
			if err != nil {
				return nil, err
			}
			summaries := make([]messageSummary, 0, len(hits))
			for _, h := range hits {
				summaries = append(summaries, hitToSummary(h))
			}
			res := listResult{Messages: summaries}
			if opts.Limit > 0 && len(hits) >= opts.Limit {
				res.NextCursor = encodeCursor(opts.Offset+len(hits), qhash)
			}
			return mcp.StructuredResult(res)
		},
	}
}

// queryStringHash is the cursor-binding hash for mail_search. Same
// 8-byte truncated-SHA shape as filterHash; binds the cursor to the
// query string so paging through stale results isn't possible.
func queryStringHash(query string) string {
	sum := sha256.Sum256([]byte("Q=" + query))
	return hex.EncodeToString(sum[:8])
}

// (compile-only guard) — fmt is used elsewhere in the package; if
// this file ends up not needing it directly, the import gets dropped
// by goimports.
var _ = fmt.Sprintf
