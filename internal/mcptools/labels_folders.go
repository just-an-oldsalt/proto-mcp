package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// label is the in-tool result-shape representation. Stored in the
// `labels` table with type column 1 (label) or 3 (folder); we split
// them into two tools at the MCP boundary for clarity.
type label struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

// labelType is the column-value/MCP-tool split: type=1 → labels.list,
// type=3 → folders.list. Defined as constants here so the SQL stays
// in one place.
const (
	labelTypeUserLabel  = 1
	labelTypeUserFolder = 3
)

func labelsList(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "labels.list",
		Description: "List user-defined labels (color-coded tags). Returns id / name / color for each.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(labelListSchema),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			labels, err := queryLabels(ctx.Std, deps, labelTypeUserLabel)
			if err != nil {
				return nil, fmt.Errorf("labels.list: %w", err)
			}
			return mcp.StructuredResult(map[string]any{"labels": labels})
		},
	}
}

func foldersList(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "folders.list",
		Description: "List user-defined folders (mutually-exclusive locations a message can live in). Returns id / name / color for each. System folders (inbox, sent, drafts, archive, trash, spam) are not listed here — those live in messages.folder.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(folderListSchema),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			folders, err := queryLabels(ctx.Std, deps, labelTypeUserFolder)
			if err != nil {
				return nil, fmt.Errorf("folders.list: %w", err)
			}
			return mcp.StructuredResult(map[string]any{"folders": folders})
		},
	}
}

func queryLabels(ctx context.Context, deps Deps, typ int) ([]label, error) {
	rows, err := deps.Store.DB.QueryContext(ctx,
		`SELECT id, name, color FROM labels WHERE type = ? ORDER BY name`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []label
	for rows.Next() {
		var l label
		var color *string
		if err := rows.Scan(&l.ID, &l.Name, &color); err != nil {
			return nil, err
		}
		if color != nil {
			l.Color = *color
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

const labelListSchema = `{
	"type": "object",
	"properties": {
		"labels": {
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"id":    {"type": "string"},
					"name":  {"type": "string"},
					"color": {"type": "string"}
				},
				"required": ["id", "name"]
			}
		}
	},
	"required": ["labels"]
}`

const folderListSchema = `{
	"type": "object",
	"properties": {
		"folders": {
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"id":    {"type": "string"},
					"name":  {"type": "string"},
					"color": {"type": "string"}
				},
				"required": ["id", "name"]
			}
		}
	},
	"required": ["folders"]
}`
