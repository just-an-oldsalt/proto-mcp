package mcptools

import (
	"encoding/json"
	"errors"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

func accountWhoami(deps Deps) mcp.Tool {
	type result struct {
		Email       string   `json:"email"`
		DisplayName string   `json:"display_name,omitempty"`
		UserID      string   `json:"user_id"`
		Addresses   []string `json:"addresses"`
		Plan        string   `json:"plan,omitempty"`
	}

	return mcp.Tool{
		Name:        "account.whoami",
		Description: "Identify the Proton account this MCP server is signed into. Returns email, display name, user ID, list of address aliases, and (when available) plan info. Read-only, no network call — the data is the session that was established at server initialize time.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"email":        {"type": "string"},
				"display_name": {"type": "string"},
				"user_id":      {"type": "string"},
				"addresses":    {"type": "array", "items": {"type": "string"}},
				"plan":         {"type": "string"}
			},
			"required": ["email", "user_id", "addresses"]
		}`),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			if deps.Session == nil {
				return nil, errors.New("session not available — server was not properly initialized")
			}
			primary, _ := deps.Session.PrimaryAddress()
			addrs := make([]string, 0, len(deps.Session.Addresses))
			for _, a := range deps.Session.Addresses {
				addrs = append(addrs, a.Email)
			}
			return mcp.StructuredResult(result{
				Email:       primary.Email,
				DisplayName: deps.Session.User.DisplayName,
				UserID:      deps.Session.User.ID,
				Addresses:   addrs,
			})
		},
	}
}
