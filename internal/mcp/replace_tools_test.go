package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// PROTO-132 — ReplaceTools rebinds an already-registered tool's handler
// (matched by name) so the runtime can point session-backed tools at a
// freshly acquired session on unlock.
func TestReplaceTools_RebindsHandler(t *testing.T) {
	s := New(nil)
	mk := func(tag string) Tool {
		return Tool{
			Name:        "probe",
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
				return &ToolResult{Content: []Content{{Type: "text", Text: tag}}}, nil
			},
		}
	}
	s.Register(mk("v1"))

	// Replace with a same-named tool whose handler reports "v2".
	s.ReplaceTools([]Tool{mk("v2")})

	var got Tool
	for _, tl := range s.Tools() {
		if tl.Name == "probe" {
			got = tl
		}
	}
	if got.Handler == nil {
		t.Fatal("probe tool missing after ReplaceTools")
	}
	res, err := got.Handler(Context{Std: context.Background()}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if len(res.Content) == 0 || res.Content[0].Text != "v2" {
		t.Errorf("handler not rebound; got %+v, want text \"v2\"", res.Content)
	}

	// Registry count is unchanged (rebind, not append).
	if n := len(s.Tools()); n != 1 {
		t.Errorf("tool count = %d, want 1 (rebind must not duplicate)", n)
	}
}
