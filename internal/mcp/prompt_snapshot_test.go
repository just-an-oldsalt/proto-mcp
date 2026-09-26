package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
)

// Issue #116 — the state a PromptSnapshot rendered the dialog from is
// the state the handler receives; a snapshot that can't be loaded
// denies the call without prompting.

func snapshotServer(t *testing.T, helper string, snap func(context.Context, json.RawMessage) (string, string, any, error), handler Handler) *Server {
	t.Helper()
	w, _ := newTestAudit(t)
	pol := newTestPolicy(t, `
defaults:
  decision: deny
tools:
  echo: { decision: prompt, ttl: "0" }
`)
	b, err := approval.New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(nil, WithPolicy(pol), WithAudit(w), WithApproval(b))
	srv.Register(Tool{
		Name:           "echo",
		Description:    "echo",
		InputSchema:    json.RawMessage(`{"type":"object"}`),
		PromptSnapshot: snap,
		Handler:        handler,
	})
	return srv
}

func callEcho(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	return resps[1]["result"].(map[string]any)
}

func TestPromptSnapshotReachesHandler(t *testing.T) {
	var got any
	srv := snapshotServer(t, "/usr/bin/true",
		func(context.Context, json.RawMessage) (string, string, any, error) {
			return "t", "b", "draft-v1", nil
		},
		func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			got = ctx.Snapshot
			return &ToolResult{}, nil
		})
	if r := callEcho(t, srv); r["isError"] == true {
		t.Fatalf("unexpected error: %+v", r)
	}
	if got != "draft-v1" {
		t.Errorf("handler Snapshot = %v, want draft-v1", got)
	}
}

func TestPromptSnapshotErrorDenies(t *testing.T) {
	called := false
	srv := snapshotServer(t, "/usr/bin/true",
		func(context.Context, json.RawMessage) (string, string, any, error) {
			return "", "", nil, errors.New("fetch draft: timeout")
		},
		func(Context, json.RawMessage) (*ToolResult, error) {
			called = true
			return &ToolResult{}, nil
		})
	r := callEcho(t, srv)
	if called {
		t.Error("handler ran although the snapshot failed")
	}
	if r["isError"] != true {
		t.Fatalf("expected isError: %+v", r)
	}
	text := r["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "fetch draft: timeout") {
		t.Errorf("error text doesn't carry the cause: %s", text)
	}
}

func TestPromptSnapshotCanceledSkipsHandler(t *testing.T) {
	called := false
	srv := snapshotServer(t, "/usr/bin/false",
		func(context.Context, json.RawMessage) (string, string, any, error) {
			return "t", "b", "draft-v1", nil
		},
		func(Context, json.RawMessage) (*ToolResult, error) {
			called = true
			return &ToolResult{}, nil
		})
	if r := callEcho(t, srv); r["isError"] != true {
		t.Fatalf("expected cancel error: %+v", r)
	}
	if called {
		t.Error("handler ran after the user canceled")
	}
}
