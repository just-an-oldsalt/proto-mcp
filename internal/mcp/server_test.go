package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// roundtrip drives one request/response cycle against a Server.
// Multiple requests can be packed into reqLines (one per element);
// the function returns each response as a parsed map for easy
// assertion. Notifications still consume an input line but produce
// no output, which the caller can verify via len(out).
func roundtrip(t *testing.T, s *Server, reqLines ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(reqLines, "\n") + "\n")
	var out bytes.Buffer
	if err := s.Serve(context.Background(), in, &out); err != nil && err != io.EOF {
		t.Fatalf("Serve: %v", err)
	}
	var responses []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		responses = append(responses, m)
	}
	return responses
}

func TestInitializeHandshake(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	r := resps[0]
	if r["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v", r["jsonrpc"])
	}
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result: %+v", r)
	}
	if res["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v", res["protocolVersion"])
	}
	info, ok := res["serverInfo"].(map[string]any)
	if !ok || info["name"] != ServerName {
		t.Errorf("serverInfo = %v", res["serverInfo"])
	}
}

func TestToolsListRequiresInitialized(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error, got %+v", resps[0])
	}
	if int(errObj["code"].(float64)) != CodeInvalidRequest {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeInvalidRequest)
	}
}

func TestToolsListAndCall(t *testing.T) {
	s := New(nil)
	called := false
	s.Register(Tool{
		Name:        "echo",
		Description: "Echoes its input back.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}`),
		Handler: func(ctx Context, params json.RawMessage) (*ToolResult, error) {
			called = true
			var in struct {
				Msg string `json:"msg"`
			}
			if err := json.Unmarshal(params, &in); err != nil {
				return nil, NewError(CodeInvalidParams, err.Error())
			}
			return StructuredResult(map[string]string{"echoed": in.Msg})
		},
	})

	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`,
	)
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3 (init + tools/list + tools/call; notification has no response)", len(resps))
	}

	// tools/list response
	list := resps[1]["result"].(map[string]any)
	tools := list["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Errorf("tools/list result = %+v", list)
	}

	// tools/call response
	call := resps[2]["result"].(map[string]any)
	if call["isError"] == true {
		t.Errorf("isError unexpectedly true: %+v", call)
	}
	structured := call["structuredContent"].(map[string]any)
	if structured["echoed"] != "hi" {
		t.Errorf("echo result = %+v", structured)
	}
	content := call["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["type"] != "text" {
		t.Errorf("content shape = %+v", content)
	}
	if !called {
		t.Error("handler not called")
	}
}

func TestToolExecutionErrorBecomesIsError(t *testing.T) {
	// A handler returning a plain error gets mapped to a tool result
	// with isError: true (the LLM sees the message), NOT a JSON-RPC
	// error response.
	s := New(nil)
	s.Register(Tool{
		Name:        "boom",
		Description: "Always fails.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, params json.RawMessage) (*ToolResult, error) {
			return nil, errors.New("expected explosion")
		},
	})
	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom","arguments":{}}}`,
	)
	call := resps[1]["result"].(map[string]any)
	if call["isError"] != true {
		t.Fatalf("expected isError:true, got %+v", call)
	}
	content := call["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "expected explosion") {
		t.Errorf("error text didn't include cause: %q", text)
	}
}

func TestProtocolErrorMapping(t *testing.T) {
	// Returning a *Error from the handler should produce a JSON-RPC
	// error response (not a tool result).
	s := New(nil)
	s.Register(Tool{
		Name:        "bad_params",
		Description: "Rejects everything as invalid.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, params json.RawMessage) (*ToolResult, error) {
			return nil, NewError(CodeInvalidParams, "no thanks")
		},
	})
	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bad_params","arguments":{}}}`,
	)
	if _, hasResult := resps[1]["result"]; hasResult {
		t.Errorf("expected no result; got %+v", resps[1])
	}
	errObj := resps[1]["error"].(map[string]any)
	if int(errObj["code"].(float64)) != CodeInvalidParams {
		t.Errorf("error code = %v", errObj["code"])
	}
}

func TestUnknownTool(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
	)
	errObj := resps[1]["error"].(map[string]any)
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("unknown tool error code = %v, want %d", errObj["code"], CodeMethodNotFound)
	}
}

func TestParseErrorBecomesJSONRPCError(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s, `{this is not json`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj := resps[0]["error"].(map[string]any)
	if int(errObj["code"].(float64)) != CodeParseError {
		t.Errorf("parse error code = %v", errObj["code"])
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	)
	if len(resps) != 1 {
		t.Errorf("notification should produce no response; got %d responses total", len(resps))
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	s := New(nil)
	tool := Tool{
		Name:        "x",
		Description: "x",
		InputSchema: json.RawMessage(`{}`),
		Handler:     func(Context, json.RawMessage) (*ToolResult, error) { return &ToolResult{}, nil },
	}
	s.Register(tool)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	s.Register(tool)
}

func TestPing(t *testing.T) {
	s := New(nil)
	resps := roundtrip(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	)
	if _, ok := resps[1]["result"]; !ok {
		t.Errorf("ping response missing result: %+v", resps[1])
	}
}
