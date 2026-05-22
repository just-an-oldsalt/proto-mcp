// Package mcp is the hand-rolled Model Context Protocol server.
//
// Wire format is JSON-RPC 2.0 with newline-delimited messages per the
// MCP 2025-06-18 stdio transport spec. Each request, notification, or
// response is exactly one line; no embedded newlines inside messages.
// stdout is reserved for protocol traffic — anything else (debug
// prints, library chatter) corrupts the stream. Logging goes to
// stderr via slog (configured in internal/logging).
//
// Server is a small registry that maps tool names → handlers, with
// initialize / tools/list / tools/call as the only built-in methods.
// Tools register themselves with a JSON-Schema input + output and a
// handler that takes parsed arguments and returns either a result or
// an error.
//
// Error mapping per spec (Tools section):
//
//   - Protocol-level failures (unknown tool, malformed args,
//     server-internal) → JSON-RPC error field with a numeric code.
//   - Tool-execution failures (decrypt fail, message not found,
//     business-logic problems) → tool result with isError: true plus
//     a text content describing the problem. The LLM sees the error
//     message inside the tool result instead of an opaque protocol
//     failure.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the MCP spec version this server speaks. The
// initialize handshake echoes this back so the client can decide
// whether to fall through to a compatibility shim.
const ProtocolVersion = "2025-06-18"

// Request is a JSON-RPC 2.0 request OR notification. Notifications
// have no ID (the JSON field is absent), requests have a non-nil ID.
// Per spec, the ID may be a string, number, or null; we keep it as
// json.RawMessage to round-trip exactly what the client sent.
type Request struct {
	JSONRPC string          `json:"jsonrpc"` // always "2.0"
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request lacks an ID (per JSON-RPC
// 2.0, notifications are fire-and-forget — no response is sent).
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// Response is a JSON-RPC 2.0 response. Exactly one of Result or Error
// is populated. ID echoes the request's ID verbatim (or is null for
// errors on un-parseable requests).
type Response struct {
	JSONRPC string          `json:"jsonrpc"`        // always "2.0"
	ID      json.RawMessage `json:"id"`             // matches Request.ID; "null" for parse errors
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC error object. Codes follow the spec's
// reservation: -32700 parse error, -32600 invalid request, -32601
// method not found, -32602 invalid params, -32603 internal error.
// MCP defines no additional codes — implementations are free to use
// the -32000..-32099 server-error range for transport-specific
// failures, which we currently don't need.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// NewError returns an *Error with the given code + message.
func NewError(code int, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// Tool is one entry in the server's registry. Name is what the client
// passes to tools/call; Description + InputSchema + OutputSchema are
// what the client sees from tools/list. Handler is the function the
// server invokes when the tool is called.
//
// Schemas are raw JSON to avoid the boilerplate of generating them
// from Go types. Each tool author hand-writes its schema as a
// json.RawMessage literal next to the handler. The cost is duplication
// vs. reflection; the win is clarity (no struct-tag magic, no
// surprises about what gets emitted).
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Handler      Handler         `json:"-"`
}

// Handler is the tool's actual implementation. params is the raw
// JSON of the tool-call arguments; the handler is responsible for
// unmarshaling into its own typed struct.
//
// Return shape:
//
//   - (result, nil)   → tool succeeded. result becomes the "result"
//                       field of the JSON-RPC response.
//   - (nil, *Error)   → protocol-level failure (typically invalid
//                       params). Caller emits a JSON-RPC error.
//   - (nil, error)    → tool-execution failure. Caller wraps it as
//                       a tool result with isError: true so the LLM
//                       sees the message.
type Handler func(ctx Context, params json.RawMessage) (*ToolResult, error)

// Context is a small bag of per-call state. Kept as a struct rather
// than passing context.Context directly so future additions (request
// ID for tracing, caller identity in Phase 4 policy decisions) don't
// break the Handler signature.
type Context struct {
	// Std is the standard context for cancellation / deadlines.
	// Handlers that make HTTP calls should pass it through.
	Std context.Context
}

// Initialize / InitializeResult are the handshake message shapes per
// the lifecycle section of the spec. We respond with a static
// capabilities block (tools-only for v1) and the server's name + version.

type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
}

type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientCapabilities mirrors the spec but we don't act on any of
// these yet — kept as RawMessage so we don't break on unfamiliar
// fields a future client sends.
type ClientCapabilities struct {
	Experimental json.RawMessage `json:"experimental,omitempty"`
	Roots        json.RawMessage `json:"roots,omitempty"`
	Sampling     json.RawMessage `json:"sampling,omitempty"`
}

// ServerCapabilities. v1 advertises tools only; no resources,
// prompts, or logging endpoints. listChanged is false — we don't
// emit tools/list_changed notifications today.
type ServerCapabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

// ListToolsResult is the tools/list response. nextCursor is reserved
// for pagination; v1 returns everything in one shot.
type ListToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// CallToolParams is the tools/call request shape.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolResult is the tools/call response shape. content is required
// (even if empty), structuredContent is optional. isError signals
// tool-execution failure (vs JSON-RPC error).
//
// Per spec: a tool that emits structured output SHOULD also include
// the serialized JSON as a text content for backwards compatibility
// with clients that don't validate against outputSchema. Our helpers
// (StructuredResult, ErrorResult) do this for callers.
type ToolResult struct {
	Content           []Content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

// Content is one entry in a ToolResult.Content array. We currently
// only emit text content; image / audio / resource_link / embedded
// resource are part of the spec but not used by our read tools.
type Content struct {
	Type string `json:"type"`           // always "text" for now
	Text string `json:"text,omitempty"` // populated when Type == "text"
}

// StructuredResult builds a ToolResult with both text + structured
// content. JSON-encodes structured into the text body so clients that
// don't validate against outputSchema still see the same payload.
func StructuredResult(structured any) (*ToolResult, error) {
	js, err := json.Marshal(structured)
	if err != nil {
		return nil, fmt.Errorf("marshal structured result: %w", err)
	}
	return &ToolResult{
		Content:           []Content{{Type: "text", Text: string(js)}},
		StructuredContent: structured,
	}, nil
}

// ErrorResult builds a ToolResult with isError:true and a single
// text-content explaining the failure. Use for tool-execution errors
// the LLM should see and reason about, NOT protocol-level failures
// (those return *Error from the handler).
func ErrorResult(format string, args ...any) *ToolResult {
	return &ToolResult{
		Content: []Content{{Type: "text", Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}
