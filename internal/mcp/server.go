package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// ServerName is what we report in the initialize handshake's
// serverInfo. Distinct from internal/proton.AppVersion (which goes
// out as the x-pm-appversion header to Proton); this string only
// the MCP client sees.
const ServerName = "protonmcp"

// ServerVersion is bumped manually. The MCP spec doesn't require any
// particular versioning scheme; clients use it only for diagnostics.
const ServerVersion = "0.0.1"

// Server is the registry-plus-loop for the JSON-RPC NDJSON
// conversation. Build with New(), register tools with Register(),
// then call Serve(ctx, in, out) — typically with stdin/stdout when
// running under Claude Desktop's stdio transport.
//
// Server is safe to use concurrently from a single Serve loop. Don't
// call Serve more than once on the same Server — there's no
// re-initialize support and the handshake state would be stale.
type Server struct {
	tools  map[string]Tool
	mu     sync.RWMutex
	logger *slog.Logger

	// initialized flips to true after the client sends the
	// initialized notification. tools/list and tools/call before
	// that point are rejected per spec.
	initialized bool
	initMu      sync.Mutex

	// Phase 4 middleware. Each is optional; nil → that pipeline
	// stage is a no-op (preserves Phase-3 behavior for tests that
	// construct mcp.New without options).
	middleware *Middleware
}

// Option configures the Server during construction. Use the
// With{Policy,Audit,Approval} constructors.
type Option func(*Server)

// WithPolicy installs a policy engine. nil engine → every tool
// implicitly DecisionAllow.
func WithPolicy(e *policy.Engine) Option {
	return func(s *Server) {
		if s.middleware == nil {
			s.middleware = &Middleware{}
		}
		s.middleware.policy = e
	}
}

// WithAudit installs an audit writer.
func WithAudit(w *audit.Writer) Option {
	return func(s *Server) {
		if s.middleware == nil {
			s.middleware = &Middleware{}
		}
		s.middleware.audit = w
	}
}

// WithApproval installs an approval broker. If policy returns
// DecisionPrompt and no broker is installed, the middleware safely
// falls through to deny — we never silently allow a prompted call.
func WithApproval(b *approval.Broker) Option {
	return func(s *Server) {
		if s.middleware == nil {
			s.middleware = &Middleware{}
		}
		s.middleware.broker = b
	}
}

// WithCallerResolver installs the caller identity resolver. nil
// resolver → handlers see a zero-valued Caller.
func WithCallerResolver(r *caller.Resolver) Option {
	return func(s *Server) {
		if s.middleware == nil {
			s.middleware = &Middleware{}
		}
		s.middleware.resolver = r
	}
}

// New returns a Server with the given logger and any number of
// functional options. nil logger uses slog.Default(); no options →
// the Phase-3 baseline (no audit, no policy, no approval — every
// tool runs unconditionally).
func New(logger *slog.Logger, opts ...Option) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		tools:  map[string]Tool{},
		logger: logger,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Register adds a tool to the server. Re-registering the same name
// is treated as a programmer error and panics — tool tables should
// be static at server-construction time.
func (s *Server) Register(t Tool) {
	if t.Name == "" {
		panic("mcp: tool name is required")
	}
	if t.Handler == nil {
		panic("mcp: tool " + t.Name + " has nil handler")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.tools[t.Name]; dup {
		panic("mcp: duplicate tool registration: " + t.Name)
	}
	s.tools[t.Name] = t
}

// Tools returns a snapshot of the registry. Used by tools/list and
// by tests; the returned slice is owned by the caller.
func (s *Server) Tools() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, t)
	}
	return out
}

// Serve runs the NDJSON read loop against the given reader / writer.
// Returns nil on clean EOF (client closed our stdin — normal
// shutdown), or any non-EOF error from read/write that prevents
// further progress.
//
// One Serve call handles one entire conversation, including the
// initialize handshake. Cancelling ctx interrupts the loop on the
// next message boundary.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Default Scanner buffer is 64 KiB; allow up to 8 MiB per message
	// to fit large attachment-metadata responses and similar.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	enc := json.NewEncoder(out)
	// MCP requires no embedded newlines inside a message; Encoder
	// emits one newline after each object which is exactly the
	// frame delimiter we need.
	enc.SetEscapeHTML(false)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue // tolerate blank lines defensively
		}
		s.handleLine(ctx, line, enc)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("mcp: read input: %w", err)
	}
	return nil
}

// handleLine parses one NDJSON line and dispatches. Errors are
// written back as JSON-RPC error responses; nothing here returns to
// the caller — Serve only stops on transport failure.
func (s *Server) handleLine(ctx context.Context, line []byte, enc *json.Encoder) {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		// Parse error → JSON-RPC -32700 with null id per spec.
		s.write(enc, &Response{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   NewError(CodeParseError, "parse error: "+err.Error()),
		})
		return
	}
	if req.JSONRPC != "2.0" {
		s.write(enc, &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   NewError(CodeInvalidRequest, "jsonrpc must be \"2.0\""),
		})
		return
	}

	resp := s.dispatch(ctx, &req)
	if req.IsNotification() {
		// Per spec: notifications get no response. dispatch returns a
		// Response for symmetry but we drop it.
		return
	}
	s.write(enc, resp)
}

// dispatch routes one request to the right method handler and
// returns the response. Always returns non-nil for non-notification
// requests; notifications return a sentinel that the caller
// discards.
func (s *Server) dispatch(ctx context.Context, req *Request) *Response {
	resp := &Response{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		result, jrErr := s.handleInitialize(req.Params)
		if jrErr != nil {
			resp.Error = jrErr
			return resp
		}
		resp.Result = result
		return resp

	case "notifications/initialized":
		s.initMu.Lock()
		s.initialized = true
		s.initMu.Unlock()
		// Notification — caller discards.
		return resp

	case "tools/list":
		if !s.isInitialized() {
			resp.Error = NewError(CodeInvalidRequest, "server not initialized")
			return resp
		}
		result, jrErr := s.handleToolsList(req.Params)
		if jrErr != nil {
			resp.Error = jrErr
			return resp
		}
		resp.Result = result
		return resp

	case "tools/call":
		if !s.isInitialized() {
			resp.Error = NewError(CodeInvalidRequest, "server not initialized")
			return resp
		}
		result, jrErr := s.handleToolsCall(ctx, req.Params)
		if jrErr != nil {
			resp.Error = jrErr
			return resp
		}
		resp.Result = result
		return resp

	case "ping":
		// MCP defines ping as a heartbeat returning an empty result.
		resp.Result = struct{}{}
		return resp

	default:
		resp.Error = NewError(CodeMethodNotFound, "unknown method: "+req.Method)
		return resp
	}
}

func (s *Server) isInitialized() bool {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	return s.initialized
}

func (s *Server) handleInitialize(raw json.RawMessage) (*InitializeResult, *Error) {
	var p InitializeParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, NewError(CodeInvalidParams, "initialize: "+err.Error())
		}
	}
	// We accept any client protocol version and echo our own back —
	// per spec, the client decides whether the negotiated version is
	// acceptable. Future tightening: refuse versions below 2025-06-18.
	return &InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: ServerCapabilities{
			Tools: &ToolsCapability{ListChanged: false},
		},
		ServerInfo: Implementation{Name: ServerName, Version: ServerVersion},
	}, nil
}

func (s *Server) handleToolsList(_ json.RawMessage) (*ListToolsResult, *Error) {
	// We ignore the cursor param for v1 — every registered tool fits
	// in one response. If the registry ever gets huge (50+ tools)
	// we'll add real pagination here.
	return &ListToolsResult{Tools: s.Tools()}, nil
}

func (s *Server) handleToolsCall(ctx context.Context, raw json.RawMessage) (*ToolResult, *Error) {
	var p CallToolParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, NewError(CodeInvalidParams, "tools/call: "+err.Error())
	}
	s.mu.RLock()
	t, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return nil, NewError(CodeMethodNotFound, "unknown tool: "+p.Name)
	}

	// Phase 4: if middleware is configured, route through the
	// wrapped pipeline (audit → policy → broker → handler →
	// audit complete). Otherwise fall back to the Phase-3
	// direct-call behavior so existing tests still pass.
	if s.middleware != nil {
		return s.middleware.runTool(ctx, t, p.Arguments, s.logger)
	}

	result, err := t.Handler(Context{Std: ctx}, p.Arguments)
	if err != nil {
		// Distinguish protocol-level (already-typed *Error) from
		// tool-execution failures (any other error). Per spec, the
		// latter should land in result.isError so the LLM sees the
		// message, not bubble up as a JSON-RPC error.
		var jrErr *Error
		if errors.As(err, &jrErr) {
			return nil, jrErr
		}
		s.logger.Warn("tool execution failed",
			"tool", p.Name, "err", err.Error())
		return ErrorResult("%s failed: %v", p.Name, err), nil
	}
	if result == nil {
		// Defensive: a handler that returns (nil, nil) is a bug. We
		// surface it rather than crash the loop on a nil deref later.
		return nil, NewError(CodeInternalError,
			fmt.Sprintf("tool %s returned nil result with no error", p.Name))
	}
	return result, nil
}

// write encodes one response to out, swallowing the error (if the
// pipe is broken there's nothing we can do — the next read will
// EOF and Serve returns). Logged at Warn for diagnostics.
func (s *Server) write(enc *json.Encoder, resp *Response) {
	if err := enc.Encode(resp); err != nil {
		s.logger.Warn("write response", "err", err.Error())
	}
}
