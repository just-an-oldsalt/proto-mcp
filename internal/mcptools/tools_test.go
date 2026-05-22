package mcptools

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// claudeDesktopNamePattern is the regex Claude Desktop validates tool
// names against on its end. Keep this guard so a future tool with a
// dot, space, or other reserved char gets caught by `go test` before
// it gets caught by a confused user — which is how we found this in
// the first place. Q1 of the Phase 3 planning leaned underscores;
// I was talked into dots; live test surfaced the validation error
// "FrontendRemoteMcpToolDefinition.name: String should match pattern
// '^[a-zA-Z0-9_-]{1,64}$'".
var claudeDesktopNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// TestToolNamesAreClaudeDesktopCompatible enforces the
// [a-zA-Z0-9_-]{1,64} constraint Claude Desktop's UI applies. The
// MCP spec itself doesn't restrict tool names this tightly, but the
// desktop client does, and failing this check means tools/list
// responses get rejected wholesale.
func TestToolNamesAreClaudeDesktopCompatible(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, tl := range All(Deps{Store: st}) {
		if !claudeDesktopNamePattern.MatchString(tl.Name) {
			t.Errorf("tool name %q does not match Claude Desktop's required pattern %q",
				tl.Name, claudeDesktopNamePattern)
		}
	}
}

// TestAllToolsBuild verifies every tool's Tool literal constructs
// cleanly: non-empty name, description, input schema, valid JSON in
// the schemas, non-nil handler. Doesn't invoke any handler — that
// needs a live Session or a deeper test fixture and lives at the
// integration layer.
func TestAllToolsBuild(t *testing.T) {
	// Minimal Deps — store opens but no session. Tools that need a
	// session will fail at handler-invocation time (covered by the
	// per-tool tests below); this just checks the metadata.
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	tools := All(Deps{Store: st})
	if len(tools) != 14 {
		t.Errorf("expected 14 tools, got %d", len(tools))
	}

	want := map[string]bool{
		"account_whoami":        false,
		"mail_list":             false,
		"mail_search":           false,
		"mail_read":             false,
		"mail_read_thread":      false,
		"mail_list_attachments": false,
		"labels_list":           false,
		"folders_list":          false,
		"mail_sync":             false,
		// Phase 5/A state mutations.
		"mail_mark_read":   false,
		"mail_mark_unread": false,
		"mail_move":        false,
		"mail_label":       false,
		"mail_trash":       false,
	}
	for _, tl := range tools {
		if _, ok := want[tl.Name]; !ok {
			t.Errorf("unexpected tool name: %q", tl.Name)
			continue
		}
		want[tl.Name] = true
		if tl.Description == "" {
			t.Errorf("%s: empty description", tl.Name)
		}
		if len(tl.InputSchema) == 0 {
			t.Errorf("%s: empty input schema", tl.Name)
		}
		if !json.Valid(tl.InputSchema) {
			t.Errorf("%s: input schema is not valid JSON", tl.Name)
		}
		if len(tl.OutputSchema) > 0 && !json.Valid(tl.OutputSchema) {
			t.Errorf("%s: output schema is not valid JSON", tl.Name)
		}
		if tl.Handler == nil {
			t.Errorf("%s: nil handler", tl.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing expected tool: %s", name)
		}
	}
}

// TestAllToolsRegisterIntoServer wires every tool into a real
// mcp.Server and runs initialize + tools/list against it. Catches
// duplicate-name panics and schema-as-RawMessage missteps.
func TestAllToolsRegisterIntoServer(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	srv := mcp.New(nil)
	for _, tl := range All(Deps{Store: st}) {
		srv.Register(tl)
	}
	got := srv.Tools()
	if len(got) != 14 {
		t.Errorf("server registry has %d tools, want 14", len(got))
	}
}

// TestCursorRoundTrip exercises the opaque-cursor encode/decode path
// and the hash-mismatch rejection.
func TestCursorRoundTrip(t *testing.T) {
	const hash = "abcd1234"
	c := encodeCursor(50, hash)

	off, ok := decodeCursor(c, hash)
	if !ok {
		t.Fatal("decode failed")
	}
	if off != 50 {
		t.Errorf("offset = %d, want 50", off)
	}

	// Different hash → reject.
	if _, ok := decodeCursor(c, "deadbeef"); ok {
		t.Error("expected hash-mismatch to reject cursor")
	}

	// Garbage → reject.
	if _, ok := decodeCursor("not-base64!!", hash); ok {
		t.Error("expected garbage cursor to reject")
	}

	// Empty cursor → success, offset 0.
	if off, ok := decodeCursor("", hash); !ok || off != 0 {
		t.Errorf("empty cursor = (%d, %v), want (0, true)", off, ok)
	}
}
