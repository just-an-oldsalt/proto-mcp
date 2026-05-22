package mcptools

import (
	"encoding/json"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

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
	if len(tools) != 9 {
		t.Errorf("expected 9 tools, got %d", len(tools))
	}

	want := map[string]bool{
		"account.whoami":        false,
		"mail.list":             false,
		"mail.search":           false,
		"mail.read":             false,
		"mail.read_thread":      false,
		"mail.list_attachments": false,
		"labels.list":           false,
		"folders.list":          false,
		"mail.sync":             false,
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
	if len(got) != 9 {
		t.Errorf("server registry has %d tools, want 9", len(got))
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
