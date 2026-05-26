package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestMailSaveAttachment_SchemaValid(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tl := mailSaveAttachment(Deps{Store: st})
	if tl.Name != "mail_save_attachment" {
		t.Errorf("Name = %q", tl.Name)
	}
	if !json.Valid(tl.InputSchema) {
		t.Errorf("InputSchema not valid JSON")
	}
	if !json.Valid(tl.OutputSchema) {
		t.Errorf("OutputSchema not valid JSON")
	}
	if tl.PromptBody == nil {
		t.Error("PromptBody must be set — policy is confirm:true")
	}
}

func TestMailSaveAttachment_MissingArgs(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := mailSaveAttachment(Deps{Store: st})
	ctx := mcp.Context{Std: context.Background()}

	for _, raw := range []string{`{}`, `{"message_id":"x"}`, `{"attachment_id":"x"}`} {
		_, err := tl.Handler(ctx, json.RawMessage(raw))
		var pe *mcp.Error
		if !errors.As(err, &pe) || pe.Code != mcp.CodeInvalidParams {
			t.Errorf("raw=%s: got err=%v, want CodeInvalidParams", raw, err)
		}
	}
}

// Cache-hit save: pre-populate the cache, point HOME at a temp
// dir, save, verify file written to <tmp>/Downloads.
func TestMailSaveAttachment_CacheHitWritesFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "test", "x@y", "X",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID:    "msg-1",
		AttachmentID: "att-A",
		Filename:     "report.pdf",
		MIMEType:     "application/pdf",
		SizeBytes:    11,
		Content:      []byte("hello world"),
	}); err != nil {
		t.Fatal(err)
	}

	tl := mailSaveAttachment(Deps{Store: st})
	res, err := tl.Handler(
		mcp.Context{Std: ctx},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`),
	)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("handler returned error result: %+v", res)
	}

	wantPath := filepath.Join(tmp, "Downloads", "report.pdf")
	got, readErr := os.ReadFile(wantPath)
	if readErr != nil {
		t.Fatalf("expected file at %s: %v", wantPath, readErr)
	}
	if string(got) != "hello world" {
		t.Errorf("file contents = %q, want %q", got, "hello world")
	}
}

// Collision handling: second save of the same filename writes a
// "report (2).pdf" sibling.
func TestMailSaveAttachment_CollisionAppendsSuffix(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "test", "x@y", "X",
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID: "msg-1", AttachmentID: "att-A",
		Filename: "report.pdf", MIMEType: "application/pdf",
		SizeBytes: 1, Content: []byte("a"),
	})

	tl := mailSaveAttachment(Deps{Store: st})

	res1, err := tl.Handler(mcp.Context{Std: ctx},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`))
	if err != nil || res1.IsError {
		t.Fatalf("first save: %v / %+v", err, res1)
	}
	res2, err := tl.Handler(mcp.Context{Std: ctx},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`))
	if err != nil || res2.IsError {
		t.Fatalf("second save: %v / %+v", err, res2)
	}

	// Both files should now exist; the second should have a "(2)" suffix.
	first := filepath.Join(tmp, "Downloads", "report.pdf")
	second := filepath.Join(tmp, "Downloads", "report (2).pdf")
	if _, err := os.Stat(first); err != nil {
		t.Errorf("missing first file: %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("missing (2) file: %v", err)
	}
}

// Path-traversal defense: filename with / or .. gets neutralized
// by sanitize.Filename + filepath.Base + Clean. The file ends up
// in ~/Downloads with substituted underscores, NOT outside.
func TestMailSaveAttachment_RefusesTraversal(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _ = st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "test", "x@y", "X",
	)
	_ = st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID: "msg-1", AttachmentID: "att-A",
		Filename: "ok.pdf", MIMEType: "x",
		SizeBytes: 1, Content: []byte("x"),
	})

	tl := mailSaveAttachment(Deps{Store: st})
	res, err := tl.Handler(mcp.Context{Std: ctx}, json.RawMessage(
		`{"message_id":"msg-1","attachment_id":"att-A","filename":"../../etc/evil.txt"}`,
	))
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	// The file must NOT exist at /etc or outside tmp.
	if _, err := os.Stat("/etc/evil.txt"); err == nil {
		t.Fatal("traversal succeeded — file at /etc/evil.txt")
	}
	// The saved path must be inside ~/Downloads.
	if res != nil && !res.IsError {
		// Parse the result to confirm saved_path is inside Downloads.
		body := resultText(res)
		if !strings.Contains(body, filepath.Join(tmp, "Downloads")) {
			t.Errorf("saved_path not inside ~/Downloads: %s", body)
		}
		// Sanitized filename retains "etc" as a literal substring
		// (the slashes became underscores). The defense is that
		// nothing was written OUTSIDE ~/Downloads — checked above
		// via /etc/evil.txt stat — and the saved_path string
		// shows the directory is the temp HOME's Downloads dir.
		if strings.Contains(body, "/etc/") {
			t.Errorf("saved_path resolved into /etc/: %s", body)
		}
	}
}

// resultText is a tiny helper to pull the JSON payload of a
// StructuredResult for substring checks.
func resultText(r *mcp.ToolResult) string {
	if r == nil {
		return ""
	}
	for _, c := range r.Content {
		if c.Type == "text" {
			return c.Text
		}
	}
	return ""
}
