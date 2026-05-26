package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestMailDownloadAttachment_SchemaValid(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tl := mailDownloadAttachment(Deps{Store: st})

	if tl.Name != "mail_download_attachment" {
		t.Errorf("Name = %q, want mail_download_attachment", tl.Name)
	}
	if tl.Description == "" {
		t.Error("Description is empty")
	}
	if !json.Valid(tl.InputSchema) {
		t.Errorf("InputSchema is not valid JSON: %s", tl.InputSchema)
	}
	if !json.Valid(tl.OutputSchema) {
		t.Errorf("OutputSchema is not valid JSON: %s", tl.OutputSchema)
	}
	if tl.Handler == nil {
		t.Error("Handler is nil")
	}
	if tl.PromptBody == nil {
		t.Error("PromptBody is nil — required for prompt+confirm flow")
	}
}

func TestMailDownloadAttachment_MissingArgs(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tl := mailDownloadAttachment(Deps{Store: st})
	ctx := mcp.Context{Std: context.Background()}

	cases := []struct {
		name string
		raw  string
	}{
		{"empty object", `{}`},
		{"only message_id", `{"message_id":"abc"}`},
		{"only attachment_id", `{"attachment_id":"def"}`},
		{"missing both", `{"unrelated":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tl.Handler(ctx, json.RawMessage(tc.raw))
			if err == nil {
				t.Fatalf("expected invalid-params error, got nil")
			}
			var protoErr *mcp.Error
			if !errors.As(err, &protoErr) {
				t.Fatalf("expected *mcp.Error, got %T: %v", err, err)
			}
			if protoErr.Code != mcp.CodeInvalidParams {
				t.Errorf("Code = %d, want CodeInvalidParams (%d)", protoErr.Code, mcp.CodeInvalidParams)
			}
		})
	}
}

// PromptBody must produce a stable + sanitized prompt regardless
// of input shape. We don't have a real session to look up the
// subject, so the closure falls back to shortID — the assertion is
// that it doesn't panic and emits a non-empty title + body.
func TestMailDownloadAttachment_PromptBodyFallback(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tl := mailDownloadAttachment(Deps{Store: st})

	title, body := tl.PromptBody(json.RawMessage(`{"message_id":"msg-abcdefghijkl","attachment_id":"att-xyz12345"}`))
	if title == "" {
		t.Error("PromptBody returned empty title")
	}
	if body == "" {
		t.Error("PromptBody returned empty body")
	}
}

// Cache hit short-circuit: a pre-populated cache row should be
// returned without touching the (nil) session. Locks in the
// no-network-on-cache-hit contract.
func TestMailDownloadAttachment_CacheHit(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Seed a parent message so the FK on attachment_cache is satisfied.
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

	// Session is nil deliberately — cache hit must not touch it.
	tl := mailDownloadAttachment(Deps{Store: st})
	res, err := tl.Handler(
		mcp.Context{Std: ctx},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`),
	)
	if err != nil {
		t.Fatalf("Handler returned err: %v", err)
	}
	if res == nil {
		t.Fatal("Handler returned nil result")
	}
	if res.IsError {
		t.Errorf("Handler returned ErrorResult on cache hit: %+v", res)
	}
}
