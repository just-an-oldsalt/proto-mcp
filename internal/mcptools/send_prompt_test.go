package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestSanitizeField_CollapsesLineBreaks(t *testing.T) {
	got := sanitizeField("real@y.com\nBCC: evil@x.com\r\tx")
	if strings.ContainsAny(got, "\r\n\t") {
		t.Errorf("sanitizeField left a line break / tab in %q", got)
	}
}

func TestAddressesFromJSON(t *testing.T) {
	got := addressesFromJSON(`[{"name":"A","address":"a@x.com"},{"name":"","address":"b@x.com"}]`)
	if len(got) != 2 || got[0] != "a@x.com" || got[1] != "b@x.com" {
		t.Errorf("addressesFromJSON = %v, want [a@x.com b@x.com]", got)
	}
	if addressesFromJSON("") != nil || addressesFromJSON("not json") != nil {
		t.Errorf("addressesFromJSON should return nil for empty/garbage")
	}
}

// PROTO-126 — a recipient value carrying an embedded newline must NOT be
// able to inject a second framework line (e.g. a fake "BCC:") into the
// approval dialog. SanitizePromptText keeps newlines, so the defense is
// per-field sanitization before assembly.
func TestSendPromptBody_NoNewlineInjection(t *testing.T) {
	pb := sendPromptBodyWithDeps(Deps{}, "mail_send")
	_, body := pb(json.RawMessage(`{"to":["real@y.com\nBCC: evil@x.com"],"subject":"hi"}`))

	// The only BCC framework line is the legitimate (empty) one we add.
	if strings.Contains(body, "\nBCC: evil@x.com") {
		t.Errorf("newline injection produced a fake BCC line:\n%s", body)
	}
	// The evil address still appears — inline on the To line, as data.
	if !strings.Contains(body, "evil@x.com") {
		t.Errorf("expected the smuggled address to show inline as data:\n%s", body)
	}
	// Exactly one BCC *line* (the framework's empty one); the smuggled
	// "BCC:" text is inline on the To line (space-separated), not a line.
	if strings.Count(body, "\nBCC:") != 1 {
		t.Errorf("expected exactly one framework BCC line, body was:\n%s", body)
	}
}

// PROTO-126 — reply / reply-all approval prompts resolve real recipients
// from the local mirror instead of a generic "original sender" line.
func TestLookupReplyRecipients(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "hi", "sender@proton.me", "Sender",
		`[{"name":"Me","address":"me@x.com"},{"name":"","address":"team@x.com"}]`,
		`[{"name":"","address":"cc@x.com"}]`,
	)
	if err != nil {
		t.Fatal(err)
	}

	deps := Deps{Store: st}

	reply := lookupReplyRecipients(deps, "msg-1", false)
	if reply != "To: sender@proton.me" {
		t.Errorf("reply recipients = %q, want \"To: sender@proton.me\"", reply)
	}

	all := lookupReplyRecipients(deps, "msg-1", true)
	for _, want := range []string{"sender@proton.me", "me@x.com", "team@x.com", "cc@x.com"} {
		if !strings.Contains(all, want) {
			t.Errorf("reply-all recipients %q missing %q", all, want)
		}
	}

	// Unknown message → empty, so the caller falls back.
	if lookupReplyRecipients(deps, "nope", false) != "" {
		t.Errorf("expected empty for unknown message")
	}
}
