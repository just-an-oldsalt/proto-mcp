package mcptools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeField_CollapsesLineBreaks(t *testing.T) {
	got := sanitizeField("real@y.com\nBCC: evil@x.com\r\tx")
	if strings.ContainsAny(got, "\r\n\t") {
		t.Errorf("sanitizeField left a line break / tab in %q", got)
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
