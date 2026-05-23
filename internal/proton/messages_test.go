package proton

import (
	"encoding/json"
	"net/mail"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

// D11 — oversized raw_json must NOT corrupt JSON. Prior behaviour
// appended `..."[truncated]"` which made the bytes syntactically
// invalid. Now we substitute the whole blob with a structured marker
// that json.Unmarshal can parse.
func TestToStoreMessage_RawJSONTruncationStaysValid(t *testing.T) {
	// Build a metadata struct whose marshaled JSON exceeds the cap.
	// The Subject field is unbounded in the upstream struct so we can
	// pad it deliberately.
	big := strings.Repeat("X", MaxRawJSONBytes+1024)
	meta := gpa.MessageMetadata{
		ID:        "msg-big",
		AddressID: "addr-1",
		Subject:   big,
		Sender:    &mail.Address{Address: "alice@example.com"},
	}
	got, err := ToStoreMessage(meta)
	if err != nil {
		t.Fatalf("ToStoreMessage: %v", err)
	}
	if len(got.RawJSON) == 0 {
		t.Fatal("RawJSON empty after truncation; expected marker")
	}
	// Most important: the bytes must parse as JSON, otherwise any
	// future consumer doing json.Unmarshal(row.RawJSON, ...) errors.
	var probe map[string]any
	if err := json.Unmarshal([]byte(got.RawJSON), &probe); err != nil {
		t.Fatalf("post-truncation RawJSON does not parse: %v\nbytes: %s",
			err, string(got.RawJSON))
	}
	if probe["truncated"] != true {
		t.Errorf("marker missing truncated=true; got %v", probe)
	}
	if probe["id"] != "msg-big" {
		t.Errorf("marker missing original id; got %v", probe["id"])
	}
}

func TestToStoreMessage_BasicFields(t *testing.T) {
	meta := gpa.MessageMetadata{
		ID:        "msg-1",
		AddressID: "addr-1",
		LabelIDs:  []string{gpa.InboxLabel, "user-label-xyz", gpa.StarredLabel},
		Subject:   "Portage gear list",
		Sender:    &mail.Address{Name: "Alice", Address: "alice@example.com"},
		ToList: []*mail.Address{
			{Name: "Richard", Address: "rdort@proton.me"},
		},
		CCList:         nil,
		Time:           1_700_000_000,
		Size:           4096,
		Unread:         true,
		NumAttachments: 2,
	}

	got, err := ToStoreMessage(meta)
	if err != nil {
		t.Fatalf("ToStoreMessage: %v", err)
	}

	if got.ID != "msg-1" || got.ThreadID != "msg-1" {
		t.Errorf("ID/ThreadID = %s/%s, want msg-1/msg-1", got.ID, got.ThreadID)
	}
	if got.Subject != "Portage gear list" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.FromName != "Alice" || got.FromAddress != "alice@example.com" {
		t.Errorf("Sender = %q <%s>", got.FromName, got.FromAddress)
	}
	if !got.Unread {
		t.Error("Unread should be true")
	}
	if !got.Starred {
		t.Error("Starred should be true (StarredLabel in LabelIDs)")
	}
	if !got.HasAttachments {
		t.Error("HasAttachments should be true (NumAttachments > 0)")
	}
	if got.Folder != "inbox" {
		t.Errorf("Folder = %q, want inbox", got.Folder)
	}
	if got.SizeBytes != 4096 {
		t.Errorf("SizeBytes = %d", got.SizeBytes)
	}

	// ToJSON should round-trip into the expected JSON shape.
	var to []map[string]string
	if err := json.Unmarshal([]byte(got.ToJSON), &to); err != nil {
		t.Fatalf("unmarshal ToJSON: %v (%q)", err, got.ToJSON)
	}
	if len(to) != 1 || to[0]["address"] != "rdort@proton.me" {
		t.Errorf("ToJSON = %s", got.ToJSON)
	}

	// CcJSON should be an empty JSON array, not "" or "null".
	if got.CcJSON != "[]" {
		t.Errorf("CcJSON = %q, want []", got.CcJSON)
	}

	if got.RawJSON == "" {
		t.Error("RawJSON should be populated")
	}
}

func TestPrimaryFolder(t *testing.T) {
	cases := []struct {
		name   string
		labels []string
		want   string
	}{
		{"inbox", []string{gpa.InboxLabel}, "inbox"},
		{"sent", []string{gpa.SentLabel}, "sent"},
		{"drafts", []string{gpa.DraftsLabel}, "drafts"},
		{"trash", []string{gpa.TrashLabel}, "trash"},
		{"spam", []string{gpa.SpamLabel}, "spam"},
		{"archive", []string{gpa.ArchiveLabel}, "archive"},
		{"inbox wins over allmail", []string{gpa.AllMailLabel, gpa.InboxLabel}, "inbox"},
		{"inbox wins over user labels", []string{"user-foo", gpa.InboxLabel}, "inbox"},
		{"trash wins over user labels", []string{"user-foo", gpa.TrashLabel}, "trash"},
		// D1/D2 fix: fallback is "" (no system folder), not "all".
		// The literal "all" value created a shadow bucket the LLM
		// kept selecting when it asked for "all folders" — see
		// DEFECTS.html.
		{"fallback to empty", []string{"user-only"}, ""},
		{"fallback when empty", []string{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := primaryFolder(tc.labels)
			if got != tc.want {
				t.Errorf("primaryFolder(%v) = %q, want %q", tc.labels, got, tc.want)
			}
		})
	}
}
