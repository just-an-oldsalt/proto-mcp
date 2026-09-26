package mcptools

import (
	"context"
	"slices"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

func createDraft(t *testing.T, deps Deps, args string) string {
	t.Helper()
	return callOK(t, mailDraftCreate(deps), args).StructuredContent.(draftResult).DraftID
}

// Issue #122: mail_trash and mail_draft_delete called Client.DeleteMessage,
// Proton's permanent delete, while telling the user the move was
// reversible. Both must leave the message retrievable, labelled Trash.
func TestTrashTools_MoveToTrashNotDelete(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tool  func(Deps) mcp.Tool
		field string
	}{
		{"mail_trash", mailTrash, "message_id"},
		{"mail_draft_delete", mailDraftDelete, "draft_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, c, _ := fakeProtonEnv(t)
			id := createDraft(t, deps, `{"subject":"s","to":["a@b.com"],"body_text":"hello"}`)

			callOK(t, tc.tool(deps), `{"`+tc.field+`":"`+id+`"}`)

			m, err := c.GetMessage(context.Background(), id)
			if err != nil {
				t.Fatalf("message is gone after %s (permanently deleted): %v", tc.name, err)
			}
			if !slices.Contains(m.LabelIDs, gpa.TrashLabel) {
				t.Errorf("after %s labels = %v, want Trash (%s)", tc.name, m.LabelIDs, gpa.TrashLabel)
			}
		})
	}
}
