package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// systemFolderToLabelID maps the LLM-facing folder names back to
// Proton's label-ID convention. These are the IDs `mail_move` writes
// to when the destination is one of the built-in folders. User-
// defined folders pass through their label_id directly via mail_label
// instead.
//
// Inverse of the priority list in proton.primaryFolder.
var systemFolderToLabelID = map[string]string{
	"inbox":   gpa.InboxLabel,
	"sent":    gpa.SentLabel,
	"drafts":  gpa.DraftsLabel,
	"archive": gpa.ArchiveLabel,
	"trash":   gpa.TrashLabel,
	"spam":    gpa.SpamLabel,
}

// mailMarkRead — clear the Unread flag.
func mailMarkRead(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
	}
	return mcp.Tool{
		Name:        "mail_mark_read",
		Description: "Mark a message as read. Reversible via mail_mark_unread. Local mirror updated immediately.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"message_id": {"type": "string"}},
			"required": ["message_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := decodeMessageIDInput(raw, &in, &in.MessageID, "mail_mark_read"); err != nil {
				return nil, err
			}
			if err := deps.Session.Client.MarkMessagesRead(ctx.Std, in.MessageID); err != nil {
				return mcp.ErrorResult("mail_mark_read: %v", err), nil
			}
			if err := updateMessageFlag(ctx.Std, deps, in.MessageID, func(m *store.Message) { m.Unread = false }); err != nil {
				// Mirror update is best-effort; the action succeeded
				// on the server. Surface as a result message but
				// don't isError, since the user-visible outcome
				// (message is read on Proton) is correct.
				return mcp.StructuredResult(stateActionOK(in.MessageID, "marked_read",
					"warning: local mirror update failed: "+err.Error()))
			}
			return mcp.StructuredResult(stateActionOK(in.MessageID, "marked_read", ""))
		},
	}
}

// mailMarkUnread — symmetric reverse.
func mailMarkUnread(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
	}
	return mcp.Tool{
		Name:        "mail_mark_unread",
		Description: "Mark a message as unread. Reversible via mail_mark_read. Local mirror updated immediately.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"message_id": {"type": "string"}},
			"required": ["message_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := decodeMessageIDInput(raw, &in, &in.MessageID, "mail_mark_unread"); err != nil {
				return nil, err
			}
			if err := deps.Session.Client.MarkMessagesUnread(ctx.Std, in.MessageID); err != nil {
				return mcp.ErrorResult("mail_mark_unread: %v", err), nil
			}
			if err := updateMessageFlag(ctx.Std, deps, in.MessageID, func(m *store.Message) { m.Unread = true }); err != nil {
				return mcp.StructuredResult(stateActionOK(in.MessageID, "marked_unread",
					"warning: local mirror update failed: "+err.Error()))
			}
			return mcp.StructuredResult(stateActionOK(in.MessageID, "marked_unread", ""))
		},
	}
}

// mailMove — move a message to a destination folder. Implemented as
// "label with destination, unlabel current" rather than a single
// Proton move endpoint (Proton's label system handles this natively).
//
// Destination is one of the system folder names (inbox / sent /
// drafts / archive / trash / spam) OR a user-folder label_id. For
// system folders the LLM-facing name is friendlier; user folders
// require the label_id from folders_list since their names can
// collide with system ones.
func mailMove(deps Deps) mcp.Tool {
	type input struct {
		MessageID   string `json:"message_id"`
		Destination string `json:"destination"`
	}
	return mcp.Tool{
		Name: "mail_move",
		Description: "Move a message to a different folder. " +
			"Destination is one of the system folders (inbox, sent, drafts, archive, trash, spam) " +
			"OR the label_id of a user-defined folder (from folders_list). " +
			"Reversible — call mail_move again with the original folder.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id":  {"type": "string"},
				"destination": {"type": "string", "description": "System folder name or user folder label_id"}
			},
			"required": ["message_id", "destination"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_move: "+err.Error())
			}
			if in.MessageID == "" || in.Destination == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_move: message_id and destination are required")
			}

			destLabelID := in.Destination
			destFriendly := in.Destination
			if labelID, ok := systemFolderToLabelID[in.Destination]; ok {
				destLabelID = labelID
			} else {
				destFriendly = "" // unknown; we don't know the name
			}

			// Read current state from the mirror to find the source
			// folder we need to unlabel. Falls back to no-unlabel if
			// the row isn't there (sync hadn't run yet).
			var sourceLabelID string
			if m, err := deps.Store.GetMessage(ctx.Std, in.MessageID); err == nil {
				if id, ok := systemFolderToLabelID[m.Folder]; ok {
					sourceLabelID = id
				}
			}

			if err := deps.Session.Client.LabelMessages(ctx.Std, []string{in.MessageID}, destLabelID); err != nil {
				return mcp.ErrorResult("mail_move: label %s: %v", destLabelID, err), nil
			}
			if sourceLabelID != "" && sourceLabelID != destLabelID {
				if err := deps.Session.Client.UnlabelMessages(ctx.Std, []string{in.MessageID}, sourceLabelID); err != nil {
					// Destination label already applied — the move
					// is half-done. Surface as warning, not failure.
					return mcp.StructuredResult(stateActionOK(in.MessageID, "moved",
						fmt.Sprintf("warning: failed to unlabel source %s: %v", sourceLabelID, err)))
				}
			}

			// Mirror update.
			newFolder := destFriendly
			if newFolder == "" {
				newFolder = destLabelID // user folder id
			}
			_ = updateMessageFlag(ctx.Std, deps, in.MessageID, func(m *store.Message) {
				m.Folder = newFolder
			})

			return mcp.StructuredResult(stateActionOK(in.MessageID, "moved_to:"+newFolder, ""))
		},
	}
}

// mailLabel — add or remove a single label from a message. For moves
// between folders use mail_move instead; this is the verb for
// applying classification labels (not folders).
func mailLabel(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
		LabelID   string `json:"label_id"`
		Action    string `json:"action"` // "add" | "remove"
	}
	return mcp.Tool{
		Name: "mail_label",
		Description: "Add or remove a single label from a message. " +
			"Reversible — call again with the opposite action. " +
			"Use label_id values from labels_list; for moving between folders use mail_move.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id": {"type": "string"},
				"label_id":   {"type": "string"},
				"action":     {"type": "string", "enum": ["add", "remove"]}
			},
			"required": ["message_id", "label_id", "action"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_label: "+err.Error())
			}
			if in.MessageID == "" || in.LabelID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_label: message_id and label_id are required")
			}
			switch in.Action {
			case "add":
				if err := deps.Session.Client.LabelMessages(ctx.Std, []string{in.MessageID}, in.LabelID); err != nil {
					return mcp.ErrorResult("mail_label add: %v", err), nil
				}
				return mcp.StructuredResult(stateActionOK(in.MessageID, "labeled:"+in.LabelID, ""))
			case "remove":
				if err := deps.Session.Client.UnlabelMessages(ctx.Std, []string{in.MessageID}, in.LabelID); err != nil {
					return mcp.ErrorResult("mail_label remove: %v", err), nil
				}
				return mcp.StructuredResult(stateActionOK(in.MessageID, "unlabeled:"+in.LabelID, ""))
			default:
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					`mail_label: action must be "add" or "remove"`)
			}
		},
	}
}

// mailTrash — move to trash. Reversible by mail_move back to the
// original folder while the message still exists in trash. (Proton
// has a separate "permanent delete" verb gated as deny by default —
// see mail_delete_permanent in 5/D.)
func mailTrash(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
	}
	return mcp.Tool{
		Name: "mail_trash",
		Description: "Move a message to Trash. Reversible — call mail_move with the original folder. " +
			"For permanent deletion see mail_delete_permanent (gated as deny by default).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"message_id": {"type": "string"}},
			"required": ["message_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := decodeMessageIDInput(raw, &in, &in.MessageID, "mail_trash"); err != nil {
				return nil, err
			}
			// Proton's DeleteMessage moves to Trash (recoverable);
			// the true permanent delete is a different endpoint.
			if err := deps.Session.Client.DeleteMessage(ctx.Std, in.MessageID); err != nil {
				return mcp.ErrorResult("mail_trash: %v", err), nil
			}
			_ = updateMessageFlag(ctx.Std, deps, in.MessageID, func(m *store.Message) {
				m.Folder = "trash"
			})
			return mcp.StructuredResult(stateActionOK(in.MessageID, "trashed", ""))
		},
	}
}

// stateActionResult is the shared output shape for the five state
// mutation tools. Keeps the wire shape uniform across the family.
type stateActionResult struct {
	MessageID string `json:"message_id"`
	Action    string `json:"action"`
	Warning   string `json:"warning,omitempty"`
}

func stateActionOK(id, action, warning string) stateActionResult {
	return stateActionResult{MessageID: id, Action: action, Warning: warning}
}

const stateActionSchema = `{
	"type": "object",
	"properties": {
		"message_id": {"type": "string"},
		"action":     {"type": "string"},
		"warning":    {"type": "string"}
	},
	"required": ["message_id", "action"]
}`

// decodeMessageIDInput is the shared parse path for the simple
// {message_id: string} tools (mark_read/unread, trash). Returns a
// JSON-RPC *Error if parsing fails or the message_id is empty.
func decodeMessageIDInput(raw json.RawMessage, dst any, idPtr *string, toolName string) *mcp.Error {
	if err := json.Unmarshal(raw, dst); err != nil {
		return mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
	}
	if *idPtr == "" {
		return mcp.NewError(mcp.CodeInvalidParams, toolName+": message_id is required")
	}
	return nil
}

// updateMessageFlag fetches the message from the local mirror,
// applies mut, and writes it back. ErrNotFound is non-fatal — we
// return an error so the caller knows but tool success isn't gated
// on the mirror being current. (Sync would have written the row
// eventually; we're just being eager.)
func updateMessageFlag(ctx context.Context, deps Deps, id string, mut func(*store.Message)) error {
	m, err := deps.Store.GetMessage(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // sync will pick it up next round
		}
		return err
	}
	mut(&m)
	return deps.Store.UpsertMessage(ctx, m)
}
