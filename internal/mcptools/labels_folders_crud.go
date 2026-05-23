package mcptools

import (
	"context"
	"encoding/json"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// labels_create / _update / _delete and folders_create / _update /
// _delete are six tools backed by three SDK methods. Proton unifies
// the two namespaces via `LabelType`: 1 = user label, 3 = user
// folder. We split at the MCP boundary for clarity — the LLM can
// reason about "labels" (a message can have many) vs "folders" (a
// message lives in exactly one) without first learning Proton's
// labelType enum.

// Decision: prompt for create / update; prompt + confirm for delete.
// Policy stubs already exist in default.yaml from Phase 4.

// crudLabelInput / crudLabelUpdateInput keep the shape compact so
// labels_* and folders_* can share the parser.
type crudLabelInput struct {
	Name     string `json:"name"`
	Color    string `json:"color,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

type crudLabelUpdateInput struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Color    string `json:"color,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

type crudLabelDeleteInput struct {
	ID string `json:"id"`
}

type crudLabelResult struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
	Type  int    `json:"type"` // 1=label, 3=folder
}

// labelsCreate / foldersCreate share createImpl; the only difference
// is the LabelType they pass and the storage type they upsert.

func labelsCreate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "labels_create",
		Description:  "Create a user label (color-coded tag a message can have many of). For mutually-exclusive locations use folders_create.",
		InputSchema:  json.RawMessage(crudCreateSchema),
		OutputSchema: json.RawMessage(crudResultSchema),
		PromptBody:   crudCreatePromptBody("labels_create", "label"),
		Handler:      makeCreateHandler(deps, "labels_create", gpa.LabelTypeLabel, labelTypeUserLabel),
	}
}

func foldersCreate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "folders_create",
		Description:  "Create a user folder (a message lives in exactly one folder; the system folders inbox/sent/drafts/archive/trash/spam are immutable). For non-exclusive tags use labels_create.",
		InputSchema:  json.RawMessage(crudCreateSchema),
		OutputSchema: json.RawMessage(crudResultSchema),
		PromptBody:   crudCreatePromptBody("folders_create", "folder"),
		Handler:      makeCreateHandler(deps, "folders_create", gpa.LabelTypeFolder, labelTypeUserFolder),
	}
}

func labelsUpdate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "labels_update",
		Description:  "Rename / recolor / reparent a user label.",
		InputSchema:  json.RawMessage(crudUpdateSchema),
		OutputSchema: json.RawMessage(crudResultSchema),
		PromptBody:   crudUpdatePromptBody(deps, "labels_update", "label"),
		Handler:      makeUpdateHandler(deps, "labels_update", labelTypeUserLabel),
	}
}

func foldersUpdate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "folders_update",
		Description:  "Rename / recolor / reparent a user folder.",
		InputSchema:  json.RawMessage(crudUpdateSchema),
		OutputSchema: json.RawMessage(crudResultSchema),
		PromptBody:   crudUpdatePromptBody(deps, "folders_update", "folder"),
		Handler:      makeUpdateHandler(deps, "folders_update", labelTypeUserFolder),
	}
}

func labelsDelete(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "labels_delete",
		Description:  "Delete a user label. Messages keep existing — they just lose this label from their classification.",
		InputSchema:  json.RawMessage(crudDeleteSchema),
		OutputSchema: json.RawMessage(crudDeleteResultSchema),
		PromptBody:   crudDeletePromptBody(deps, "labels_delete", "label"),
		Handler:      makeDeleteHandler(deps, "labels_delete"),
	}
}

func foldersDelete(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:         "folders_delete",
		Description:  "Delete a user folder. Proton may refuse if the folder still contains messages; surface that as the tool result.",
		InputSchema:  json.RawMessage(crudDeleteSchema),
		OutputSchema: json.RawMessage(crudDeleteResultSchema),
		PromptBody:   crudDeletePromptBody(deps, "folders_delete", "folder"),
		Handler:      makeDeleteHandler(deps, "folders_delete"),
	}
}

// crudCreatePromptBody — "create label 'Important' (color #00ff00)".
// Doesn't take deps because the create input already carries the
// human-readable name; nothing to look up.
func crudCreatePromptBody(toolName, kind string) func(json.RawMessage) (string, string) {
	return func(raw json.RawMessage) (string, string) {
		var in crudLabelInput
		_ = json.Unmarshal(raw, &in)
		body := "create " + kind + " " + quote(in.Name)
		if in.Color != "" {
			body += " (color " + in.Color + ")"
		}
		if in.ParentID != "" {
			body += " under parent " + shortID(in.ParentID)
		}
		title := mcp.SanitizePromptText("Approve "+toolName+"?", 120)
		return title, mcp.SanitizePromptText(body, 4000)
	}
}

// crudUpdatePromptBody — "rename label 'Important' to 'Critical'".
// Captures deps to look up the current Name from the local mirror,
// because the input only carries the id + the new value.
func crudUpdatePromptBody(deps Deps, toolName, kind string) func(json.RawMessage) (string, string) {
	return func(raw json.RawMessage) (string, string) {
		var in crudLabelUpdateInput
		_ = json.Unmarshal(raw, &in)
		oldName := lookupLabelName(deps, in.ID)
		var changes []string
		if in.Name != "" {
			changes = append(changes, "name → "+quote(in.Name))
		}
		if in.Color != "" {
			changes = append(changes, "color → "+in.Color)
		}
		if in.ParentID != "" {
			changes = append(changes, "parent → "+shortID(in.ParentID))
		}
		body := "update " + kind + " " + oldName
		if len(changes) > 0 {
			body += " (" + joinComma(changes) + ")"
		}
		title := mcp.SanitizePromptText("Approve "+toolName+"?", 120)
		return title, mcp.SanitizePromptText(body, 4000)
	}
}

// crudDeletePromptBody — "delete label 'Important'". Captures deps
// to resolve the id to a name.
func crudDeletePromptBody(deps Deps, toolName, kind string) func(json.RawMessage) (string, string) {
	return func(raw json.RawMessage) (string, string) {
		var in crudLabelDeleteInput
		_ = json.Unmarshal(raw, &in)
		name := lookupLabelName(deps, in.ID)
		body := "delete " + kind + " " + name
		if kind == "label" {
			body += " (messages stay; classification removed)"
		} else {
			body += " (Proton refuses if folder still contains messages)"
		}
		title := mcp.SanitizePromptText("Approve "+toolName+"?", 120)
		return title, mcp.SanitizePromptText(body, 4000)
	}
}

func joinComma(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}

func makeCreateHandler(deps Deps, toolName string, lt gpa.LabelType, _ int) mcp.Handler {
	return func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
		var in crudLabelInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
		}
		if in.Name == "" {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": name is required")
		}
		req := gpa.CreateLabelReq{
			Name:     in.Name,
			Color:    in.Color,
			Type:     lt,
			ParentID: in.ParentID,
		}
		label, err := deps.Session.Client.CreateLabel(ctx.Std, req)
		if err != nil {
			return mcp.ErrorResult("%s: %v", toolName, err), nil
		}
		mirrorUpsertLabel(ctx.Std, deps, label)
		return mcp.StructuredResult(labelToResult(label))
	}
}

func makeUpdateHandler(deps Deps, toolName string, requiredType int) mcp.Handler {
	return func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
		var in crudLabelUpdateInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
		}
		if in.ID == "" {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": id is required")
		}

		// Fetch current to fill any unspecified fields (UpdateLabel
		// requires Name + Color; we don't want to clobber them).
		current, err := deps.Store.GetLabel(ctx.Std, in.ID)
		if err == nil && current.Type != requiredType {
			return nil, mcp.NewError(mcp.CodeInvalidParams,
				toolName+": id refers to a different label type")
		}
		req := gpa.UpdateLabelReq{
			Name:     pickStr(in.Name, current.Name),
			Color:    pickStr(in.Color, current.Color),
			ParentID: in.ParentID,
		}
		label, err := deps.Session.Client.UpdateLabel(ctx.Std, in.ID, req)
		if err != nil {
			return mcp.ErrorResult("%s: %v", toolName, err), nil
		}
		mirrorUpsertLabel(ctx.Std, deps, label)
		return mcp.StructuredResult(labelToResult(label))
	}
}

func makeDeleteHandler(deps Deps, toolName string) mcp.Handler {
	return func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
		var in crudLabelDeleteInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
		}
		if in.ID == "" {
			return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": id is required")
		}
		if err := deps.Session.Client.DeleteLabel(ctx.Std, in.ID); err != nil {
			return mcp.ErrorResult("%s: %v", toolName, err), nil
		}
		_ = deps.Store.DeleteLabel(ctx.Std, in.ID)
		return mcp.StructuredResult(map[string]any{
			"id":      in.ID,
			"deleted": true,
		})
	}
}

func mirrorUpsertLabel(ctx context.Context, deps Deps, l gpa.Label) {
	_ = deps.Store.UpsertLabel(ctx, store.Label{
		ID:    l.ID,
		Name:  l.Name,
		Color: l.Color,
		Type:  int(l.Type),
	})
}

func labelToResult(l gpa.Label) crudLabelResult {
	return crudLabelResult{
		ID:    l.ID,
		Name:  l.Name,
		Color: l.Color,
		Type:  int(l.Type),
	}
}

func pickStr(preferred, fallback string) string {
	if preferred != "" {
		return preferred
	}
	return fallback
}

const crudCreateSchema = `{
	"type": "object",
	"properties": {
		"name":      {"type": "string"},
		"color":     {"type": "string", "description": "Hex color like #aabbcc"},
		"parent_id": {"type": "string", "description": "Parent folder id for nesting (folders only)"}
	},
	"required": ["name"],
	"additionalProperties": false
}`

const crudUpdateSchema = `{
	"type": "object",
	"properties": {
		"id":        {"type": "string"},
		"name":      {"type": "string"},
		"color":     {"type": "string"},
		"parent_id": {"type": "string"}
	},
	"required": ["id"],
	"additionalProperties": false
}`

const crudDeleteSchema = `{
	"type": "object",
	"properties": {
		"id": {"type": "string"}
	},
	"required": ["id"],
	"additionalProperties": false
}`

const crudResultSchema = `{
	"type": "object",
	"properties": {
		"id":    {"type": "string"},
		"name":  {"type": "string"},
		"color": {"type": "string"},
		"type":  {"type": "integer"}
	},
	"required": ["id", "name", "type"]
}`

const crudDeleteResultSchema = `{
	"type": "object",
	"properties": {
		"id":      {"type": "string"},
		"deleted": {"type": "boolean"}
	},
	"required": ["id", "deleted"]
}`
