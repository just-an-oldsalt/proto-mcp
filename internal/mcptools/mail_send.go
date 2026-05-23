package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// The send family. Five tools sharing one core send path:
//
//	mail_send         — compose + send (new draft → send → done)
//	mail_send_draft   — send an existing draft (mail_draft_create → send later)
//	mail_reply        — reply to one message; To = original sender
//	mail_reply_all    — reply to all; CC = original To+CC minus self
//	mail_forward      — forward; new To list, body prefixed with quote header
//
// All five are decision:prompt + confirm:true in default.yaml. The
// Touch-ID prompt + NSAlert literal-recipient body fires before any
// network call. allowed_recipients and rate_limit enforcement happen
// in the MCP middleware between policy and broker (see
// internal/mcp/middleware.go).

// sendInput is the public shape for mail_send. Reply / reply_all /
// forward use variants that reference an existing message_id.
type sendInput struct {
	Subject  string   `json:"subject"`
	To       []string `json:"to"`
	CC       []string `json:"cc,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
	BodyText string   `json:"body_text,omitempty"`
	BodyHTML string   `json:"body_html,omitempty"`
}

type sendResult struct {
	MessageID  string   `json:"message_id"`
	Subject    string   `json:"subject"`
	Recipients []string `json:"recipients"`
	Sent       bool     `json:"sent"`
}

func mailSend(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_send",
		Description: "Compose and send a message in one step. IRREVERSIBLE — once sent, " +
			"it cannot be unsent. The NSAlert shown before Touch ID approval lists every " +
			"recipient and the literal subject so the user can verify what's being sent.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"subject":   {"type": "string"},
				"to":        {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":        {"type": "array", "items": {"type": "string"}},
				"bcc":       {"type": "array", "items": {"type": "string"}},
				"body_text": {"type": "string"},
				"body_html": {"type": "string"}
			},
			"required": ["subject", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   extractSendRecipients,
		PromptBody:   sendPromptBody("mail_send"),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in sendInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send: "+err.Error())
			}
			if in.Subject == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_send: subject and at least one to recipient are required")
			}
			return sendCompose(ctx, deps, "mail_send", "", in)
		},
	}
}

func mailSendDraft(deps Deps) mcp.Tool {
	type input struct {
		DraftID string `json:"draft_id"`
	}
	return mcp.Tool{
		Name:        "mail_send_draft",
		Description: "Send an existing draft. IRREVERSIBLE. Recipients and subject come from the draft itself; the NSAlert reads them back so the user verifies.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"draft_id": {"type": "string"}},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		// For send_draft we need to fetch the draft to know
		// recipients. The Recipients extractor signature is
		// pure-args, so we can't reach the server here. Leave nil:
		// allowed_recipients enforcement still works once the
		// handler runs and validates recipients before SendDraft.
		Recipients: nil,
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			return "Approve mail_send_draft?",
				"Send draft " + in.DraftID + " to its stored recipients."
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send_draft: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send_draft: draft_id is required")
			}
			return sendDraftByID(ctx, deps, "mail_send_draft", in.DraftID)
		},
	}
}

func mailReply(deps Deps) mcp.Tool {
	type input struct {
		InReplyTo string `json:"in_reply_to"`
		BodyText  string `json:"body_text,omitempty"`
		BodyHTML  string `json:"body_html,omitempty"`
	}
	return mcp.Tool{
		Name: "mail_reply",
		Description: "Reply to a message. IRREVERSIBLE once sent. To = original sender. " +
			"Subject prefixed Re: if not already.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"in_reply_to": {"type": "string"},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"}
			},
			"required": ["in_reply_to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		// For reply, the recipient comes from the original message
		// — needs a network fetch to extract. Skip server-side
		// allowlist check; the handler validates before SendDraft.
		Recipients: nil,
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			return "Approve mail_reply?",
				"Reply to message " + in.InReplyTo + " (recipient = original sender)."
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply: "+err.Error())
			}
			if in.InReplyTo == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply: in_reply_to is required")
			}
			return sendReply(ctx, deps, "mail_reply", in.InReplyTo, false, in.BodyText, in.BodyHTML)
		},
	}
}

func mailReplyAll(deps Deps) mcp.Tool {
	type input struct {
		InReplyTo string `json:"in_reply_to"`
		BodyText  string `json:"body_text,omitempty"`
		BodyHTML  string `json:"body_html,omitempty"`
	}
	return mcp.Tool{
		Name: "mail_reply_all",
		Description: "Reply-all to a message. IRREVERSIBLE. " +
			"To = original sender. CC = original To+CC minus your own addresses. " +
			"BCC dropped (BCC by definition not visible to other recipients).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"in_reply_to": {"type": "string"},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"}
			},
			"required": ["in_reply_to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   nil,
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			return "Approve mail_reply_all?",
				"Reply-all to message " + in.InReplyTo + " (sender + original To/CC minus you)."
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply_all: "+err.Error())
			}
			if in.InReplyTo == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply_all: in_reply_to is required")
			}
			return sendReply(ctx, deps, "mail_reply_all", in.InReplyTo, true, in.BodyText, in.BodyHTML)
		},
	}
}

func mailForward(deps Deps) mcp.Tool {
	type input struct {
		ForwardOf string   `json:"forward_of"`
		To        []string `json:"to"`
		CC        []string `json:"cc,omitempty"`
		BCC       []string `json:"bcc,omitempty"`
		BodyText  string   `json:"body_text,omitempty"`
		BodyHTML  string   `json:"body_html,omitempty"`
	}
	return mcp.Tool{
		Name: "mail_forward",
		Description: "Forward a message to new recipients. IRREVERSIBLE. " +
			"Subject prefixed Fwd:. Body is the new content; the original message " +
			"is NOT quoted automatically — pass it as part of body_text if desired.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"forward_of": {"type": "string"},
				"to":         {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":         {"type": "array", "items": {"type": "string"}},
				"bcc":        {"type": "array", "items": {"type": "string"}},
				"body_text":  {"type": "string"},
				"body_html":  {"type": "string"}
			},
			"required": ["forward_of", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients: func(args json.RawMessage) []string {
			var in input
			if err := json.Unmarshal(args, &in); err != nil {
				return nil
			}
			return append(append(append([]string{}, in.To...), in.CC...), in.BCC...)
		},
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			return "Approve mail_forward?",
				fmt.Sprintf("Forward message %s\nTo: %s\nCC: %s\nBCC: %s",
					in.ForwardOf,
					strings.Join(in.To, ", "),
					strings.Join(in.CC, ", "),
					strings.Join(in.BCC, ", "))
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_forward: "+err.Error())
			}
			if in.ForwardOf == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_forward: forward_of and at least one to recipient are required")
			}
			return sendForward(ctx, deps, in)
		},
	}
}

// ============================================================
// Helpers
// ============================================================

// extractSendRecipients pulls To+CC+BCC out of a mail_send arg
// payload for the allowed_recipients middleware stage. Returns nil
// on parse failure — the handler's own validation will catch that
// later with a clearer error message.
func extractSendRecipients(args json.RawMessage) []string {
	var in sendInput
	if err := json.Unmarshal(args, &in); err != nil {
		return nil
	}
	out := make([]string, 0, len(in.To)+len(in.CC)+len(in.BCC))
	out = append(out, in.To...)
	out = append(out, in.CC...)
	out = append(out, in.BCC...)
	return out
}

// sendPromptBody returns a PromptBody func that formats the literal
// To / CC / BCC / Subject lines the user sees in the NSAlert.
// Body content is replaced with sha256+bytes via the redact path
// — recipient list, subject, and counts are what matter at approval
// time.
func sendPromptBody(toolName string) func(json.RawMessage) (string, string) {
	return func(args json.RawMessage) (string, string) {
		var in sendInput
		_ = json.Unmarshal(args, &in)
		body := fmt.Sprintf(
			"To: %s\nCC: %s\nBCC: %s\nSubject: %s",
			strings.Join(in.To, ", "),
			strings.Join(in.CC, ", "),
			strings.Join(in.BCC, ", "),
			in.Subject,
		)
		return "Approve " + toolName + "?", body
	}
}

// sendCompose is mail_send: create a draft, send it, return.
func sendCompose(ctx mcp.Context, deps Deps, toolName, parentID string, in sendInput) (*mcp.ToolResult, error) {
	tpl, mimeType, err := buildDraftTemplate(deps, in.Subject, in.To, in.CC, in.BCC, in.BodyText, in.BodyHTML)
	if err != nil {
		return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
	}
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	createReq := gpa.CreateDraftReq{
		Message:  tpl,
		ParentID: parentID,
	}
	draft, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, createReq)
	if err != nil {
		return mcp.ErrorResult("%s: create draft: %v", toolName, err), nil
	}
	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, allRecipients(in.To, in.CC, in.BCC))
}

// sendDraftByID is mail_send_draft: load draft, send.
func sendDraftByID(ctx mcp.Context, deps Deps, toolName, draftID string) (*mcp.ToolResult, error) {
	draft, err := deps.Session.Client.GetMessage(ctx.Std, draftID)
	if err != nil {
		return mcp.ErrorResult("%s: fetch draft: %v", toolName, err), nil
	}
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	mimeType := "text/plain"
	if string(draft.MIMEType) == "text/html" {
		mimeType = "text/html"
	}
	recipients := allRecipients(
		addressStrings(draft.ToList),
		addressStrings(draft.CCList),
		addressStrings(draft.BCCList),
	)
	tpl := gpa.DraftTemplate{
		Subject:  draft.Subject,
		Sender:   draft.Sender,
		ToList:   draft.ToList,
		CCList:   draft.CCList,
		BCCList:  draft.BCCList,
		Body:     draft.Body,
		MIMEType: draft.MIMEType,
	}
	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, recipients)
}

// sendReply is the reply / reply_all body. Fetches the original,
// builds the recipient lists, calls sendCompose with ParentID.
func sendReply(ctx mcp.Context, deps Deps, toolName, parentID string, replyAll bool, bodyText, bodyHTML string) (*mcp.ToolResult, error) {
	parent, err := deps.Session.Client.GetMessage(ctx.Std, parentID)
	if err != nil {
		return mcp.ErrorResult("%s: fetch parent: %v", toolName, err), nil
	}

	// Subject — prefix Re: if not already.
	subject := parent.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}

	// Recipients.
	to := []string{}
	if parent.Sender != nil {
		to = append(to, parent.Sender.Address)
	}
	cc := []string{}
	if replyAll {
		self := selfAddresses(deps)
		for _, a := range parent.ToList {
			if a != nil && !contains(self, strings.ToLower(a.Address)) && !contains(to, a.Address) {
				cc = append(cc, a.Address)
			}
		}
		for _, a := range parent.CCList {
			if a != nil && !contains(self, strings.ToLower(a.Address)) && !contains(to, a.Address) {
				cc = append(cc, a.Address)
			}
		}
	}

	return sendCompose(ctx, deps, toolName, parentID, sendInput{
		Subject:  subject,
		To:       to,
		CC:       cc,
		BodyText: bodyText,
		BodyHTML: bodyHTML,
	})
}

// sendForward is the forward body. Subject Fwd:-prefixed; body
// passed through unchanged.
func sendForward(ctx mcp.Context, deps Deps, in struct {
	ForwardOf string   `json:"forward_of"`
	To        []string `json:"to"`
	CC        []string `json:"cc,omitempty"`
	BCC       []string `json:"bcc,omitempty"`
	BodyText  string   `json:"body_text,omitempty"`
	BodyHTML  string   `json:"body_html,omitempty"`
}) (*mcp.ToolResult, error) {
	parent, err := deps.Session.Client.GetMessage(ctx.Std, in.ForwardOf)
	if err != nil {
		return mcp.ErrorResult("mail_forward: fetch parent: %v", err), nil
	}
	subject := parent.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "fwd:") {
		subject = "Fwd: " + subject
	}
	return sendCompose(ctx, deps, "mail_forward", in.ForwardOf, sendInput{
		Subject:  subject,
		To:       in.To,
		CC:       in.CC,
		BCC:      in.BCC,
		BodyText: in.BodyText,
		BodyHTML: in.BodyHTML,
	})
}

// finalizeSend is the shared "build packages → SendDraft → return"
// tail used by every send tool. Encapsulates the per-recipient
// public-key lookup + AddTextPackage call.
func finalizeSend(ctx mcp.Context, deps Deps, toolName string, addrKR *crypto.KeyRing, draft gpa.Message, tpl gpa.DraftTemplate, mimeType string, recipients []string) (*mcp.ToolResult, error) {
	prefs, err := buildSendPreferences(ctx.Std, deps, recipients, mimeType)
	if err != nil {
		return mcp.ErrorResult("%s: build send preferences: %v", toolName, err), nil
	}
	req := gpa.SendDraftReq{}
	if err := req.AddTextPackage(addrKR, tpl.Body, mimeTypeForSend(mimeType), prefs, map[string]*crypto.SessionKey{}); err != nil {
		return mcp.ErrorResult("%s: build text package: %v", toolName, err), nil
	}
	sent, err := deps.Session.Client.SendDraft(ctx.Std, draft.ID, req)
	if err != nil {
		return mcp.ErrorResult("%s: send: %v", toolName, err), nil
	}
	return mcp.StructuredResult(sendResult{
		MessageID:  sent.ID,
		Subject:    sent.Subject,
		Recipients: recipients,
		Sent:       true,
	})
}

// allRecipients merges To+CC+BCC into one slice.
func allRecipients(to, cc, bcc []string) []string {
	out := make([]string, 0, len(to)+len(cc)+len(bcc))
	out = append(out, to...)
	out = append(out, cc...)
	out = append(out, bcc...)
	return out
}

// selfAddresses returns lowercase strings of every address attached
// to this session, so reply_all can drop us from CC.
func selfAddresses(deps Deps) []string {
	if deps.Session == nil {
		return nil
	}
	out := make([]string, 0, len(deps.Session.Addresses))
	for _, a := range deps.Session.Addresses {
		out = append(out, strings.ToLower(a.Email))
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ensureValidEmail returns nil if s parses as a single RFC5322
// address. Used by handlers that take addresses from the LLM and
// want to fail fast before the SDK does.
func ensureValidEmail(s string) error {
	if _, err := mail.ParseAddress(s); err != nil {
		return fmt.Errorf("invalid email %q: %w", s, err)
	}
	return nil
}

// (compile-only guards)
var (
	_ = errors.New
	_ = context.Background
	_ = ensureValidEmail
)

const sendResultSchema = `{
	"type": "object",
	"properties": {
		"message_id": {"type": "string"},
		"subject":    {"type": "string"},
		"recipients": {"type": "array", "items": {"type": "string"}},
		"sent":       {"type": "boolean"}
	},
	"required": ["message_id", "sent"]
}`
