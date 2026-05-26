package mcptools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// decodeBase64 is a thin wrapper for clarity at call sites that
// decode SDK-returned base64 (KeyPackets, etc.).
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

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
	Subject     string                `json:"subject"`
	To          []string              `json:"to"`
	CC          []string              `json:"cc,omitempty"`
	BCC         []string              `json:"bcc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
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
			"it cannot be unsent. Optional `attachments` array uploads files alongside " +
			"the body (each entry: filename, mime_type, content_b64). Refuses individual " +
			"or cumulative attachment sizes exceeding max_attachment_bytes (default 25 MiB). " +
			"Refuses PGP/MIME-encrypted external recipients — send to a Proton address or " +
			"a recipient without an on-file PGP key instead. The NSAlert shown before " +
			"Touch ID approval lists every recipient, the literal subject, and a one-line " +
			"attachment summary.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"subject":     {"type": "string"},
				"to":          {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":          {"type": "array", "items": {"type": "string"}},
				"bcc":         {"type": "array", "items": {"type": "string"}},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
			},
			"required": ["subject", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   extractSendRecipients,
		PromptBody:   sendPromptBodyWithDeps(deps, "mail_send"),
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
			return mcp.SanitizePromptText("Approve mail_send_draft?", 120),
				mcp.SanitizePromptText("Send draft "+in.DraftID+" to its stored recipients.", 4000)
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
		InReplyTo   string                `json:"in_reply_to"`
		BodyText    string                `json:"body_text,omitempty"`
		BodyHTML    string                `json:"body_html,omitempty"`
		Attachments []sendAttachmentInput `json:"attachments,omitempty"`
	}
	return mcp.Tool{
		Name: "mail_reply",
		Description: "Reply to a message. IRREVERSIBLE once sent. To = original sender. " +
			"Subject prefixed Re: if not already. Optional `attachments` array attaches " +
			"new files (does NOT carry over parent attachments — use mail_forward for that).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"in_reply_to": {"type": "string"},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
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
			body := "Reply to message " + in.InReplyTo + " (recipient = original sender)."
			if decoded, err := decodeAndValidateAttachments(deps, in.Attachments); err == nil {
				if s := attachmentsSummary(decoded); s != "" {
					body += "\n" + s
				}
			}
			return mcp.SanitizePromptText("Approve mail_reply?", 120),
				mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply: "+err.Error())
			}
			if in.InReplyTo == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply: in_reply_to is required")
			}
			return sendReply(ctx, deps, "mail_reply", in.InReplyTo, false, in.BodyText, in.BodyHTML, in.Attachments)
		},
	}
}

func mailReplyAll(deps Deps) mcp.Tool {
	type input struct {
		InReplyTo   string                `json:"in_reply_to"`
		BodyText    string                `json:"body_text,omitempty"`
		BodyHTML    string                `json:"body_html,omitempty"`
		Attachments []sendAttachmentInput `json:"attachments,omitempty"`
	}
	return mcp.Tool{
		Name: "mail_reply_all",
		Description: "Reply-all to a message. IRREVERSIBLE. " +
			"To = original sender. CC = original To+CC minus your own addresses. " +
			"BCC dropped (BCC by definition not visible to other recipients). " +
			"Optional `attachments` array — same shape as mail_send.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"in_reply_to": {"type": "string"},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
			},
			"required": ["in_reply_to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   nil,
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			body := "Reply-all to message " + in.InReplyTo + " (sender + original To/CC minus you)."
			if decoded, err := decodeAndValidateAttachments(deps, in.Attachments); err == nil {
				if s := attachmentsSummary(decoded); s != "" {
					body += "\n" + s
				}
			}
			return mcp.SanitizePromptText("Approve mail_reply_all?", 120),
				mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply_all: "+err.Error())
			}
			if in.InReplyTo == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_reply_all: in_reply_to is required")
			}
			return sendReply(ctx, deps, "mail_reply_all", in.InReplyTo, true, in.BodyText, in.BodyHTML, in.Attachments)
		},
	}
}

func mailForward(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_forward",
		Description: "Forward a message to new recipients. IRREVERSIBLE. " +
			"Subject prefixed Fwd:. Body is the new content; the original message " +
			"is NOT quoted automatically — pass it as part of body_text if desired. " +
			"Optional `attachments` array attaches new files. Parent attachments are " +
			"NOT carried over automatically in 8/B — that's a Phase 8/C shortcut " +
			"(include_parent_attachments). For now, download + re-upload via " +
			"mail_download_attachment if you need them on the forwarded message.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"forward_of":  {"type": "string"},
				"to":          {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":          {"type": "array", "items": {"type": "string"}},
				"bcc":         {"type": "array", "items": {"type": "string"}},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
			},
			"required": ["forward_of", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients: func(args json.RawMessage) []string {
			var in forwardInput
			if err := json.Unmarshal(args, &in); err != nil {
				return nil
			}
			return append(append(append([]string{}, in.To...), in.CC...), in.BCC...)
		},
		PromptBody: func(args json.RawMessage) (string, string) {
			var in forwardInput
			_ = json.Unmarshal(args, &in)
			body := fmt.Sprintf("Forward message %s\nTo: %s\nCC: %s\nBCC: %s",
				in.ForwardOf,
				strings.Join(in.To, ", "),
				strings.Join(in.CC, ", "),
				strings.Join(in.BCC, ", "))
			if decoded, err := decodeAndValidateAttachments(deps, in.Attachments); err == nil {
				if s := attachmentsSummary(decoded); s != "" {
					body += "\n" + s
				}
			}
			return mcp.SanitizePromptText("Approve mail_forward?", 120),
				mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in forwardInput
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

// forwardInput is the parsed input for mail_forward. Hoisted to the
// package level so sendForward and the inner Recipients/PromptBody
// closures share a single struct shape. Phase 8/B.
type forwardInput struct {
	ForwardOf   string                `json:"forward_of"`
	To          []string              `json:"to"`
	CC          []string              `json:"cc,omitempty"`
	BCC         []string              `json:"bcc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
}

// ============================================================
// Helpers
// ============================================================

// extractSendRecipients pulls To+CC+BCC out of a mail_send arg
// payload for the allowed_recipients middleware stage.
//
// SECURITY D7: each entry runs through mail.ParseAddressList rather
// than being passed raw. That:
//   - Strips display names ("Alice <alice@example.com>" → "alice@example.com")
//     so the allowlist comparison sees the bare address.
//   - Explodes any multi-address entries ("a@x.com,b@y.com" → ["a@x.com",
//     "b@y.com"]) so a smuggled second recipient lands in the
//     allowlist check rather than getting hidden in the display
//     portion. (The actual SDK send path uses mail.ParseAddress
//     singular and rejects multi-addr entries; this is defense
//     in depth so the allowlist sees what the SDK would actually
//     attempt.)
//
// Returns nil on parse failure — the handler's own validation will
// catch that later with a clearer error message.
func extractSendRecipients(args json.RawMessage) []string {
	var in sendInput
	if err := json.Unmarshal(args, &in); err != nil {
		return nil
	}
	out := make([]string, 0, len(in.To)+len(in.CC)+len(in.BCC))
	for _, entry := range append(append(append([]string{}, in.To...), in.CC...), in.BCC...) {
		out = append(out, normalizeRecipientList(entry)...)
	}
	return out
}

// normalizeRecipientList parses one address-list string into bare
// .Address values. If parsing fails completely, returns the raw
// input as a single-element slice so the allowlist still sees
// SOMETHING (rather than the empty list, which would skip the
// check entirely — fail closed, not open).
func normalizeRecipientList(s string) []string {
	addrs, err := mail.ParseAddressList(s)
	if err != nil || len(addrs) == 0 {
		return []string{s}
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a != nil && a.Address != "" {
			out = append(out, a.Address)
		}
	}
	if len(out) == 0 {
		return []string{s}
	}
	return out
}

// sendPromptBody returns a PromptBody func that formats the literal
// To / CC / BCC / Subject lines the user sees in the NSAlert.
// Body content is replaced with sha256+bytes via the redact path
// — recipient list, subject, and counts are what matter at approval
// time. Phase 8/B — also appends an attachment summary line when
// the call carries attachments.
func sendPromptBody(toolName string) func(json.RawMessage) (string, string) {
	return sendPromptBodyWithDeps(Deps{}, toolName)
}

// sendPromptBodyWithDeps is the Phase 8/B variant — passes Deps so
// the closure can validate + summarize the attachments list for
// display. Validation errors are swallowed (the handler will
// surface them with a better message); the closure best-efforts
// the prompt-body fields and lets the user approve based on what
// did parse.
func sendPromptBodyWithDeps(deps Deps, toolName string) func(json.RawMessage) (string, string) {
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
		if decoded, err := decodeAndValidateAttachments(deps, in.Attachments); err == nil {
			if s := attachmentsSummary(decoded); s != "" {
				body += "\n" + s
			}
		}
		return mcp.SanitizePromptText("Approve "+toolName+"?", 120),
			mcp.SanitizePromptText(body, 4000)
	}
}

// sendCompose is mail_send: create a draft, send it, return.
// Phase 8/B — uploads attachments to the draft between CreateDraft
// and SendDraft so they ride on the same send call.
func sendCompose(ctx mcp.Context, deps Deps, toolName, parentID string, in sendInput) (*mcp.ToolResult, error) {
	decoded, err := decodeAndValidateAttachments(deps, in.Attachments)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
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
	attKeys, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, draft.ID, decoded)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, allRecipients(in.To, in.CC, in.BCC), attKeys)
}

// sendDraftByID is mail_send_draft: load draft, send.
//
// Phase 8/B — existing draft attachments are already uploaded to
// the server; we just need to recover their session keys via the
// sender keyring so AddTextPackage can re-encrypt them per
// recipient. No new upload, no attachment input on this tool.
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

	// Recover session keys for existing attachments on the draft.
	attKeys, err := recoverDraftAttachmentKeys(addrKR, draft)
	if err != nil {
		return mcp.ErrorResult("%s: recover draft attachment keys: %v", toolName, err), nil
	}

	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, recipients, attKeys)
}

// recoverDraftAttachmentKeys returns the (attachment_id → session
// key) map for every attachment already on the given draft. Used
// by mail_send_draft (and the 8/C forward shortcut) so existing
// attachments fan out per recipient inside AddTextPackage.
//
// SDK shape: each Attachment.KeyPackets is the base64-encoded
// session key encrypted to the sender's public key. Decrypting it
// with addrKR gets us the symmetric session key.
func recoverDraftAttachmentKeys(addrKR *crypto.KeyRing, draft gpa.Message) (map[string]*crypto.SessionKey, error) {
	if len(draft.Attachments) == 0 {
		return nil, nil
	}
	out := make(map[string]*crypto.SessionKey, len(draft.Attachments))
	for _, a := range draft.Attachments {
		kpBytes, err := decodeBase64(a.KeyPackets)
		if err != nil {
			return nil, fmt.Errorf("attachment %s (%s): decode KeyPackets: %w", a.ID, a.Name, err)
		}
		sk, err := addrKR.DecryptSessionKey(kpBytes)
		if err != nil {
			return nil, fmt.Errorf("attachment %s (%s): %w", a.ID, a.Name, err)
		}
		out[a.ID] = sk
	}
	return out, nil
}

// sendReply is the reply / reply_all body. Fetches the original,
// builds the recipient lists, calls sendCompose with ParentID.
// Phase 8/B — accepts attachments and forwards them through
// sendCompose's upload + send path.
func sendReply(ctx mcp.Context, deps Deps, toolName, parentID string, replyAll bool, bodyText, bodyHTML string, attachments []sendAttachmentInput) (*mcp.ToolResult, error) {
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
		Subject:     subject,
		To:          to,
		CC:          cc,
		BodyText:    bodyText,
		BodyHTML:    bodyHTML,
		Attachments: attachments,
	})
}

// sendForward is the forward body. Subject Fwd:-prefixed; body
// passed through unchanged. Phase 8/B — accepts new attachments.
// Phase 8/C will add include_parent_attachments to carry over
// parent attachments without a byte-round-trip.
func sendForward(ctx mcp.Context, deps Deps, in forwardInput) (*mcp.ToolResult, error) {
	parent, err := deps.Session.Client.GetMessage(ctx.Std, in.ForwardOf)
	if err != nil {
		return mcp.ErrorResult("mail_forward: fetch parent: %v", err), nil
	}
	subject := parent.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "fwd:") {
		subject = "Fwd: " + subject
	}
	return sendCompose(ctx, deps, "mail_forward", in.ForwardOf, sendInput{
		Subject:     subject,
		To:          in.To,
		CC:          in.CC,
		BCC:         in.BCC,
		BodyText:    in.BodyText,
		BodyHTML:    in.BodyHTML,
		Attachments: in.Attachments,
	})
}

// finalizeSend is the shared "build packages → SendDraft → return"
// tail used by every send tool. Encapsulates the per-recipient
// public-key lookup + AddTextPackage call.
//
// SECURITY D6: this is also the choke point where handler-side
// allowed_recipients re-validation happens. reply / reply_all /
// send_draft can't expose recipients via Tool.Recipients (the list
// comes from a server fetch, not from raw args), so the middleware
// allowlist stage skips them. We close that gap here — every send
// tool that ends up calling SendDraft must pass through this
// function, and every call validates against the active policy
// before any encryption or network call to /mail/v4/send.
func finalizeSend(ctx mcp.Context, deps Deps, toolName string, addrKR *crypto.KeyRing, draft gpa.Message, tpl gpa.DraftTemplate, mimeType string, recipients []string, attKeys map[string]*crypto.SessionKey) (*mcp.ToolResult, error) {
	// Normalize the recipients we got from wherever (raw args via
	// allRecipients, draft fetch via addressStrings, reply build) so
	// the allowlist comparison sees the same shape extractSendRecipients
	// produces for the middleware path.
	normalized := make([]string, 0, len(recipients))
	for _, r := range recipients {
		normalized = append(normalized, normalizeRecipientList(r)...)
	}
	if deps.Policy != nil {
		if _, pol := deps.Policy.Decide(toolName, nil, mcpCallerFromContext(ctx)); pol != nil && len(pol.AllowedRecipients) > 0 {
			if bad := firstDisallowedRecipient(normalized, pol.AllowedRecipients); bad != "" {
				return mcp.ErrorResult("%s denied: recipient %s not on allowlist", toolName, bad), nil
			}
		}
	}

	prefs, err := buildSendPreferences(ctx.Std, deps, normalized, mimeType)
	if err != nil {
		return mcp.ErrorResult("%s: build send preferences: %v", toolName, err), nil
	}
	req := gpa.SendDraftReq{}
	if attKeys == nil {
		attKeys = map[string]*crypto.SessionKey{}
	}
	if err := req.AddTextPackage(addrKR, tpl.Body, mimeTypeForSend(mimeType), prefs, attKeys); err != nil {
		return mcp.ErrorResult("%s: build text package: %v", toolName, err), nil
	}
	sent, err := deps.Session.Client.SendDraft(ctx.Std, draft.ID, req)
	if err != nil {
		return mcp.ErrorResult("%s: send: %v", toolName, err), nil
	}
	return mcp.StructuredResult(sendResult{
		MessageID:  sent.ID,
		Subject:    sent.Subject,
		Recipients: normalized,
		Sent:       true,
	})
}

// mcpCallerFromContext maps mcp.CallerInfo (a plain struct on
// Context) to policy.Caller (which is caller.Caller). The two have
// the same shape; the conversion is here rather than upstream so
// the internal/mcp package doesn't need to depend on policy.Caller
// shape.
func mcpCallerFromContext(ctx mcp.Context) policy.Caller {
	return policy.Caller{
		PID:    ctx.Caller.PID,
		UID:    ctx.Caller.UID,
		Binary: ctx.Caller.Binary,
	}
}

// firstDisallowedRecipient is duplicated from internal/mcp's
// middleware so the handler-side D6 check uses identical
// semantics. Same matching rules: full address (case-insensitive)
// OR domain suffix ("@example.com").
func firstDisallowedRecipient(extracted, allowed []string) string {
	if len(allowed) == 0 {
		return ""
	}
	full := map[string]struct{}{}
	var domains []string
	for _, a := range allowed {
		if strings.HasPrefix(a, "@") {
			domains = append(domains, strings.ToLower(a))
		} else {
			full[strings.ToLower(a)] = struct{}{}
		}
	}
	for _, addr := range extracted {
		lower := strings.ToLower(addr)
		if _, ok := full[lower]; ok {
			continue
		}
		matched := false
		for _, d := range domains {
			if strings.HasSuffix(lower, d) {
				matched = true
				break
			}
		}
		if !matched {
			return addr
		}
	}
	return ""
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
