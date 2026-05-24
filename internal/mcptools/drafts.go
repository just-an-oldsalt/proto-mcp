package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gluon/rfc822"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Drafts. Four tools sharing the encryption-on-write path that the
// SDK hides behind CreateDraft / UpdateDraft (Proton encrypts the
// body with the sender's keyring before persisting).
//
// Inputs accept either body_text or body_html (or both). HTML goes
// through sanitize.Outbound first — same bluemonday policy as
// inbound, so scripts / iframes / remote-image refs are stripped
// before encryption. The LLM cannot send markup we wouldn't have
// accepted from a stranger.

type draftInputCreate struct {
	Subject  string   `json:"subject"`
	To       []string `json:"to"`
	CC       []string `json:"cc,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
	BodyText string   `json:"body_text,omitempty"`
	BodyHTML string   `json:"body_html,omitempty"`
}

type draftInputUpdate struct {
	DraftID  string   `json:"draft_id"`
	Subject  string   `json:"subject,omitempty"`
	To       []string `json:"to,omitempty"`
	CC       []string `json:"cc,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
	BodyText string   `json:"body_text,omitempty"`
	BodyHTML string   `json:"body_html,omitempty"`
}

type draftResult struct {
	DraftID  string   `json:"draft_id"`
	Subject  string   `json:"subject"`
	To       []string `json:"to,omitempty"`
	CC       []string `json:"cc,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
	MIMEType string   `json:"mime_type"`
}

func mailDraftCreate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_draft_create",
		Description: "Create a new draft message. Proton encrypts the body with your address keyring before persisting. " +
			"Body can be plain text (body_text) or HTML (body_html) — HTML is sanitized through the same allowlist " +
			"as inbound mail before encryption (scripts / iframes / tracking pixels stripped). " +
			"Returns the draft_id which mail_send_draft / mail_draft_update / mail_draft_delete take.",
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
		OutputSchema: json.RawMessage(draftResultSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in draftInputCreate
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_create: "+err.Error())
			}
			if in.Subject == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_draft_create: subject and at least one to recipient are required")
			}

			tpl, mimeType, err := buildDraftTemplate(deps, in.Subject, in.To, in.CC, in.BCC, in.BodyText, in.BodyHTML)
			if err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_create: "+err.Error())
			}

			senderAddrID, addrKR, err := senderKeyring(deps)
			if err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}
			_ = senderAddrID

			msg, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, gpa.CreateDraftReq{
				Message: tpl,
				Action:  gpa.ReplyAction, // zero value; ParentID empty = new draft
			})
			if err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}
			mirrorUpsertDraft(ctx, deps, msg, "drafts")
			return mcp.StructuredResult(draftResult{
				DraftID:  msg.ID,
				Subject:  msg.Subject,
				To:       addressStrings(msg.ToList),
				CC:       addressStrings(msg.CCList),
				BCC:      addressStrings(msg.BCCList),
				MIMEType: mimeType,
			})
		},
	}
}

func mailDraftUpdate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "mail_draft_update",
		Description: "Update an existing draft. Any field you don't pass is preserved. body_html still runs through outbound sanitization.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"draft_id":  {"type": "string"},
				"subject":   {"type": "string"},
				"to":        {"type": "array", "items": {"type": "string"}},
				"cc":        {"type": "array", "items": {"type": "string"}},
				"bcc":       {"type": "array", "items": {"type": "string"}},
				"body_text": {"type": "string"},
				"body_html": {"type": "string"}
			},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(draftResultSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in draftInputUpdate
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: draft_id is required")
			}

			// Fetch the current draft so unspecified fields persist.
			current, err := deps.Session.Client.GetMessage(ctx.Std, in.DraftID)
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: fetch current: %v", err), nil
			}

			subject := pickStr(in.Subject, current.Subject)
			to := pickAddrList(in.To, current.ToList)
			cc := pickAddrList(in.CC, current.CCList)
			bcc := pickAddrList(in.BCC, current.BCCList)
			// body_text / body_html / nothing — if nothing supplied,
			// keep the existing body via empty pass to buildDraftTemplate
			// (which treats both empty as plain text "" — wrong).
			// Instead, default to text version of current body so the
			// SDK keeps the same content.
			text, html := in.BodyText, in.BodyHTML
			if text == "" && html == "" {
				text = sanitize.Text(current.Body)
			}

			toStrs := toEmailStrings(to)
			ccStrs := toEmailStrings(cc)
			bccStrs := toEmailStrings(bcc)
			tpl, mimeType, err := buildDraftTemplate(deps, subject, toStrs, ccStrs, bccStrs, text, html)
			if err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: "+err.Error())
			}

			_, addrKR, err := senderKeyring(deps)
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}
			msg, err := deps.Session.Client.UpdateDraft(ctx.Std, in.DraftID, addrKR, gpa.UpdateDraftReq{
				Message: tpl,
			})
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}
			mirrorUpsertDraft(ctx, deps, msg, "drafts")
			return mcp.StructuredResult(draftResult{
				DraftID:  msg.ID,
				Subject:  msg.Subject,
				To:       addressStrings(msg.ToList),
				CC:       addressStrings(msg.CCList),
				BCC:      addressStrings(msg.BCCList),
				MIMEType: mimeType,
			})
		},
	}
}

func mailDraftDelete(deps Deps) mcp.Tool {
	type input struct {
		DraftID string `json:"draft_id"`
	}
	return mcp.Tool{
		Name:        "mail_draft_delete",
		Description: "Delete a draft. This is a Proton DeleteMessage on the draft, which trashes it (recoverable from Trash).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"draft_id": {"type": "string"}},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"draft_id": {"type": "string"},
				"deleted":  {"type": "boolean"}
			},
			"required": ["draft_id", "deleted"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			subj := lookupSubject(deps, in.DraftID)
			title := mcp.SanitizePromptText("Approve mail_draft_delete?", 120)
			body := "delete draft " + subj + " (moves to Trash; recoverable)"
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_delete: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_delete: draft_id is required")
			}
			if err := deps.Session.Client.DeleteMessage(ctx.Std, in.DraftID); err != nil {
				return mcp.ErrorResult("mail_draft_delete: %v", err), nil
			}
			_ = deps.Store.DeleteMessage(ctx.Std, in.DraftID)
			return mcp.StructuredResult(map[string]any{
				"draft_id": in.DraftID,
				"deleted":  true,
			})
		},
	}
}

func mailDraftList(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "mail_draft_list",
		Description: "List drafts from the local mirror, newest-first. Convenience over mail_list folder=\"drafts\" — same data, narrower default.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"limit":  {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
				"cursor": {"type": "string"}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(messageListSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in struct {
				Limit  int    `json:"limit,omitempty"`
				Cursor string `json:"cursor,omitempty"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_list: "+err.Error())
				}
			}
			opts := store.SearchOpts{
				Limit:  in.Limit,
				Filter: store.ListFilter{Folder: "drafts"},
			}
			qhash := filterHash(opts.Filter)
			if in.Cursor != "" {
				off, ok := decodeCursor(in.Cursor, qhash)
				if !ok {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						"mail_draft_list: cursor is stale or belongs to a different query")
				}
				opts.Offset = off
			}
			hits, err := deps.Store.Search(ctx.Std, "", opts)
			if err != nil {
				return nil, err
			}
			summaries := make([]messageSummary, 0, len(hits))
			for _, h := range hits {
				summaries = append(summaries, hitToSummary(h))
			}
			res := listResult{Messages: summaries}
			if opts.Limit > 0 && len(hits) >= opts.Limit {
				res.NextCursor = encodeCursor(opts.Offset+len(hits), qhash)
			}
			return mcp.StructuredResult(res)
		},
	}
}

// buildDraftTemplate is the shared body-building path. Handles
// outbound HTML sanitization and the MIME-type decision (plain
// text when no HTML, HTML when html is provided — and if both
// supplied, HTML wins since rich body is more expressive).
func buildDraftTemplate(deps Deps, subject string, to, cc, bcc []string, bodyText, bodyHTML string) (gpa.DraftTemplate, string, error) {
	body := bodyText
	mimeType := "text/plain"
	if bodyHTML != "" {
		// SECURITY: outbound sanitization. Same allowlist as inbound.
		body = sanitize.Outbound(bodyHTML)
		mimeType = "text/html"
	}

	sender, err := primarySenderAddress(deps)
	if err != nil {
		return gpa.DraftTemplate{}, "", err
	}
	toList, err := parseAddrList(to)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("to: %w", err)
	}
	ccList, err := parseAddrList(cc)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("cc: %w", err)
	}
	bccList, err := parseAddrList(bcc)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("bcc: %w", err)
	}

	return gpa.DraftTemplate{
		Subject:  subject,
		Sender:   sender,
		ToList:   toList,
		CCList:   ccList,
		BCCList:  bccList,
		Body:     body,
		MIMEType: rfc822.MIMEType(mimeType),
	}, mimeType, nil
}

// primarySenderAddress returns the primary-address mail.Address for
// the current session.
func primarySenderAddress(deps Deps) (*mail.Address, error) {
	if deps.Session == nil {
		return nil, errors.New("no active session")
	}
	addr, ok := deps.Session.PrimaryAddress()
	if !ok {
		return nil, errors.New("no primary address resolved on session")
	}
	return &mail.Address{
		Name:    addr.DisplayName,
		Address: addr.Email,
	}, nil
}

// senderKeyring returns (addressID, *crypto.KeyRing) for the primary
// address. Used by CreateDraft / UpdateDraft for body encryption.
func senderKeyring(deps Deps) (string, *crypto.KeyRing, error) {
	if deps.Session == nil {
		return "", nil, errors.New("no active session")
	}
	addr, ok := deps.Session.PrimaryAddress()
	if !ok {
		return "", nil, errors.New("no primary address resolved on session")
	}
	kr, ok := deps.Session.AddrKRs[addr.ID]
	if !ok || kr == nil {
		return "", nil, fmt.Errorf("no keyring for address %s", addr.ID)
	}
	return addr.ID, kr, nil
}

func parseAddrList(addrs []string) ([]*mail.Address, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make([]*mail.Address, 0, len(addrs))
	for _, s := range addrs {
		a, err := mail.ParseAddress(s)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func toEmailStrings(addrs []*mail.Address) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.Address)
	}
	return out
}

func pickAddrList(preferred []string, fallback []*mail.Address) []*mail.Address {
	if len(preferred) > 0 {
		parsed, _ := parseAddrList(preferred)
		return parsed
	}
	return fallback
}

func addressStrings(addrs []*mail.Address) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.Address)
	}
	return out
}

func mirrorUpsertDraft(ctx mcp.Context, deps Deps, m gpa.Message, folder string) {
	row, err := protonMessageToStore(m)
	if err != nil {
		return
	}
	row.Folder = folder
	_ = deps.Store.UpsertMessage(ctx.Std, row)
}

// protonMessageToStore is a lightweight translator that pulls
// envelope fields off a full gpa.Message (the SDK returns this for
// CreateDraft / UpdateDraft / GetMessage). The full proton →
// store.Message translator (proton.ToStoreMessage) is metadata-only;
// we synthesize what we need here for drafts.
func protonMessageToStore(m gpa.Message) (store.Message, error) {
	toJSON, err := marshalAddrJSON(m.ToList)
	if err != nil {
		return store.Message{}, err
	}
	ccJSON, err := marshalAddrJSON(m.CCList)
	if err != nil {
		return store.Message{}, err
	}
	fromAddr, fromName := "", ""
	if m.Sender != nil {
		fromAddr, fromName = m.Sender.Address, m.Sender.Name
	}
	return store.Message{
		ID:          m.ID,
		ThreadID:    m.ID, // drafts get a self-thread until reply
		Subject:     m.Subject,
		FromAddress: fromAddr,
		FromName:    fromName,
		ToJSON:      toJSON,
		CcJSON:      ccJSON,
		Date:        time.Unix(m.Time, 0).UTC(),
		Unread:      false,
		SizeBytes:   int64(m.Size),
	}, nil
}

func marshalAddrJSON(addrs []*mail.Address) (string, error) {
	if len(addrs) == 0 {
		return "[]", nil
	}
	out := make([]map[string]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, map[string]string{
			"name":    a.Name,
			"address": a.Address,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

const draftResultSchema = `{
	"type": "object",
	"properties": {
		"draft_id":  {"type": "string"},
		"subject":   {"type": "string"},
		"to":        {"type": "array", "items": {"type": "string"}},
		"cc":        {"type": "array", "items": {"type": "string"}},
		"bcc":       {"type": "array", "items": {"type": "string"}},
		"mime_type": {"type": "string"}
	},
	"required": ["draft_id", "subject", "mime_type"]
}`
