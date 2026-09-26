package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
)

// --- Issue #116: the approval dialog and the send act on one snapshot ---
//
// mail_send_draft / mail_reply / mail_reply_all used to fetch the
// draft or parent twice: once to render the Touch ID dialog, once in
// the handler to build the send. A concurrent mail_draft_update
// (decision: allow, and the daemon serves several connections) could
// rewrite the draft while the dialog was up, so the user approved one
// set of recipients and a different one was sent.
//
// Now each of these tools uses mcp.Tool.PromptSnapshot: one fetch
// renders the dialog, and that same message reaches the handler as
// mcp.Context.Snapshot. For drafts, which stay mutable on the server,
// the handler re-fetches under draftLocks and refuses if anything
// differs from the approved snapshot; mail_draft_update takes the
// same lock, so it can't slip in between that check and SendDraft.
// Edits made outside this daemon (the Proton web UI) can still land
// in that last round-trip — those are the user's own hands.

// draftLocks serializes mutation of a draft (mail_draft_update)
// against its verify-and-send (mail_send_draft). Package-level:
// draft IDs are account-global and Deps is passed by value.
var draftLocks keyedMutex

// keyedMutex is a set of mutexes keyed by string, created on demand
// and dropped when the last holder releases.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	mu   sync.Mutex
	refs int
}

// Lock blocks until key is free, then returns its unlock func.
func (k *keyedMutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyedEntry{}
	}
	e := k.m[key]
	if e == nil {
		e = &keyedEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

// promptSnapshotTimeout bounds the fetch behind a PromptSnapshot.
// Longer than promptLookupTimeout: that one only degrades a dialog to
// a generic line, whereas a failed snapshot denies the call.
const promptSnapshotTimeout = 10 * time.Second

// fetchForPrompt is the single server read behind a PromptSnapshot.
func fetchForPrompt(ctx context.Context, deps Deps, id string) (gpa.Message, error) {
	if deps.Session == nil || deps.Session.Client == nil {
		return gpa.Message{}, errors.New("no active Proton session")
	}
	ctx, cancel := context.WithTimeout(ctx, promptSnapshotTimeout)
	defer cancel()
	return deps.Session.Client.GetMessage(ctx, id)
}

// draftPromptSnapshot is mail_send_draft's PromptSnapshot.
func draftPromptSnapshot(deps Deps) func(context.Context, json.RawMessage) (string, string, any, error) {
	return func(ctx context.Context, args json.RawMessage) (string, string, any, error) {
		var in struct {
			DraftID string `json:"draft_id"`
		}
		_ = json.Unmarshal(args, &in)
		if in.DraftID == "" {
			return "", "", nil, errors.New("draft_id is required")
		}
		draft, err := fetchForPrompt(ctx, deps, in.DraftID)
		if err != nil {
			return "", "", nil, fmt.Errorf("fetch draft: %w", err)
		}
		title, body, err := sendApprovalDialog("mail_send_draft", draftPromptBody(draft))
		if err != nil {
			return "", "", nil, err
		}
		return title, body, draft, nil
	}
}

// draftPromptBody renders everything about a draft that decides where
// it goes and what rides along: every recipient, the subject, and
// every attachment (all of them — the snapshot check compares all of
// them, so the dialog shows all of them). Recipients come first and
// as bare addresses (issue #125).
func draftPromptBody(d gpa.Message) string {
	parts := []string{"Send draft " + capField(d.ID, promptNameMaxRunes)}
	parts = append(parts, recipientLines(
		joinAddrs(addressStrings(d.ToList)),
		joinAddrs(addressStrings(d.CCList)),
		joinAddrs(addressStrings(d.BCCList)),
	)...)
	parts = append(parts, "Subject: "+capField(d.Subject, promptSubjectMaxRunes))
	if s := messageAttachmentsList(d.Attachments); s != "" {
		parts = append(parts, "Attachments: "+s)
	}
	return strings.Join(parts, "\n")
}

// recipientLines renders the To / CC / BCC lines of a send dialog from
// already-joined bare-address lists. All three always appear, "(none)"
// when empty, so the user can see there is no BCC.
func recipientLines(to, cc, bcc string) []string {
	return []string{"To: " + orNone(to), "CC: " + orNone(cc), "BCC: " + orNone(bcc)}
}

// messageAttachmentsList renders every attachment already on a server
// message as "name (size), …", each name capped. "" when none.
func messageAttachmentsList(atts []gpa.Attachment) string {
	out := make([]string, 0, len(atts))
	for _, a := range atts {
		out = append(out, fmt.Sprintf("%s (%s)", capField(a.Name, promptNameMaxRunes), humanBytes(a.Size)))
	}
	return strings.Join(out, ", ")
}

// draftChange names the first thing that differs between the draft
// the user approved and the one about to be sent, or "" if none.
// Body is compared as ciphertext: UpdateDraft re-encrypts, so any
// edit changes it even when the plaintext can't be shown in a dialog.
func draftChange(approved, current gpa.Message) string {
	switch {
	case approved.Subject != current.Subject:
		return "subject"
	case !sameAddr(approved.Sender, current.Sender):
		return "sender"
	case !sameAddrs(approved.ToList, current.ToList),
		!sameAddrs(approved.CCList, current.CCList),
		!sameAddrs(approved.BCCList, current.BCCList):
		return "recipients"
	case approved.MIMEType != current.MIMEType, approved.Body != current.Body:
		return "body"
	case !sameAttachments(approved.Attachments, current.Attachments):
		return "attachments"
	}
	return ""
}

func sameAddr(a, b *mail.Address) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Name == b.Name && strings.EqualFold(a.Address, b.Address)
}

func sameAddrs(a, b []*mail.Address) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameAddr(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameAttachments(a, b []gpa.Attachment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name || a[i].Size != b[i].Size {
			return false
		}
	}
	return true
}

// replyPromptSnapshot is mail_reply / mail_reply_all's PromptSnapshot.
// The dialog shows the literal To/CC the handler will send to,
// computed by the same replyRecipients call from the same parent.
func replyPromptSnapshot(deps Deps, toolName string, replyAll bool) func(context.Context, json.RawMessage) (string, string, any, error) {
	return func(ctx context.Context, args json.RawMessage) (string, string, any, error) {
		var in struct {
			InReplyTo   string                `json:"in_reply_to"`
			Attachments []sendAttachmentInput `json:"attachments,omitempty"`
		}
		_ = json.Unmarshal(args, &in)
		if in.InReplyTo == "" {
			return "", "", nil, errors.New("in_reply_to is required")
		}
		parent, err := fetchForPrompt(ctx, deps, in.InReplyTo)
		if err != nil {
			return "", "", nil, fmt.Errorf("fetch parent: %w", err)
		}
		title, body, err := sendApprovalDialog(toolName,
			replyPromptBody(deps, parent, in.InReplyTo, replyAll, in.Attachments))
		if err != nil {
			return "", "", nil, err
		}
		return title, body, parent, nil
	}
}

// replyPromptBody renders a reply dialog from the fetched parent:
// recipients first (issue #125), then the subject the reply will
// carry, then any new attachments.
func replyPromptBody(deps Deps, parent gpa.Message, parentID string, replyAll bool, attachments []sendAttachmentInput) string {
	verb := "Reply to"
	if replyAll {
		verb = "Reply-all to"
	}
	to, cc := replyRecipients(deps, parent, replyAll)
	parts := []string{verb + " message " + capField(parentID, promptNameMaxRunes)}
	parts = append(parts, recipientLines(joinAddrs(to), joinAddrs(cc), "")...)
	parts = append(parts, "Subject: "+capField(replySubject(parent.Subject), promptSubjectMaxRunes))
	if decoded, err := decodeAndValidateAttachments(deps, attachments); err == nil {
		if s := attachmentsSummary(decoded); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

// forwardPromptSnapshot is mail_forward's PromptSnapshot (issue #125).
// It fetches the parent once so the dialog can say what is being
// forwarded (its subject and, when include_parent_attachments is set,
// its attachments); sendForward then forwards that same parent.
func forwardPromptSnapshot(deps Deps) func(context.Context, json.RawMessage) (string, string, any, error) {
	return func(ctx context.Context, args json.RawMessage) (string, string, any, error) {
		var in forwardInput
		_ = json.Unmarshal(args, &in)
		if in.ForwardOf == "" {
			return "", "", nil, errors.New("forward_of is required")
		}
		parent, err := fetchForPrompt(ctx, deps, in.ForwardOf)
		if err != nil {
			return "", "", nil, fmt.Errorf("fetch parent: %w", err)
		}
		title, body, err := sendApprovalDialog("mail_forward", forwardPromptBody(deps, parent, in))
		if err != nil {
			return "", "", nil, err
		}
		return title, body, parent, nil
	}
}

// forwardPromptBody renders a forward dialog: recipients (bare
// addresses, from args), the subject the forward will carry, new
// attachments, and — when the call carries them over — every one of
// the parent's attachments.
func forwardPromptBody(deps Deps, parent gpa.Message, in forwardInput) string {
	parts := []string{"Forward message " + capField(in.ForwardOf, promptNameMaxRunes)}
	parts = append(parts, recipientLines(promptAddrs(in.To), promptAddrs(in.CC), promptAddrs(in.BCC))...)
	parts = append(parts, "Subject: "+capField(forwardSubject(parent.Subject), promptSubjectMaxRunes))
	if decoded, err := decodeAndValidateAttachments(deps, in.Attachments); err == nil {
		if s := attachmentsSummary(decoded); s != "" {
			parts = append(parts, s)
		}
	}
	if in.IncludeParentAttachments {
		parts = append(parts, "Forwarded attachments: "+orNone(messageAttachmentsList(parent.Attachments)))
	}
	return strings.Join(parts, "\n")
}

// forwardSubject prefixes Fwd: unless already present.
func forwardSubject(s string) string {
	if strings.HasPrefix(strings.ToLower(s), "fwd:") {
		return s
	}
	return "Fwd: " + s
}

// replySubject prefixes Re: unless already present.
func replySubject(s string) string {
	if strings.HasPrefix(strings.ToLower(s), "re:") {
		return s
	}
	return "Re: " + s
}

// replyRecipients: reply → the original sender; reply-all → sender in
// To, and the original To+CC minus our own addresses in CC.
func replyRecipients(deps Deps, parent gpa.Message, replyAll bool) (to, cc []string) {
	to = []string{}
	if parent.Sender != nil {
		to = append(to, parent.Sender.Address)
	}
	cc = []string{}
	if replyAll {
		self := selfAddresses(deps)
		for _, list := range [][]*mail.Address{parent.ToList, parent.CCList} {
			for _, a := range list {
				if a != nil && !contains(self, strings.ToLower(a.Address)) && !contains(to, a.Address) {
					cc = append(cc, a.Address)
				}
			}
		}
	}
	return to, cc
}
