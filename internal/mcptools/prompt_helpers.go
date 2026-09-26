package mcptools

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// --- PROTO-126: faithful recipient display in send-approval dialogs ---

// sanitizeField collapses line breaks and tabs in a single
// user-supplied value to spaces. SanitizePromptText deliberately
// PRESERVES newlines (they're the framework's field separators in the
// To/CC/BCC/Subject body), so a recipient or subject containing
// "\nBCC: evil@x" would otherwise inject a fake line and make the
// approval dialog misrepresent the send. We neutralize line breaks
// inside each value; only our own separators remain. Issue #125 added
// the Unicode line breaks (NEL, LINE / PARAGRAPH SEPARATOR), which
// render as new lines just like "\n".
func sanitizeField(s string) string {
	return fieldLineBreaks.Replace(s)
}

var fieldLineBreaks = strings.NewReplacer(
	"\r", " ", "\n", " ", "\t", " ",
	"\u0085", " ", "\u2028", " ", "\u2029", " ",
)

// joinAddrs sanitizes each address (PROTO-126) then comma-joins for
// display in an approval prompt. Addresses are never shortened: a
// cut-off address would misrepresent where the mail goes, so a list
// too long to show is refused by sendApprovalDialog instead.
func joinAddrs(addrs []string) string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, sanitizeField(a))
	}
	return strings.Join(out, ", ")
}

// --- Issue #125: approval dialogs that can't misrepresent a send ---
//
// The Touch ID dialog is the control that stops an injected
// instruction from sending mail (docs/security.md), so every
// send-family dialog follows the same rules:
//
//   - Recipients (To, CC, BCC) come before Subject and anything else
//     long or attacker-influenced.
//   - Recipients are bare addresses. A display name is free text and
//     could say anything, including another address.
//   - Each free-text field (subject, file names, IDs) is capped on its
//     own, so one long value can't push the rest out of view.
//   - The finished body is never truncated. If it is still over
//     promptBodyMaxRunes (hundreds of recipients, say), the call is
//     refused instead of shown in part.

const (
	// promptBodyMaxRunes is the most a send-family dialog may hold.
	promptBodyMaxRunes = 4000
	// promptSubjectMaxRunes caps the Subject line.
	promptSubjectMaxRunes = 200
	// promptNameMaxRunes caps a file name or message ID.
	promptNameMaxRunes = 100
)

// capField sanitizes one value for a dialog line and shortens it to
// max runes, ending with "..." when cut. (Not "…": SanitizePromptText's
// NFKC pass would expand it to "..." anyway.) Not for addresses; see
// joinAddrs.
func capField(s string, max int) string {
	s = sanitizeField(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-3]) + "..."
}

// promptAddrs renders raw recipient arguments (as the LLM passed them)
// as bare addresses, splitting any entry that holds several. An entry
// that doesn't parse is shown as given, since the send would fail on
// it anyway. An empty list renders as "(none)".
func promptAddrs(entries []string) string {
	var addrs []string
	for _, e := range entries {
		addrs = append(addrs, normalizeRecipientList(e)...)
	}
	return orNone(joinAddrs(addrs))
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// sendApprovalDialog is the one exit for every send-family dialog. It
// sanitizes the body without truncating it, and fails closed with an
// error (so PromptSnapshot denies the call) when the body is too long
// to show in full.
func sendApprovalDialog(toolName, body string) (title, sanitized string, err error) {
	sanitized, err = mcp.SanitizePromptTextStrict(body, promptBodyMaxRunes)
	if err != nil {
		return "", "", fmt.Errorf("%w; nothing was sent. Send to fewer recipients or attachments per call", err)
	}
	return mcp.SanitizePromptText("Approve "+toolName+"?", 120), sanitized, nil
}

// Phase 7/A — D36. Helpers that translate opaque IDs (message_id,
// label_id, folder destination) into human-readable strings for the
// Touch ID prompt body. Each tool's PromptBody closure calls these
// to assemble a sentence the user can actually verify before
// approving.
//
// Why deps lookups belong in PromptBody, not in the handler:
// the prompt fires BEFORE the handler runs. If we showed the user a
// generic "mail_move was requested" they'd have nothing to decide
// against. Subject and folder names come from the local mirror —
// already populated by backfill / sync — so the lookups are cheap
// (a single SQLite SELECT) and don't add a round-trip to Proton.
//
// All lookups time out at 1 second. The mirror is local SQLite; if
// it can't answer in that time something else is very wrong and we
// fall back to the raw ID. Better a slightly-uglier prompt than a
// stalled approval dialog.

const promptLookupTimeout = 1 * time.Second

// lookupSubject returns the message's Subject from the local mirror.
// Returns the messageID itself (truncated) if the lookup fails — the
// prompt is still readable, just less friendly.
func lookupSubject(deps Deps, messageID string) string {
	if deps.Store == nil || messageID == "" {
		return shortID(messageID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), promptLookupTimeout)
	defer cancel()
	m, err := deps.Store.GetMessage(ctx, messageID)
	if err != nil || m.Subject == "" {
		return shortID(messageID)
	}
	return quote(m.Subject)
}

// lookupSubjectAndFolder returns the Subject + current Folder name
// for a message. Used by mail_move and mail_trash where the prompt
// wants to say "move 'X' from Y to Z".
func lookupSubjectAndFolder(deps Deps, messageID string) (subject, folder string) {
	if deps.Store == nil || messageID == "" {
		return shortID(messageID), ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), promptLookupTimeout)
	defer cancel()
	m, err := deps.Store.GetMessage(ctx, messageID)
	if err != nil {
		return shortID(messageID), ""
	}
	if m.Subject == "" {
		subject = shortID(messageID)
	} else {
		subject = quote(m.Subject)
	}
	return subject, m.Folder
}

// lookupLabelName returns the label's display name from the mirror.
// Returns the labelID itself (truncated) on miss.
func lookupLabelName(deps Deps, labelID string) string {
	if deps.Store == nil || labelID == "" {
		return shortID(labelID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), promptLookupTimeout)
	defer cancel()
	l, err := deps.Store.GetLabel(ctx, labelID)
	if err != nil || l.Name == "" {
		return shortID(labelID)
	}
	return quote(l.Name)
}

// destinationName resolves a mail_move destination string to a
// friendly name. System folders map to their lower-case spelling
// ("Archive"); user-folder label_ids get resolved to their Name via
// the local mirror.
func destinationName(deps Deps, destination string) string {
	if destination == "" {
		return "(unspecified)"
	}
	// systemFolderToLabelID keys are the friendly names already.
	if _, isSystem := systemFolderToLabelID[strings.ToLower(destination)]; isSystem {
		return strings.Title(strings.ToLower(destination)) //nolint:staticcheck // Title is fine for ASCII folder names
	}
	// Otherwise it's a user-folder label_id — resolve via the
	// labels mirror.
	return lookupLabelName(deps, destination)
}

// shortID returns the first 8 characters of an ID followed by … so
// fallback prompts don't display 40+ chars of base64 noise. The
// redact carve-out already lets the FULL id pass through to the
// audit row; PromptBody just trims for readability.
func shortID(id string) string {
	if id == "" {
		return "(no id)"
	}
	if len(id) <= 12 {
		return id
	}
	return id[:8] + "…"
}

// quote wraps a string in matching single quotes for display.
// Strips newlines (a multi-line subject would corrupt the prompt
// layout). Truncates at 80 chars with an ellipsis.
func quote(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return "'" + s + "'"
}

// statePromptBody is the shared closure shape for the simple
// state-change tools (mark_read / mark_unread / star / unstar /
// move / trash). The caller supplies the verb phrase template; we
// inject Subject + (optionally) destination.
//
// Example: statePromptBody("trash %s") + a message with Subject
// "Re: gear list" → "trash 'Re: gear list'".
func statePromptBody(_ Deps, verb string) string {
	return verb
}

// ensure compiler doesn't drop unused symbols if a caller refactors.
var _ = fmt.Sprintf
var _ = store.Message{}
