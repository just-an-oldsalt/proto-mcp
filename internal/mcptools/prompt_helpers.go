package mcptools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

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
