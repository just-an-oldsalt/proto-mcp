// Package mcptools assembles the read-side MCP tools that Phase 3
// wires into the JSON-RPC server. Each tool is a thin handler over
// the work the lower layers already do:
//
//	mail_list                store.ListMessages
//	mail_search              store.Search
//	mail_read                proton.FetchAndDecryptMessage + body cache
//	mail_read_thread         store + body cache, oldest-first
//	mail_list_attachments    messages.raw_json parse
//	labels_list              store.labels (type=1)
//	folders_list             store.labels (type=3)
//	mail_sync                internal/sync.RunOnce
//	account_whoami           proton.Session info
//
// Decisions from Phase 3 planning sign-off:
//
//	Q1 dotted names           Q4 eager session at initialize
//	Q2 structured + outputSchema  Q5 oldest-first threads
//	Q3 opaque base64 cursors  Q6 both text + html in mail_read
//	Q7 mail_sync as a tool, model decides when to call it
package mcptools

import (
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Deps is what every tool needs to do its work. Tools never reach
// for global state; they take a Deps value at construction time and
// hold the references via closures in the Handler.
type Deps struct {
	// Session is the unlocked Proton session. Tools that need to
	// hit the API (mail_read on cache miss, mail_sync) reach
	// through this. Read-from-mirror tools (mail_list, mail_search,
	// labels_list) don't touch it.
	Session *protonclient.Session

	// Store is the local SQLite mirror.
	Store *store.Store
}

// All returns every tool registered, in the order the server should
// advertise them. Order influences nothing functionally — it only
// affects how tools/list reads if a human inspects the wire transcript.
func All(deps Deps) []mcp.Tool {
	return []mcp.Tool{
		accountWhoami(deps),
		mailList(deps),
		mailSearch(deps),
		mailRead(deps),
		mailReadThread(deps),
		mailListAttachments(deps),
		labelsList(deps),
		foldersList(deps),
		mailSync(deps),
		// Phase 5/A — state mutations.
		mailMarkRead(deps),
		mailMarkUnread(deps),
		mailMove(deps),
		mailLabel(deps),
		mailTrash(deps),
		// Phase 5/B — labels and folders CRUD.
		labelsCreate(deps),
		labelsUpdate(deps),
		labelsDelete(deps),
		foldersCreate(deps),
		foldersUpdate(deps),
		foldersDelete(deps),
		// Phase 5/C — drafts (outbound sanitization on the encrypt path).
		mailDraftCreate(deps),
		mailDraftUpdate(deps),
		mailDraftDelete(deps),
		mailDraftList(deps),
		// Phase 5/D — send family (irreversible; per-tool prompt body).
		mailSend(deps),
		mailSendDraft(deps),
		mailReply(deps),
		mailReplyAll(deps),
		mailForward(deps),
	}
}

// store.ListFilter (in internal/store) replaced an earlier
// listFilter sketch here — mail_list and mail_read_thread both build
// store.SearchOpts with the right filter and call store.Search with
// an empty query string. No package-local filter type needed.

// (no helpers — every tool inlines what it needs)
var _ = protonclient.AppVersion // keep the import; used by Description verbiage elsewhere
