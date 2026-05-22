// Package mcptools assembles the read-side MCP tools that Phase 3
// wires into the JSON-RPC server. Each tool is a thin handler over
// the work the lower layers already do:
//
//	mail.list                store.ListMessages
//	mail.search              store.Search
//	mail.read                proton.FetchAndDecryptMessage + body cache
//	mail.read_thread         store + body cache, oldest-first
//	mail.list_attachments    messages.raw_json parse
//	labels.list              store.labels (type=1)
//	folders.list             store.labels (type=3)
//	mail.sync                internal/sync.RunOnce
//	account.whoami           proton.Session info
//
// Decisions from Phase 3 planning sign-off:
//
//	Q1 dotted names           Q4 eager session at initialize
//	Q2 structured + outputSchema  Q5 oldest-first threads
//	Q3 opaque base64 cursors  Q6 both text + html in mail.read
//	Q7 mail.sync as a tool, model decides when to call it
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
	// hit the API (mail.read on cache miss, mail.sync) reach
	// through this. Read-from-mirror tools (mail.list, mail.search,
	// labels.list) don't touch it.
	Session *protonclient.Session

	// Store is the local SQLite mirror.
	Store *store.Store
}

// All returns every read-tool registered, in the order the server
// should advertise them. Order influences nothing functionally — it
// only affects how tools/list reads if a human inspects the wire
// transcript.
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
	}
}

// store.ListFilter (in internal/store) replaced an earlier
// listFilter sketch here — mail.list and mail.read_thread both build
// store.SearchOpts with the right filter and call store.Search with
// an empty query string. No package-local filter type needed.

// (no helpers — every tool inlines what it needs)
var _ = protonclient.AppVersion // keep the import; used by Description verbiage elsewhere
