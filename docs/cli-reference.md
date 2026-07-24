# CLI & tool reference

## The `protonmcp` CLI

Run `protonmcp <command>`. The commands you'll actually use day to day are
`login`, `daemon`, and `install`; the rest are for inspection and
maintenance. When something isn't working, start with `protonmcp doctor`.

| Command | What it does |
|---|---|
| `setup` | Run first-time setup end to end: sign in, copy the mailbox index, start the background service, connect Claude, then verify. Skips any step already complete, so it doubles as a repair command. Flags: `--db`, `--force`. |
| `doctor` | Check every part of the install — binaries and version skew, Touch ID / lockwatch helpers, keychain session, local mirror, daemon, recorded binary hash, and Claude client registration — then print the exact command to fix anything broken. Never prompts for Touch ID. Exits non-zero if something is wrong. Flags: `--db`. |
| `version` | Print the build version, commit, and platform. `protonmcpd --version` and `protonmcp-shim --version` do the same, which is how `doctor` detects a partial upgrade. |
| `login` | Run the full Proton login flow (SRP password + TOTP + key unlock) and save the session to the macOS Keychain. |
| `logout` | Revoke the server-side session and delete the Keychain entry. |
| `whoami` | Print an account summary. Resumes the saved session, or falls back to a one-time login. |
| `backfill` | Drain message metadata into the local SQLite mirror. Flags: `--db`, `--yes`, `--limit`. |
| `calendar-backfill` | Mirror calendars + event metadata. Pass `--decrypt` to decrypt every event now (warms `calendar_events` full-text search). Flags: `--db`, `--decrypt`. |
| `read` | Print a single decrypted message (text + sanitized HTML) as JSON. Flags: `--db`, `--refresh`. |
| `search` | Query the local mirror. DSL: `from:`, `to:`, `subject:`, `in:`, `before:`, `after:`, `has:attachment`, plus bare full-text terms. Flags: `--db`, `--limit`, `--offset`. |
| `sync` | Drain pending events into the mirror (incremental) — mail and calendar. Flags: `--db`. |
| `serve-stdio` | Run as an MCP server over stdin/stdout (single-process mode). Prefer `install`. |
| `install` | Register proto-mcp with Claude Desktop and/or Claude Code. Flags: `--client {desktop\|code\|all}`, `--dry-run`. |
| `uninstall` | Remove proto-mcp from the selected client config(s). |
| `daemon` | `install` / `uninstall` / `start` / `stop` / `restart` / `status` — manage the LaunchAgent. |
| `policy` | `reload` / `show` / `validate` — see [configuration.md](./configuration.md). |
| `lock` / `unlock` | Lock or Touch-ID-unlock the running daemon. |
| `purge` | Trim the cached-body window. Flags: `--older-than`, `--vacuum`. |

## The 34 MCP tools

These are what Claude calls. Reads are allow-by-default; every write is
deny-by-default and Touch-ID gated (see [security.md](./security.md)).

### Read & search (9)

| Tool | Purpose |
|---|---|
| `account_whoami` | Account summary for the active session. |
| `mail_list` | List messages with filters (folder, label, read state…). |
| `mail_search` | Full-text + structured search over the local mirror. |
| `mail_read` | Read one message (decrypted text + sanitized HTML). |
| `mail_read_thread` | Reconstruct and read a full conversation. |
| `mail_list_attachments` | List a message's attachments (names, sizes, types). |
| `labels_list` | List labels. |
| `folders_list` | List folders. |
| `mail_sync` | Pull the latest changes from Proton into the mirror. |

### Organize (5)

| Tool | Purpose |
|---|---|
| `mail_mark_read` | Mark message(s) read. |
| `mail_mark_unread` | Mark message(s) unread. |
| `mail_move` | Move message(s) to a folder. |
| `mail_label` | Add/remove labels on message(s). |
| `mail_trash` | Move message(s) to Trash. |

### Labels & folders (6)

`labels_create`, `labels_update`, `labels_delete`,
`folders_create`, `folders_update`, `folders_delete` — full CRUD, with
colour-palette validation on create/update.

### Drafts (4)

`mail_draft_create`, `mail_draft_update`, `mail_draft_delete`,
`mail_draft_list`.

### Send (5)

| Tool | Purpose |
|---|---|
| `mail_send` | Compose and send a new message. TTL 0 — always re-prompts. |
| `mail_send_draft` | Send an existing draft. |
| `mail_reply` | Reply to the sender. |
| `mail_reply_all` | Reply to everyone. |
| `mail_forward` | Forward a message (carries attachments). |

### Attachments (2)

| Tool | Purpose |
|---|---|
| `mail_download_attachment` | Decrypt an attachment and return it as `{path, sha256, size_bytes}`. |
| `mail_save_attachment` | Save a decrypted attachment to a chosen path. |

### Calendar (3, read-only)

| Tool | Purpose |
|---|---|
| `calendar_list` | List the user's calendars. |
| `calendar_events` | List/search events by date range, calendar, and/or full-text query. Cursor-paginated. |
| `calendar_read_event` | Read one event in full, including description and attendees. |

Proton Calendar is end-to-end encrypted; events decrypt locally with the
same keyring as mail. Notes & limitations:

- **Read-only.** `go-proton-api` exposes no calendar write/encrypt path, so
  there is no create/edit/delete or RSVP.
- **Recurrence** is surfaced as the master event plus its raw `rrule`
  (`recurring: true`); individual occurrences are **not** expanded.
- **Full-text search** (`calendar_events query=…`) matches only events
  already decrypted. Background sync mirrors metadata lazily; run
  `protonmcp calendar-backfill --decrypt` to decrypt everything up front and
  warm the index, or just list a date range once (which decrypts that page).
- Decrypted event text is cached in SQLite — same plaintext-at-rest posture
  as message bodies (see [security.md](./security.md)), swept by
  `protonmcp purge`.

> There is deliberately **no permanent-delete tool**. `mail_trash` moves a
> message to Trash and is reversible with `mail_move`; nothing Claude can
> call destroys mail irrecoverably. `internal/policy/default.yaml`
> reserves a `mail_delete_permanent: deny` stanza so the name is spoken
> for if it is ever implemented — setting it to `prompt` today does
> nothing, because no such tool exists.
