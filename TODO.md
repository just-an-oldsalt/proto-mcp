# proto-mcp — TODO

> Working doc for incremental build of the Proton MCP daemon described in
> the design spec (root of this repo, pasted into the kick-off conversation).
> Keep this in sync as you go. Update statuses; move stale stuff to the
> "Done / decided" section at the bottom rather than deleting it.
>
> Resumption rule: a future Claude Code session should be able to open this
> file and continue work without re-reading the original conversation. Add
> any context that future-you will need.

## Status at a glance

- [x] Phase 0 — repo skeleton, Go toolchain, pinned deps, auth smoke test
- [ ] Phase 1 — SQLite + full backfill of message metadata
- [ ] Phase 2 — event-loop sync, lazy body decrypt, FTS5 search
- [ ] Phase 3 — MCP server (hand-rolled JSON-RPC over stdio for now)
- [ ] Phase 4 — policy engine + audit log + Touch ID approval broker
- [ ] Phase 5 — write tools (drafts, send, trash, label/folder CRUD)
- [ ] Phase 6 — Unix socket daemon, shim, launchd, Keychain, lock/unlock
- [ ] Phase 7 — polish (rate limit, log rotation, signing/notarization, docs)

## Quickstart for whoever picks this up

```sh
# build
go build -o bin/protonmcp ./cmd/protonmcp

# verify auth (one-password account, no 2FA)
PROTONMCP_EMAIL=you@proton.me \
PROTONMCP_PASSWORD='...' \
  ./bin/protonmcp whoami

# with TOTP 2FA
PROTONMCP_EMAIL=you@proton.me \
PROTONMCP_PASSWORD='...' \
PROTONMCP_TOTP=123456 \
  ./bin/protonmcp whoami

# with legacy two-password mailbox
PROTONMCP_EMAIL=you@proton.me \
PROTONMCP_PASSWORD='login-pass' \
PROTONMCP_MAILBOX_PASSWORD='mailbox-pass' \
  ./bin/protonmcp whoami
```

Successful output prints user ID, primary address, address count, password
mode, 2FA mode, storage used, and login+unlock duration.

## Repo layout

```
cmd/
  protonmcp/        # CLI entry point — currently only `whoami`
internal/
  proton/           # go-proton-api wrapper: Login, Session, key unlock
  config/           # (empty — placeholder for policy.yaml loading)
helpers/
  touchid/          # (empty — Swift Touch ID helper goes here in Phase 4)
docs/               # (empty — threat model + tool reference land here)
```

## Phase 0 — Foundation (done)

- [x] `go mod init github.com/just-an-oldsalt/proto-mcp`. Spec calls out
      `protonmcp` as the working name; no wittier alt has stuck. Folder /
      repo are `proto-mcp`; binary is `protonmcp`.
- [x] Pinned `github.com/ProtonMail/go-proton-api` to
      `v0.4.1-0.20260319112440-799673ddc2db` — the version proton-bridge
      `v3.24.2` ships with.
- [x] Mirrored Bridge's `replace` directive for resty
      (`github.com/ProtonMail/resty/v2`) — required, replace directives in
      dependencies don't propagate.
- [x] `cmd/protonmcp` with `whoami` subcommand driven by env vars.
- [x] `internal/proton.Login` does SRP login → optional Auth2FA → GetUser
      → GetAddresses → GetSalts → key unlock. Wipes keyring on Session.Close.
- [x] App version header impersonates Bridge: `macos-bridge@3.24.2`. Proton
      validates AppVersion against an allowlist; using our own ID would 400.
      **Decision to revisit:** apply for our own client identifier before
      any public release.

## Phase 1 — Local SQLite mirror (next up)

Goal: cold backfill of message metadata into a local SQLite store so reads
and search can be answered offline.

- [ ] Decide migration tool: `pressly/goose` vs `golang-migrate`. Goose has
      embedded migrations and is simpler. Pick goose unless we hit a wall.
- [ ] Add `internal/store` package wrapping `database/sql` + `mattn/go-sqlite3`.
      Open `~/Library/Application Support/protonmcp/store.db` with WAL mode.
- [ ] Implement schema from the design spec — see "Local SQLite schema
      (sketch)" section. Tables: `messages`, `message_labels`, `labels`,
      `messages_fts` (FTS5 virtual), `sync_state`, `audit_log`.
- [ ] `proton.Session` helper `ListAllMessageMetadata(ctx)` that pages
      through `client.GetMessageMetadataPage` (check exact name in
      `message.go`) and yields `MessageMetadata` items.
- [ ] Cold backfill command: `protonmcp backfill` — reads creds via env
      (same as whoami for now), logs in, drains pages, writes rows, prints
      progress every N batches.
- [ ] Persist sync cursor: after backfill, call `client.GetLatestEventID`
      (check name) and store under `sync_state` key `event_cursor`.
- [ ] **Skip body fetch in this phase.** Body decryption is in Phase 2.
      Just metadata: envelope fields, label IDs, folder, flags.

Gotchas:
- The page size for `GetMessageMetadataPage` is API-capped at 150; loop
  with the right cursor or filter.
- Some accounts have hundreds of thousands of messages. Print a count
  first and confirm before draining — backfill is the only operation
  that scans the whole mailbox.

## Phase 2 — Sync loop + lazy decrypt + FTS

- [ ] `internal/sync` goroutine. Calls `client.GetEvent(ctx, cursor)` every
      `poll_interval` (30s active, 5m idle). Applies the diff: created,
      updated, deleted messages; label changes; folder moves; etc. Use
      `proton.Event` and `EventResponse` types.
- [ ] On first `mail.read` for a given message_id, fetch the full message
      (`client.GetFullMessage` or `GetMessage` — verify), decrypt body
      using the appropriate address keyring (`Session.AddrKRs[addressID]`),
      cache `body_text`/`body_html` in the row, set `body_cached_at = now`.
- [ ] FTS5 index population: triggers on insert/update of `messages` mirror
      relevant columns into `messages_fts`. Tokenizer `porter unicode61`.
- [ ] Search implementation: translate a small query DSL
      (`from:alice subject:gear`) into FTS5 `MATCH` syntax + WHERE clauses.

Gotchas:
- HTML body must be sanitized before returning to the LLM. Use
  `microcosm-cc/bluemonday` strict policy. Strip `<script>`, `<iframe>`,
  remote image `src` (tracking pixels).
- Snippets: Proton-side snippets can be empty. Generate locally from
  decrypted body text — first 200 chars of the text body, collapse
  whitespace, strip quoted-reply markers (`> `).
- Body cache TTL: 24h per design spec. Run a periodic prune.

## Phase 3 — MCP server (read tools only)

Spec calls for hand-rolled JSON-RPC, not a library. ~200 lines.

- [ ] `internal/mcp` package: framing (Content-Length headers per LSP-style
      stdio, or newline-delimited — check current MCP spec), request/reply
      types, registry mapping `tool_name → handler`.
- [ ] Wire read tools first: `mail.list`, `mail.search`, `mail.read`,
      `mail.read_thread`, `mail.list_attachments`, `account.whoami`,
      `labels.list`, `folders.list`.
- [ ] `cmd/protonmcp serve-stdio` subcommand: reads JSON-RPC from stdin,
      writes to stdout. This is what Claude Desktop will spawn directly
      in the **interim** (before the daemon+shim split lands in Phase 6).
- [ ] End-to-end test from Claude Desktop with a local config pointing to
      this binary. Confirm `mail.list` and `mail.search` round-trip.

## Phase 4 — Policy engine, audit log, Touch ID

- [ ] `internal/policy`: YAML loader for `policy.default.yaml` (embedded
      with `//go:embed`) and `~/Library/Application Support/protonmcp/policy.yaml`
      (user override, shallow-merged on tool keys). Default policy verbatim
      from spec.
- [ ] Hot reload on `SIGHUP` and `protonmcp policy reload`. Invalid YAML
      keeps the previous policy in place.
- [ ] Middleware that wraps every tool handler:
      `decide(tool, args, caller) → allow|prompt|deny`. Decisions written
      to `audit_log` before action attempt; outcome filled in after.
- [ ] Audit log writer: SQLite row + JSONL mirror at
      `~/Library/Application Support/protonmcp/audit.log` for tailing.
      Redact per spec rules (body sha256+bytes, never literal body or
      passwords; recipient addresses logged in full).
- [ ] Swift Touch ID helper at `helpers/touchid/main.swift` (~50 LOC).
      Build with `swiftc -O -o helpers/touchid/protonmcp-touchid main.swift`.
      Reads structured JSON payload from stdin (title, body, caller),
      shows `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`,
      exits 0 on approve / 1 on deny / 2 on cancel.
- [ ] `internal/approval`: broker that execs the Swift helper, parses the
      result, caches approvals per-tool for the configured `ttl`. For
      `confirm: true` tools, also drive a native `NSAlert` for the
      second-step confirmation showing literal operation details (see
      spec "Approval prompt content" section).

## Phase 5 — Write tools

All gated through Phase 4 middleware.

- [ ] Drafts: `mail.draft_create`, `_update`, `_delete`, `_list`. These are
      `allow` by policy (no external effect).
- [ ] Send family: `mail.send`, `mail.send_draft`, `mail.reply`,
      `mail.reply_all`, `mail.forward`. All `prompt` + `confirm: true` +
      `rate_limit: 20/hour`. Confirmation prompt must include literal
      recipient list and subject (per spec).
- [ ] Trash and permanent delete: `mail.trash` (prompt, ttl 2m),
      `mail.delete_permanent` (prompt + confirm). `mail.empty_trash` and
      `mail.empty_spam` default to `deny` — opt-in only via user policy.
- [ ] Organize: `mail.move`, `mail.archive`, label apply/remove, mark
      read/unread, star/unstar. Mostly `allow` (reversible) except
      `mail.move` which is `prompt + ttl: 5m`.
- [ ] Labels/folders CRUD. Creation/rename = `prompt`; deletion =
      `prompt + confirm`.

## Phase 6 — Daemon, IPC, multi-client

This is the architecture flip described in the spec under "Why not
stdio-only?". The MCP-over-stdio interim build from Phase 3 keeps working
during this transition.

- [ ] `cmd/protonmcpd` long-running daemon. Listens on
      `~/Library/Application Support/protonmcp/protonmcp.sock`.
      Peer-credential check via `SO_PEERCRED` (only matching UID accepted).
- [ ] `cmd/protonmcp-shim` — stdio↔socket bridge MCP clients spawn.
      Forwards JSON-RPC frames either direction. Discovers the daemon
      socket via well-known path.
- [ ] `cmd/protonmcp install` writes a launchd plist to
      `~/Library/LaunchAgents/zone.dort.protonmcp.plist` and `launchctl load`s
      it. `protonmcp uninstall` reverses. Picks a stable label — see
      "Open: naming" below.
- [ ] Keychain integration: store mailbox password (and optional TOTP
      secret — see open question) in macOS Keychain via the Security
      framework. ACL restricts access to the signed `protonmcpd` binary.
      Use `keybase/go-keychain` or shell out to `security` CLI for v1.
- [ ] Lock/unlock state machine. Triggers per spec:
      `com.apple.screenIsLocked` distributed notification,
      `NSWorkspaceWillSleepNotification`, idle timeout
      (`idle_lock_minutes`, default 30), `protonmcp lock` CLI, `SIGUSR1`.
      In LOCKED state every tool call returns
      `{error: "daemon_locked", recovery: "run 'protonmcp unlock'"}`.
      Sync loop pauses but preserves `event_cursor`.
- [ ] `protonmcp setup` interactive flow per spec:
      "Proton email / Password / 2FA code / Touch ID consent to store
      credentials / install plist / start daemon".
- [ ] `protonmcp` CLI subcommands: `status`, `lock`, `unlock`,
      `policy reload`, `audit tail`, `audit query --tool ... --since ...`.

## Phase 7 — Polish

- [ ] Rate limiting per tool, per-window token bucket. Hard cap regardless
      of policy (e.g. `mail.send: 20/hour` even under `allow`).
- [ ] Token refresh on 401 — register `AuthHandler` / `DeauthHandler` on
      the proton.Client (see `client.go:53,60` in the SDK). On `Deauth`
      transition daemon to LOCKED.
- [ ] Log rotation: 50MB cap, keep 10 generations.
- [ ] Code signing + notarization for distribution. Even for local use,
      Touch ID prompt looks worse on unsigned binaries.
- [ ] README with threat model summary (one-paragraph version is in the
      spec — expand).
- [ ] GitHub Actions: lint (golangci-lint), test, build artifacts.

## Open questions still to decide

| # | Question | Status |
|---|----------|--------|
| 1 | MCP framing — newline-delimited JSON-RPC vs LSP-style Content-Length headers. Settle when starting Phase 3. | open |
| 2 | TOTP secret storage — store the secret in Keychain so unlock is hands-free, or always re-prompt? Storing defeats the second factor. **Lean: re-prompt only.** | open |
| 3 | HTML sanitization library — `bluemonday` strict policy is the default plan. | leaning bluemonday |
| 4 | Multi-address sending — spec defers to v1.1. Track `from: address` parameter in send tool schemas as TODO. | deferred |
| 5 | `mail.read: allow` default means a malicious email can prompt-inject Claude into reading more. Accepted in spec. Document loudly in README threat model. | accepted, document |
| 6 | Shim discovery path — `protonmcp install` writes absolute path of the shim into `~/Library/Application Support/Claude/claude_desktop_config.json`. | decided in spec |
| 7 | Naming — `protonmcp` is the working name. Folder is `proto-mcp`. No wittier alt has stuck. Reverse-DNS label `zone.dort.protonmcp` is a placeholder, change before publishing. | open, not blocking |

## Discovered gotchas (keep this list growing)

- `go-proton-api` ships with a `replace` directive pointing resty at
  `github.com/ProtonMail/resty/v2`. **Replace directives don't propagate
  from dependencies** — must be mirrored in our `go.mod`. Without it,
  builds fail on missing `resty.MultiPartStream` / `NewByteMultipartStream`.
- `WithAppVersion` is validated server-side against a known allowlist.
  Random strings get rejected. Use a real client identifier
  (`macos-bridge@<ver>`) for now.
- `proton.Keys.Primary()` **panics** if no primary key exists. Guard with
  `len(user.Keys) > 0`. (We don't currently guard the "keys but no primary"
  case — every Proton account has one, but if you hit a weird account add
  the iteration manually.)
- `proton.Auth.TwoFA.Enabled` is `0` when 2FA is disabled, otherwise one
  of the `TwoFAStatus` constants. `HasFIDO2` and `HasFIDO2AndTOTP` aren't
  supported yet — return a clear error.

## Done / decided

- 2026-05-21 — Picked hand-rolled JSON-RPC over `mark3labs/mcp-go`.
- 2026-05-21 — Pinned go-proton-api to Bridge v3.24.2's version
  (`v0.4.1-0.20260319112440-799673ddc2db`).
- 2026-05-21 — Module path `github.com/just-an-oldsalt/proto-mcp` matches
  the private GitHub repo created on the same day.
- 2026-05-21 — `whoami` works end-to-end from env-var credentials.
