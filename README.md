# proto-mcp

**A signed, notarized, Touch-ID-gated bridge between Proton Mail and
Claude — running entirely on your Mac.**

`proto-mcp` exposes 29 [Model Context Protocol](https://modelcontextprotocol.io)
tools that let Claude Desktop and Claude Code read, search, compose,
label, and send Proton Mail on your behalf. Every write is gated by
a per-tool YAML policy and a macOS Touch ID prompt that shows the
literal recipients and subject before the message goes out. Every
call writes a redacted row to a local audit log. Nothing leaves
your laptop except the mail itself.

> **Status:** `v1.0.0-alpha`. Phase 1–6 merged; Phase 7 (signing +
> notarization + Homebrew + Keychain ACL) shipping in PRs #58–#62.
> Personal-use, technical-audience early access. Read the caveats
> below before installing.

---

## What you get

| Class | Tools |
|---|---|
| **Read** | `mail_list`, `mail_search`, `mail_read`, `mail_read_thread`, `mail_list_attachments`, `labels_list`, `folders_list`, `account_whoami`, `mail_sync` |
| **State** | `mail_mark_read`, `mail_mark_unread`, `mail_move`, `mail_label`, `mail_trash` |
| **Labels & folders** | `labels_create`, `labels_update`, `labels_delete`, `folders_create`, `folders_update`, `folders_delete` |
| **Drafts** | `mail_draft_create`, `mail_draft_update`, `mail_draft_delete`, `mail_draft_list` |
| **Send** | `mail_send`, `mail_reply`, `mail_reply_all`, `mail_forward`, `mail_send_draft` |
| **Reserved** | `mail_delete_permanent` (denied by default; opt-in via policy) |

29 callable tools; one explicit deny-by-default.

## Architecture (Phase 6 daemon model)

```
                Claude Desktop          Claude Code
                      │                       │
              (stdio, JSON-RPC over NDJSON per MCP spec)
                      │                       │
                      ▼                       ▼
              protonmcp-shim        protonmcp-shim       <- one per client
                      │                       │            (tiny stdio↔socket forwarder)
                      └────── Unix socket ────┘
                              (0600, in ~/Library/Application Support/protonmcp/)
                              ▼
                       protonmcpd                          <- one long-running daemon
                              │                              (LaunchAgent, KeepAlive)
                              │
              ┌──────────────┬──────────────┬──────────────┬──────────────┐
              │              │              │              │              │
        internal/proton  internal/store  internal/policy  internal/      internal/audit
        (go-proton-api  (SQLite mirror,  (default.yaml + (Swift Touch  (SQLite + JSONL,
          + GPG)        FTS5, body cache,  user override) ID helper)    rotated at 50MB)
                        SQLCipher TBD)
```

`protonmcp serve-stdio` is the old single-process mode — still
runnable for power users, but the default install registers the
shim with Claude clients so multiple clients share one daemon and
one Touch-ID-unlocked session.

## Security model

The Keychain item that holds your Proton session is sealed behind
**three layers**:

1. **macOS Keychain encryption** — the standard at-rest protection
   for any keychain item. Anything below assumes the user is logged
   in and the keychain is unlocked.
2. **Touch ID at session-acquire time** — the daemon prompts for
   biometric (or password fallback per Apple's
   `.deviceOwnerAuthentication`) on every startup AND every
   `protonmcp unlock` after a manual or auto-lock. Touch-ID-at-
   startup runs inside the daemon process; SecAccessControl on the
   keychain item (Phase 7/D) means the OS issues its own prompt for
   any read attempt.
3. **Per-call approval** — every `prompt`-gated tool (everything
   that writes) fires a custom NSAlert + Touch ID prompt showing
   the literal recipients and subject. Cached approvals expire per
   policy TTL; `mail_send` has TTL 0, so every send re-prompts.

Plus:

- **Hardened-runtime + Developer-ID-signed + Apple-notarized**
  binaries. Gatekeeper accepts them without the "developer
  unknown" dialog.
- **SHA-256 binary integrity check** at daemon startup. If
  `protonmcpd` was replaced between install and launch, the daemon
  refuses to start.
- **SO_PEERCRED / LOCAL_PEERPID** on every shim connection — the
  daemon records the real connecting client's PID + UID in audit
  rows.
- **Default-deny policy** for unknown tools. Adding a new tool
  without a policy stub fails registration; you can't accidentally
  ship an unguarded write.
- **Auto-lock triggers**: screen lock, sleep, and
  `idle_lock_minutes`. Walking away from your laptop locks the
  daemon; unlocking requires Touch ID.
- **Redacted audit log**. Passwords / tokens / cookies become
  `[REDACTED]`. Bodies become `{sha256, bytes}`. Recipient
  addresses stay literal (so the prompt verification chain is
  honest).

[`SECURITY.md`](./SECURITY.md) has the audit trail and per-defect
fix log. [`DEFECTS.html`](./DEFECTS.html) is the open issue list
(currently 5 open / 33 resolved; the open set is all medium / low).

## Install

Requires macOS 13+, [Go 1.26+](https://go.dev/dl/), and Xcode
Command Line Tools (for `swiftc`).

```sh
git clone https://github.com/just-an-oldsalt/proto-mcp.git
cd proto-mcp
make all                          # builds bin/* + Swift helpers
./bin/protonmcp login             # interactive: SRP + TOTP + key unlock
./bin/protonmcp backfill          # one-time: drains every message envelope
./bin/protonmcp daemon install    # registers + starts the LaunchAgent
./bin/protonmcp install           # registers shim with Claude Desktop + Claude Code
```

Restart Claude Desktop / Claude Code. The 29 tools show up under
`protonmcp` in `/mcp`.

**Coming in Phase 7/E:** `brew install --cask just-an-oldsalt/protonmcp/protonmcp`
(pending the Proton AppVersion grant and a Homebrew tap.) Signed
+ notarized; no developer warning.

## A Touch ID prompt looks like this

When Claude says "move 'Re: gear list' from inbox to archive," the
NSAlert that fires says exactly that — not a redacted argument
dump. Specifically:

```
┌──────────────────────────────────────────────┐
│ protonmcp-touchid is trying to              │
│ move message 'Re: gear list' from inbox      │
│ to Archive                                   │
│                                              │
│ Touch ID or enter your password to allow.   │
│              [ Cancel ]    [ Touch ID ]      │
└──────────────────────────────────────────────┘
```

The verb phrase comes from a per-tool `PromptBody` closure
(`internal/mcptools/prompt_helpers.go`) that looks up `message_id →
Subject` and `label_id → Name` from the local SQLite mirror. You
read what you're approving.

For sends, the format is stricter:
```
┌──────────────────────────────────────────────┐
│ Send mail_send?                              │
│                                              │
│ To: alice@example.com                        │
│ CC: charlie@example.com                      │
│ Subject: Re: gear list                       │
│                                              │
│ [ Cancel ]              [ Send & Touch ID ]  │
└──────────────────────────────────────────────┘
```

Body content is replaced with a SHA-256 reference in the audit log
but the recipient list is always verbatim in the prompt — that's
the verification surface you tap against.

## Configuring policy

Defaults are in [`internal/policy/default.yaml`](./internal/policy/default.yaml)
(embedded into the binary). Override per-tool by creating
`~/Library/Application Support/protonmcp/policy.yaml`:

```yaml
tools:
  mail_send:
    decision: prompt
    confirm: true
    rate_limit: 5/hour                       # cap LLM-driven sends
    allowed_recipients: ["@mydomain.com"]    # restrict to one domain
  mail_delete_permanent:
    decision: deny                           # default; remove this to enable with prompt

# Phase 7/A — auto-lock idle timer
idle_lock_minutes: 30                        # lock if no tool call for 30 minutes (0 = disabled)
```

Reload without restarting:
```sh
./bin/protonmcp policy reload      # SIGHUP to every running daemon / serve-stdio
./bin/protonmcp policy show        # print the merged effective policy
./bin/protonmcp policy validate ./my-policy.yaml
```

Rate-limit buckets persist to SQLite (Phase 6/E), so a daemon
restart doesn't reset the per-hour cap.

## Locking

```sh
./bin/protonmcp lock      # SIGUSR1 — daemon zeros its in-memory session
./bin/protonmcp unlock    # SIGUSR2 — Touch ID prompt re-acquires from Keychain
```

The daemon also auto-locks on:
- macOS screen lock (`com.apple.screenIsLocked` distributed notification)
- system sleep (`NSWorkspaceWillSleepNotification`)
- idle timeout (`idle_lock_minutes` policy field; default 0 = disabled)

While locked, every tool call returns `daemon is locked (<reason>);
run \`protonmcp unlock\` to resume`. No audit row is written for the
attempt (logged at WARN instead).

## Observability

Two log destinations, both auto-rotated at 50MB × 10 generations
(Phase 7/B):

```sh
# Tail the audit log (one JSON object per completed tool call)
tail -f ~/Library/Application\ Support/protonmcp/audit.log

# Tail the daemon's slog output
tail -f ~/Library/Logs/protonmcp/daemon.log
```

Or query the SQLite source of truth for richer analytics:

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db \
  'SELECT tool, outcome, policy_decision, duration_ms
     FROM audit_log
    ORDER BY id DESC LIMIT 20;'
```

Every audit row has: tool name, caller PID + UID + binary, policy
decision, outcome (ok / denied / error), approval source (touchid /
cached / policy), error message (if any), duration in ms, and
redacted args.

## Caveats — read before installing

### Plaintext bodies on disk (until Phase 8)

When Claude reads a message via `mail_read`, the decrypted body
caches in SQLite for 30 days (`protonmcp purge --older-than 7d` to
shrink the window). On laptop theft + iCloud-restored disk imaging
that's recoverable cleartext. The `secure_delete=on` pragma zeros
deleted cells on the next page write; `protonmcp purge --vacuum`
forces it immediately. SQLCipher / envelope encryption is Phase 8.

### Proton AppVersion (resolved when Phase 7/E lands)

Today, `proto-mcp` sends `AppVersion: macos-bridge@3.24.2` — Proton
Bridge's identifier, not ours. Phase 7/E swaps in a legitimate
`protonmcp@<version>` once Proton grants it (request email is in
[`docs/proton-appversion-request.md`](./docs/proton-appversion-request.md)).
Until then: **don't rate-abuse, scrape, or run multi-account
automation through `proto-mcp`**. Anything that violates Proton's
[Terms](https://proton.me/legal/terms) is no less violating because
we're using Bridge's header.

### macOS only

`internal/keystore` uses `keybase/go-keychain` + cgo against
`Security.framework` (Phase 7/D adds a `SecAccessControl`
wrapper). The Swift helpers need LAContext + AppKit + workspace
notifications. Linux builds compile (testing only) but the auth
flow won't work.

### License

GPLv3. We transitively depend on `proton-bridge` (also GPLv3) via
`go-proton-api`; that constrains us. See [`LICENSE`](./LICENSE).

## Testing

For end-to-end validation see [`TESTING.md`](./TESTING.md) — a
sectioned playbook another agent (or you) can run to validate
build, signing, daemon lifecycle, Touch ID, lock/unlock, per-tool
correctness, audit log, and defect regressions. Reports go directly
into `DEFECTS.html` using the existing D-numbering.

For day-to-day development:
```sh
make test         # go test ./...
make race         # go test -race ./...
make verify-sign  # codesign --verify each binary (after make sign)
```

## Project status

| Phase | Scope | Status |
|---|---|---|
| 0–2 | Build, store, sanitize, sync | Merged |
| 3 | MCP server + 9 read tools | Merged |
| 4 | Policy + audit + Touch ID + middleware | Merged |
| 5 | 20 write tools + rate limit + allowed_recipients | Merged |
| 5.5 | Security audit follow-up (21 findings closed) | Merged |
| 6 | Daemon + shim + launchd + lock/unlock + persistent rate-limit | All sub-PRs in flight |
| 7 | Signing, notarization, Keychain ACL, Homebrew, AppVersion | Sub-PRs 7/0–7/D shipped; 7/E pending Proton |
| 8 | SQLCipher / envelope encryption at rest | Planning |

[`TODO.html`](./TODO.html) has the full per-phase plan and the
backlog. [`DEFECTS.html`](./DEFECTS.html) is the truth about what's
broken.

## Contributing

This is alpha software. PRs welcome but **please open an issue
first** — most architectural direction is locked by the design spec
in `TODO.html` and unsolicited big-scope PRs probably won't land.

`.github/CODEOWNERS` defines required reviewers for security-load-
bearing paths (`internal/redact/`, `internal/keystore/`,
`internal/policy/`, `internal/approval/`, `helpers/touchid/`,
`helpers/lockwatch/`).

## Acknowledgements

- [Proton AG](https://proton.me) for `proton-bridge` and
  `go-proton-api`, on which the entire crypto + transport layer
  rests. Working on a legitimate AppVersion grant; appreciate the
  publish of a real Go client.
- [Anthropic](https://anthropic.com) for the MCP specification and
  the Claude clients this server targets.
- Every defect in [`DEFECTS.html`](./DEFECTS.html) that took the
  shape it did because someone — `cmd-r`, `claude-review`,
  `claude-security-review`, or a live testing session — looked at
  the same code more carefully than I would have on my own.
