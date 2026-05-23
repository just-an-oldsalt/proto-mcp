# proto-mcp

A local-only macOS [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes your [Proton Mail](https://proton.me) account to Claude Desktop and
Claude Code via Touch-ID-gated tool calls.

**Status: `v1.0.0-alpha`. Personal-use, technical-audience early access. Read the
caveats below before installing.**

## What it does

29 MCP tools across reads (`mail_list`, `mail_search`, `mail_read`,
`labels_list`, …) and writes (`mail_send`, `mail_reply`, `mail_move`,
`labels_create`, `mail_draft_*`, …). Every write tool is gated by a YAML policy
engine + Touch ID approval; every tool call writes a redacted row to a local
audit log.

Architecture sketch:

```
Claude Desktop / Claude Code
        │  (stdio, JSON-RPC over NDJSON per the MCP spec)
        ▼
   protonmcp serve-stdio
        │
        ├─ internal/proton ── go-proton-api ── /mail/v4 → Proton servers
        ├─ internal/store  ── SQLite mirror @ ~/Library/Application Support/protonmcp/store.db
        ├─ internal/policy ── policy.yaml (allow/prompt/deny per tool)
        ├─ internal/approval ─ Swift Touch ID helper (helpers/touchid/)
        └─ internal/audit ── SQLite + JSONL mirror
```

See [`TODO.html`](./TODO.html) for the full design + per-phase plan and
[`DEFECTS.html`](./DEFECTS.html) for the open issue list (currently 7 open /
24 resolved).

## Read this before installing

### 1. AppVersion impersonation

`proto-mcp` sends `AppVersion: macos-bridge@3.24.2` on every Proton API
request. **That's Proton Bridge's identifier, not ours.** Proton allowlists
`AppVersion` headers and using an unrecognized one returns HTTP 400.

This is a deliberate development-stage shortcut. We are NOT registered with
Proton as a recognized client. The implications:

- Anything that violates Proton's [Terms](https://proton.me/legal/terms) —
  rate-abuse, scraping, multi-account automation, etc. — is no less violating
  because we're using Bridge's header. Don't.
- Proton's security team may revoke `macos-bridge@3.24.2`'s allowlist entry
  in any future Bridge release. If that happens, `proto-mcp` stops working
  until either Bridge ships a new version we re-pin to, or we apply for and
  receive our own client ID.
- Filing a ticket with Proton's security team requesting a legitimate
  `protonmcp@x.y.z` client ID is the right long-term answer; it's a
  follow-up after alpha.

**By installing and running `proto-mcp` you accept that this is a
personal-use development tool, not a sanctioned third-party client.**

### 2. Plaintext bodies on disk

When you read a message via `mail_read`, the decrypted body lives in your
local SQLite store for 30 days (configurable via `protonmcp purge
--older-than D`). On laptop loss / theft / iCloud-backed-up disk imaging,
that's recoverable cleartext. The `secure_delete=on` pragma zeroes deleted
cells on the next page write; `protonmcp purge --vacuum` forces it
immediately. Phase 6 will add SQLCipher / envelope encryption.

### 3. macOS only

`internal/keystore` uses `keybase/go-keychain` (cgo against
`Security.framework`); the Swift Touch ID helper requires `LAContext`.
Linux builds compile but the auth flow won't work.

### 4. License

GPLv3. We depend transitively on `proton-bridge` (also GPLv3) via the
`go-proton-api` SDK; that constrains us. See [`LICENSE`](./LICENSE).

## Install (alpha)

Requires macOS, [Go 1.26+](https://go.dev/dl/), and the Xcode command-line
tools (for `swiftc`).

```sh
git clone https://github.com/just-an-oldsalt/proto-mcp.git
cd proto-mcp
make all                           # builds bin/protonmcp + the Swift Touch ID helper
./bin/protonmcp login              # interactive: SRP login, TOTP if enabled, key unlock
./bin/protonmcp backfill           # one-time: drains every message envelope + label
./bin/protonmcp install            # registers MCP server with both Claude Desktop AND Claude Code
```

Restart whichever Claude client(s) you're using. The 29 tools show up under
`protonmcp` in the `/mcp` listing.

## Configuring policy

Defaults are in [`internal/policy/default.yaml`](./internal/policy/default.yaml)
(embedded into the binary). Override per-tool by creating
`~/Library/Application Support/protonmcp/policy.yaml`. Reload with:

```sh
./bin/protonmcp policy reload      # SIGHUPs every running serve-stdio
./bin/protonmcp policy show        # print the merged effective policy
./bin/protonmcp policy validate ./my-policy.yaml
```

Common tightening:

```yaml
tools:
  mail_send:
    decision: prompt
    confirm: true
    rate_limit: 5/hour                       # cap LLM-driven sends
    allowed_recipients: ["@mydomain.com"]    # restrict to one domain
  mail_delete_permanent:
    decision: deny                           # default; remove this entry to enable with a prompt
```

## Verifying what just happened

```sh
tail -f ~/Library/Application\ Support/protonmcp/audit.log
```

Each line includes tool, caller PID + binary, policy decision, outcome, and
redacted args. Use the SQLite source-of-truth for richer queries:

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db \
  'SELECT tool, outcome, duration_ms FROM audit_log ORDER BY id DESC LIMIT 20;'
```

## Security model in one paragraph

`proto-mcp` is a local-only tool. It listens only on stdin/stdout
(`internal/mcp/trustguard.go` panics at init if any code tries
`net.Listen("tcp", …)`). The Touch ID helper is invoked as a subprocess for
every prompted tool call; cached approvals last per-tool TTL (typically 5
minutes for reversible operations, `0` for irreversible ones like
`mail_send` so every send re-prompts). Args are redacted before they hit
the audit log: passwords / tokens / refresh tokens become `[REDACTED]`,
draft bodies become `{sha256, bytes}`, recipient addresses stay literal.
[`SECURITY.md`](./SECURITY.md) has the full audit trail.

## What's not done yet

- **Phase 6** — daemon + Unix-domain socket + launchd + persistent rate-limit state across restarts + Keychain ACL hardening. Currently each Claude client spawns its own short-lived `serve-stdio` process; the daemon split is the architecture flip the audit's been pointing at.
- **Phase 7** — Developer ID signing + notarization, log rotation, Homebrew formula.
- **Open audit items**: 7 issues, mostly Phase-6 territory ([`DEFECTS.html`](./DEFECTS.html)).

## Contributing

This is alpha software. PRs welcome but please open an issue first — most of
the architectural direction is locked by the design spec in `TODO.html` and
unsolicited big-scope PRs probably won't land.

`.github/CODEOWNERS` defines required reviewers for security-load-bearing
paths.

## Acknowledgements

- [Proton AG](https://proton.me) for `proton-bridge` and `go-proton-api`,
  on which the entire crypto + transport layer rests.
- [Anthropic](https://anthropic.com) for the MCP specification and the
  Claude clients this server targets.
