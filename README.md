<div align="center">

# proto-mcp

**Give Claude your inbox — without giving up control.**

A signed, notarized, Touch-ID-gated bridge between **Proton Mail** and
**Claude**, running entirely on your Mac. Claude reads, searches,
organizes, drafts, and sends your mail — and reads your calendar — through 34 [Model Context
Protocol](https://modelcontextprotocol.io) tools — and every message
that goes out needs your fingerprint on a prompt that names the real
recipient.

Nothing leaves your laptop except the mail itself.

![platform: macOS](https://img.shields.io/badge/platform-macOS%2013%2B-black?logo=apple)
![Go 1.26.4+](https://img.shields.io/badge/Go-1.26.4%2B-00ADD8?logo=go&logoColor=white)
![signed & notarized](https://img.shields.io/badge/Apple-signed%20%26%20notarized-success?logo=apple)
![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-ready-8A63D2)
![license: GPLv3](https://img.shields.io/badge/license-GPLv3-blue)

</div>

---

## What it feels like

You talk to Claude. Claude talks to your mailbox. You stay in the loop on
anything that matters.

> *"What did I miss from the climbing group this week?"*
> → Claude searches the local mirror, reads the thread, summarizes it. No prompt — reading is safe.

> *"File all the newsletters under Reading and mark them read."*
> → Claude moves and marks them. Organizing is gated, but quiet.

> *"Reply to Alice that I'm in for Saturday, and send it."*
> → A Touch ID prompt appears: **To: alice@example.com · Subject: Re: gear list**. You tap. It sends. You didn't.

Every read is served from a local SQLite mirror, so it's fast and works
offline. Every **write** is governed by a per-tool policy. Every **send**
re-prompts, every time, showing the literal recipients — that fingerprint
tap is the line between "Claude drafted it" and "Claude sent it."

## Quickstart

```sh
brew tap just-an-oldsalt/proto-mcp
brew install --cask proto-mcp

protonmcp login            # Proton SRP password + 2FA + key unlock
protonmcp backfill         # one-time: pull your message envelopes into the local mirror
protonmcp daemon install   # register + start the background daemon
protonmcp install          # connect it to Claude Desktop + Claude Code
```

Restart Claude, and the tools show up under `protonmcp` in `/mcp`. That's
it — signed, notarized binaries, no Gatekeeper warning, no network
listener.

> Prefer to build it yourself? See [Build from source](#build-from-source).

## What Claude can do

34 tools, grouped by what they touch. Reads run free; everything that
changes state is deny-by-default and Touch-ID gated.

| | |
|---|---|
| 📖 **Read & search** | List, full-text search, read messages, reconstruct threads, list attachments, list labels/folders, sync. |
| 🗂️ **Organize** | Mark read/unread, move, label, trash. |
| 🏷️ **Labels & folders** | Full CRUD with colour-palette validation. |
| ✍️ **Drafts** | Create, update, delete, list. |
| 📤 **Send** | Send, reply, reply-all, forward, send-draft — each one re-prompts. |
| 📎 **Attachments** | Decrypt and download, save to disk. |
| 📅 **Calendar** | List calendars, browse/search events by date range, read full event detail. Read-only. |

Full list with descriptions: **[docs/cli-reference.md](./docs/cli-reference.md)**.

## Why it's safe

proto-mcp is built so that an LLM driving your mailbox is a *convenience*,
never a *liability*. The guarantees that make that true:

- **🔐 Your fingerprint on every send.** Each write fires a native prompt
  showing the **literal** recipients and subject. `mail_send` has a TTL of
  zero, so it re-prompts every single time. No blanket approvals for sends.
- **🛡️ Default-deny by construction.** Unknown tools don't run. A tool
  with no policy entry fails to register — you can't accidentally ship an
  unguarded write.
- **🍎 Signed, notarized, and self-checking.** Hardened-runtime,
  Developer-ID-signed, Apple-notarized binaries, plus a SHA-256 integrity
  check at startup that refuses to run a swapped daemon.
- **🔒 Locks when you walk away.** Screen lock, sleep, or an idle timer
  zero the in-memory session; resuming takes Touch ID.
- **🧾 Honest, redacted audit log.** Every call is logged — secrets
  scrubbed, bodies reduced to `{sha256, bytes}`, recipients kept literal
  so the verification chain stays truthful.
- **🏠 Local-only.** The daemon listens on a `0600` Unix socket, never a
  network port. Mail content goes to Proton over TLS; nothing else leaves.

What a prompt actually looks like:

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

The full threat model — including the risks proto-mcp **doesn't** defend
against — is in **[docs/security.md](./docs/security.md)**. Read it before
you point this at a live mailbox.

## How it works

One background daemon holds your Touch-ID-unlocked session and serves
every tool over a local socket. Claude Desktop and Claude Code each attach
through a tiny forwarder, so they share one session: unlock once, use
everywhere; lock once, everything locks.

```
Claude Desktop ─┐                          ┌─ go-proton-api + GPG
Claude Code ────┼─ shim ─ socket ─ protonmcpd ┼─ SQLite mirror + FTS5
                ┘     (0600)               └─ Touch ID + policy + audit
```

The full design — every binary, package, and the local mirror — is in
**[docs/architecture.md](./docs/architecture.md)**.

## Configuration

Tune per-tool policy, rate limits, allowed recipients, the idle-lock
timer, and the cached-body TTL with a single YAML file. For example, to
cap LLM-driven sends and restrict them to one domain:

```yaml
tools:
  mail_send:
    decision: prompt
    rate_limit: 5/hour
    allowed_recipients: ["@mydomain.com"]
idle_lock_minutes: 30
```

Full reference, plus locking and the audit/observability commands:
**[docs/configuration.md](./docs/configuration.md)**.

## Build from source

Requires macOS 13+, [Go 1.26.4+](https://go.dev/dl/), and Xcode Command
Line Tools (for `swiftc`).

```sh
git clone https://github.com/just-an-oldsalt/proto-mcp.git
cd proto-mcp
make all                          # builds bin/* + the Swift helpers
./bin/protonmcp login
./bin/protonmcp backfill
./bin/protonmcp daemon install
./bin/protonmcp install
```

Source builds are ad-hoc signed by default and work fully (the Touch ID
gate, policy, audit, and lock/unlock all run the same). For a
locally-signed build, see
[`scripts/signing-setup.md`](./scripts/signing-setup.md).

## Good to know

- **macOS only.** The keystore and biometric helpers use
  `Security.framework`, `LAContext`, and AppKit. Linux builds compile for
  testing, but the auth flow won't work.
- **Be a good Proton citizen.** proto-mcp currently sends Proton Bridge's
  `AppVersion` header while a dedicated identifier is requested from Proton
  (see [`docs/proton-appversion-request.md`](./docs/proton-appversion-request.md)).
  Don't rate-abuse, scrape, or run multi-account automation through it —
  anything that violates Proton's [Terms](https://proton.me/legal/terms)
  is no less a violation for borrowing Bridge's header.
- **Cached bodies are plaintext-in-SQLite.** Decrypted message bodies are
  cached locally (TTL-bounded, `secure_delete` on). On a stolen, imaged
  disk that's recoverable cleartext until purged. Envelope encryption
  (SQLCipher) is a post-1.0 item. `protonmcp purge --older-than 7d
  --vacuum` shrinks the window now.
- **Personal use.** Built for one person and their mailbox on their Mac.

## Documentation

| Doc | Contents |
|---|---|
| [docs/architecture.md](./docs/architecture.md) | The daemon model, binaries, packages, and local mirror. |
| [docs/security.md](./docs/security.md) | Security layers + the full, honest threat model. |
| [docs/configuration.md](./docs/configuration.md) | Policy YAML, locking, observability, purging. |
| [docs/cli-reference.md](./docs/cli-reference.md) | Every CLI command and all 34 MCP tools. |
| [SECURITY.md](./SECURITY.md) | Security policy + per-defect fix log / audit trail. |
| [TESTING.md](./TESTING.md) | End-to-end validation playbook. |

Issues, defects, and roadmap are tracked in Jira (project **PROTO**), the
source of truth. `TODO.html` and `DEFECTS.html` are retained as historical
design records from the build-out.

## Contributing

PRs welcome, but **please open an issue first** — most architectural
direction is settled, and unsolicited big-scope PRs probably won't land.
`.github/CODEOWNERS` defines required reviewers for the
security-load-bearing paths (`internal/redact/`, `internal/keystore/`,
`internal/policy/`, `internal/approval/`, `helpers/touchid/`,
`helpers/lockwatch/`).

## License & acknowledgements

GPLv3 — see [`LICENSE`](./LICENSE). proto-mcp depends transitively on
`proton-bridge` (also GPLv3) via `go-proton-api`.

- [**Proton AG**](https://proton.me) for `proton-bridge` and
  `go-proton-api`, on which the entire crypto + transport layer rests.
- [**Anthropic**](https://anthropic.com) for the Model Context Protocol
  and the Claude clients this server targets.
- Every defect that took the shape it did because `cmd-r`,
  `claude-review`, `claude-security-review`, or a live testing session
  looked at the code more carefully than I would have alone.
