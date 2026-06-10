# Architecture

proto-mcp runs as a small constellation of local processes. Nothing
listens on a network port; everything talks over a `0600` Unix socket
inside your home directory.

```
                Claude Desktop          Claude Code
                      │                       │
              (stdio, JSON-RPC over NDJSON per the MCP spec)
                      │                       │
                      ▼                       ▼
              protonmcp-shim          protonmcp-shim      ← one per client
                      │                       │             (tiny stdio↔socket forwarder)
                      └────── Unix socket ────┘
                              (0600, in ~/Library/Application Support/protonmcp/)
                                      │
                                      ▼
                               protonmcpd                  ← one long-running daemon
                                      │                      (LaunchAgent, KeepAlive)
                                      │
        ┌──────────────┬─────────────┼─────────────┬──────────────────┐
        │              │             │             │                  │
  internal/proton  internal/store  internal/policy  helpers/touchid  internal/audit
  (go-proton-api   (SQLite mirror,  (default.yaml +  (Swift LAContext  (SQLite + JSONL,
   + GPG crypto)    FTS5, body cache) user override)   biometric gate)  rotated at 50 MB)
```

## The pieces

| Binary | Role |
|---|---|
| `protonmcp` | The CLI. Login, backfill, daemon control, policy, install. What you run by hand. |
| `protonmcpd` | The daemon. One long-running process holding the Touch-ID-unlocked session and serving every MCP tool over the socket. |
| `protonmcp-shim` | A tiny stdio↔socket forwarder. Claude Desktop and Claude Code each spawn their own shim; both share the one daemon. |
| `protonmcp-touchid` | Swift helper that puts up the biometric prompt (`LAContext` / `.deviceOwnerAuthentication`). |
| `protonmcp-lockwatch` | Swift helper that watches for screen lock and sleep so the daemon can auto-lock. |

## Why a daemon instead of one process per client

The original design (`protonmcp serve-stdio`) ran a fresh server inside
each Claude client. That meant every client kept its own session and
prompted for Touch ID independently. The Phase 6 daemon model collapses
that: **one** daemon owns **one** unlocked session, and any number of
clients attach through their own shim. Unlock once, use everywhere; lock
once, and every client is locked.

`protonmcp serve-stdio` still exists for power users who want the
single-process model, but the default install registers the shim.

## The local mirror

`internal/store` keeps a SQLite mirror of your mailbox — message
envelopes (always) and decrypted bodies (cached on read, with a TTL).
Searches, listing, and thread reconstruction run against this mirror via
SQLite FTS5, so most reads never hit the network. `mail_sync` drains
Proton's event stream to keep the mirror current; the daemon also syncs
on its own cadence.

See [configuration.md](./configuration.md) for the body-cache TTL and
purge controls, and [security.md](./security.md) for what is and isn't
encrypted at rest.

## Internal packages

| Package | Responsibility |
|---|---|
| `internal/proton` | Proton transport + crypto via `go-proton-api` and `gopenpgp`. |
| `internal/store` | SQLite mirror, FTS5 search, body cache, migrations. |
| `internal/policy` | The default-deny YAML policy engine (embedded `default.yaml` + user override). |
| `internal/approval` | Per-call approval cache + TTL enforcement. |
| `internal/keystore` | macOS Keychain read/write for the session blob (cgo against `Security.framework`). |
| `internal/audit` | Redacted audit log (SQLite + JSONL). |
| `internal/redact` | Scrubbing of secrets/tokens/bodies before anything is logged. |
| `internal/caller` | `SO_PEERCRED` / `LOCAL_PEERPID` peer-credential checks on each socket connection. |
| `internal/serve` | The MCP runtime shared by `serve-stdio` and the daemon. |
| `internal/mcptools` | The 31 tools. |

Security-load-bearing paths (`internal/redact`, `internal/keystore`,
`internal/policy`, `internal/approval`, `helpers/touchid`,
`helpers/lockwatch`) have required reviewers in `.github/CODEOWNERS`.
