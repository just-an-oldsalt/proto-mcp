# Configuration, locking & observability

## Policy

Every tool's behavior is governed by a YAML policy. Defaults live in
[`../internal/policy/default.yaml`](../internal/policy/default.yaml)
(embedded into the binary). Override per-tool by creating
`~/Library/Application Support/protonmcp/policy.yaml`:

```yaml
tools:
  mail_send:
    decision: prompt
    confirm: true
    rate_limit: 5/hour                       # cap LLM-driven sends
    allowed_recipients: ["@mydomain.com"]    # restrict to one domain
  mail_trash:
    decision: prompt                         # reversible; mail_move puts it back

# Auto-lock idle timer
idle_lock_minutes: 30                        # lock if no tool call for 30 min (0 = disabled)
```

Each tool's `decision` is one of `allow`, `prompt`, or `deny`. Writes are
`prompt` by default; reads are `allow`; anything unknown is `deny`. The
default-deny stance is enforced at registration — a tool with no policy
entry won't load, so you can't accidentally ship an unguarded write.

Reload without restarting:

```sh
protonmcp policy reload                 # SIGHUP every running daemon / serve-stdio
protonmcp policy show                   # print the merged effective policy
protonmcp policy validate ./my-policy.yaml
```

Rate-limit buckets persist to SQLite, so a daemon restart doesn't reset
the per-hour cap.

## Locking

```sh
protonmcp lock      # daemon zeros its in-memory session
protonmcp unlock    # Touch ID prompt re-acquires the session from the Keychain
```

The daemon also auto-locks on:

- macOS screen lock (`com.apple.screenIsLocked`)
- system sleep (`NSWorkspaceWillSleepNotification`)
- idle timeout (`idle_lock_minutes`; default `0` = disabled)

While locked, every tool call returns `daemon is locked (<reason>); run
protonmcp unlock to resume`. No audit row is written for the blocked
attempt (it's logged at WARN instead).

## Observability

Two log destinations, both auto-rotated at 50 MB × 10 generations:

```sh
# Audit log — one JSON object per completed tool call
tail -f ~/Library/Application\ Support/protonmcp/audit.log

# Daemon slog output
tail -f ~/Library/Logs/protonmcp/daemon.log
```

Or query the SQLite source of truth for richer analytics:

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db \
  'SELECT tool, outcome, policy_decision, duration_ms
     FROM audit_log
    ORDER BY id DESC LIMIT 20;'
```

Every audit row carries: tool name, caller PID + UID + binary, policy
decision, outcome (`ok` / `denied` / `error`), approval source (`touchid`
/ `cached` / `policy`), error message (if any), duration in ms, and
redacted arguments.

## At-rest data & purging

When Claude reads a message, the decrypted body is cached in SQLite with
a TTL (default 30 days) so repeat reads are instant and offline. That
cache is plaintext-in-SQLite, mitigated by the `secure_delete=on` pragma
(deleted cells are zeroed on the next page write) and TTL purging:

```sh
protonmcp purge --older-than 7d         # shrink the cached-body window
protonmcp purge --vacuum                # force secure_delete to reclaim now
```

Envelope encryption of the body cache (SQLCipher) is a post-1.0 item; see
[security.md](./security.md) for the at-rest threat discussion.
