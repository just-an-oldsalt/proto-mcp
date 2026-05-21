# SECURITY.md

Security groundwork for proto-mcp. Drafted from a read-only audit before the
codebase grows past its current 4-file footprint. Items are prioritized — the
**Foundational** section is the load-bearing one; everything else gets cheaper
if those decisions are made first.

Audited commit context: `e6f660a` bootstrap → `bdf18cc` /dev/tty prompt →
`6998097` TODO.html. No secrets in repo, no `InsecureSkipVerify`, no
template-injection sinks today.

---

## Foundational invariants — decide before writing more features

These are 10x more expensive to retrofit once Phases 3-7 land. Treat them as
project invariants, not suggestions.

1. **Introduce a `Secret` type now.** `[]byte`-backed wrapper with `Bytes()`,
   `Zero()`, `String() → "[REDACTED]"`, and `MarshalJSON` that errors. Every
   credential field (`Credentials.Password`, `MailboxPassword`, `TOTP`, the
   SRP-derived `saltedPass`) becomes `Secret`, not `string`. ~50 LOC today;
   a week of refactor after credentials sprinkle across Phases 4-6.

2. **Pick a structured logger with built-in redaction before the first
   `log.Printf`.** `log/slog` + a custom `ReplaceAttr` that redacts known
   sensitive keys (`password`, `mailbox_password`, `totp`, `auth_token`,
   `refresh_token`, `body`, `body_html`). The audit-log table's `args_json`
   column will eat passwords the first time a write-tool's arg schema
   includes one.

3. **MCP trust model — write it down before Phase 3 lands the JSON-RPC
   server.** The single most important invariant in this project:
   - Transport is **local Unix-domain stdio only**.
   - `SO_PEERCRED` + UID match required.
   - **Panic on TCP bind** — make this an `init()`-time assertion in the
     listener so it can never regress silently.
   - Every authenticated Proton call is initiated by an unauthenticated
     stdio peer → assume confused-deputy risk on every tool handler.

4. **Default-deny tool policy.** Unknown tool name = deny. The Phase 4
   policy engine should require an explicit allow entry per tool. Allow-by-
   default registries are very hard to unwind once tools exist.

5. **Token persistence story before Phase 6 Keychain work.** Document which
   tokens persist, under whose ACL (signed binary only), and what
   `protonmcp lock` actually zeroes. TODO open question #2 already flags
   this — answer it before the Keychain code lands or it becomes a junk
   drawer.

6. **Rate-limit the login flow, not just tools.** A buggy MCP client
   looping on auth failure will trip Proton's anti-abuse and lock the
   account. Phase 7's per-tool limits aren't enough on their own.

7. **HTML sanitization at the MCP boundary, not the storage boundary.**
   Keep raw HTML in SQLite (bodies may need to be re-sanitized later under
   a stricter policy). Run `bluemonday` on the way out to the MCP client.
   Prompt-injection-via-mail (TODO open question #5) needs a runtime
   banner on first start — not just a README line.

8. **`govulncheck` + Dependabot in CI early.** ~30 modules including
   Proton-controlled forks of `bcrypt`, `gopenpgp`, `go-srp`, `resty`.
   Pull this from Phase 7 forward to Phase 1.

---

## High — fix before next commit

### H-1. Credentials live in Go `string`, never zeroed

`cmd/protonmcp/main.go:74-98`, `internal/cli/prompt.go:69`,
`internal/proton/client.go:41-49, 216`.

- `os.Getenv("PROTONMCP_PASSWORD")` is readable via `ps eww` and
  `/proc/<pid>/environ` for the full process lifetime.
- `term.ReadPassword` returns `[]byte` (good), but `prompt.go:69` upcasts
  it to `string` (immutable, GC-managed, can be duplicated by the
  runtime). The original `[]byte` is never zeroed before return.
- `Session.Close` clears the *unlocked keyring* but not the original
  passwords or the SRP-derived `saltedPass`.

Fix: implement the `Secret` type (Foundational #1). For env vars,
`os.Unsetenv("PROTONMCP_PASSWORD")` immediately after copying into a
`Secret` — env vars can never be made truly safe, but this caps the
exposure window. In `prompt.go:69`, zero the `[]byte` before returning.

### H-2. Keyring wipe and SRP material wipe are best-effort only

`cmd/protonmcp/main.go:114`, `internal/proton/client.go:216-222`.

- `defer sess.Close(...)` skips on SIGKILL / SIGTERM mid-print.
- `saltedPass` (`client.go:216`) is never zeroed even on success — only
  the unlocked keyring is.
- `Session.Close` uses bare `context.Background()` with no timeout — a
  hung network blocks shutdown indefinitely.

Fix: wire `signal.NotifyContext`'s cancel through a `sync.Once` shutdown
path that explicitly zeroes raw `Credentials` and `saltedPass` *and*
calls `Session.Close`. Add `context.WithTimeout(2*time.Second)` inside
`Close`. Add `defer crypto.ClearBytes(saltedPass)` at `client.go:216`.

### H-3. Server-side session not revoked on Ctrl-C during login

`internal/proton/client.go:141-149`.

`mgr.NewClientWithLogin` succeeds, then `GetUser` / `GetAddresses` /
`GetSalts` / `Unlock` fails. `cleanup()` calls `AuthDelete(ctx)` on the
*original* request context — if the user hit Ctrl-C, that context is
cancelled and revocation silently fails, leaving an authenticated
session alive on Proton's side.

Fix: in `cleanup`, use a detached short-timeout context
(`context.WithTimeout(context.Background(), 5*time.Second)`). Same
pattern needed for `Session.Close` shutdown path.

---

## Medium — fix before this leaves the author's laptop

### M-1. Bridge AppVersion impersonation is a time bomb

`internal/proton/client.go:29` — `AppVersion = "macos-bridge@3.24.2"`.
Already TODO-flagged. Proton can ban this user-agent at any moment,
breaking every install in the field with no graceful degradation.
Minimum: surface the AppVersion in `whoami` output and log a one-line
warning until a real Proton client ID is granted. Don't ship publicly
on the impersonated ID.

### M-2. SQLite DB file inherits umask

`internal/store/store.go:59-67`. `MkdirAll(..., 0o700)` is correct, but
`sql.Open` creates `.db` / `-wal` / `-shm` files with default perms
(`0644` on macOS). For a store that will hold message bodies and the
audit log, this is too permissive. Fix: `os.Chmod(path, 0o600)` after
first `Ping`, same for the `-wal` / `-shm` siblings.

### M-3. No `syscall.Umask(0o077)` at process start

`cmd/protonmcp/main.go`. One-line foundational decision so every file
the daemon creates (logs, audit mirror, body cache) is owner-only by
default. Painful to retrofit once dozens of write sites exist.

### M-4. Error wrapping echoes credentials material into the chain

`internal/proton/client.go:225` — `"unlock keyring: %w (wrong mailbox
password?)"`. `%w` chains gopenpgp errors that historically include key
fingerprints and ciphertext snippets. Fine today; lands on disk the
moment Phase 4 structured logging starts persisting errors.

Fix: define `ErrUnlockFailed` (and friends) as sentinels. Cross package
boundaries with `%v`, not `%w`. Rule: library errors never reach disk
logs without redaction.

### M-5. Error classification before stringifying

`cmd/protonmcp/main.go:42` — `fmt.Fprintln(os.Stderr, "error:", err)`
prints the chain verbatim. Future log redaction has nothing to match
on. Classify into `ErrUserCanceled` / `ErrAuthFailed` / `ErrNetwork`
before output.

---

## Low / hygiene

- **L-1** `internal/cli/prompt.go:45` — `if err != nil && (line == "" || err
  != io.EOF)` silently drops non-EOF errors when line is non-empty.
  Tighten to `if err != nil && err != io.EOF`.
- **L-2** `internal/cli/prompt.go:69` — zero the `pw []byte` before
  returning the string copy (covered by Foundational #1 once `Secret`
  lands, but worth a defensive wipe even before).
- **L-3** `cmd/protonmcp/main.go:34` — `_ = args` discards subcommand
  arguments. Either accept no args strictly or wire a real flag parser
  before adding more subcommands.
- **L-4** `internal/store/store.go:67` — DSN built via string
  concatenation. Safe today (path comes from `DefaultPath`), becomes a
  SQLite URI injection vector (`?_pragma=...`) the moment
  `--store-path` is a flag. Build DSN via `net/url` now.
- **L-5** `cmd/protonmcp/main.go:36` — `signal.NotifyContext` registers
  `SIGINT` + `SIGTERM` but not `SIGHUP`. TODO Phase 4 plans `SIGHUP`
  for policy reload; install the handler now or document why not.
- **L-6** `go.sum` has parallel `golang.org/x/crypto` v0.48.0 + v0.50.0.
  Run `go mod tidy`.
- **L-7** `TODO.html` was hand-authored, not generated. If a conversion
  script gets added later, it becomes a template-injection sink — put
  any such tool in `cmd/` and treat as security-relevant code.
- **L-8** `bin/protonmcp` is gitignored locally but ensure CI release
  artifacts are never built from a tree that has held test credentials.

---

## How to use this doc

- **Treat the Foundational section as invariants.** New PRs should
  reference which invariants they uphold (or explicitly waive, with
  rationale).
- **High items** should be addressed before the next non-trivial
  commit. They are not blockers for in-flight Phase work but should
  land alongside it.
- **Medium items** can wait until immediately before the first
  non-author user sees the daemon.
- When in doubt: ask whether the change would survive an audit by
  someone who assumes the MCP peer is hostile.
