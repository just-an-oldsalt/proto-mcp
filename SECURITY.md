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

---

# Re-audit — through commit `8d9a71b` (Phase 1.5 complete)

Read-only re-audit covering everything from `0344f76` (SQLite store) through
`8d9a71b` (CI). Verifies the original findings and audits the new attack
surface (`internal/secret`, `internal/keystore`, `internal/logging`,
`internal/store`, `cmd/protonmcp/backfill`).

## Verification matrix vs. original findings

| ID | Status | Evidence |
|---|---|---|
| Foundational #1 (`Secret`) | **FIXED** — see B-1, B-3 caveats | `internal/secret/secret.go:34-114` |
| Foundational #2 (redacting logger) | **PARTIAL** — denylist with blind spots | `internal/logging/logging.go:26-43`; see B-4 |
| Foundational #3 (MCP trust model) | **NOT YET** — no JSON-RPC server, no TCP-bind guard |
| Foundational #4 (default-deny policy) | **NOT YET** — no policy engine yet |
| Foundational #5 (token persistence story) | **PARTIAL** — code shipped; doc thin; see B-7 |
| Foundational #6 (login rate-limit) | **NOT YET** |
| Foundational #7 (HTML sanitization) | **NOT YET** — no bodies stored yet |
| Foundational #8 (govulncheck + Dependabot) | **FIXED** with caveats — see B-5 |
| H-1 (creds in `string`, never zeroed) | **FIXED** — `main.go:167-169`, `prompt.go:130-132` |
| H-2 (shutdown wipe + timeout) | **PARTIAL** — `sync.Once` + 5 s timeout in (`client.go:158, 217-245, 54-63, 259`); signal-driven path still deferred |
| H-3 (detached revoke on Ctrl-C) | **FIXED** — `client.go:367-372`, `resume.go:95-104` |
| M-1 (AppVersion warning) | **PARTIAL** — only printed in `whoami` (`main.go:217-218`); `backfill`/`login` silent |
| M-2 (DB file perms) | **FIXED** — `store.go:84-91` chmods `.db`/`-wal`/`-shm` to 0600 (silent on chmod failure — minor) |
| M-3 (umask 0o077) | **FIXED** — `main.go:44`, first runtime call |
| M-4 (error wrapping leaks crypto chain) | **NOT FIXED** — `client.go:460` still `%w`s gopenpgp errors; no sentinel |
| M-5 (error classification) | **NOT FIXED** — `main.go:98` still prints raw chain |
| L-1 (prompt error swallow) | **FIXED** — `prompt.go:87` |
| L-2 (zero `pw []byte`) | **FIXED** — `prompt.go:131` |
| L-3 (`_ = args`) | **FIXED** — `requireNoArgs` (`main.go:227-232`) |
| L-4 (DSN URI injection) | **PARTIAL** — `buildDSN` uses `net/url` (`store.go:108-124`) but `path` is still raw-concat before `?` — see B-6 |
| L-5 (SIGHUP) | **FIXED** — `main.go:62` |
| L-6 (parallel x/crypto) | **FIXED** — pinned to v0.50.0 only |
| L-7 / L-8 | N/A (no converter, no release pipeline) |

## New findings — Critical

### B-1. `SaltedKeyPass` round-trips through ungarbageable strings on every Save/Load

`internal/keystore/keystore.go:108, 116` — `base64.StdEncoding.EncodeToString(l.SaltedKeyPass.Bytes())` produces an immutable string assigned to `savedBlob.SaltedKeyPassB64`, then `json.Marshal` produces a `data []byte` (which *is* zeroed). On `Load`, `blob.SaltedKeyPassB64` is a GC-owned string the `Secret` cannot reach.

Result: the salted PGP key material has at least one ungarbageable string copy per Save/Load round-trip — defeats the point of `Secret`.

Recommendation: encode directly into a pre-sized `[]byte` (`base64.StdEncoding.Encode`), use `json.Encoder` over a `bytes.Buffer`, zero everything.

### B-2. TOTP code upcast to `string` and survives in GC heap; also visible in `debugTransport`

`internal/proton/client.go:319` — `gpa.Auth2FAReq{TwoFactorCode: string(creds.TOTP.Bytes())}`. Comment acknowledges "30s validity" leak. But: with `PROTONMCP_DEBUG=1`, the TOTP lands verbatim in `httputil.DumpRequestOut` to stderr (`client.go:36-39`), bypassing the slog redactor entirely.

Recommendation: either fork the SDK to accept `[]byte`, or strip headers/body from `httputil.Dump*` before printing.

## New findings — High

### B-3. `Secret`'s value-semantics + `Live` value-passing = `SaltedKeyPass.Zero()` is never called in the CLI flow

`internal/secret/secret.go:84-89`. `Zero()` mutates the receiver's backing array — but `keystore.Live` is passed *by value* throughout (`session.go:130-138, 147-153`, `login.go:64-70`). Grep for `Live{}.Zero|stored.Zero` returns zero hits.

Result: salted pass stays live on heap for every `whoami` / `backfill` / `logout` run.

Recommendation: pointer-pass `Live`, or `defer stored.Zero()` at every `keystore.Load` call site.

### B-4. Logging redactor is a tiny denylist with concrete misses

`internal/logging/logging.go:26-43`. Specific holes:

- `slog.Warn("…", "err", err.Error())` (`session.go:53, 74, 117, 156`, `login.go:57`) — if the wrapped error contains `"refreshToken":"…"`, the redactor never sees it (key is `err`).
- Camel-case fields (`Token`) under arbitrary keys pass through.
- Proton-specific headers (`X-Pm-Uid`, `X-Pm-Human-Verification-Token`, `Proxy-Authorization`) not listed.

Recommendation: add a value-side heuristic backstop — base64/JWT-shaped strings over ~32 chars get redacted regardless of key. Denylists are always incomplete.

### B-5. Weekly `govulncheck` runs on Ubuntu where keystore CGO can't link → silent failures

`.github/workflows/govulncheck-weekly.yml:21` is `ubuntu-latest`. The main CI file itself comments that Ubuntu can't link `keybase/go-keychain` (`ci.yml:36-40`). The weekly job will fail at the loading-packages step and CVE alerts will never reach the maintainer.

Also: no `CODEOWNERS`, no visible branch protection — Dependabot PRs can be merged with one click.

Recommendation: move weekly to `macos-14`; add `CODEOWNERS` requiring explicit approval for security-impacting paths.

## New findings — Medium

### B-6. DSN `path` raw-concatenated before query → pragma injection via `--db` flag

`internal/store/store.go:115, 123` — `return path + "?" + v.Encode(), nil`. `--db` flag (`backfill.go:35`) accepts arbitrary user input. `--db '/tmp/x.db?_pragma=key(...)'` would inject. Fix: `url.PathEscape(path)` or `url.URL{Scheme:"file", Opaque:path, RawQuery:v.Encode()}.String()`.

### B-7. Keychain ACL is process-agnostic — any user-process can read the blob

`internal/keystore/keystore.go:124-127` — `AccessibleWhenUnlocked` only gates *device* state, not *which process* reads. No `SetAccessControl`. Any unsigned binary running as the user (malicious Homebrew, curl-piped installer) can `SecItemCopyMatching` service=`zone.dort.protonmcp` and exfiltrate refresh token + base64'd `SaltedKeyPass` → full account takeover, no re-prompt.

TODO.html flags this as deferred-until-codesigning. That's defensible — but it must be **loud** in this doc and in `login`'s success output ("readable by any process running as you until codesigning lands").

Adjacent: `keybase/go-keychain v0.0.1` is effectively unmaintained (last upstream release 2018). Track migration to `99designs/keyring` or a maintained fork.

### B-8. `logout` server-revoke is silent best-effort; failure leaves a live server session

`cmd/protonmcp/login.go:60-75`. If `Resume` fails (network down, expired refresh), code falls through, `keystore.Delete` succeeds, user sees "Logged out" — but Proton still has an authenticated session. No warning. Print an explicit "couldn't revoke server-side; visit account.proton.me to manually revoke" on the error path.

### B-9. Backfill writes unbounded attacker-controlled bytes into SQLite

`cmd/protonmcp/backfill.go:94-110`, `internal/proton/messages.go:24-51`. Full API response goes into `raw_json` verbatim. Page count is unbounded; a compromised midbox or malicious server returning 150 novel IDs forever is an unbounded memory/disk DoS. No size cap on `subject` / `from_address` / `raw_json`.

Fix: max-pages stop, per-row size guard on `RawJSON` (truncate at ~1 MiB with a `slog.Warn`).

### B-10. SQLite missing `secure_delete=ON` — once Phase 2 caches bodies, deleted plaintext lingers in free pages

`internal/store/store.go:118-123`. Schema is set up to FTS-index `body_text` (`migrations/0001_initial.sql:53-71`). Add `v.Add("_pragma", "secure_delete(on)")` before bodies start landing.

## New findings — Low

- **B-11.** `inspect.go:31-32` truncates tokens to 16 chars but writes to stdout — easy to accidentally pipe. Gate behind `PROTONMCP_DEBUG=1`.
- **B-12.** `debugTransport` (`client.go:30-48`) bypasses the slog redactor — any stderr-to-log wiring leaks raw bodies.
- **B-13.** `go-proton-api` and `gopenpgp/v2-proton` excluded from Dependabot (`dependabot.yml:21`). Pragmatic, but adds a manual quarterly review TODO.
- **B-14.** `keystore.Save` requires non-empty `RefreshToken` but not non-empty `SaltedKeyPass`. Guard at save time, not just at `Resume`.
- **B-15.** SIGHUP semantics will change in Phase 4 (shutdown → policy reload). Already in code; flag at the call site so the reassignment doesn't surprise.

## Updated foundational recommendations

1. **Replace the redaction denylist with a value-heuristic backstop.** Audit-log `args_json` (Phase 4) will hold arbitrary tool args — a tool named `secret_input` will not match the denylist. Add length + base64-class detection.
2. **Pointer-pass `Secret`-bearing structs.** `Credentials` is `*Credentials`; `Live` is value-passed → `SaltedKeyPass.Zero()` is never invoked in the CLI flow.
3. **Land the sentinel error set now.** Without `ErrUserCanceled` / `ErrAuthFailed` / `ErrNetwork` / `ErrUnlockFailed`, M-4 and M-5 reopen on every new wrapped error.
4. **Document the Keychain threat model explicitly.** "Pre-codesigned binary → any user-process read" is currently buried in a TODO; needs to be loud in SECURITY.md and in the `login` success message.
5. **Audit-log column needs its own redaction pass** before the first INSERT — shared helper with the slog redactor, not the slog redactor itself.
6. **Pre-Phase-3 invariant: refuse to start in daemon mode with `PROTONMCP_DEBUG=1`.** Today `debugTransport` is harmless (no daemon). Once a launchd plist exists, that env will leak refresh tokens to whatever captures stderr.

## Net assessment

Genuinely done: H-1, H-3, L-1/2/3/5/6, M-2, M-3, Foundational #1 and #8.
Structurally done, deferred path: H-2 (signal-driven shutdown).
Still open: M-1, M-4, M-5, Foundational #2 (partial), #3, #4, #5 (partial), #6, #7.
Biggest *new* risks introduced by Phase 1.5: B-1 (Secret round-trip via strings), B-4 (denylist redactor), B-5 (Ubuntu vulncheck), B-7 (unscoped Keychain ACL).
