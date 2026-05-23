# SECURITY.md

> ## ⚠ AppVersion impersonation (alpha-1.0 scoping)
>
> proto-mcp sends `AppVersion: macos-bridge@3.24.2` on every Proton API
> request. **That is Proton Bridge's identifier, not ours.** We are not
> registered with Proton as a recognized client; the impersonation is a
> deliberate development shortcut so the API allowlist accepts our
> requests at all.
>
> Implications:
>
> - Anything that violates Proton's
>   [Terms](https://proton.me/legal/terms) — rate-abuse, scraping,
>   multi-account automation, etc. — is no less violating because the
>   header reads "Bridge." Don't.
> - Proton's security team may revoke `macos-bridge@3.24.2`'s allowlist
>   entry in any future Bridge release. If that happens, proto-mcp
>   stops working until we re-pin to a newer Bridge version OR we
>   apply for and receive our own client identifier.
> - A `protonmcp@x.y.z` registration with Proton is the right
>   long-term answer; it's a follow-up after alpha.
>
> By installing and running proto-mcp, you accept that this is a
> personal-use development tool, not a sanctioned third-party client.
> The full README mirrors this paragraph for first-time visibility.

---

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

---

# Re-audit #2 — through commit `f7dc0d8` (Phase 2 complete)

Read-only review covering `b6a8897` (pre-Phase-2 hotfix) through `f7dc0d8`
(event-loop sync + B-9 backfill bounds). Three new packages
(`internal/sanitize`, `internal/sync`) and significant new attack surface in
`internal/proton/body.go`, `internal/store/{search,query,messages}.go`,
`cmd/protonmcp/{read,search,sync,login}.go`.

## Verification matrix

| ID | Status | Evidence |
|---|---|---|
| **B-5** govulncheck on macOS + CODEOWNERS | **PARTIAL** | `.github/workflows/govulncheck-weekly.yml:26` now `macos-14`. No `CODEOWNERS` file exists — second half never landed. |
| **B-7** loud Keychain risk + `SetAccessControl` | **PARTIAL** | Warning added at `cmd/protonmcp/login.go:50-57` and in SECURITY.md. `SetAccessControl` still **not** wired in `internal/keystore/keystore.go:128-131` — comment defers it. Doc-only fix, as the original finding allowed. |
| **B-8** logout warn-on-revoke-fail | **FIXED** | `cmd/protonmcp/login.go:82-94` prints the explicit recovery URL. Caveat: `CloseAndRevoke` discards its internal `AuthDelete` error — see C-3. |
| **B-9** max-pages + per-row size guard | **PARTIAL** | `internal/proton/messages.go:31,57-59` adds `MaxBackfillPages=10000`; `MaxRawJSONBytes=1MiB` enforced at `messages.go:108-110`. Missing: no cap on `Subject`/`FromAddress`/`FromName`; no `slog.Warn` on truncation; truncation produces invalid JSON (`raw[:1MiB]+"...[truncated]"`) that crashes any later `json.Unmarshal`. |
| **B-11** `inspect` debug gating | **FIXED** | `cmd/protonmcp/inspect.go:25-29` errors unless `PROTONMCP_DEBUG=1`. Bonus: `defer stored.Zero()` at line 44 partially addresses B-3 for this site. |
| **B-1** Secret base64 round-trip | **FIXED** | `internal/keystore/keystore.go:81-100` — blob v3, `SaltedKeyPass` is `[]byte`, `zero(data)` + `zero(blob.SaltedKeyPass)` fire on Save+Load. |
| **B-2** TOTP debug leak | **FIXED** | `internal/proton/client.go:60-91` adds `redactDump` over headers + JSON body; `redact_test.go` covers TwoFactorCode, ClientProof, Authorization, Set-Cookie. The TOTP-string-on-heap (`client.go:363`) remains acknowledged as a 30 s leak. |
| **B-3** Secret/Live pass-by-value | **PARTIAL** | `inspect.go:44` zeroes. The two hot paths — `session.go:84` and `login.go:64` — still don't. `SaltedKeyPass` stays on the heap for every `whoami`/`backfill`/`sync`/`read`/`search`/`logout`. |
| **B-4** denylist redactor | **FIXED** | `internal/logging/logging.go:75-113` adds `looksLikeToken` value-heuristic; tests at `logging_test.go:73-117`. Acknowledged limitation: embedded-in-prose tokens still pass. |
| **B-6** DSN pragma injection | **NOT FIXED** | `internal/store/store.go:116,129` still `path + "?" + v.Encode()`. `--db` now exposed by `backfill`, `read`, `search`, `sync`. |
| **B-10** `secure_delete` | **FIXED** | `internal/store/store.go:115,128` adds `_pragma=secure_delete(on)` to both DSN paths. |
| **B-12** `debugTransport` redaction | **FIXED** | Covered by B-2. |
| **B-13** Proton-fork Dependabot exclusion | **UNCHANGED** | Pragmatic; manual review TODO. |
| **B-14** Save guards | **NOT FIXED** | `keystore.go:104` still guards only `Email`/`UID`/`RefreshToken`. |
| **M-1** AppVersion warning surface | **UNCHANGED** | Still only printed in `whoami`. |
| **M-4** error wrapping with `%w` | **NOT FIXED** | `client.go:504` + new `body.go:55` still chain gopenpgp errors. |
| **M-5** error classification | **NOT FIXED** | `main.go:104` still prints raw chain. |
| **Foundational #7** HTML sanitization at MCP boundary | **IN PROGRESS but inverted** | Sanitization landed at **storage** boundary, not the MCP boundary — see C-1. |
| **Foundational #3 / #4 / #6** MCP trust model, default-deny, login rate-limit | **NOT YET** | Phase 2 hasn't touched these. |

## New findings — Critical

### C-1. Decrypted plaintext bodies persisted to SQLite without a documented threat model

`internal/proton/body.go:38-88`, `internal/store/messages.go:283-305`,
`cmd/protonmcp/read.go:107-114`, `migrations/0001_initial.sql:53-71`.

Phase 2/B caches **decrypted plaintext** message bodies in `body_text` /
`body_html`, indexed verbatim into `messages_fts.body_text`. The Keychain
protects the PGP keys but not the on-disk SQLite file — file perms are 0600
(M-2/M-3, good) but Time Machine backups, Spotlight indexing, cloud-synced
Documents folders, and forensic disposal images all bypass perms entirely.

The original Foundational #7 said: *keep raw HTML in SQLite (bodies may
need to be re-sanitized later under a stricter policy); sanitize on the way
out to the MCP client.* Phase 2 **inverted** this — `body.go:73-74` stores
`sanitize.HTML(body)` and `sanitize.Text(body)`, dropping the original.
That forecloses re-sanitization under a stricter future policy **and**
persists plaintext on disk — the worst of both options.

No SECURITY.md entry, no TODO open question, no README warning reflects
this material posture shift (Phase 1: only credentials at rest → Phase 2:
credentials + plaintext mail at rest).

`BodyTTL = 24*time.Hour` (`messages.go:264`) is illusion — `GetCachedBody`
treats stale entries as "missing" but **does not delete** them. Rows
persist past TTL; only a follow-on `SetCachedBody` overwrites. No eviction
job, no `protonmcp purge`, no startup sweeper.

Recommendation: (a) document the threat model loudly (SECURITY.md +
`read` first-run banner); (b) ship `protonmcp purge` and a startup sweep
that hard-deletes `body_text`/`body_html` past TTL (relies on
`secure_delete=on` from B-10, now in place); (c) seriously consider
SQLCipher or an envelope-encryption layer keyed off the same Keychain blob.

### C-2. Plaintext bodies emitted to stdout without ANSI/control-char sanitization — terminal-escape injection from attacker-controlled mail

`cmd/protonmcp/read.go:130-133`, `cmd/protonmcp/search.go:85-87`,
`internal/sanitize/sanitize.go:112-128`.

`sanitize.Text` strips HTML/quotes/whitespace but does **not** strip ESC
(`0x1b`), other C0/C1 control chars, OSC, or DCS. A malicious sender can
embed `\x1b]0;hacked\x07` (window-title rewrite), `\x1b[6n` (cursor query
that injects into next shell command), or — most concerning —
`\x1b]52;c;<base64>\x07` (xterm OSC 52 clipboard write, default-on in
iTerm2 and several modern terminals).

`encoding/json` escapes control chars (``), so the current JSON
output paths are safe **as long as output stays JSON**. But:

- `internal/store/search.go:128` writes `h.Snippet = snippet(*bodyText, 200)`
  on a path that flows to MCP responses in Phase 3.
- The future `mail.read` tool delivers plaintext to an LLM where ANSI
  sequences become prompt-injection vectors against the transcript renderer.

Recommendation: in `sanitize.Text`, strip all bytes `< 0x20` except `\n`/`\t`
and strip the C1 range (`0x80-0x9f`). Five-line change, zero downside.

## New findings — High

### C-3. `CloseAndRevoke` discards `AuthDelete` error → logout claims success even when server-side revoke fails on the success path

`internal/proton/client.go:278-289`, `cmd/protonmcp/login.go:80-94`.

B-8's fix correctly handles `Resume` failure. But on `Resume` success,
`CloseAndRevoke` does `_ = s.Client.AuthDelete(ctx)`. If Proton returns 500
or the network drops between Resume and AuthDelete, the user sees
"Logged out." while their session lives on — the **exact** failure mode
B-8 was meant to close, just on a different branch.

Recommendation: change to `CloseAndRevoke() error`, surface the error
through login's existing warn-and-recovery path.

### C-4. `Session.releaseLocal` zeroes `SaltedKeyPass` on Close — racy with `OnAuthUpdate` keystore re-Save during long sync runs

`internal/proton/client.go:294-304`, `cmd/protonmcp/session.go:146-158`,
`internal/sync/sync.go`.

`releaseLocal` calls `s.SaltedKeyPass.Zero()`. The keystore-sync
`OnAuthUpdate` hook reads `b.Session.SaltedKeyPass` to re-Save on token
rotation. With `Secret`'s shared-backing-array semantics, a late-arriving
OnAuthUpdate sees an empty `SaltedKeyPass`. Since `keystore.Save` doesn't
refuse empty `SaltedKeyPass` (B-14, still open), a corrupted blob is
written. Next `Resume` fails at `resume.go:72` ("re-login required"),
forcing an unexpected re-login.

Race-only today, but the new sync loop drains `GetEvent` calls serially —
exactly when token rotation is most likely.

Recommendation: don't zero `SaltedKeyPass` in `releaseLocal`, OR guard
`OnAuthUpdate` against `SaltedKeyPass.Empty()` and skip the Save, OR close
the auth handler before zeroing in a strict order. Pick one.

### C-5. Event-sync loop has no backoff and an off-by-one paging break

`internal/sync/sync.go:88-119`.

- `GetEvent` errors return immediately. No exponential backoff for
  transient 5xx/network; no auth-failure detection. Fine for CLI one-shot;
  bad for the Phase 6 daemon (per the package doc, 30 s cadence). A brief
  Proton outage will spam re-Resume attempts. Foundational #6 (login rate
  limit) is now overdue — sync makes the threat bigger.
- `if len(events) < 2 { break }` (line 116). Comment says "GetEvent
  chunked up to its internal limit (50)" — true, but the check breaks on
  `< 2`, not `< 50`. A legitimate single-event page exits the loop,
  leaving a one-event gap; cursor advanced inside the inner loop hides it
  on next `RunOnce`. Phase 4 audit deletion entries would be lost.

Recommendation: compare against the actual page size (50 with a TODO),
add 30 s+jitter backoff on consecutive `GetEvent` errors, and detect auth
expiry via `isAuthExpired` (`resume.go:152`) so sync can surface
"needs re-login" cleanly.

## New findings — Medium

### C-6. HTML sanitizer drops `<a href>` entirely — phishing destination disguise

`internal/sanitize/sanitize.go:46-67`.

Documented choice: LLM sees "click here" with no URL. Mitigates one
threat (prompt injection via href) and enables another: a phishing email
with "log in at [Proton Support](https://attacker.example/)" becomes "log
in at Proton Support" with no destination visible. An LLM downstream
suggesting "click X" has lost the signal that the URL was suspicious.

Recommendation: emit href as plaintext adjacent to link text —
`"<text> [<href>]"` — via a bluemonday element rewriter. Both the LLM and
any human looking at `read` output can see destination mismatches.

### C-7. `sanitize` policy lacks test coverage for SVG, MathML, `<noscript>`, entity-encoded `javascript:`

`internal/sanitize/sanitize.go:38-44`, `sanitize_test.go`.

bluemonday's `NewPolicy()` is empty-allowlist, so SVG/MathML/`<noscript>`
*should* drop today. But no tests prove it; future allowlist additions
could silently widen surface. Specifically untested:

- `<svg><script>` (foreign content)
- `<math>`
- `<noscript><script>...</script></noscript>`
- `<a href="javascript&#58;alert(1)">` — bluemonday normalizes entities in
  attribute values; combined with C-6 (href drops to plain text), the
  decoded `javascript:` URL surfaces into LLM context.

Recommendation: add these as explicit test cases; decide whether stripped
elements' text content survives.

### C-8. `search.Search` builds `ORDER BY`/`LIMIT`/`OFFSET` via `fmt.Sprintf`

`internal/store/search.go:101-107`.

`Limit` is clamped `[0, 200]` (safe). `Offset` is **not** clamped —
negative values produce confusing SQLite errors. `orderBy` is one of two
hard-coded literals (safe today). `where` uses bound `?` (safe). No SQL
injection today.

Real risk when (a) Phase 3 MCP passes `offset` straight from an LLM call,
or (b) someone adds `--sort-by` without remembering this path is `Sprintf`.

Recommendation: bind `Limit`/`Offset` as `?` parameters now; clamp
`Offset` to `0..N`; add a doc-comment on `orderBy` warning that new values
MUST be literals.

### C-9. FTS5 MATCH passes user input through verbatim — DoS via `NEAR`, syntax errors surface raw

`internal/store/search.go:65-66`, `internal/store/query.go:73-77, 96-98`.

User input is `?`-bound (not SQL-injectable), but FTS5 has its own query
language with `*`, `^`, `:`, `"`, `NEAR/N`, operators, parentheses. A
crafted `"NEAR/0 \"a\" \"b\""` against a large corpus hits FTS5's worst
case. Unterminated quotes in `tokenizeQuery` are silently dropped, which
masks the bug class rather than fixing it.

Recommendation: escape FTS5 metacharacters in bare terms, or wrap bare
terms in `"…"` (phrase form, non-greedy w.r.t. operators). Add a 5 s
per-context statement cancel.

### C-10. `protonmcp read` shell-redirect inherits process umask, not SQLite secure-delete semantics

`cmd/protonmcp/read.go:116-127`. Documentation-only: redirecting `read`
output to a file produces `0600` (umask 0o077 from M-3 — good) but the
file has no secure-delete behavior if later moved/deleted/backed up. Add a
docstring warning.

## Updated foundational recommendations

1. **Document the on-disk plaintext posture before any external user
   touches this binary.** C-1 is the single biggest residual risk. The
   project's threat model has materially changed and no public-facing
   document reflects the shift.
2. **Strip control characters in `sanitize.Text`.** Five-line change that
   closes C-2 and the bytes-LLMs-don't-like class. Independent of Phase 3.
3. **Land the sentinel error set.** Still open. Now larger surface —
   `body.go` and `sync.go` both wrap library errors with `%w`. M-4 keeps
   reopening on every new code path.
4. **`CODEOWNERS` is overdue.** Half of B-5 wasn't done. Without it any
   maintainer (including Dependabot auto-merge) can land changes to
   `internal/keystore`, `internal/proton`, `internal/sanitize`
   unreviewed.
5. **Auth-failure detection + real backoff in `sync.RunOnce`.** Before
   Phase 6 daemon ships, not after.

## Net assessment

**Genuinely improved this cycle:** B-1 (Secret round-trip), B-2/B-12
(debug-dump redaction), B-4 (value-heuristic redaction), B-8 (logout warn),
B-10 (`secure_delete=on`), B-11 (inspect gating). Several long-standing
foundational items crossed off cleanly.

**Still open, now in heavier code:** M-4 / M-5 (error wrapping &
classification), B-3 (`Secret.Zero` not called in hot paths), B-6 (DSN
pragma injection — `--db` now in four subcommands), B-14 (Save guards),
M-1 (AppVersion warning surface).

**New attack surface introduced by Phase 2/B-C-D:** cached plaintext
bodies (C-1) are the most consequential single change in the project's
history. Sanitization is sound for the threats it considered
(script/iframe/href-prompt-inject) and miscalibrated for the threats it
didn't (terminal-escape, link-destination loss, on-disk-at-rest). The
sync loop (C-5) is a future operational hazard, not a today-attacker one.

**Single biggest residual risk:** **C-1**. Every other finding has a
contained blast radius; the plaintext-mail-at-rest decision changes who
the threat model is for. If the laptop is lost, stolen, iCloud-backed-up,
or imaged for support, every message ever opened in `protonmcp` is
recoverable in cleartext without the Keychain.

---

# Re-audit #3 — through Phase 4/D + Phase 5 send tools (2026-05-22)

Read-only re-audit covering everything from `f7dc0d8` (Phase 2 complete)
through `a657a61` (Phase 4/D MCP middleware) and the in-tree Phase 5 send
tools (`internal/mcptools/{mail_send,mail_state,drafts,labels_folders_crud,
recipients}.go`). Three new package families landed: MCP server
(`internal/mcp`, `internal/mcptools`, `internal/mcperrors`), policy +
audit + Touch ID approval (`internal/policy`, `internal/audit`,
`internal/approval`, `helpers/touchid`), and the redactor extraction
(`internal/redact`).

The audit surfaced 28 findings (D4–D31 in [`DEFECTS.html`](./DEFECTS.html))
plus three from live MCP testing (D32–D34). Five fix PRs (#43–#47) landed
the same day and closed **20 of the 28 audit findings + all 3 live-test
findings = 23 fixed**, leaving **8 open** (mostly Low + Phase-6-adjacent).
This re-audit section is structured around what shipped vs. what remains,
not around the audit's findings list (DEFECTS.html holds that).

## Fix batch — what shipped in PRs #43–#47

| PR | Commit | Findings closed | Themes |
|---|---|---|---|
| **#43** | `5315158` | D4, D5, D9, D31 | env-var hygiene in `serve-stdio`; pgrep-based PID discovery replaces unauthenticated PID file |
| **#44** | `c709963` | D6, D7, D21, D23, D32 | send-family allowlist re-validation post-fetch; `mail.ParseAddressList` for CSV/display-name safety; NSAlert prompt sanitization; `labels_list`/`folders_list` backfill |
| **#45** | `097fcfb` | D13 (C-1) | `protonmcp purge --older-than D` + startup sweep with 30-day default retention; closes the single biggest residual risk pending Phase-6 envelope encryption |
| **#46** | `a7e85d1` | D8, D14, D18 | audit writes on detached 5s ctx; approval cache dropped on policy reload; JSONL row gains tool/caller/policy_decision |
| **#47** | `19b0bf5` | D10, D15, D16, D17, D19, D25, D27, D29 | `.github/CODEOWNERS` finally landed; `defer stored.Zero()` in tryResume/runLogout; `errors.Is` on deadline; keystore empty-SaltedKeyPass guard; sync loop respects GetEvent `more`; JWT/Bearer detection in redactor; `mail_read_thread` no longer leaks raw decryption error |

Live-MCP-test findings (D32, D33, D34) were closed under their respective
PRs. D33/D34 specifically: pgrep discovery now post-filters by executable
identity via `libproc.proc_pidpath` + `os.SameFile`, so the Claude.app
disclaimer wrapper and editors/greps with matching command lines no
longer receive spurious SIGHUPs.

## Verification matrix vs. re-audit #2

| ID | Status | Notes |
|---|---|---|
| **B-3** Secret/Live pass-by-value | **FIXED** | PR #47 added `defer stored.Zero()` at both hot paths. → D10 resolved |
| **B-5** CODEOWNERS | **FIXED** | PR #47 landed `.github/CODEOWNERS` covering keystore/approval/policy/audit/redact/proton/cmd/helpers paths. → D27 resolved |
| **B-6** DSN pragma injection | **STILL OPEN** | `internal/store/store.go:116,129` still `path + "?" + v.Encode()`. → D12 (medium) |
| **B-9** backfill bounds / truncation | **STILL PARTIAL** | Per-row 1 MiB cap landed in re-audit #2; truncation still emits invalid JSON. → D11 (high) |
| **B-14** keystore Save guards | **FIXED** | PR #47 added empty-SaltedKeyPass guard with diagnostic error. → D16 resolved |
| **M-1** AppVersion warning surface | **DOCUMENTED** | Top-of-file banner added to `SECURITY.md`; user-facing decision rather than code change |
| **M-4** error wrapping with `%w` | **PARTIAL** | PR #47's redactor handles JWT/Bearer/quoted-JSON cases (→ D19 resolved); D29 fixed `mail_read_thread`'s raw-error leak. Architectural `%w` use in library wrappers unchanged |
| **M-5** error classification | **STILL NOT FIXED** | Sentinel error set in `internal/mcperrors` is used for MCP classification; CLI stderr still prints raw chains. Open |
| **C-1** plaintext bodies at rest | **FIXED** | PR #45 shipped `protonmcp purge` + startup sweep. Three cycles open, now closed. → D13 resolved. Phase-6 envelope encryption is the long-term follow-up |
| **C-2** terminal-escape injection | **FIXED** (re-audit #2) | `internal/sanitize/sanitize.go` strips C0/C1 controls |
| **C-3** `CloseAndRevoke` discards error | **FIXED** (re-audit #2) | Error surfaces through login's recovery path |
| **C-4** `releaseLocal` / `OnAuthUpdate` race | **FIXED** (via D16) | The empty-SaltedKeyPass guard closes the observable symptom |
| **C-5** sync loop backoff + paging | **PARTIAL** | PR #47 fixed the off-by-one (`more` bool replaces `len(events) < 2`); auth-failure backoff still pending (Foundational #6 territory) |
| **C-6 / C-7** sanitizer link-loss + missing test cases | **PARTIAL** | bluemonday policy hardened; href-as-plaintext rewriter still not landed |
| **C-8** Sprintf in store | **PARTIAL** | `search.Search` fixed with `?` binding; `messages.SearchMessages` still uses Sprintf for `LIMIT`. → D28 (low, copy-paste footgun) |
| **C-9** FTS5 query DSL | **FIXED** (re-audit #2) | `internal/store/query.go` phrase-wraps every term via `ftsQuote` |
| **Foundational #2** redacting logger | **FIXED** | Value-heuristic in `internal/redact/redact.go` + PR #47's JWT/Bearer handling closes the prose-context gap. → D19 resolved |
| **Foundational #3** MCP trust model | **FIXED in stdio mode** | `internal/mcp/trustguard.go` panics on any `net.Listen`. Caveat: `caller.UID` records the daemon's own UID, not the spawner's. → D20 (medium) |
| **Foundational #4** default-deny policy | **FIXED** | `internal/policy/policy.go` engine with `default.yaml`; explicit allow per tool; SIGHUP-driven atomic reload + approval-cache invalidation (PR #46) |
| **Updated #6** (re-audit #1): refuse `PROTONMCP_DEBUG=1` in daemon mode | **FIXED** | PR #43 made `serve-stdio` refuse to start when the env var is set, then `Unsetenv`s it. → D5 resolved |
| **Foundational #5** token persistence story | **PARTIAL** | Code shipped; Phase 6 Keychain ACL hardening still pending |
| **Foundational #6** login rate-limit | **STILL NOT YET** | Tools have per-call limits; login flow doesn't. Sync loop partial-fix (C-5) reduces, doesn't eliminate, pressure |
| **Foundational #7** HTML sanitization at MCP boundary | **STILL INVERTED** | Sanitization happens at storage, not at MCP boundary. `D13` fix mitigates by purging plaintext at rest, but the architectural inversion remains |

## Still open after the fix batch (8 defects)

Full per-defect detail in [`DEFECTS.html`](./DEFECTS.html). Grouped by
severity:

- **High (1)** — **D11** (B-9 partial): `raw_json` truncation still
  produces invalid JSON. No current consumer parses `raw_json`, but the
  poisoned row breaks any future `json.Unmarshal`.
- **Medium (4)** — **D12** (B-6, three cycles): DSN escaping via `--db`.
  **D20**: `caller.Resolver` records daemon's own UID, not spawner's —
  misleading audit field, actively wrong once Phase 6 lands SO_PEERCRED.
  **D22**: `mail_read` allow-by-default with no structured
  `<UNTRUSTED_INPUT>` marker; the description-string warning is the only
  prompt-injection mitigation. **D24**: no integrity check on the
  running protonmcp binary path (PATH-swap defense-in-depth, blocked on
  Phase 7 code signing).
- **Low (3)** — **D26**: `args_json` binding hygiene (no impact, copy
  cost only). **D28** (C-8 partial): `SearchMessages` Sprintf for
  `LIMIT` — safe today, copy-paste footgun. **D30**: Touch ID helper
  has no password fallback; hardware-without-Touch-ID Macs can't use
  prompted tools.

## Net assessment

**Genuinely improved this cycle:** Foundational #3 (MCP trust model —
stdio + TCP-bind panic via `trustguard.go`), Foundational #4 (default-deny
policy + engine + atomic reload + approval-cache invalidation),
Foundational #2 (value-heuristic redactor + JWT/Bearer handling), C-1
(plaintext-body eviction + `purge` subcommand — closes the single biggest
residual risk after three cycles open), env-var trust hygiene in
serve-stdio (D4/D5/D31), send-family allowlist correctness (D6/D7),
NSAlert prompt sanitization (D21/D23), audit-log integrity under
cancellation (D8), `.github/CODEOWNERS` (two cycles open, now closed),
C-2/C-3/C-9 + B-1/B-2/B-12 holding from re-audit #2.

**Notable about the cadence:** the audit was run on 2026-05-22 and the
five fix PRs (#43–#47) landed the same day. Every Critical and every
High was closed except D11 (which is a partial of B-9, has no current
exploit path, and was triaged below the in-day batch). The remaining 8
items are dominated by Low (3) and Medium defense-in-depth / Phase-6-
adjacent work (D20, D22, D24). The two-cycle-open hygiene items
(CODEOWNERS, plaintext bodies, B-3, B-14) all shipped in this batch.

**Phase 4 architecturally validated.** Every Phase-4 finding (D4, D6, D8,
D14) was a configuration / boundary issue rather than a design flaw, and
all four shipped fixes within the day. The policy engine, audit log,
Touch ID broker, and middleware composition are working as designed; the
seams to the spawning process (which Phase 4 doesn't own) needed the
hardening.

**Residual risk profile:**

- **D11 (high)** — corruption-class, not a leak; safe to land in next
  hygiene round. No current consumer of `raw_json`.
- **D12 (B-6, three cycles)** — local attack requiring `--db` control;
  consequence is `secure_delete(off)` / `journal_mode(off)` injection.
  Mitigated by `D13`'s purge sweeper running at startup with
  `secure_delete=on` already on the DSN.
- **D22 (mail_read prompt-injection)** — the residual write-tool risk
  rests on the user reading the Touch ID dialog carefully. The Phase 5
  recipient allowlist + literal recipients in NSAlert (post-D7/D21) is
  the practical protection; structured `<UNTRUSTED_INPUT>` tagging is
  a defense-in-depth upgrade for the next cycle.
- **D24 (binary integrity)** — chicken-and-egg with Phase 7 code
  signing; the recommended interim is SHA-pinning in
  `~/Library/Application Support/protonmcp/expected_sha`.

The next non-trivial code paths (Phase 6 daemon, Phase 7 signing) will
likely reopen Foundational #3 (peer UID once SO_PEERCRED matters), close
D24 (signing), and clear the D20 misattribution. Until then this audit
cycle has consumed every actionable finding it raised.
