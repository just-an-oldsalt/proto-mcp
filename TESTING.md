# TESTING.md — proto-mcp validation guide

End-to-end validation playbook for `proto-mcp`. Sequenced so an agent
(or human) starting cold can work through it and produce a structured
report. Each section is independently runnable; later sections may
depend on earlier ones (e.g., signing tests need a build).

## How to use this doc

- Work top-to-bottom. Sections are ordered by setup cost (cheap fast
  checks first).
- Each test has **Goal**, **Steps**, **Expected**, and an **On
  failure** note. Mark each test pass / fail / skipped in your
  report.
- "Pass" means the **Expected** matches verbatim or with documented
  variation. Partial matches are fail until rationalized.
- Findings get reported into `DEFECTS.html` using the existing
  D-numbering. The current ceiling is D40; pick the next free
  integer. Use the same severity scheme (critical / high / medium /
  low) the rest of the file uses.
- Don't smoke-test against a Proton account that isn't yours.

## Audience

You are an agent or engineer asked to validate `proto-mcp`. You can
read code, run shell commands, edit files, and use `git`. You should
not push commits or open PRs unless explicitly asked.

---

## Prerequisites

Required before any section runs:

- macOS 13+ (Ventura or newer). Some sections require macOS 14
  (Sonoma) for full Touch ID API support.
- Go 1.26+ on PATH. `go version` should print `go1.26` or higher.
- Xcode Command Line Tools — `swiftc -v` must succeed. Run
  `xcode-select --install` if missing.
- `git`, `make`, `zip`, `shasum`, `xcrun`, `codesign`, `launchctl`,
  `spctl`, `security` available on PATH.
- A Proton Mail account credentials available (for sections that
  require a live session). The account does NOT need a paid plan.

Optional, required for signing tests:
- An Apple Developer Program account with a Developer ID
  Application certificate installed in the login keychain. Confirm
  via `security find-identity -p codesigning -v` — look for a line
  starting with `Developer ID Application:`.
- `xcrun notarytool` keychain profile set up. Confirm via `xcrun
  notarytool history --keychain-profile <profile-name>` — it should
  return a history listing, not "Keychain password item not found."

---

## Section 1 — Build verification (3 minutes)

### 1.1 — Clean build of every binary

**Goal.** Confirm all five binaries (CLI, daemon, shim, two Swift
helpers) build from a clean tree on the current host.

**Steps.**
```sh
make clean
make all
```

**Expected.** Five files appear under `bin/` and `helpers/`:
```
bin/protonmcp
bin/protonmcpd
bin/protonmcp-shim
helpers/touchid/protonmcp-touchid
helpers/lockwatch/protonmcp-lockwatch
```
Each is a valid Mach-O 64-bit executable for `arm64` or `x86_64`
(check with `file bin/protonmcp`).

**On failure.** If `swiftc` is missing, install Xcode CLT. If a Go
target fails, capture the full output and file as a Build defect.

### 1.2 — `go vet` is clean

```sh
go vet ./...
```

**Expected.** No output (exit 0).

**On failure.** Each `vet` complaint is a real issue. File one
defect per category found.

### 1.3 — `go test ./...` passes

```sh
go test ./...
```

**Expected.** Every package reports `ok`. The full set is currently:

```
ok  cmd/protonmcp
ok  cmd/protonmcp-shim
ok  cmd/protonmcpd
ok  internal/approval
ok  internal/audit
ok  internal/caller
ok  internal/keystore
ok  internal/logging
ok  internal/mcp
ok  internal/mcperrors
ok  internal/mcptools
ok  internal/policy
ok  internal/proton
ok  internal/redact
ok  internal/sanitize
ok  internal/secret
ok  internal/serve
ok  internal/store
ok  internal/sync
```

(17–19 ok lines depending on which test files have been added.)

**On failure.** Capture the failing test name + output. Failures
in `internal/redact`, `internal/policy`, `internal/mcp`, or
`internal/audit` block security claims and should be reported as
high severity.

### 1.4 — Race-detector clean

```sh
make race
```

**Expected.** Every package passes under `-race`. Slower than 1.3
(adds ~2–5x).

**On failure.** Any data race output is high severity — the daemon
shares Runtime state across goroutines so races there are
load-bearing.

---

## Section 2 — Signing pipeline (10 minutes; requires Apple Developer ID)

Skip this section if you don't have a Developer ID certificate.
Note "skipped: no Developer ID" in your report.

### 2.1 — `make sign` produces hardened-runtime signed binaries

**Prereq.** Export your Developer ID:
```sh
export DEVELOPER_ID='Developer ID Application: <YOUR NAME> (<TEAMID>)'
```
The exact string comes from `security find-identity -p codesigning -v`.

**Steps.**
```sh
make sign
```

**Expected.**
```
codesign bin/protonmcp
bin/protonmcp: replacing existing signature
codesign bin/protonmcpd
...
All binaries signed with Developer ID Application: ...
```

No "Failed to parse entitlements" or "AMFIUnserializeXML" errors
(D38-class regression). Four codesign lines, one summary.

**On failure.** The most common cause is the keychain being locked
— run `security unlock-keychain ~/Library/Keychains/login.keychain-db`
and retry.

### 2.2 — `make verify-sign` passes

```sh
make verify-sign
```

**Expected.** Per binary:
```
verify bin/protonmcp
bin/protonmcp: valid on disk
bin/protonmcp: satisfies its Designated Requirement
```
Final line: `All binaries pass codesign --verify`.

### 2.3 — `make notarize` returns Accepted from Apple

Requires the `protonmcp-notary` keychain profile (see
`scripts/signing-setup.md`).

```sh
make notarize
```

**Expected.** A `notarytool submit` block ending with
`status: Accepted`, followed by:
```
Notarization registered with Apple.
Stapling skipped: bare Mach-O CLI binaries cannot be stapled...
Confirm acceptance with: make verify-notarized
```

The "stapling skipped" message is intentional — Apple's stapler
rejects bare Mach-O with error 73. See `scripts/signing-setup.md`.

**On failure.** Notarytool returns an error log URL on rejection.
Fetch it with `xcrun notarytool log <id> --keychain-profile
protonmcp-notary`. Common cause: missing entitlement.

### 2.4 — `make verify-notarized` confirms each binary is on Apple's accept list

```sh
make verify-notarized
```

**Expected.** Per binary:
```
check bin/protonmcp
bin/protonmcp: valid on disk
bin/protonmcp: satisfies its Designated Requirement
bin/protonmcp: explicit requirement satisfied
```
Final line: `All binaries satisfy the =notarized requirement`.

---

## Section 3 — Daemon lifecycle (10 minutes; requires Proton login)

These tests touch your live Proton account. Use your own account.

### 3.1 — Fresh login

**Goal.** Confirm the SRP login + Keychain save round-trips.

```sh
./bin/protonmcp login
```

**Expected.** Interactive prompt for email + password (+ TOTP if
enabled). On success: `Login succeeded.` and a Keychain item named
"Proton MCP session" appears (visible in Keychain Access.app under
the `zone.dort.protonmcp` service).

### 3.2 — Resume from Keychain

```sh
./bin/protonmcp whoami
```

**Expected.** Account summary (email, addresses, plan) printed
within 2 seconds. No interactive prompts.

**On failure.** If the OS-level Touch ID prompt fires here, that's
expected post-7/D — Touch ID and the printed summary should both
succeed.

### 3.3 — Backfill mirror

```sh
./bin/protonmcp backfill --yes
```

**Expected.** Progress lines as pages drain. Final summary like
`drained 14738 messages, 27 labels, 6 folders in 42s`. The SQLite
store at `~/Library/Application Support/protonmcp/store.db` is now
populated.

### 3.4 — Daemon install

```sh
./bin/protonmcp daemon install
```

**Expected.**
```
Installed LaunchAgent: /Users/.../Library/LaunchAgents/zone.dort.protonmcpd.plist
  Binary:    /Users/.../bin/protonmcpd
  Log file:  /Users/.../Library/Logs/protonmcp/daemon.log
  Daemon should now be running. `protonmcp daemon status` to verify.
```

If a daemon was already installed, you may see a `Bootstrap failed:
5: Input/output error` — that's D39 (launchctl race). Re-run the
command; the second invocation always succeeds.

### 3.5 — Daemon status reports healthy

```sh
./bin/protonmcp daemon status
```

**Expected.**
```
protonmcp daemon status
  Plist installed:   true
  launchctl loaded:  true
  Socket reachable:  true
  Process PID:       <some number>

Healthy.
```

### 3.6 — D24 SHA-256 integrity check fires at startup

**Goal.** Confirm the daemon refuses to start with a mismatched
binary hash.

```sh
tail -f ~/Library/Logs/protonmcp/daemon.log &
LOG_PID=$!
launchctl kickstart -k "gui/$(id -u)/zone.dort.protonmcpd"
sleep 3
kill $LOG_PID
```

**Expected.** A new log line:
```
level=INFO msg="binary integrity check passed" sha256=<hash>...
```

### 3.7 — D24 swap-attack negative path

```sh
cp ~/Library/Application\ Support/protonmcp/expected_sha256 /tmp/_sha.bak
echo "0000000000000000000000000000000000000000000000000000000000000000  /tmp/bogus" > \
  ~/Library/Application\ Support/protonmcp/expected_sha256
launchctl kickstart -k "gui/$(id -u)/zone.dort.protonmcpd"
sleep 3
tail -5 ~/Library/Logs/protonmcp/daemon.log
```

**Expected.**
```
level=ERROR msg="refusing to start" err="binary integrity check FAILED..."
```

The error may have `[REDACTED-TOKEN]` placeholders where the SHA
and path should be — that's D38, an over-redaction in the slog
handler. The "refusing to start" + "binary was replaced" text
should be visible regardless.

**Cleanup.**
```sh
cp /tmp/_sha.bak ~/Library/Application\ Support/protonmcp/expected_sha256
launchctl kickstart -k "gui/$(id -u)/zone.dort.protonmcpd"
```

Approve any Touch ID prompts that fire; daemon should return to
healthy state within ~10 seconds.

### 3.8 — Daemon uninstall

```sh
./bin/protonmcp daemon uninstall
./bin/protonmcp daemon status
```

**Expected.** Uninstall removes the plist; status reports `Not
installed`.

(Re-install after if you need the daemon for later tests.)

---

## Section 4 — Touch ID + Keychain hardening (5 minutes; requires Touch ID hardware)

### 4.1 — Touch ID helper basic call

```sh
echo '{"title":"Test","body":"Approve test"}' | ./helpers/touchid/protonmcp-touchid
echo "exit=$?"
```

**Expected.** Touch ID prompt appears with body "Approve test."
Approving returns exit 0; canceling returns exit 1.

### 4.2 — Password fallback works (D30)

On a Mac WITHOUT Touch ID (or with it disabled in System Settings →
Touch ID & Password): the helper should still fall back to
password authentication.

```sh
echo '{"title":"Test","body":"Approve password fallback"}' | \
  ./helpers/touchid/protonmcp-touchid
```

**Expected.** A system password dialog appears (not a Touch ID
sensor prompt). Entering the user password returns exit 0.

**On failure.** If the helper exits 1 with "biometric not
available," D30 has regressed — the LAContext policy got reverted
to `.deviceOwnerAuthenticationWithBiometrics`.

### 4.3 — Keychain ACL v3→v4 migration (7/D, D37)

**Goal.** A first-launch after upgrade triggers the v3-to-v4 ACL
upgrade. Subsequent loads trigger OS-issued Touch ID.

**Setup.** You need a v3 blob (an older login predating 7/D). If
your current install is already v4, do `protonmcp logout` then a
fresh `protonmcp login` and manually downgrade the Keychain item to
v3 (advanced; skip this section if not feasible).

**Steps.** Start the daemon fresh and watch the log:
```sh
launchctl kickstart -k "gui/$(id -u)/zone.dort.protonmcpd"
sleep 3
tail -20 ~/Library/Logs/protonmcp/daemon.log | grep keystore
```

**Expected.** A line:
```
keystore: upgraded blob from v3 to v4 (SecAccessControl now requires Touch ID on next load)
```

### 4.4 — Subsequent loads trigger OS-issued Touch ID

Once the blob is v4, every Load triggers a Touch ID prompt issued
by macOS itself (system-styled, says "protonmcpd wants to use
your confidential information stored in 'Proton MCP session' in
your keychain").

```sh
./bin/protonmcp whoami
```

**Expected.** Touch ID prompt appears BEFORE the account summary
prints.

---

## Section 5 — Lock / unlock + auto-lock (5 minutes)

### 5.1 — Manual lock via CLI

```sh
./bin/protonmcp lock
sleep 1
./bin/protonmcp whoami
```

**Expected.** Lock command reports `sent SIGUSR1 to protonmcp pid
<pid>`. `whoami` (which talks via the shim) fails with
`daemon is locked (SIGUSR1); run \`protonmcp unlock\` to resume`.

### 5.2 — Manual unlock via CLI

```sh
./bin/protonmcp unlock
sleep 2
./bin/protonmcp whoami
```

**Expected.** Touch ID prompt appears (inside the daemon process).
After approval, `whoami` succeeds.

### 5.3 — Screen lock triggers daemon lock (requires lockwatch helper)

**Prereq.** `helpers/lockwatch/protonmcp-lockwatch` exists (built
by `make lockwatch` or `make all`).

```sh
# Lock the screen: Control-Command-Q on macOS.
# Wait a few seconds, then unlock the screen with your password.
./bin/protonmcp whoami
```

**Expected.** `whoami` fails with `daemon is locked
(screen_locked); run \`protonmcp unlock\` to resume`. Then run
`protonmcp unlock` to bring it back.

### 5.4 — Idle timeout (requires policy override)

Add to `~/Library/Application Support/protonmcp/policy.yaml`:
```yaml
idle_lock_minutes: 1
```

```sh
./bin/protonmcp policy reload
./bin/protonmcp whoami     # bumps activity
# wait 90 seconds
./bin/protonmcp whoami
```

**Expected.** Second `whoami` fails with `daemon is locked
(idle_timeout)`.

**Cleanup.** Remove `idle_lock_minutes` from policy.yaml or set
back to 0 (disabled).

---

## Section 6 — Per-tool validation via Claude (15–30 minutes)

These tests require Claude Desktop or Claude Code with the
`protonmcp` server registered. Run `./bin/protonmcp install` if
not already done.

Use a separate Claude conversation per tool category so tool calls
don't get mixed up.

### 6.1 — Read tools

Ask Claude:
> List my most recent 5 emails.

**Expected.** Claude calls `mail_list` (no Touch ID prompt — read
tools are allow-by-default). Returns envelope data (subject,
sender, date) for 5 messages.

Variants to test:
- `mail_search query:"from:alice"` (FTS query)
- `mail_read message_id:<id>` (single message decrypt + sanitize)
- `mail_read_thread thread_id:<id>` (thread expansion)
- `mail_list folder:drafts` (folder filter)
- `labels_list` and `folders_list`
- `account_whoami`

All read tools should run without a Touch ID prompt. If any prompt,
that's a policy regression — file a defect.

### 6.2 — State change tools (prompted)

Ask Claude:
> Mark the most recent email from <sender> as read.

**Expected.** Touch ID prompt with body containing the message
subject (e.g. `mark message 'Re: gear list' as read`). After
approval, the message is marked read in Proton AND in the local
mirror.

D36 regression check: if the prompt body shows `[REDACTED-VALUE]`
for message_id or destination instead of the actual subject /
folder name, file a defect against the new D-number.

Variants:
- `mail_move` (with destination)
- `mail_trash`
- `mail_label add` / `mail_label remove`

### 6.3 — Send tools (prompted + confirm)

These are irreversible. Use a test recipient (your own address is
fine).

Ask Claude:
> Send a test email to my-own@proton.me with subject "test" and body "hello"

**Expected.** NSAlert appears showing the literal `To:`, `CC:`,
`BCC:`, `Subject:` lines. After clicking Send, Touch ID prompt
fires. After biometric approval, message lands in the recipient's
inbox within ~5 seconds.

### 6.4 — Drafts

```
Create a draft to me@own.proton.me, subject "draft test", body "this is a draft"
```

**Expected.** Touch ID prompt. Draft appears in `mail_list
folder:drafts`. `mail_read` on the draft_id returns the body.
`mail_send_draft draft_id:<id>` sends it (another Touch ID
prompt).

### 6.5 — Labels and folders CRUD

```
Create a label called "TEST-DELETE-ME" with color #00ff00
```

**Expected.** Touch ID prompt body reads `create label
'TEST-DELETE-ME' (color #00ff00)`. After approval, label exists
in Proton + `labels_list` shows it.

```
Delete the label TEST-DELETE-ME
```

**Expected.** Prompt body reads `delete label 'TEST-DELETE-ME'
(messages stay; classification removed)`. After approval, label
gone.

Same flow for folders.

### 6.6 — Rate-limit enforcement (6/E persistent state)

Send 20 messages in rapid succession (use small test recipient).
The 21st should fail with `rate limit 20/hour exceeded`.

**Then restart the daemon:** `protonmcp daemon restart`.

The 22nd attempt should STILL fail — the rate-limit state
persists across restarts (D-prior limitation closed by 6/E).
Without persistence, the 22nd would succeed because the limiter
would start fresh.

### 6.7 — `mail_delete_permanent` is denied by default

```
Permanently delete message <id>
```

**Expected.** Claude reports `tool mail_delete_permanent denied by
policy`. No Touch ID prompt. This is intentional — the policy
ships deny for permanent delete to prevent LLM-driven data loss.

---

## Section 7 — Audit log + observability (5 minutes)

### 7.1 — Audit log has rows for recent tool calls

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db \
  'SELECT tool, outcome, policy_decision, duration_ms FROM audit_log ORDER BY id DESC LIMIT 10;'
```

**Expected.** 10 rows, each with a tool name, outcome (ok / denied
/ error), policy_decision (allow / prompt / deny), and a duration.

### 7.2 — JSONL mirror tails cleanly

```sh
tail ~/Library/Application\ Support/protonmcp/audit.log
```

**Expected.** One JSON object per line. Each object has `tool`,
`caller_binary`, `caller_pid`, `policy_decision`, `outcome`,
`approval_source`, `duration_ms`. The `args` field contains
redacted call arguments.

### 7.3 — Body content is redacted in args

Send a draft with a memorable body. Then:

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db \
  "SELECT args_json FROM audit_log WHERE tool='mail_draft_create' ORDER BY id DESC LIMIT 1;"
```

**Expected.** The `body_text` / `body_html` field appears as
`{"sha256":"<hex>","bytes":<count>}` — not the literal body.

The recipient addresses (`to`, `cc`, `bcc`) SHOULD be literal.
That's by design — recipient verification is the whole point of
the prompt. Lock-in test `TestJSONRecipientAddressesSurvive` in
`internal/redact/redact_test.go` enforces this.

### 7.4 — Log rotation at 50MB (7/B)

Hard to trigger naturally. Manual verification: write
`~/Library/Application Support/protonmcp/audit.log` to >50MB:

```sh
yes "garbage line" | head -n 4000000 >> ~/Library/Application\ Support/protonmcp/audit.log
ls -lh ~/Library/Application\ Support/protonmcp/audit.log*
```

Then trigger any tool call. After the next audit write:
```sh
ls -lh ~/Library/Application\ Support/protonmcp/audit.log*
```

**Expected.** The original 50MB+ file moved to `audit.log.1`. The
new `audit.log` is small (just the latest write). Continued usage
rotates through `.1` → `.2` → ... → `.10`.

**Cleanup.** `rm ~/Library/Application Support/protonmcp/audit.log*`
and start a clean daemon.

---

## Section 8 — Defect regression tests

For each fixed defect, a representative test confirms it stays
fixed. Run these whenever DEFECTS.html grows or when a refactor
might touch the relevant surface.

| Defect | Surface | Quick check |
|---|---|---|
| **D1/D2** | `primaryFolder` | `sqlite3 store.db "SELECT DISTINCT folder FROM messages WHERE folder IS NOT NULL AND folder != ''"` — no `all` value should appear |
| **D4** | Touch ID helper substitution | `unset PROTONMCP_TOUCHID; protonmcp daemon restart` — daemon should not silently use a different helper |
| **D5** | Debug stderr token leak | `PROTONMCP_DEBUG=1 ./bin/protonmcpd` — refuses to start with "SECURITY D5" message |
| **D7** | Recipient allowlist bypass | Set `allowed_recipients: ["alice@allowed.com"]`; try sending to `"Bob <bob@evil.com>, alice@allowed.com"` — must be denied |
| **D8** | Audit ctx cancellation | Send SIGTERM mid-tool-call; audit row must still be Complete (no NULL outcome) |
| **D11** | raw_json valid after truncation | `sqlite3 store.db "SELECT raw_json FROM messages WHERE LENGTH(raw_json) > 0 LIMIT 1" | jq .` — must parse |
| **D24** | Binary integrity | See section 3.6 + 3.7 |
| **D26** | Audit args_json []byte bind | Smoke: any tool call writes a row without errors |
| **D28** | Search LIMIT binding | `protonmcp search --limit 5 hello` — returns 5 results, no SQL errors |
| **D30** | Touch ID password fallback | See section 4.2 |
| **D33** | pgrep-by-exe for policy reload | `protonmcp policy reload` only signals real daemons, not editors / greps |
| **D35** | All tools have a non-deny policy default | `go test ./internal/policy/ -run TestEveryToolHasNonDenyPolicyDefault` |
| **D36** | Touch ID prompt readability | See section 6.2 |
| **D37** | Keychain ACL via SecAccessControl | See section 4.3 + 4.4 |

For open defects:
- **D12** (DSN injection): try `protonmcp whoami --db
  '/tmp/x.db?_pragma=journal_mode(off)'` — currently runs (bug
  still open); confirm the fix once it lands.
- **D22** (mail_read prompt injection): no automated test — review
  the description string + consider runtime banner.
- **D38, D39, D40** (Phase 7/C smoke-test paper cuts + 7/D
  double-prompt UX): see DEFECTS.html for one-line repro recipes.

---

## Section 9 — Reporting

After running through the sections you can, produce a report with
this shape:

```
## proto-mcp validation report

Date:      YYYY-MM-DD
Branch:    <git rev-parse HEAD>
Host:      macOS <version>, <chip> <chip-model>

### Sections covered
- [x] 1 — Build verification
- [x] 2 — Signing pipeline
- [ ] 3 — Daemon lifecycle (skipped: no Proton account on this host)
- ...

### Defects found
- D41 — <title> — severity: <level> — section <n.n> reproduces it.
  <One-paragraph description matching DEFECTS.html entry shape.>

### Confirmed-still-fixed
- D11, D24, D26, D28, D30, D35, D36, D37

### Notes
- <Any surprises, perf observations, UX friction not rising to a
  defect, etc.>
```

File new defects directly into `DEFECTS.html` following the existing
pattern. Match severity to impact: data loss / unauthorized access =
critical or high; UX friction or hygiene = medium or low.

Do not push or merge unless explicitly authorized.
