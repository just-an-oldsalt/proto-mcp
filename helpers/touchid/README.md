# protonmcp-touchid

Touch ID + NSAlert helper invoked by `internal/approval.Broker`.

## Build

From the repo root:

```sh
make helpers/touchid/protonmcp-touchid
```

Or by hand:

```sh
swiftc -O -o helpers/touchid/protonmcp-touchid helpers/touchid/main.swift
```

Requires macOS with the Swift toolchain (`xcode-select --install`).
Ad-hoc signed by `swiftc`; for distribution see "Phase 7 TODO" below.

## Wire protocol

stdin: one JSON object.

```json
{
  "title":   "Approve mail_send?",
  "body":    "Send to alice@example.com\nSubject: Re: gear list",
  "caller":  "Claude Desktop (pid 1234)",
  "confirm": true
}
```

Fields:
- `title`     (required) — short string shown as the NSAlert headline.
- `body`      (required) — the literal operation details (recipients,
                           subject, etc.). Used as the localized reason
                           in the Touch ID sheet too.
- `caller`    (optional) — appended to the alert as "Requested by: ...".
- `confirm`   (optional) — if true, show NSAlert with Send/Cancel BEFORE
                           the biometric prompt. False / absent skips
                           straight to Touch ID.

Exit codes:
- `0` — user approved (clicked Send, then biometric succeeded).
- `1` — user declined OR biometric failed OR no Touch ID hardware /
        Touch ID disabled in System Settings.
- `2` — malformed stdin.

## Manual test checklist

1. `echo '{"title":"Test","body":"This is a test","confirm":false}' | ./protonmcp-touchid && echo OK` — Touch ID sheet appears; touch sensor approves with exit 0.
2. Add `"confirm":true` — NSAlert appears first with the body text; click Send, then biometric.
3. Click Cancel on the alert — exits with 1 immediately (no biometric).
4. Pipe garbage to stdin: `echo 'xyz' | ./protonmcp-touchid; echo $?` — exits 2.
5. With Touch ID disabled in System Settings → Touch ID & Password → check biometric-not-available path returns 1 with a useful stderr message.

## Phase 7 TODO — signing / notarization

For distribution (binaries that leave the dev machine):

- `codesign --sign "Developer ID Application: NAME (TEAMID)" --options runtime --entitlements helpers/touchid/protonmcp-touchid.entitlements protonmcp-touchid`
- Bundle into `protonmcp.app/Contents/MacOS/protonmcp-touchid` with an `Info.plist` containing `NSFaceIDUsageDescription`.
- `xcrun notarytool submit` + staple the ticket.

Local development uses ad-hoc signing only; Gatekeeper allows binaries built locally without complaint.
