# Signing setup (Phase 7/C)

Operator-side notes for setting up Developer ID signing + notarization
on a dev machine. Read once, then use the `make sign` / `make
notarize` targets from then on.

## Prerequisites

1. **Apple Developer Program enrollment** ($99/year). The team has
   to be enrolled before any of this is possible.

2. **Developer ID Application certificate**, downloaded into the
   build keychain (typically the login keychain):

   - Sign in to https://developer.apple.com/account
   - Certificates, Identifiers & Profiles → Certificates
   - Create a new "Developer ID Application" certificate
   - Download the `.cer` file, double-click to import into Keychain
     Access
   - Confirm via:
     ```sh
     security find-identity -p codesigning -v
     ```
     You should see a line like:
     ```
     1) ABCDEF1234... "Developer ID Application: <YOUR NAME> (TEAMID)"
     ```
     Note the full identity string (the quoted part). Export it as
     `DEVELOPER_ID` so the Makefile targets pick it up:
     ```sh
     export DEVELOPER_ID='Developer ID Application: Your Name (TEAMID)'
     ```

3. **App-specific password** for `notarytool`:

   - Sign in to https://appleid.apple.com
   - Sign-In and Security → App-Specific Passwords → Generate
   - Label it `protonmcp-notary`
   - Save the password (you can't view it again — keychain it now)

4. **Store credentials in the keychain** so `notarytool` doesn't
   prompt every run:

   ```sh
   xcrun notarytool store-credentials protonmcp-notary \
       --apple-id <your-apple-id-email> \
       --team-id <TEAMID> \
       --password <app-specific-password-from-step-3>
   ```

   This puts an item named `protonmcp-notary` in the login keychain.
   The `make notarize` target references this profile name.

## Day-to-day flow

Build → sign → verify → notarize → confirm:

```sh
export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'
make all                 # build all 4 binaries unsigned
make sign                # codesign each with hardened runtime + entitlements
make verify-sign         # codesign --verify (signature validity)
make notarize            # zip → notarytool submit --wait
make verify-notarized    # codesign --test-requirement "=notarized"
```

If `verify-notarized` reports "All binaries satisfy the =notarized
requirement," Apple's database has accepted them and Gatekeeper
will run them on first launch without the developer-unknown
dialog.

## A note about stapling (Error 73)

The Makefile's `notarize` target intentionally does NOT call
`xcrun stapler staple`. Stapling fails with error 73 on bare
Mach-O CLI binaries:

> The signed item cannot be stapled. Notarization tickets cannot
> be attached to individual signed binaries — only to `.app` /
> `.pkg` / `.dmg` containers.

This is a documented macOS limitation, not a bug in our setup. For
bare CLI tools, Gatekeeper performs an online ticket lookup against
Apple's database at first launch and caches the result. Notarization
still works; the ticket just isn't physically attached.

Phase 7/E wraps the binaries in a `.pkg` (or `.dmg`) for Homebrew
distribution, and THAT container CAN be stapled. End users then get
offline-checkable tickets.

To verify a binary is notarized without launching it:

```sh
codesign --test-requirement="=notarized" --verify --verbose <binary>
```

A successful line reads `explicit requirement satisfied`. That's
the truthful "Apple has notarized this" answer.

## Why `spctl --assess --type execute` rejects CLI binaries

`spctl --assess --type execute` is the Gatekeeper assessment tool,
but the `execute` type specifically certifies `.app` bundles. Bare
CLI binaries trip a different rule and get rejected with "the code
is valid but does not seem to be an app" — even when notarized.

This is why the Makefile uses `codesign --test-requirement` instead
for `verify-notarized`. When Phase 7/E ships an actual `.app`
bundle or `.pkg`, `spctl --assess` becomes the right tool for that
container.

## What gets signed

All four executables get the SAME entitlements and Team ID, so
library validation works in our favor (the helpers can only be
launched by a binary signed by the same team):

| Binary | Path | Type |
|---|---|---|
| `protonmcp` | `bin/protonmcp` | CLI |
| `protonmcpd` | `bin/protonmcpd` | Daemon |
| `protonmcp-shim` | `bin/protonmcp-shim` | Shim |
| `protonmcp-touchid` | `helpers/touchid/protonmcp-touchid` | Touch ID helper |
| `protonmcp-lockwatch` | `helpers/lockwatch/protonmcp-lockwatch` | Lockwatch helper (Phase 7/A) |

## CI

GitHub Actions has the cert + the notarytool credentials stored as
encrypted secrets. The release workflow (Phase 7/E) is:

```
on: push of tag v*
  → macos-14 runner
  → install cert from secret into a temp keychain
  → make all → make sign → make notarize
  → create GH release with the stapled zip
```

See `.github/workflows/release.yml` (added in 7/E).

## Troubleshooting

**"Code signing failed: errSecInternalComponent"**
The build keychain may be locked. Run:
```sh
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

**"Notarization rejected: ..."**
Read the submission log:
```sh
xcrun notarytool log <submission-id> --keychain-profile protonmcp-notary
```
The most common cause is missing entitlements (we don't request
hardened runtime) or hard-linked symbols (we use the Go runtime's
mmap which needs `allow-unsigned-executable-memory`).

**Gatekeeper still complains after notarization**
Confirm the staple worked:
```sh
xcrun stapler validate bin/protonmcpd
```
A staple ticket has to be attached to each binary, not the zip.
If validation fails, re-run `xcrun stapler staple <binary>` after
notarization completes.

**"Operation not permitted" on first run after install**
Initial Gatekeeper check has to read the binary's metadata. On a
fresh machine this triggers a one-shot "Are you sure?" dialog. After
the first approval the binary is on Gatekeeper's allow list. Not
fixable; documented for user awareness.

## Adding a new helper

When Phase 7/D adds the Keychain ACL cgo wrapper or any other new
binary, add to the Makefile's `SIGN_TARGETS` list (Phase 7/C
sign target) so it gets signed alongside the rest. Forgetting
this breaks library validation — the daemon's signed but a child
helper isn't, and macOS refuses to launch the chain.

## D37 provisioning (the .app bundle with the OS-level Keychain Touch ID ACL)

The bare-binary flow above is Developer-ID signing + notarization only.
D37 — storing the Proton session blob with an OS-enforced
`SecAccessControl(userPresence)` ACL so a *read* triggers Touch ID at
the kernel level — needs the **restricted `keychain-access-groups`
entitlement**, and that entitlement is only honored when the binary
carries an **Apple provisioning profile**. A profile can only be
embedded in a bundle, so D37 = a `.app` (`scripts/build-app.sh`).

Notarization (what your other projects do) is NOT enough — that just
proves "not malware." The profile is a *separate* artifact that proves
"Apple authorized this App ID to use this restricted entitlement."

### One-time portal setup (developer.apple.com → Certificates, IDs & Profiles)

1. **Identifiers → App IDs → +.** Register an App ID whose Bundle ID is
   your reverse-DNS id (default `zone.dort.protonmcp`; finalize the name
   first — PROTO-112). Under **Capabilities**, enable **Keychain Sharing**
   and add the keychain group `zone.dort.protonmcp` (the same string the
   entitlement uses, minus the team prefix).
2. **Profiles → +.** Create a profile of type **Developer ID** (the
   "outside the App Store" kind, NOT "Mac App Store" or "Development").
   Select the App ID from step 1 and your Developer ID Application
   certificate. Download the `.provisionprofile`.
   - If the Developer ID profile type isn't offered for this App ID, it's
     usually because the cert isn't a Developer ID Application cert, or
     the capability wasn't saved — re-check step 1.
3. Note your 10-char **Team ID** (the `(ABCDE12345)` in your
   `Developer ID Application: …` identity).

### Per-build

```sh
export DEVELOPER_ID='Developer ID Application: Your Name (ABCDE12345)'
export TEAM_ID='ABCDE12345'
export PROVISION_PROFILE=~/Downloads/proto_mcp_developerid.provisionprofile
# export BUNDLE_ID=zone.dort.protonmcp   # only if you changed it
./scripts/build-app.sh
```

`build-app.sh` assembles `build/proto-mcp.app` (all five binaries in
`Contents/MacOS`), substitutes `Team.Bundle` into the entitlements,
embeds the profile at `Contents/embedded.provisionprofile`, signs
inside-out with the entitlements + hardened runtime, then notarizes and
**staples** (an `.app` can be stapled; the bare CLIs can't).

### Re-enabling the cgo path (do this LAST, after the bundle is proven)

The protected keychain path lives dormant in
`internal/keystore/access_control_darwin.{h,c,go}` and
`keystore.go` (`blobVersion = 3`, plain `AccessibleWhenUnlocked` path
active). Only after `build-app.sh` produces a launchable bundle:

1. Bump `blobVersion` and route the save path through `saveProtected`
   (and add a v3→v4 migration, mirroring the v3→v4 migration already in
   `migrate_test.go`).
2. Run the daemon **from inside the bundle** (`proto-mcp.app/Contents/MacOS/protonmcpd`)
   and confirm a keychain read actually triggers the OS Touch ID prompt
   and returns the blob (not OSStatus -34018). If it SIGKILLs at launch,
   the profile/entitlement/bundle-id three-way match is off.
3. Update the Homebrew cask to install the `.app` and point the
   LaunchAgent at `Contents/MacOS/protonmcpd` instead of a bare binary.

Until step 2 passes on a real machine, keep `blobVersion = 3` — a
half-enabled protected path locks users out of their own session.
