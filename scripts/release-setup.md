# Release setup (Phase 7/E)

One-time operator setup so `git push <v*>` tags can trigger an
automated signed + notarized release via
`.github/workflows/release.yml`. Read once, then never again unless
something rotates.

## Prerequisites

You already have:
- An Apple Developer Program account (active)
- A Developer ID Application certificate in your local login keychain
- A `notarytool` keychain profile working locally (Phase 7/C setup
  in `scripts/signing-setup.md`)
- Maintainer access to the GitHub repo

## Step 1 — Export the cert + private key as a .p12

```sh
# Open Keychain Access.app
# Find "Developer ID Application: <YOUR NAME> (<TEAMID>)" in
# "login" keychain → My Certificates
# Right-click → Export "Developer ID Application: ..."
# Format: Personal Information Exchange (.p12)
# Save to ~/Downloads/protonmcp-developer-id.p12 with a strong
# password (you'll paste this into a GH secret)
```

Then base64 it for transport into GitHub Actions:

```sh
base64 < ~/Downloads/protonmcp-developer-id.p12 | pbcopy
# (clipboard now has the base64-encoded blob)
```

After uploading the secret (next step), delete the local .p12:

```sh
rm ~/Downloads/protonmcp-developer-id.p12
```

## Step 2 — Generate an app-specific password for notarytool

If you already have one from `scripts/signing-setup.md`, reuse it.
Otherwise:

- Sign in to https://appleid.apple.com
- Sign-In and Security → App-Specific Passwords → Generate
- Label: `protonmcp-notary-ci` (so you can revoke this one
  independently of your local-dev profile)
- Save the password somewhere; you'll paste into a GH secret next

## Step 3 — Add GitHub repository secrets

Settings → Secrets and variables → Actions → New repository secret.
Add each of these:

| Name | Value |
|---|---|
| `APPLE_DEVELOPER_ID_CERT_P12_BASE64` | The base64 blob from step 1 |
| `APPLE_DEVELOPER_ID_CERT_PASSWORD` | The .p12 export password from step 1 |
| `APPLE_DEVELOPER_ID` | `Developer ID Application: <YOUR NAME> (<TEAMID>)` — match the literal string from `security find-identity -p codesigning -v` |
| `APPLE_NOTARY_APPLE_ID` | Your Apple ID email |
| `APPLE_NOTARY_TEAM_ID` | Your Team ID (e.g. `346JJCHZP7`) |
| `APPLE_NOTARY_PASSWORD` | The app-specific password from step 2 |

Six secrets. None of them ever leave the runner; the workflow
cleans up the transient keychain on exit.

## Step 4 — Tag a release

```sh
git tag -a v1.0.0 -m "v1.0.0 — first signed release"
git push origin v1.0.0
```

The workflow fires on the tag push. Watch progress at
https://github.com/just-an-oldsalt/proto-mcp/actions. On success
it creates a **draft** release with:

- `protonmcp-1.0.0.tar.gz` (signed + notarized binaries + docs)
- `protonmcp-1.0.0.tar.gz.sha256` (for the Homebrew cask sha256)

Edit the release in the GitHub UI to fill in release notes, then
publish.

## Step 5 — Update the Homebrew cask

After publishing the release:

```sh
# Grab the artifact sha256 from the .sha256 sidecar in the release
EXPECTED_SHA=$(curl -sL https://github.com/just-an-oldsalt/proto-mcp/releases/download/v1.0.0/protonmcp-1.0.0.tar.gz.sha256 | awk '{print $1}')
```

Then edit `Formula/protonmcp.rb` (or the tap-repo equivalent):

```ruby
version "1.0.0"
sha256 "<paste $EXPECTED_SHA here>"
```

Commit + push the tap. Users then run:

```sh
brew tap just-an-oldsalt/protonmcp
brew install --cask protonmcp
```

The cask downloads the same `.tar.gz` the release CI produced and
installs all five binaries into the Homebrew prefix's `bin/`.

## Troubleshooting

**"Failed to verify notarization" on first try, success on retry**
Apple's ticket-propagation cache can lag the notarytool "Accepted"
status by a few seconds. The workflow already retries once with a
30s wait; if it fails twice, something deeper is wrong (check the
notarytool log via `xcrun notarytool log <id>`).

**Keychain "User interaction is not allowed" error**
The cert import step's `set-key-partition-list` call requires the
keychain to be unlocked AND the password to be the one we set in
the same step. Failure here usually means a leftover keychain from
a prior crashed run — delete `$RUNNER_TEMP/protonmcp-release.keychain-db`
and retry.

**"Disallowing protonmcp because no eligible provisioning profiles
found"** (kernel SIGKILL)
You added a restricted entitlement (like `keychain-access-groups`)
without an embedded provisioning profile. Remove the entitlement
or do the proper Phase 7/E .app-bundle work. See
[`DEFECTS.html`](../DEFECTS.html) D37 for the deferred path.

## Rotation

When secrets need to rotate (cert expires, password compromised,
team member leaves):

1. Generate the new artifact (cert .p12, app password, etc.)
2. Replace the corresponding GH secret. Old workflow runs
   referencing the old value continue to fail; new tag pushes
   pick up the new value.
3. The .p12 cert specifically expires every ~3 years for
   Developer ID. Calendar reminder for ~30 days before to
   regenerate without panic.
