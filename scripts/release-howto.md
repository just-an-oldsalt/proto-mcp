# Release howto

How to cut a signed + notarized release of proto-mcp. **Local-only**
for the MVP — your Developer ID cert + private key never leave your
machine. If release cadence grows or you add maintainers, the
parked `.github/workflows/release.yml` documents the eventual CI
path; see "Switching to CI later" at the end.

## Prerequisites (one-time)

You already have these from `scripts/signing-setup.md`:

- An Apple Developer Program account with a Developer ID
  Application certificate in your login keychain
- `notarytool` keychain profile working locally (test:
  `xcrun notarytool history --keychain-profile protonmcp-notary`
  returns a list, not "Keychain password item not found")
- `DEVELOPER_ID` env var ready to set:
  ```sh
  export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'
  ```

Plus the GitHub CLI:

- `gh` installed (`brew install gh`)
- `gh auth login` completed against `github.com`
- `gh auth status` confirms you're authenticated

## Day-of-release flow

```sh
# Make sure your working tree is clean and you're on main with the
# changes you want to release.
git checkout main
git pull origin main
git status

# Sign, notarize, package, tag, and create a draft GitHub release
# in one command. ~3 minutes wall clock (most of it Apple's
# notarization round-trip).
export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'
make release VERSION=v1.0.0
```

What `make release` does step-by-step (and what to do if any step
fails):

1. **clean + build** — `make clean && make all`. Rebuild
   everything from a clean tree. Fails here mean the source
   doesn't compile; fix and retry.
2. **sign** — `make sign`. codesign each binary with hardened
   runtime + entitlements. Fails here mean either the keychain is
   locked (run
   `security unlock-keychain ~/Library/Keychains/login.keychain-db`)
   or the entitlements plist is malformed.
3. **verify-sign** — `codesign --verify` each binary. Should
   always pass after step 2 succeeds.
4. **notarize** — submit to Apple's notary service. 1–5 minutes
   typical. If Apple returns Rejected, run
   `xcrun notarytool log <id> --keychain-profile protonmcp-notary`
   to see why.
5. **verify-notarized** — confirm Gatekeeper accepts via `spctl`.
   The script auto-retries once with a 30s wait if the first
   attempt hits Apple's ticket-propagation lag.
6. **package** — bundle all five binaries + LICENSE / README /
   SECURITY into `dist/protonmcp-<version>.tar.gz`, write a
   sidecar sha256 file.
7. **tag + release** — `git tag` (annotated), push the tag, run
   `gh release create --draft` with the tarball + sha256 attached.

The release is a **draft** until you publish it manually. That
lets you write release notes before flipping the visibility.

## After the script finishes

1. **Write release notes.** Visit the draft URL the script printed
   (or run `gh release view v1.0.0`). Edit notes in the GitHub UI.
2. **Publish.** Click the green Publish button (or
   `gh release edit v1.0.0 --draft=false`).
3. **Update the Homebrew cask.** Copy `Formula/protonmcp.rb` from
   this repo into your `homebrew-protonmcp` tap repo. Update:
   ```ruby
   version "1.0.0"
   sha256 "<the sha from dist/protonmcp-1.0.0.tar.gz.sha256>"
   ```
   Commit + push the tap. Users then run:
   ```sh
   brew tap just-an-oldsalt/protonmcp
   brew install --cask protonmcp
   ```

## What if I tagged but the build failed?

```sh
git tag -d v1.0.0                            # delete local tag
git push --delete origin v1.0.0              # delete remote tag
gh release delete v1.0.0 --yes               # delete the draft release
```

Then fix the failure and re-run `make release VERSION=v1.0.0`.

## Switching to CI later (deferred)

The parked workflow at `.github/workflows/release.yml` documents
the GitHub Actions path. To activate it:

1. Decide it's worth the trust trade-off. See "Risk you're
   accepting" below.
2. Generate a CI-only Developer ID cert (Apple allows multiple per
   team; the CI cert can be revoked independently if compromised).
3. Add the six secrets the workflow file lists at the top.
4. Switch the trigger from `workflow_dispatch:` to
   `push: tags: - "v*"`.
5. Pin all `uses:` directives to SHA hashes instead of `@v2` tags
   (defense against Action-publisher account compromise).
6. Enable branch protection on `.github/workflows/` to require
   review on workflow changes.
7. Make sure your GitHub account has a hardware-key second factor.

### Risk you're accepting by using CI signing

| Risk | Mitigation |
|---|---|
| Workflow injection via malicious PR modifying release.yml | Trigger is `tags:` only (you control), AND require code review on workflow files. Still: someone with merge rights can ship a malicious tag. |
| GitHub account compromise → cert exfil via API | Hardware second factor + audit secret-access logs |
| Malicious dependency / Action update | Pin to SHA + audit each Action |
| GitHub-side compromise (rare) | Apple can revoke your cert at any time; do so within an hour of discovery |
| Apple ID password reuse → notary submission attack | App-specific password (rotatable independently) |

For a small project the realistic recommendation is: stay local
until the operational pain of manual releases outweighs the trust
budget you're spending. Most maintainers find local releases
sustainable for "a release every month or two" cadence.

## Troubleshooting

**`error: working tree is not clean`**
Commit / stash your changes before tagging. Releases should
correspond to an exact main commit.

**`error: tag v1.0.0 already exists locally`**
Either bump the version or delete the existing tag (see
"What if I tagged but the build failed?" above).

**Notarization rejected**
Apple's notary submission log has the actual reason:
```sh
xcrun notarytool log <submission-id> --keychain-profile protonmcp-notary
```
Common causes: missing entitlement (we keep these minimal), hard-
linked symbols (Go runtime needs `allow-unsigned-executable-memory`,
which is already in the entitlements plist).

**Gatekeeper still warns after publishing**
The cask installs binaries — Gatekeeper's online ticket lookup
happens at first launch. If a user gets a developer-unknown
warning, either notarization didn't actually succeed (re-check
`make verify-notarized`) or they're offline at first launch (rare).

**Tag pushed but no release created**
The script tags BEFORE running `gh release create`, so if the
release step failed, you'd see a tag without a release. Fix the
failure, then:
```sh
gh release create v1.0.0 --draft --generate-notes \
    --title "v1.0.0" \
    dist/protonmcp-1.0.0.tar.gz dist/protonmcp-1.0.0.tar.gz.sha256
```
