#!/usr/bin/env bash
# Local release pipeline for proto-mcp.
#
# Runs the full sign → notarize → package → upload flow from your
# own machine. No secrets in cloud. Invoked by `make release
# VERSION=v1.0.0`.
#
# Requires:
#   - DEVELOPER_ID env var set to the signing identity string
#   - notarytool keychain profile "protonmcp-notary" already
#     configured (see scripts/signing-setup.md)
#   - `gh` CLI authenticated (run `gh auth status` to verify)
#   - clean working tree (uncommitted changes? probably want to
#     commit them before tagging)
#
# Usage:
#   export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'
#   make release VERSION=v1.0.0
#
# Or directly:
#   ./scripts/release.sh v1.0.0

set -euo pipefail

VERSION_INPUT="${1:-}"
if [ -z "$VERSION_INPUT" ]; then
    echo "usage: $0 <version>   (e.g. $0 v1.0.0)" >&2
    exit 2
fi

# Normalize: accept both "v1.0.0" and "1.0.0".
VERSION="${VERSION_INPUT#v}"
TAG="v$VERSION"

if [ -z "${DEVELOPER_ID:-}" ]; then
    echo "error: DEVELOPER_ID environment variable not set." >&2
    echo "  Run: export DEVELOPER_ID='Developer ID Application: <NAME> (<TEAMID>)'" >&2
    echo "  See scripts/signing-setup.md." >&2
    exit 1
fi

# Sanity: gh is logged in?
if ! gh auth status >/dev/null 2>&1; then
    echo "error: \`gh\` CLI is not authenticated. Run 'gh auth login' first." >&2
    exit 1
fi

# Working tree clean? Tagging an untracked-state release is usually
# a mistake — abort with a clear prompt.
if [ -n "$(git status --porcelain)" ]; then
    echo "error: working tree is not clean. Commit / stash changes before releasing." >&2
    echo "  Run 'git status' to see what's outstanding." >&2
    exit 1
fi

# Tag already exists locally? Refuse — caller should bump.
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "error: tag $TAG already exists locally. Bump the version or delete the tag." >&2
    exit 1
fi

echo "=== Release pipeline for $TAG ==="
echo

# Step 1: clean build.
echo "--- (1/7) make clean && make all ---"
make clean
make all

# Step 2: sign.
echo
echo "--- (2/7) make sign ---"
make sign

# Step 3: verify signatures.
echo
echo "--- (3/7) make verify-sign ---"
make verify-sign

# Step 4: notarize (this is the slow one — 1–5 minutes typically).
echo
echo "--- (4/7) make notarize (1-5 min round trip to Apple) ---"
make notarize

# Step 5: verify Gatekeeper accepts.
echo
echo "--- (5/7) make verify-notarized ---"
# Apple's ticket cache can lag the notarytool 'Accepted' status by
# a few seconds. Retry once after a 30s wait if the first attempt
# fails.
if ! make verify-notarized; then
    echo "First verify-notarized failed; waiting 30s for Apple to propagate ticket..."
    sleep 30
    make verify-notarized
fi

# Step 6: package the flat tarball that the Homebrew cask consumes.
echo
echo "--- (6/7) packaging dist/protonmcp-$VERSION.tar.gz ---"
STAGE=$(mktemp -d)
STAGEDIR="$STAGE/protonmcp-$VERSION"
mkdir -p "$STAGEDIR"
cp bin/protonmcp        "$STAGEDIR/protonmcp"
cp bin/protonmcpd       "$STAGEDIR/protonmcpd"
cp bin/protonmcp-shim   "$STAGEDIR/protonmcp-shim"
cp helpers/touchid/protonmcp-touchid     "$STAGEDIR/protonmcp-touchid"
cp helpers/lockwatch/protonmcp-lockwatch "$STAGEDIR/protonmcp-lockwatch"
cp LICENSE README.md SECURITY.md "$STAGEDIR/"

mkdir -p dist
TAR="dist/protonmcp-$VERSION.tar.gz"
(cd "$STAGE" && tar -czf - "protonmcp-$VERSION") > "$TAR"
SHA=$(shasum -a 256 "$TAR" | awk '{print $1}')
echo "$SHA  protonmcp-$VERSION.tar.gz" > "$TAR.sha256"
rm -rf "$STAGE"

echo "  $TAR"
echo "  sha256: $SHA"

# Step 7: tag + upload via gh CLI. The tag is annotated so the
# release notes have something to work from; the release itself is
# created as a DRAFT so you can edit notes before publishing.
echo
echo "--- (7/7) tag $TAG + create draft GitHub release ---"
git tag -a "$TAG" -m "$TAG"
git push origin "$TAG"

gh release create "$TAG" \
    --draft \
    --generate-notes \
    --title "$TAG" \
    "$TAR" \
    "$TAR.sha256"

echo
echo "=== Release prepared ==="
echo
echo "Draft release URL:"
gh release view "$TAG" --json url --jq .url
echo
echo "Next steps:"
echo "  1. Edit the draft on GitHub to fill in release notes."
echo "  2. Click Publish."
echo "  3. Update Formula/protonmcp.rb in your homebrew-protonmcp tap:"
echo "       version \"$VERSION\""
echo "       sha256 \"$SHA\""
echo "     Commit + push the tap. Then \`brew install --cask\` Just Works."
