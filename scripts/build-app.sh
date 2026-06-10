#!/usr/bin/env bash
# build-app.sh — assemble, sign, notarize, and staple the D37 .app
# bundle (the one with the OS-level Keychain Touch ID ACL).
#
# This is the D37 / Phase 7/E delta on top of the bare-binary flow in
# scripts/release.sh. The ONLY thing here your normal notarization
# doesn't do is embed a *provisioning profile* — the artifact that
# authorizes the restricted `keychain-access-groups` entitlement. You
# get the profile from the Apple Developer portal (one-time setup in
# scripts/signing-setup.md, "D37 provisioning" section), not from
# notarytool.
#
# Required env:
#   DEVELOPER_ID         'Developer ID Application: <NAME> (<TEAMID>)'
#   TEAM_ID              your 10-char Apple Team ID (the (<TEAMID>) above)
#   PROVISION_PROFILE    path to the downloaded .provisionprofile
#   NOTARY_PROFILE       notarytool keychain profile name (default: protonmcp-notary)
# Optional env:
#   BUNDLE_ID            default: zone.dort.protonmcp  (see PROTO-112 — finalize before release)
#   VERSION              default: 0.0.0-dev
#
# Usage:
#   export DEVELOPER_ID='Developer ID Application: Your Name (ABCDE12345)'
#   export TEAM_ID='ABCDE12345'
#   export PROVISION_PROFILE=~/Downloads/proto_mcp_developerid.provisionprofile
#   ./scripts/build-app.sh
#
# Output: build/proto-mcp.app  (signed + notarized + stapled)

set -euo pipefail
cd "$(dirname "$0")/.."

: "${DEVELOPER_ID:?set DEVELOPER_ID — see scripts/signing-setup.md}"
: "${TEAM_ID:?set TEAM_ID — your 10-char Apple Team ID}"
: "${PROVISION_PROFILE:?set PROVISION_PROFILE — path to the downloaded .provisionprofile}"
NOTARY_PROFILE="${NOTARY_PROFILE:-protonmcp-notary}"
BUNDLE_ID="${BUNDLE_ID:-zone.dort.protonmcp}"
VERSION="${VERSION:-0.0.0-dev}"

if [ ! -f "$PROVISION_PROFILE" ]; then
    echo "error: PROVISION_PROFILE not found: $PROVISION_PROFILE" >&2
    exit 1
fi

APP="build/proto-mcp.app"
MACOS="$APP/Contents/MacOS"
ENTITLEMENTS="build/proto-mcp.app.entitlements"

echo "=== D37 .app build: $BUNDLE_ID ($VERSION), team $TEAM_ID ==="

# 1. Fresh binaries.
echo "--- (1/7) make all ---"
make all

# 2. Assemble the bundle skeleton.
echo "--- (2/7) assemble $APP ---"
rm -rf "$APP"
mkdir -p "$MACOS"
cp bin/protonmcp        "$MACOS/protonmcp"
cp bin/protonmcpd       "$MACOS/protonmcpd"
cp bin/protonmcp-shim   "$MACOS/protonmcp-shim"
cp helpers/touchid/protonmcp-touchid     "$MACOS/protonmcp-touchid"
cp helpers/lockwatch/protonmcp-lockwatch "$MACOS/protonmcp-lockwatch"

# Info.plist (CFBundleIdentifier must match the App ID + the profile).
sed -e "s/__BUNDLE_ID__/$BUNDLE_ID/g" -e "s/__VERSION__/$VERSION/g" \
    scripts/proto-mcp.Info.plist.template > "$APP/Contents/Info.plist"

# Embed the provisioning profile — THIS is the D37 piece. macOS only
# reads embedded.provisionprofile from a bundle, never from a bare
# binary, which is why D37 needs a .app at all.
cp "$PROVISION_PROFILE" "$APP/Contents/embedded.provisionprofile"

# Entitlements with the team-scoped keychain access group.
sed -e "s/__TEAM_ID__/$TEAM_ID/g" -e "s/__BUNDLE_ID__/$BUNDLE_ID/g" \
    scripts/proto-mcp.app.entitlements.template > "$ENTITLEMENTS"

# 3. Sign — inner Mach-Os first, then the bundle, all with hardened
# runtime + the D37 entitlements + a secure timestamp. Nested binaries
# must be signed before the enclosing bundle (codesign --deep is
# discouraged; sign explicitly inside-out).
echo "--- (3/7) codesign (inside-out) ---"
for b in protonmcp-shim protonmcp-touchid protonmcp-lockwatch protonmcpd protonmcp; do
    codesign --force --timestamp --options runtime \
        --entitlements "$ENTITLEMENTS" \
        --sign "$DEVELOPER_ID" \
        "$MACOS/$b"
done
codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$DEVELOPER_ID" \
    "$APP"

# 4. Verify the signature shape + that the profile/entitlement stuck.
echo "--- (4/7) verify signature + entitlements ---"
codesign --verify --strict --verbose=2 "$APP"
echo "Embedded entitlements:"
codesign -d --entitlements :- "$APP" 2>/dev/null | grep -A2 keychain-access-groups || true

# 5. Notarize (zip → notarytool → wait). Unlike CLI binaries, an .app
# CAN be stapled, so the ticket travels with the artifact offline.
echo "--- (5/7) notarize (1-5 min round trip) ---"
ZIP="build/proto-mcp.app.zip"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait

# 6. Staple the ticket onto the .app.
echo "--- (6/7) staple ---"
xcrun stapler staple "$APP"

# 7. Gatekeeper assessment.
echo "--- (7/7) spctl assessment ---"
spctl --assess --type execute --verbose=4 "$APP" || \
    echo "NOTE: spctl execute-assessment on an LSUIElement payload can warn; the staple above is the source of truth."

echo
echo "=== Done: $APP (signed, notarized, stapled) ==="
echo "Next: flip internal/keystore blobVersion to the protected path and"
echo "verify a real Touch-ID-gated keychain read before shipping (see"
echo "scripts/signing-setup.md, 'D37 provisioning')."
