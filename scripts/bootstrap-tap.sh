#!/usr/bin/env bash
# Bootstrap or update the Homebrew tap repo for proto-mcp.
#
# Homebrew's tap convention: a SEPARATE GitHub repo named
# `homebrew-<tap-name>`. For us that's:
#   github.com/just-an-oldsalt/homebrew-proto-mcp
#
# Inside the tap repo, casks live in `Casks/<token>.rb`. We copy
# Formula/proto-mcp.rb from this repo to Casks/proto-mcp.rb in the
# tap repo (Homebrew accepts either layout in custom taps, but
# `Casks/` is the convention for cask-only taps and what
# `brew install --cask` discovers cleanest).
#
# Usage:
#
#   First-time bootstrap (creates the GitHub repo + initial cask
#   with placeholder version/sha256 so `brew tap` succeeds):
#     ./scripts/bootstrap-tap.sh
#
#   Update with a real release's version + sha256:
#     ./scripts/bootstrap-tap.sh 1.0.0 <sha256>
#
# Requires `gh` CLI authenticated. Creates a public tap repo
# unless TAP_VISIBILITY=private is set in the environment.

set -euo pipefail

VERSION="${1:-}"
SHA256="${2:-}"

TAP_OWNER="just-an-oldsalt"
TAP_NAME="homebrew-proto-mcp"
TAP_FULL="$TAP_OWNER/$TAP_NAME"
TAP_VISIBILITY="${TAP_VISIBILITY:-public}"

REPO_ROOT=$(git rev-parse --show-toplevel)
SOURCE_CASK="$REPO_ROOT/Formula/proto-mcp.rb"

if [ ! -f "$SOURCE_CASK" ]; then
    echo "error: $SOURCE_CASK not found — run this from a proto-mcp checkout." >&2
    exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
    echo "error: \`gh\` CLI is not authenticated. Run 'gh auth login' first." >&2
    exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# Step 1: ensure the tap repo exists on GitHub.
if gh repo view "$TAP_FULL" >/dev/null 2>&1; then
    echo "Tap repo $TAP_FULL already exists; will update."
    gh repo clone "$TAP_FULL" "$WORKDIR/$TAP_NAME"
else
    echo "Creating $TAP_FULL ($TAP_VISIBILITY)..."
    gh repo create "$TAP_FULL" \
        "--$TAP_VISIBILITY" \
        --description "Homebrew tap for proto-mcp" \
        --clone=false
    # Initialize locally; gh repo create with --clone needs an
    # initial commit before clone works, so we init + push.
    mkdir -p "$WORKDIR/$TAP_NAME"
    cd "$WORKDIR/$TAP_NAME"
    git init -q -b main
    git remote add origin "git@github.com:$TAP_FULL.git" 2>/dev/null \
        || git remote add origin "https://github.com/$TAP_FULL.git"
    cd "$REPO_ROOT"
fi

cd "$WORKDIR/$TAP_NAME"
mkdir -p Casks

# Step 2: copy the cask file. If version + sha256 args supplied,
# inject them; otherwise keep the placeholder values from the
# source cask.
if [ -n "$VERSION" ] && [ -n "$SHA256" ]; then
    echo "Updating cask to version $VERSION + sha256 $SHA256..."
    # macOS sed needs -i ''; we write to a temp + mv to avoid
    # platform sed flags drifting.
    sed -e "s|version \"0\.0\.0\"|version \"$VERSION\"|" \
        -e "s|sha256 :no_check|sha256 \"$SHA256\"|" \
        "$SOURCE_CASK" > Casks/proto-mcp.rb
elif [ -n "$VERSION" ] || [ -n "$SHA256" ]; then
    echo "error: provide BOTH version and sha256, or neither (for placeholder bootstrap)." >&2
    exit 1
else
    echo "Copying cask with placeholder version/sha256 (bootstrap mode)..."
    cp "$SOURCE_CASK" Casks/proto-mcp.rb
fi

# Step 3: README so the tap repo doesn't look abandoned.
cat > README.md <<EOF
# homebrew-proto-mcp

Homebrew tap for [proto-mcp](https://github.com/$TAP_OWNER/proto-mcp).

\`\`\`sh
brew tap $TAP_FULL_DISPLAY
brew install --cask proto-mcp
\`\`\`

This tap is maintained automatically by [bootstrap-tap.sh](https://github.com/$TAP_OWNER/proto-mcp/blob/main/scripts/bootstrap-tap.sh)
in the main proto-mcp repo. Don't edit \`Casks/proto-mcp.rb\` here
directly — the canonical source is \`Formula/proto-mcp.rb\` in the
main repo, copied here on every release.

See the main repo for documentation, install steps, and security
posture.
EOF
# substitute the display tap name (without the homebrew- prefix)
TAP_DISPLAY="$TAP_OWNER/proto-mcp"
sed -i.bak "s|\$TAP_FULL_DISPLAY|$TAP_DISPLAY|g" README.md && rm README.md.bak

# Step 4: commit + push.
git add Casks/proto-mcp.rb README.md
if git diff --cached --quiet; then
    echo "No changes to commit; tap is already up to date."
    exit 0
fi

if [ -n "$VERSION" ]; then
    MSG="proto-mcp $VERSION"
else
    MSG="initial bootstrap (placeholder version)"
fi
git -c user.name="bootstrap-tap.sh" \
    -c user.email="$(git -C "$REPO_ROOT" config user.email)" \
    commit -q -m "$MSG"

git push -u origin main 2>&1 | tail -3

echo
echo "Tap repo: https://github.com/$TAP_FULL"
echo
if [ -z "$VERSION" ]; then
    echo "Bootstrap done with placeholder cask. To install:"
    echo "  brew tap $TAP_DISPLAY"
    echo "  brew install --cask proto-mcp   # will fail until a real release lands"
    echo
    echo "After your first \`make release VERSION=v1.0.0\`, run:"
    echo "  ./scripts/bootstrap-tap.sh 1.0.0 \$(awk '{print \$1}' dist/proto-mcp-1.0.0.tar.gz.sha256)"
else
    echo "Cask updated to $VERSION. Test:"
    echo "  brew tap $TAP_DISPLAY"
    echo "  brew install --cask proto-mcp"
fi
