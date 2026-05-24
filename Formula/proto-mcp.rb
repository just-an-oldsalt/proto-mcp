# proto-mcp Homebrew cask formula.
#
# Phase 7/E. Lives in the main repo for now; will migrate to a
# dedicated tap (`homebrew-proto-mcp`) once the first signed
# release is published. The url + sha256 are populated by the
# release pipeline on tag push; the placeholders below are the
# contract.
#
# Install:
#   brew tap just-an-oldsalt/proto-mcp
#   brew install --cask proto-mcp
#
# Cask token is `proto-mcp` (with hyphen) deliberately — keeps
# our branding clearly distinct from Proton AG's products and
# avoids implying an official "Proton MCP" relationship. The
# binaries inside the tarball stay named `protonmcp`,
# `protonmcpd`, etc. (changing those would invalidate every
# existing user's keychain service ID + LaunchAgent label).

cask "proto-mcp" do
  version "0.0.0"  # release.sh replaces on tag (e.g. "1.0.0")
  sha256 :no_check # release.sh replaces with the artifact sha256

  url "https://github.com/just-an-oldsalt/proto-mcp/releases/download/v#{version}/proto-mcp-#{version}.tar.gz"
  name "proto-mcp"
  desc "Local macOS MCP server bridging Proton Mail to Claude"
  homepage "https://github.com/just-an-oldsalt/proto-mcp"

  depends_on macos: ">= :ventura"
  depends_on arch: :arm64  # initial release is Apple-silicon-only; Phase 8 adds amd64

  # The tarball lays everything in a single flat dir
  # (proto-mcp-<version>/). All five binaries land in
  # HOMEBREW_PREFIX/bin which matches the path-resolution code in
  # internal/approval/path.go and internal/serve/lockwatch.go
  # (same-dir-as-running-binary lookup).
  binary "proto-mcp-#{version}/protonmcp"
  binary "proto-mcp-#{version}/protonmcpd"
  binary "proto-mcp-#{version}/protonmcp-shim"
  binary "proto-mcp-#{version}/protonmcp-touchid"
  binary "proto-mcp-#{version}/protonmcp-lockwatch"

  # No app bundle, no LaunchDaemon plist baked in — the
  # `protonmcp daemon install` subcommand wires the LaunchAgent
  # plist into ~/Library/LaunchAgents at first run. That keeps
  # the cask install fully reversible by `brew uninstall`.
  zap trash: [
    "~/Library/Application Support/protonmcp",
    "~/Library/Logs/protonmcp",
    "~/Library/LaunchAgents/zone.dort.protonmcpd.plist",
  ]

  caveats <<~CAVEATS
    To complete setup:

      protonmcp login                 # interactive: SRP + TOTP + key unlock
      protonmcp backfill              # one-time: drains every message envelope
      protonmcp daemon install        # registers + starts the LaunchAgent
      protonmcp install               # registers shim with Claude Desktop + Claude Code

    Restart Claude Desktop / Claude Code afterward. See
    https://github.com/just-an-oldsalt/proto-mcp for full docs.
  CAVEATS
end
