# proto-mcp Homebrew cask formula.
#
# Phase 7/E. Lives in the main repo for now; will migrate to a
# dedicated tap (`homebrew-protonmcp`) once the first signed release
# is published. The url + sha256 are populated by the release CI on
# tag push; the placeholders below are the contract.
#
# Install:
#   brew install --cask just-an-oldsalt/protonmcp/protonmcp
#
# (Tap registration is part of the tap-repo bootstrap, not this file.)

cask "protonmcp" do
  version "0.0.0"  # CI replaces on tag (e.g. "1.0.0")
  sha256 :no_check  # CI replaces with the artifact sha256

  url "https://github.com/just-an-oldsalt/proto-mcp/releases/download/v#{version}/protonmcp-#{version}.tar.gz"
  name "protonmcp"
  desc "Local macOS MCP server bridging Proton Mail to Claude"
  homepage "https://github.com/just-an-oldsalt/proto-mcp"

  depends_on macos: ">= :ventura"
  depends_on arch: :arm64  # initial release is Apple-silicon-only; Phase 8 adds amd64

  # The tarball lays everything in a single flat dir
  # (protonmcp-<version>/). All five binaries land in HOMEBREW_PREFIX/bin
  # which is what the path-resolution code in
  # internal/approval/path.go and internal/serve/lockwatch.go expect
  # after Phase 7/E (same-dir-as-running-binary lookup).
  binary "protonmcp-#{version}/protonmcp"
  binary "protonmcp-#{version}/protonmcpd"
  binary "protonmcp-#{version}/protonmcp-shim"
  binary "protonmcp-#{version}/protonmcp-touchid"
  binary "protonmcp-#{version}/protonmcp-lockwatch"

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
