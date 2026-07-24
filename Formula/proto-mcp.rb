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

  depends_on macos: :ventura  # ">= Ventura"; bare symbol is Homebrew's required form (the ">= :ventura" string is deprecated)
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
  # plist into ~/Library/LaunchAgents at first run.
  #
  # Because that plist is written at runtime rather than by the cask,
  # Homebrew doesn't know about it and won't unload it. Without the
  # `uninstall launchctl:` below, `brew uninstall --cask proto-mcp`
  # deleted the binaries but left the LaunchAgent bootstrapped and
  # pointing at a now-dangling symlink, so launchd kept trying to
  # spawn a binary that no longer existed. Naming the label here makes
  # Homebrew bootout the agent before removing anything.
  #
  # `delete` (not `trash`) for the plist: it's a generated file with no
  # user content, and leaving it in ~/.Trash means a later `brew
  # install` finds a stale plist if the user ever restores it.
  uninstall launchctl: "zone.dort.protonmcpd",
            delete:    "~/Library/LaunchAgents/zone.dort.protonmcpd.plist"

  # zap additionally removes user data the plain uninstall preserves:
  # the local mail mirror, the recorded binary hash, and the logs. The
  # Keychain session is NOT zapped — `protonmcp logout` revokes it
  # server-side, which a file delete cannot do.
  zap trash: [
    "~/Library/Application Support/protonmcp",
    "~/Library/Logs/protonmcp",
  ]

  caveats <<~CAVEATS
    To complete setup:

      protonmcp login                 # interactive: SRP + TOTP + key unlock
      protonmcp backfill              # one-time: drains every message envelope
      protonmcp daemon install        # registers + starts the LaunchAgent
      protonmcp install               # registers shim with Claude Desktop + Claude Code

    Restart Claude Desktop / Claude Code afterward, then verify with:

      protonmcp doctor                # checks every part of the install

    Upgrading: the daemon keeps running the previous build until it is
    restarted, so after `brew upgrade --cask proto-mcp` run:

      protonmcp daemon restart

    See https://github.com/just-an-oldsalt/proto-mcp for full docs.
  CAVEATS
end
