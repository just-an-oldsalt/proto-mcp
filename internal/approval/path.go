package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// resolveHelperPath walks the three candidate locations in order:
//
//  1. PROTONMCP_TOUCHID env var — TEST ONLY. Refuses outside
//     testing.Testing(); see SECURITY D4. The spawning process
//     (Claude Desktop / Claude Code) is untrusted; if it could
//     substitute the helper at runtime via env, every biometric
//     check would be bypassable by an attacker who could set one
//     env var (`PROTONMCP_TOUCHID=/bin/true` → all Touch ID
//     prompts auto-approve, with audit showing
//     approval_source=touchid for what is in fact no auth).
//  2. Sibling of argv[0]: helpers/touchid/protonmcp-touchid relative
//     to filepath.Dir(argv[0]).
//  3. /Applications/protonmcp.app/Contents/MacOS/protonmcp-touchid
//     (Phase 7 packaged app).
//
// Returns the first existing executable path. If none exist, returns
// an error listing all the locations tried so the user knows where
// to put the binary.
func resolveHelperPath(argv0 string) (string, error) {
	var candidates []string

	if env := os.Getenv("PROTONMCP_TOUCHID"); env != "" {
		if !testing.Testing() {
			return "", fmt.Errorf(
				"PROTONMCP_TOUCHID env var refused: this override is test-only " +
					"(SECURITY D4 — a parent process could otherwise replace the " +
					"biometric helper with /bin/true and bypass every prompt). " +
					"Unset PROTONMCP_TOUCHID and rely on the binary's own " +
					"discovery path")
		}
		candidates = append(candidates, env)
	}

	// fromBinDir emits the layout-relative candidates for a directory the
	// daemon binary might live in (sibling dev helper, two-up dev helper,
	// and the flat-prefix helper next to the daemon).
	fromBinDir := func(binDir string) {
		// Dev layout: <repo>/bin/protonmcp + <repo>/helpers/touchid/
		candidates = append(candidates,
			filepath.Join(binDir, "helpers", "touchid", "protonmcp-touchid"),
			filepath.Join(filepath.Dir(binDir), "helpers", "touchid", "protonmcp-touchid"),
			// Phase 7/E Homebrew cask layout: cask `binary` stanzas
			// drop every product directly into the prefix's bin/ —
			// protonmcp-touchid sits next to protonmcp.
			filepath.Join(binDir, "protonmcp-touchid"),
		)
	}

	if argv0 != "" {
		abs, err := filepath.Abs(argv0)
		if err == nil {
			fromBinDir(filepath.Dir(abs))
			// PROTO-127 / cask layout: a `binary` stanza symlinks the
			// daemon into Homebrew's group-writable <prefix>/bin, but the
			// real binaries sit beside each other in the owner-writable-only
			// Caskroom. The lexical candidates above land in the writable
			// bin dir and are correctly rejected by ownerWritableOnly; the
			// trusted helper is only reachable by following the daemon's
			// own symlink to its real directory. Resolve it and emit the
			// same candidates from there. Anchoring on the *daemon's*
			// resolved path (not the helper symlink, which an attacker could
			// repoint inside the writable bin dir) keeps the trust chain
			// rooted in whatever binary is actually running as the daemon.
			if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil && resolved != abs {
				fromBinDir(filepath.Dir(resolved))
			}
		}
	}

	candidates = append(candidates,
		// Phase 7 packaged app — deferred (paired with D37).
		"/Applications/protonmcp.app/Contents/MacOS/protonmcp-touchid",
		// Explicit Homebrew prefixes in case argv0 was invoked
		// via a PATH symlink and Dir(abs) didn't land in bin/.
		"/opt/homebrew/bin/protonmcp-touchid",
		"/usr/local/bin/protonmcp-touchid",
	)

	for _, c := range candidates {
		if isExecutable(c) && ownerWritableOnly(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf(
		"no trusted touchid helper found (must be executable and writable only "+
			"by its owner — a group/world-writable helper or directory is a "+
			"substitution vector, SECURITY PROTO-127); tried: %v", candidates)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return false
	}
	// Bit 0o111 covers user/group/other execute. We don't check for
	// 0o100-only (user-execute only) because dev builds typically
	// have 0o755 and packaged apps have 0o755 too.
	return fi.Mode().Perm()&0o111 != 0
}

// ownerWritableOnly reports whether the helper at p AND its containing
// directory are writable only by their owner (no group / other write
// bit). The biometric helper is the root of the application-layer Touch
// ID trust chain; if an attacker can write the binary — or drop a new
// file into a group/world-writable directory on the candidate path
// (e.g. an admin-group-writable /usr/local/bin) — they substitute a
// `#!/bin/sh; exit 0` shim that the daemon execs as the verdict oracle,
// while the audit log still attests approval_source=touchid (PROTO-127).
func ownerWritableOnly(p string) bool {
	for _, target := range []string{p, filepath.Dir(p)} {
		fi, err := os.Stat(target)
		if err != nil {
			return false
		}
		if fi.Mode().Perm()&0o022 != 0 { // group-write or other-write
			return false
		}
	}
	return true
}

// (touch a sentinel error here to anchor the doc comment in path.go)
var _ = errors.New
