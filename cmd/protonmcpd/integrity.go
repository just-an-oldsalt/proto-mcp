package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// D24 (Phase 7/C) — binary integrity check at daemon startup.
//
// When `protonmcp daemon install` runs, it records the SHA-256 of
// the protonmcpd binary into
// ~/Library/Application Support/protonmcp/expected_sha256.
//
// On every daemon launch, we recompute our own SHA-256 (via
// os.Executable() → open + hash) and compare. Mismatch means
// somebody replaced the binary at the recorded path between
// install and launch — refuse to start. Operator must re-run
// `protonmcp daemon install` to record the new hash.
//
// Failure modes:
//   * File missing → log warning, continue. Older installs that
//     predate Phase 7/C won't have the file; we don't break them.
//     A fresh `protonmcp daemon install` writes the file.
//   * Hash mismatch, binary still validly signed by expectedTeamID →
//     a legitimate upgrade (brew, or a fresh signed build). Re-record
//     the hash and continue. Without this, every `brew upgrade --cask
//     proto-mcp` left the daemon permanently down with no
//     user-visible explanation, because launchd's
//     KeepAlive{SuccessfulExit:false} honours the clean exit below.
//   * Hash mismatch, signature absent / ad-hoc / wrong team → refuse
//     to start with a clear error to stderr, then exit 0 (PROTO-113)
//     so launchd leaves the daemon down instead of respawning it into
//     the same failure every ~10s. Operator either restores the
//     original binary or re-runs install.
//   * Format error in the file → treat as missing (warn + continue).
//
// This is defense-in-depth: macOS code signing (Phase 7/C signing
// proper) is the primary protection. Integrity checking catches
// the case where a signed binary is swapped with an unsigned one
// after Gatekeeper has already approved the original path.
//
// Why the signature, not the hash, is the real trust anchor: a pinned
// hash cannot tell "the vendor shipped a new version" apart from
// "someone swapped the binary", so it rejects both. A Developer ID
// signature answers exactly the question being asked — is this still
// our binary — and an attacker able to produce one holds the signing
// key, at which point the hash pin buys nothing either. Ad-hoc-signed
// source builds keep the strict hash pin, having no signature to
// anchor to.

// VerifyBinaryIntegrity runs the SHA-256 check. Returns nil if the
// check passes OR if the expected_sha256 file is missing (graceful
// degrade for installs that predate this feature). Returns an error
// if the file exists but the hash doesn't match.
func VerifyBinaryIntegrity(logger *slog.Logger) error {
	expectedPath, err := expectedSha256Path()
	if err != nil {
		// Couldn't resolve $HOME — extremely rare. Continue
		// rather than block a daemon that might otherwise work.
		logger.Warn("integrity check skipped: could not resolve expected_sha256 path",
			"err", err.Error())
		return nil
	}
	expected, recordedPath, err := readExpectedSha256(expectedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("integrity check skipped: no expected_sha256 file",
				"path", expectedPath,
				"hint", "run `protonmcp daemon install` to record the binary hash")
			return nil
		}
		// Malformed → treat as advisory only. Logs loudly so the
		// operator notices, but doesn't block startup.
		logger.Warn("integrity check skipped: expected_sha256 unreadable",
			"path", expectedPath, "err", err.Error())
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("integrity check: os.Executable: %w", err)
	}
	actual, err := sha256File(exe)
	if err != nil {
		return fmt.Errorf("integrity check: hash %s: %w", exe, err)
	}

	if actual != expected {
		// The overwhelmingly common cause of a mismatch is a
		// legitimate upgrade: `brew upgrade --cask proto-mcp` swaps the
		// binary, the recorded hash goes stale, and the daemon refuses
		// to start until someone re-runs `protonmcp daemon install`.
		// Nothing tells the user that, so the tools just stop working.
		//
		// Before failing, ask the stronger question the hash was only
		// ever a proxy for: is this binary still one of OURS? A valid
		// Developer ID signature chaining to the Apple root and
		// carrying our team identifier answers yes, survives every
		// legitimate upgrade, and cannot be forged by the local
		// attacker this check exists to stop (they'd need our signing
		// key). If it holds, re-record the hash and carry on.
		if sigErr := verifyDeveloperIDSignature(exe); sigErr == nil {
			logger.Warn("binary changed since install; signature still trusted, re-recording hash",
				"path", exe,
				"was", expected[:16]+"…",
				"now", actual[:16]+"…",
				"team_id", expectedTeamID)
			if werr := rewriteExpectedSha256(expectedPath, actual, exe); werr != nil {
				// The signature check already passed, which is the
				// real authorization. A failed re-record just means
				// we'll repeat this dance next launch.
				logger.Warn("could not re-record expected_sha256",
					"path", expectedPath, "err", werr.Error())
			}
			return nil
		} else {
			// Not signed by us — this is the swap the check is for.
			// Ad-hoc-signed source builds land here too, which is
			// correct: they get the strict hash pin, since there's no
			// signature to anchor trust to.
			return fmt.Errorf(
				"binary integrity check FAILED\n"+
					"  running:   %s\n"+
					"  running sha256:    %s\n"+
					"  expected (from install): %s\n"+
					"  expected path: %s\n"+
					"  signature check: %v\n"+
					"  The binary was replaced after install and is not signed by the "+
					"expected Developer ID (team %s). Either restore the original "+
					"binary or, if you built this yourself, re-run "+
					"`protonmcp daemon install` to record the new hash",
				exe, actual, expected, recordedPath, sigErr, expectedTeamID,
			)
		}
	}

	logger.Info("binary integrity check passed",
		"sha256", actual[:16]+"…")
	return nil
}

// expectedTeamID is the Apple Developer Team identifier that signs
// released proto-mcp binaries. It is the trust anchor for the
// upgrade-survival path in VerifyBinaryIntegrity: a binary bearing a
// valid Developer ID signature from this team is ours regardless of its
// hash, so replacing it via a signed release is allowed while replacing
// it with anything else is not.
//
// Changing this constant changes who can silently replace the daemon.
const expectedTeamID = "346JJCHZP7"

// codesignTimeout bounds the codesign subprocess. Signature checks are
// local (no OCSP round trip with --verify alone) and finish in
// milliseconds; the timeout only exists so a wedged codesign can't hang
// daemon startup forever.
const codesignTimeout = 10 * time.Second

// verifyDeveloperIDSignature reports nil if path carries a valid,
// unbroken code signature that chains to the Apple root and was issued
// to expectedTeamID.
//
// The requirement string is evaluated by codesign itself rather than
// parsed out of `codesign -dv` text, which matters: `anchor apple
// generic` forces a real chain to Apple's root, so an attacker cannot
// satisfy it by ad-hoc signing a binary that merely claims our team
// identifier in its metadata.
func verifyDeveloperIDSignature(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), codesignTimeout)
	defer cancel()

	// Two syntax details that both fail closed but silently, so they're
	// worth spelling out:
	//   * "-R=<text>" — bare "-R <text>" makes codesign read the
	//     requirement from a FILE of that name, which errors out with
	//     "No such file or directory".
	//   * the team ID is quoted — it starts with digits, and unquoted
	//     the requirement lexer reads it as a number and rejects the
	//     expression.
	// Either mistake turns every check into an error, which would make
	// the self-heal dead code and send legitimate upgrades down the
	// hard-fail path. TestVerifyDeveloperIDSignatureAcceptsReleaseBinary
	// is what keeps that honest.
	req := fmt.Sprintf(`-R=anchor apple generic and certificate leaf[subject.OU] = %q`, expectedTeamID)
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign",
		"--verify", "--strict", req, path)

	// codesign writes its diagnostics to stderr; capture them so the
	// failure message in the log says *why* (unsigned, ad-hoc, wrong
	// team, modified since signing) rather than just "exit status 1".
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return errors.New(detail)
	}
	return nil
}

// rewriteExpectedSha256 replaces the recorded hash after a verified
// upgrade. Writes to a temp file in the same directory and renames, so
// a crash mid-write can't leave a truncated record that the next launch
// would read as "malformed" and skip.
func rewriteExpectedSha256(path, hash, binPath string) error {
	line := hash + "  " + binPath + "\n"

	tmp, err := os.CreateTemp(filepath.Dir(path), ".expected_sha256-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if _, err := tmp.WriteString(line); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func expectedSha256Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "expected_sha256"), nil
}

// readExpectedSha256 parses the one-line "<hex>  <path>\n" format
// `protonmcp daemon install` writes. Returns the hex hash and the
// recorded path. Whitespace between the two fields is one-or-more
// spaces / tabs (matches `shasum`'s output format).
func readExpectedSha256(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return "", "", fmt.Errorf("empty file")
	}
	line := strings.TrimSpace(scanner.Text())
	// Split on first run of whitespace.
	idx := strings.IndexAny(line, " \t")
	if idx == -1 {
		return "", "", fmt.Errorf("malformed: expected '<hash>  <path>', got %q", line)
	}
	hash := strings.TrimSpace(line[:idx])
	recorded := strings.TrimSpace(line[idx:])
	if len(hash) != 64 { // SHA-256 hex
		return "", "", fmt.Errorf("malformed: hash length is %d, expected 64", len(hash))
	}
	return hash, recorded, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
