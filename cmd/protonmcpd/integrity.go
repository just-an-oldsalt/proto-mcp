package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
//   * Hash mismatch → refuse to start with a clear error to stderr.
//     launchd's KeepAlive will retry but every retry hits the same
//     failure, so the daemon stays down. Operator either restores
//     the original binary or re-runs install.
//   * Format error in the file → treat as missing (warn + continue).
//
// This is defense-in-depth: macOS code signing (Phase 7/C signing
// proper) is the primary protection. Integrity checking catches
// the case where a signed binary is swapped with an unsigned one
// after Gatekeeper has already approved the original path.

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
		return fmt.Errorf(
			"binary integrity check FAILED\n"+
				"  running:   %s\n"+
				"  running sha256:    %s\n"+
				"  expected (from install): %s\n"+
				"  expected path: %s\n"+
				"  This indicates the binary was replaced after install. "+
				"Either restore the original binary or re-run "+
				"`protonmcp daemon install` to record the new hash",
			exe, actual, expected, recordedPath,
		)
	}

	logger.Info("binary integrity check passed",
		"sha256", actual[:16]+"…")
	return nil
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
