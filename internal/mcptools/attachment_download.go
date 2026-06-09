package mcptools

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// inlineAttachmentMaxBytes is the raw-byte ceiling under which
// mail_download_attachment returns the decrypted bytes inline as
// base64. Above it, the bytes are written to a staging file and the
// response carries the path instead (Phase 8/D).
//
// Returning full base64 inline blows the MCP response token cap on
// anything but tiny attachments — a 79 KB PDF expands to ~106 K base64
// characters. 16 KiB raw (~22 KB base64) keeps inline responses small
// enough to stay well under the cap while covering the common case of
// little text/JSON/icon attachments that callers want to read directly.
const inlineAttachmentMaxBytes = 16 * 1024

// attachmentCacheCeilingBytes is the hard ceiling on the on-disk
// attachment cache. After every successful download we run
// Store.EvictAttachmentsToFit at this cap, deleting the oldest
// cached_at rows until the SUM(size_bytes) is back under it.
//
// 500 MiB is the v1 number: ten 50-MiB attachments worth of slack
// before eviction kicks in, while still bounding the worst-case
// disk footprint to something a laptop user won't notice. Not
// user-configurable in v1 — adding a config knob is cheap if
// someone asks for it.
const attachmentCacheCeilingBytes int64 = 500 * 1024 * 1024

func mailDownloadAttachment(deps Deps) mcp.Tool {
	type input struct {
		MessageID    string `json:"message_id"`
		AttachmentID string `json:"attachment_id"`
	}
	type result struct {
		MessageID    string `json:"message_id"`
		AttachmentID string `json:"attachment_id"`
		Filename     string `json:"filename"`
		MIMEType     string `json:"mime_type,omitempty"`
		SizeBytes    int64  `json:"size_bytes"`
		SHA256       string `json:"sha256"`
		// Exactly one of ContentB64 / Path is set. Small attachments
		// (<= inlineAttachmentMaxBytes) come back inline as base64;
		// larger ones are written to a staging file and Path points at
		// it (Phase 8/D — keeps the MCP response under the token cap).
		ContentB64 string `json:"content_b64,omitempty"`
		Path       string `json:"path,omitempty"`
		Cached     bool   `json:"cached"`
	}

	return mcp.Tool{
		Name: "mail_download_attachment",
		Description: "Download and decrypt the bytes of a single attachment from a Proton message. " +
			"Small attachments (<= 16 KiB) come back inline as base64 in content_b64; larger ones are " +
			"written to a local staging file and the response carries its path instead (keeping the " +
			"response under the MCP token cap) — use mail_save_attachment to copy it somewhere permanent. " +
			"Either way a sha256 of the plaintext is returned. On first call, fetches from Proton, decrypts " +
			"with the address keyring, and caches locally for 30 days; subsequent calls return from cache. " +
			"Refuses attachments larger than max_attachment_bytes (policy; default 25 MiB) before any " +
			"network traffic. Filenames are sanitized — RTL spoofing, control chars, path separators, and " +
			"leading dots are stripped to defend the display + save paths.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id":    {"type": "string"},
				"attachment_id": {"type": "string"}
			},
			"required": ["message_id", "attachment_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id":    {"type": "string"},
				"attachment_id": {"type": "string"},
				"filename":      {"type": "string"},
				"mime_type":     {"type": "string"},
				"size_bytes":    {"type": "integer"},
				"sha256":        {"type": "string", "description": "Hex SHA-256 of the decrypted plaintext."},
				"content_b64":   {"type": "string", "description": "Base64 plaintext; present only for attachments <= 16 KiB."},
				"path":          {"type": "string", "description": "Path to a staging file holding the plaintext; present only for attachments > 16 KiB."},
				"cached":        {"type": "boolean"}
			},
			"required": ["message_id", "attachment_id", "filename", "size_bytes", "sha256", "cached"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			subj := lookupSubject(deps, in.MessageID)
			title := mcp.SanitizePromptText("Approve mail_download_attachment?", 120)
			body := "download attachment from " + subj +
				" (attachment " + shortID(in.AttachmentID) + ")"
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_download_attachment: "+err.Error())
			}
			if in.MessageID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_download_attachment: message_id is required")
			}
			if in.AttachmentID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_download_attachment: attachment_id is required")
			}
			if deps.Store == nil {
				return nil, errors.New("mail_download_attachment: store not available")
			}

			// Cache hit short-circuit. No size check, no network — by
			// definition we already passed the cap on the first
			// download. Filenames in the cache are already sanitized.
			if row, err := deps.Store.GetCachedAttachment(ctx.Std, in.MessageID, in.AttachmentID); err == nil {
				b64, path, sha, berr := stageOrInlineAttachment(row.AttachmentID, row.Filename, row.Content)
				if berr != nil {
					return mcp.ErrorResult("mail_download_attachment: %v", berr), nil
				}
				return mcp.StructuredResult(result{
					MessageID:    row.MessageID,
					AttachmentID: row.AttachmentID,
					Filename:     row.Filename,
					MIMEType:     row.MIMEType,
					SizeBytes:    row.SizeBytes,
					SHA256:       sha,
					ContentB64:   b64,
					Path:         path,
					Cached:       true,
				})
			} else if !errors.Is(err, store.ErrAttachmentNotCached) {
				return mcp.ErrorResult("mail_download_attachment: cache lookup failed: %v", err), nil
			}

			if deps.Session == nil {
				return nil, errors.New("mail_download_attachment: session not available")
			}

			// Pre-fetch size check from the message envelope so an
			// oversized attachment doesn't pay the bytes-on-the-wire
			// cost. mail_list_attachments already does a GetMessage —
			// we do another one here on purpose (the metadata could
			// have changed; we don't trust caller-provided size).
			m, err := deps.Session.Client.GetMessage(ctx.Std, in.MessageID)
			if err != nil {
				return mcp.ErrorResult("mail_download_attachment: fetch message envelope: %v", err), nil
			}
			var declaredSize int64
			var found bool
			for i := range m.Attachments {
				if m.Attachments[i].ID == in.AttachmentID {
					declaredSize = m.Attachments[i].Size
					found = true
					break
				}
			}
			if !found {
				return mcp.ErrorResult("mail_download_attachment: attachment %s not found in message %s", in.AttachmentID, in.MessageID), nil
			}
			cap := maxAttachmentBytes(deps)
			if declaredSize > cap {
				return mcp.ErrorResult(
					"mail_download_attachment: attachment is %d bytes; refuses larger than max_attachment_bytes (%d). "+
						"Increase the policy cap in ~/Library/Application Support/protonmcp/policy.yaml to override.",
					declaredSize, cap,
				), nil
			}

			payload, err := deps.Session.FetchAndDecryptAttachment(ctx.Std, in.MessageID, in.AttachmentID)
			if err != nil {
				return mcp.ErrorResult("mail_download_attachment: %v", err), nil
			}

			// Defense in depth: even after the metadata check, the
			// decrypted bytes might exceed the cap (e.g. metadata
			// lied). Refuse to cache; refuse to return.
			if payload.SizeBytes > cap {
				return mcp.ErrorResult(
					"mail_download_attachment: decrypted size %d > max_attachment_bytes (%d) — refusing",
					payload.SizeBytes, cap,
				), nil
			}

			if err := deps.Store.SetAttachmentCache(ctx.Std, store.AttachmentCacheRow{
				MessageID:    payload.MessageID,
				AttachmentID: payload.AttachmentID,
				Filename:     payload.Filename,
				MIMEType:     payload.MIMEType,
				SizeBytes:    payload.SizeBytes,
				Content:      payload.Content,
			}); err != nil {
				// Cache write failure is non-fatal for the user — we
				// have the bytes in memory and can return them. Log
				// + continue.
				slog.Warn("attachment_cache write failed; returning uncached", "err", err,
					"message_id", payload.MessageID, "attachment_id", payload.AttachmentID)
			} else {
				// Best-effort eviction down to the 500 MiB ceiling.
				// Errors only show up in the log; the user still gets
				// their bytes.
				if n, evictErr := deps.Store.EvictAttachmentsToFit(ctx.Std, attachmentCacheCeilingBytes); evictErr != nil {
					slog.Warn("attachment_cache eviction failed", "err", evictErr)
				} else if n > 0 {
					slog.Info("attachment_cache evicted", "rows", n, "ceiling_bytes", attachmentCacheCeilingBytes)
				}
			}

			b64, path, sha, berr := stageOrInlineAttachment(payload.AttachmentID, payload.Filename, payload.Content)
			if berr != nil {
				return mcp.ErrorResult("mail_download_attachment: %v", berr), nil
			}
			return mcp.StructuredResult(result{
				MessageID:    payload.MessageID,
				AttachmentID: payload.AttachmentID,
				Filename:     payload.Filename,
				MIMEType:     payload.MIMEType,
				SizeBytes:    payload.SizeBytes,
				SHA256:       sha,
				ContentB64:   b64,
				Path:         path,
				Cached:       false,
			})
		},
	}
}

// maxAttachmentBytes returns the active per-attachment cap. Reads
// from the policy engine if available, otherwise falls back to the
// default. Phase 8/A.
func maxAttachmentBytes(deps Deps) int64 {
	if deps.Policy != nil {
		return deps.Policy.MaxAttachmentBytes()
	}
	return policy.DefaultMaxAttachmentBytes
}

// stageOrInlineAttachment computes the SHA-256 of the decrypted bytes
// and decides how to return them: inline base64 for small attachments,
// or a staging-file path for large ones (Phase 8/D). Exactly one of the
// returned b64 / path is non-empty; sha is always set.
func stageOrInlineAttachment(attachmentID, filename string, content []byte) (b64, path, sha string, err error) {
	sum := sha256.Sum256(content)
	sha = hex.EncodeToString(sum[:])
	if int64(len(content)) <= inlineAttachmentMaxBytes {
		return base64.StdEncoding.EncodeToString(content), "", sha, nil
	}
	path, err = writeAttachmentStaging(attachmentID, filename, content)
	if err != nil {
		return "", "", "", err
	}
	return "", path, sha, nil
}

// stagingDir resolves the decrypted-attachment staging directory
// (~/Library/Application Support/protonmcp/attachment-staging/). Shared
// by the writer and the retention sweep so they can't drift.
func stagingDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "attachment-staging"), nil
}

// writeAttachmentStaging writes decrypted plaintext to a per-attachment
// file under the staging dir and returns its path. The name is
// deterministic (attachment id + sanitized filename) so re-downloading
// the same attachment overwrites rather than accumulating copies — the
// dir stays bounded by the number of distinct large attachments fetched,
// not the call count. Mode 0600 in a 0700 dir, mirroring the on-disk
// hardening the SQLite cache and socket already use. The bytes are also
// in the 500 MiB-capped SQLite cache; this is the filesystem handoff for
// callers that can't read base64 out of a token-capped response.
//
// Retention: the file is swept by SweepStagingOlderThan (wired into
// `protonmcp purge` and the startup body sweep) so this plaintext does
// not outlive its SQLite-cache counterpart (PROTO-135).
func writeAttachmentStaging(attachmentID, filename string, content []byte) (string, error) {
	dir, err := stagingDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir staging: %w", err)
	}

	// Both components are sanitized + Base'd so neither the
	// Proton-issued attachment id nor the filename can escape the
	// staging dir via separators or "..".
	stem := filepath.Base(filepath.Clean(sanitize.Filename(attachmentID)))
	name := filepath.Base(filepath.Clean(sanitize.Filename(filename)))
	if name == "" || name == "." || name == "/" || name == "\\" {
		name = "attachment"
	}
	if stem == "" || stem == "." || stem == "/" || stem == "\\" {
		stem = "att"
	}
	dest := filepath.Clean(filepath.Join(dir, stem+"__"+name))
	if filepath.Dir(dest) != filepath.Clean(dir) {
		return "", fmt.Errorf("refusing staging path outside %s (resolved to %q)", dir, dest)
	}

	// PROTO-135: O_NOFOLLOW so a pre-planted symlink at the (predictable)
	// dest can't redirect the decrypted plaintext onto an arbitrary
	// same-UID-writable target — a LaunchAgent plist, policy.yaml, the
	// SQLite DB. O_TRUNC preserves the deterministic-overwrite contract
	// for re-downloads of the same attachment. (The lexical containment
	// check above stops name-based escapes; this stops symlink escapes.)
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("open staging file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("write staging file: %w", err)
	}
	return dest, nil
}

// SweepStagingOlderThan removes decrypted-attachment staging files whose
// modtime is older than cutoff, returning the count removed. Mirrors the
// SQLite attachment cache's age retention so on-disk plaintext doesn't
// outlive its DB counterpart (PROTO-135). A missing staging dir is not an
// error (nothing has been staged yet). Best-effort: a per-file remove
// error is returned after the sweep completes, not aborted on.
func SweepStagingOlderThan(cutoff time.Time) (int, error) {
	dir, err := stagingDir()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if info.ModTime().Before(cutoff) {
			if rmErr := os.Remove(filepath.Join(dir, e.Name())); rmErr != nil {
				if firstErr == nil {
					firstErr = rmErr
				}
				continue
			}
			removed++
		}
	}
	return removed, firstErr
}
