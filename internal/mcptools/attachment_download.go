package mcptools

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

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
		ContentB64   string `json:"content_b64"`
		Cached       bool   `json:"cached"`
	}

	return mcp.Tool{
		Name: "mail_download_attachment",
		Description: "Download and decrypt the bytes of a single attachment from a Proton message. " +
			"Returns the plaintext as base64. On first call, fetches from Proton, decrypts with " +
			"the address keyring, and caches locally for 30 days. Subsequent calls return from " +
			"cache. Refuses attachments larger than max_attachment_bytes (policy; default 25 MiB) " +
			"before any network traffic. Filenames are sanitized — RTL spoofing, control chars, " +
			"path separators, and leading dots are stripped to defend the display + save paths.",
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
				"content_b64":   {"type": "string"},
				"cached":        {"type": "boolean"}
			},
			"required": ["message_id", "attachment_id", "filename", "size_bytes", "content_b64", "cached"]
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
				return mcp.StructuredResult(result{
					MessageID:    row.MessageID,
					AttachmentID: row.AttachmentID,
					Filename:     row.Filename,
					MIMEType:     row.MIMEType,
					SizeBytes:    row.SizeBytes,
					ContentB64:   base64.StdEncoding.EncodeToString(row.Content),
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

			return mcp.StructuredResult(result{
				MessageID:    payload.MessageID,
				AttachmentID: payload.AttachmentID,
				Filename:     payload.Filename,
				MIMEType:     payload.MIMEType,
				SizeBytes:    payload.SizeBytes,
				ContentB64:   base64.StdEncoding.EncodeToString(payload.Content),
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

// silence unused-import noise if a future refactor drops a use site.
var _ = fmt.Sprintf
