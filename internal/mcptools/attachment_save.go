package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Phase 8/C — mail_save_attachment. Decrypted attachment bytes
// land in ~/Downloads with a sanitized + collision-safe filename.
// Defense-in-depth path traversal: filename runs through
// sanitize.Filename, filepath.Base, then filepath.Clean; the final
// parent directory must equal the resolved ~/Downloads or we
// refuse.
//
// XDG_DOWNLOAD_DIR support deferred — hardcoded ~/Downloads is the
// v1 contract, documented in the tool description and policy stub.

func mailSaveAttachment(deps Deps) mcp.Tool {
	type input struct {
		MessageID    string `json:"message_id"`
		AttachmentID string `json:"attachment_id"`
		Filename     string `json:"filename,omitempty"`
	}
	type result struct {
		SavedPath string `json:"saved_path"`
		Filename  string `json:"filename"`
		SizeBytes int64  `json:"size_bytes"`
	}

	return mcp.Tool{
		Name: "mail_save_attachment",
		Description: "Save a decrypted attachment to ~/Downloads. " +
			"Filename is sanitized (RTL spoofing, control chars, path separators, leading dots stripped). " +
			"Refuses paths outside ~/Downloads. Existing files get a (2), (3), ... suffix rather than " +
			"overwriting. On cache miss, fetches + caches first (same path as mail_download_attachment). " +
			"Touch ID prompt shows the literal filename + target directory.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id":    {"type": "string"},
				"attachment_id": {"type": "string"},
				"filename":      {"type": "string"}
			},
			"required": ["message_id", "attachment_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"saved_path": {"type": "string"},
				"filename":   {"type": "string"},
				"size_bytes": {"type": "integer"}
			},
			"required": ["saved_path", "filename", "size_bytes"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			subj := lookupSubject(deps, in.MessageID)
			fname := in.Filename
			if fname == "" {
				fname = "(name from message)"
			} else {
				fname = sanitize.Filename(fname)
			}
			body := "save attachment from " + subj + " as " + fname + " to ~/Downloads"
			title := mcp.SanitizePromptText("Approve mail_save_attachment?", 120)
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: "+err.Error())
			}
			if in.MessageID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: message_id is required")
			}
			if in.AttachmentID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: attachment_id is required")
			}
			if deps.Store == nil {
				return nil, errors.New("mail_save_attachment: store not available")
			}

			// 1. Get bytes: cache hit first, else fetch + cache.
			row, content, err := loadOrFetchAttachment(ctx.Std, deps, in.MessageID, in.AttachmentID)
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: %v", err), nil
			}

			// 2. Pick filename. Caller override wins; else use the
			// cached sanitized name.
			fname := row.Filename
			if in.Filename != "" {
				fname = in.Filename
			}
			fname = sanitize.Filename(fname)
			// filepath.Base + Clean — defense in depth even though
			// sanitize.Filename already substituted separators.
			fname = filepath.Base(filepath.Clean(fname))
			if fname == "" || fname == "." || fname == "/" || fname == "\\" {
				return mcp.ErrorResult("mail_save_attachment: refusing empty / invalid filename %q after sanitization", fname), nil
			}

			// 3. Resolve target directory + verify containment.
			home, err := os.UserHomeDir()
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: home dir: %v", err), nil
			}
			rootDir := filepath.Clean(filepath.Join(home, "Downloads"))
			if err := os.MkdirAll(rootDir, 0o700); err != nil {
				return mcp.ErrorResult("mail_save_attachment: mkdir ~/Downloads: %v", err), nil
			}
			cleanedDest := filepath.Clean(filepath.Join(rootDir, fname))
			// Parent of cleanedDest must equal rootDir. If
			// filepath.Clean expanded any "..", the parent diverges
			// and we refuse. (sanitize.Filename should have
			// substituted slashes already; this is belt + suspenders.)
			if filepath.Dir(cleanedDest) != rootDir {
				return mcp.ErrorResult(
					"mail_save_attachment: refusing path outside ~/Downloads (resolved to %q)",
					cleanedDest,
				), nil
			}

			// 4. Open with O_EXCL; on conflict, append (N) suffix.
			finalPath, f, err := openExclusiveWithSuffix(cleanedDest)
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: open: %v", err), nil
			}
			defer f.Close()
			if _, err := f.Write(content); err != nil {
				_ = os.Remove(finalPath)
				return mcp.ErrorResult("mail_save_attachment: write: %v", err), nil
			}

			return mcp.StructuredResult(result{
				SavedPath: finalPath,
				Filename:  filepath.Base(finalPath),
				SizeBytes: int64(len(content)),
			})
		},
	}
}

// loadOrFetchAttachment returns the cached row + its plaintext
// bytes if cached, else fetches from Proton (decrypting via the
// address keyring) and caches before returning. Mirrors the
// mail_download_attachment cache-hit-or-fetch contract.
func loadOrFetchAttachment(ctx context.Context, deps Deps, messageID, attachmentID string) (store.AttachmentCacheRow, []byte, error) {
	if row, err := deps.Store.GetCachedAttachment(ctx, messageID, attachmentID); err == nil {
		return row, row.Content, nil
	} else if !errors.Is(err, store.ErrAttachmentNotCached) {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf("cache lookup: %w", err)
	}
	if deps.Session == nil {
		return store.AttachmentCacheRow{}, nil, errors.New("session not available")
	}
	cap := maxAttachmentBytes(deps)

	// Pre-fetch size check.
	m, err := deps.Session.Client.GetMessage(ctx, messageID)
	if err != nil {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf("fetch envelope: %w", err)
	}
	for _, a := range m.Attachments {
		if a.ID == attachmentID && a.Size > cap {
			return store.AttachmentCacheRow{}, nil, fmt.Errorf(
				"attachment is %d bytes; exceeds max_attachment_bytes (%d)",
				a.Size, cap,
			)
		}
	}

	payload, err := deps.Session.FetchAndDecryptAttachment(ctx, messageID, attachmentID)
	if err != nil {
		return store.AttachmentCacheRow{}, nil, err
	}
	if payload.SizeBytes > cap {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf(
			"decrypted size %d exceeds max_attachment_bytes (%d)",
			payload.SizeBytes, cap,
		)
	}
	row := store.AttachmentCacheRow{
		MessageID:    payload.MessageID,
		AttachmentID: payload.AttachmentID,
		Filename:     payload.Filename,
		MIMEType:     payload.MIMEType,
		SizeBytes:    payload.SizeBytes,
		Content:      payload.Content,
	}
	_ = deps.Store.SetAttachmentCache(ctx, row)
	_, _ = deps.Store.EvictAttachmentsToFit(ctx, attachmentCacheCeilingBytes)
	return row, payload.Content, nil
}

// openExclusiveWithSuffix opens `path` for write with O_EXCL, and
// on EEXIST appends a "(2)", "(3)", ... suffix before the extension
// until it finds a free name. Caps at 999 tries — refuses rather
// than spinning if the directory is somehow saturated with
// collisions.
func openExclusiveWithSuffix(path string) (string, *os.File, error) {
	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	for i := 0; i < 1000; i++ {
		candidate := path
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i+1, ext)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return candidate, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("could not find free filename after 999 attempts at %s", path)
}
