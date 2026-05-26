package mcptools

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gluon/rfc822"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// Phase 8/B — attachment send path. Shared between the send family
// (mail_send / mail_reply / mail_reply_all / mail_forward /
// mail_send_draft) and the draft family (mail_draft_create /
// mail_draft_update).
//
// Two helpers; one shape; one place for size enforcement and
// filename sanitization.

// sendAttachmentInput is the JSON shape every attachment-accepting
// tool exposes. Identical across send + draft inputs.
type sendAttachmentInput struct {
	// Filename is the user-visible name. Runs through
	// sanitize.Filename before upload (D21-class defense:
	// strips RTL spoofs, controls, path separators, leading
	// dots; caps at 255 bytes preserving extension).
	Filename string `json:"filename"`

	// MIMEType is the Content-Type the recipient sees. Sender
	// claims; receiver should verify. We don't sniff bytes.
	MIMEType string `json:"mime_type,omitempty"`

	// ContentB64 is the plaintext attachment bytes, base64-encoded.
	// Decoded + size-checked + then handed to the SDK's
	// UploadAttachment which encrypts before upload.
	ContentB64 string `json:"content_b64"`
}

// decodedAttachment is the in-process representation between the
// validate step and the upload step. Filename is the SANITIZED
// form; Plain is the post-base64-decode plaintext bytes.
type decodedAttachment struct {
	Filename string
	MIMEType string
	Plain    []byte
}

// attachmentInputSchemaFragment is the JSON-schema chunk every
// send/draft tool drops into its inputSchema's properties bag.
// Centralized so a future field add (e.g. content_id for inline
// attachments) only touches one place.
const attachmentInputSchemaFragment = `{
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "filename":    {"type": "string"},
            "mime_type":   {"type": "string"},
            "content_b64": {"type": "string"}
        },
        "required": ["filename", "content_b64"],
        "additionalProperties": false
    }
}`

// decodeAndValidateAttachments runs every attachment through:
//
//  1. base64 decode of content_b64 → plaintext bytes
//  2. per-attachment size check against max_attachment_bytes
//  3. sum-of-bytes check against the same cap (a 100-element list
//     of 24-MiB attachments would otherwise sneak past the per-item
//     check)
//  4. filename sanitization
//
// Returns the in-process list ready for upload, or an error that
// the caller renders as mcp.ErrorResult.
//
// The function does NOT touch the network. It's safe to call before
// CreateDraft / SendDraft so we fail fast.
func decodeAndValidateAttachments(deps Deps, atts []sendAttachmentInput) ([]decodedAttachment, error) {
	if len(atts) == 0 {
		return nil, nil
	}
	cap := maxAttachmentBytes(deps)
	out := make([]decodedAttachment, 0, len(atts))
	var total int64
	for i, a := range atts {
		if a.Filename == "" {
			return nil, fmt.Errorf("attachments[%d]: filename is required", i)
		}
		if a.ContentB64 == "" {
			return nil, fmt.Errorf("attachments[%d] (%s): content_b64 is required", i, a.Filename)
		}
		plain, err := base64.StdEncoding.DecodeString(a.ContentB64)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): content_b64 is not valid base64: %w",
				i, a.Filename, err)
		}
		if int64(len(plain)) > cap {
			return nil, fmt.Errorf(
				"attachments[%d] (%s): %d bytes exceeds max_attachment_bytes (%d). "+
					"Increase the policy cap in ~/Library/Application Support/protonmcp/policy.yaml to override.",
				i, a.Filename, len(plain), cap,
			)
		}
		total += int64(len(plain))
		if total > cap {
			return nil, fmt.Errorf(
				"attachments[0..%d]: cumulative %d bytes exceeds max_attachment_bytes (%d) — "+
					"split into multiple messages or raise the policy cap",
				i, total, cap,
			)
		}
		mt := a.MIMEType
		if mt == "" {
			mt = "application/octet-stream"
		}
		out = append(out, decodedAttachment{
			Filename: sanitize.Filename(a.Filename),
			MIMEType: mt,
			Plain:    plain,
		})
	}
	return out, nil
}

// uploadAttachmentsAndCollectKeys uploads every decoded attachment
// to the draft on the server side, then recovers each one's session
// key from its KeyPackets so they can be re-encrypted to every
// recipient. Returns the (attachmentID → SessionKey) map that
// AddTextPackage expects.
//
// Cryptographic flow per attachment:
//
//  1. UploadAttachment encrypts the plaintext via the sender's
//     keyring (SDK handles split + sign + multipart upload). The
//     returned Attachment.KeyPackets is the base64-encoded key
//     packet — encrypted to the sender's public key.
//
//  2. base64-decode KeyPackets → raw key packet bytes.
//
//  3. addrKR.DecryptSessionKey recovers the per-attachment session
//     key. This is the symmetric key the data packet is encrypted
//     under — recovering it once means we can re-encrypt it to
//     every recipient's keyring inside AddTextPackage rather than
//     re-uploading the body N times.
//
// Returns nil map (not empty) if `decoded` is empty — same value
// AddTextPackage accepts for the no-attachments case.
func uploadAttachmentsAndCollectKeys(
	ctx context.Context,
	deps Deps,
	addrKR *crypto.KeyRing,
	draftID string,
	decoded []decodedAttachment,
) (map[string]*crypto.SessionKey, error) {
	if len(decoded) == 0 {
		return nil, nil
	}
	attKeys := make(map[string]*crypto.SessionKey, len(decoded))
	for i, d := range decoded {
		att, err := deps.Session.Client.UploadAttachment(ctx, addrKR, gpa.CreateAttachmentReq{
			MessageID:   draftID,
			Filename:    d.Filename,
			MIMEType:    rfc822.MIMEType(d.MIMEType),
			Disposition: gpa.AttachmentDisposition,
			Body:        d.Plain,
		})
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): upload: %w", i, d.Filename, err)
		}
		kpBytes, err := base64.StdEncoding.DecodeString(att.KeyPackets)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): decode KeyPackets: %w", i, d.Filename, err)
		}
		sk, err := addrKR.DecryptSessionKey(kpBytes)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): recover session key: %w", i, d.Filename, err)
		}
		attKeys[att.ID] = sk
	}
	return attKeys, nil
}

// attachmentsSummary formats a one-line summary for the Touch ID
// prompt body. Sanitized filenames; sizes in a human-readable form;
// truncates after 3 with "and N more" suffix beyond.
//
// Example outputs:
//
//	"Attachments: report.pdf (2.4 MB)"
//	"Attachments: report.pdf (2.4 MB), photo.jpg (850 KB)"
//	"Attachments: a.pdf (1 KB), b.pdf (1 KB), c.pdf (1 KB) and 5 more"
func attachmentsSummary(decoded []decodedAttachment) string {
	if len(decoded) == 0 {
		return ""
	}
	const max = 3
	parts := make([]string, 0, max)
	for i, d := range decoded {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", d.Filename, humanBytes(int64(len(d.Plain)))))
	}
	out := "Attachments: " + strings.Join(parts, ", ")
	if len(decoded) > max {
		out += fmt.Sprintf(" and %d more", len(decoded)-max)
	}
	return out
}

// humanBytes formats a byte count as a short human-readable string.
// Tuned for the Touch ID prompt — not for log lines (no precision).
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
