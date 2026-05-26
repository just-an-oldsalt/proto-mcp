package proton

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// AttachmentPayload is the decrypted plaintext bytes of an attachment
// plus the metadata mail_download_attachment / mail_save_attachment
// need to return to the caller. Phase 8/A.
//
// Filename is the SANITIZED form (sanitize.Filename has run); the
// caller can rely on it being safe for display and (modulo
// path-traversal defense at mail_save_attachment) for filesystem
// use.
type AttachmentPayload struct {
	MessageID    string
	AttachmentID string
	Filename     string
	MIMEType     string
	SizeBytes    int64
	Content      []byte
}

// FetchAndDecryptAttachment pulls one attachment's encrypted data
// from Proton, recovers its session key via the appropriate address
// keyring, decrypts, and returns the plaintext bytes plus metadata.
//
// Cryptographic flow (per go-proton-api SDK; reference impl at
// message_build.go:writeAttachmentPart in the SDK source):
//
//   1. GetMessage gives us Message.Attachments[i] with KeyPackets
//      (base64) and Message.AddressID for the keyring lookup.
//   2. GetAttachment gives us the encrypted data packet (raw bytes).
//   3. base64-decode KeyPackets to get the key packet bytes.
//   4. NewPGPSplitMessage combines key + data packets into a
//      single PGPMessage.
//   5. addressKeyring.Decrypt decrypts using the address's private
//      key (which is unlocked at session resume).
//
// Errors are returned verbatim; the caller (mail_download_attachment)
// translates them to mcp.ErrorResult.
func (s *Session) FetchAndDecryptAttachment(ctx context.Context, messageID, attachmentID string) (*AttachmentPayload, error) {
	if s == nil || s.Client == nil {
		return nil, errors.New("proton: session is closed")
	}

	// 1. Fetch the message envelope to (a) locate the address keyring
	//    and (b) pick the right attachment metadata + key packets.
	m, err := s.Client.GetMessage(ctx, messageID)
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}
	kr, ok := s.AddrKRs[m.AddressID]
	if !ok {
		return nil, fmt.Errorf("proton: no unlocked keyring for address %s — re-login may be required", m.AddressID)
	}

	// Find the attachment in the message's attachment list. The
	// SDK doesn't expose a direct "get attachment by id within a
	// message" — we walk the slice.
	var attMeta *attachmentMetaSource
	for i := range m.Attachments {
		if m.Attachments[i].ID == attachmentID {
			attMeta = &attachmentMetaSource{
				Filename:   m.Attachments[i].Name,
				MIMEType:   string(m.Attachments[i].MIMEType),
				SizeBytes:  m.Attachments[i].Size,
				KeyPackets: m.Attachments[i].KeyPackets,
			}
			break
		}
	}
	if attMeta == nil {
		return nil, fmt.Errorf("proton: attachment %s not found in message %s", attachmentID, messageID)
	}

	// 2. Fetch the encrypted data packet.
	dataPacket, err := s.Client.GetAttachment(ctx, attachmentID)
	if err != nil {
		return nil, fmt.Errorf("get attachment data: %w", err)
	}

	// 3. Decode key packets.
	keyPackets, err := base64.StdEncoding.DecodeString(attMeta.KeyPackets)
	if err != nil {
		return nil, fmt.Errorf("decode key packets: %w", err)
	}

	// 4. Combine key + data packets into a single PGP message.
	split := crypto.NewPGPSplitMessage(keyPackets, dataPacket)

	// 5. Decrypt with the address keyring. Pass nil for the
	//    verification keyring (we don't verify attachment
	//    signatures; the server-side TLS + the message-level
	//    signature on the wrapping message are the integrity
	//    signals).
	plain, err := kr.Decrypt(split.GetPGPMessage(), nil, crypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("decrypt attachment: %w", err)
	}

	out := &AttachmentPayload{
		MessageID:    messageID,
		AttachmentID: attachmentID,
		Filename:     sanitize.Filename(attMeta.Filename),
		MIMEType:     attMeta.MIMEType,
		SizeBytes:    int64(len(plain.GetBinary())),
		Content:      plain.GetBinary(),
	}
	return out, nil
}

// attachmentMetaSource is the subset of fields we read off the
// SDK's Attachment struct. Keeping it private here decouples the
// `proton` package's public surface from go-proton-api's type
// shape; if the SDK renames Name → Filename in a future bump, the
// fix is one place.
type attachmentMetaSource struct {
	Filename   string
	MIMEType   string
	SizeBytes  int64
	KeyPackets string // base64
}
