package mcptools

import (
	"context"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gluon/rfc822"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// buildSendPreferences resolves every recipient's public key and
// returns the SendPreferences map AddTextPackage / AddMIMEPackage
// expects. Per-recipient encryption is the bulk of new code in 5/D;
// the SDK helpers (GetPublicKeys + AddTextPackage) hide the actual
// crypto, but the orchestration — which scheme to pick, when to
// fetch keys, what signature type — lives here.
//
// Mapping:
//
//	RecipientTypeInternal  → InternalScheme + Encrypt=true + pubkey from GetPublicKeys
//	RecipientTypeExternal  → ClearScheme + Encrypt=false (no pubkey on file)
//	                         OR PGPMIMEScheme + Encrypt=true if Proton served a key
//
// "Encrypt to external with PGP" requires the contact to have
// uploaded a public key OR for the user to have a contact-pinned
// key. SDK's GetPublicKeys returns whatever Proton has for that
// recipient; if a non-empty KeyRing comes back for an external
// address, we use PGPMIMEScheme. Otherwise the message goes
// ClearScheme (recipient gets a Proton-side "this email is
// unencrypted" disclaimer link).
func buildSendPreferences(ctx context.Context, deps Deps, recipients []string, mimeType string) (map[string]gpa.SendPreferences, error) {
	out := make(map[string]gpa.SendPreferences, len(recipients))
	for _, addr := range recipients {
		keys, recType, err := deps.Session.Client.GetPublicKeys(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("public keys for %s: %w", addr, err)
		}
		prefs := gpa.SendPreferences{
			MIMEType:      mimeTypeForSend(mimeType),
			SignatureType: gpa.DetachedSignature,
		}
		switch recType {
		case gpa.RecipientTypeInternal:
			kr, err := keys.GetKeyRing()
			if err != nil || kr == nil {
				return nil, fmt.Errorf("build keyring for internal %s: %w", addr, err)
			}
			prefs.Encrypt = true
			prefs.PubKey = kr
			prefs.EncryptionScheme = gpa.InternalScheme

		case gpa.RecipientTypeExternal:
			// Phase 8/B — PGP/MIME refusal. We send via
			// AddTextPackage which the SDK rejects for PGPMIMEScheme
			// recipients (it requires multipart/mixed via
			// AddMIMEPackage, which we don't implement). Without an
			// explicit error here the failure surfaces deep in the
			// SDK as "invalid MIME type for package: text/plain" —
			// confusing. Surface a clear refusal instead.
			//
			// Tradeoff: external recipients with on-file PGP keys
			// now fail closed (ClearScheme would be an info-leak —
			// the user uploaded a key precisely to NOT get cleartext
			// email). Phase 9 spike will add real PGP/MIME via
			// AddMIMEPackage. Until then, send to a Proton address
			// or a recipient without an on-file PGP key.
			if len(keys) > 0 {
				return nil, fmt.Errorf(
					"PGP/MIME-encrypted external recipients aren't supported yet (recipient: %s). "+
						"This recipient has a PGP key on file with Proton, which would require "+
						"multipart/mixed encryption that the current send path doesn't implement. "+
						"Send to a Proton address or a recipient without an on-file PGP key, or "+
						"wait for Phase 9 PGP/MIME support.",
					addr,
				)
			}
			prefs.EncryptionScheme = gpa.ClearScheme
			prefs.SignatureType = gpa.NoSignature

		default:
			return nil, fmt.Errorf("unknown recipient type for %s", addr)
		}
		out[addr] = prefs
	}
	return out, nil
}

// mimeTypeForSend maps our string MIME types to the SDK's
// rfc822.MIMEType. Limited to the two we emit (Phase 5 v1 doesn't
// ship multipart MIME for attachments).
func mimeTypeForSend(s string) rfc822.MIMEType {
	switch s {
	case "text/html":
		return rfc822.MIMEType("text/html")
	default:
		return rfc822.MIMEType("text/plain")
	}
}

// ensureKeyRing is a small helper for the send path that asserts a
// keyring is usable. Today inline; future-proof seam if we need to
// gracefully degrade when a pubkey can't be loaded.
func ensureKeyRing(kr *crypto.KeyRing) error {
	if kr == nil {
		return fmt.Errorf("nil keyring")
	}
	return nil
}
