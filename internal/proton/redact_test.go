package proton

import (
	"strings"
	"testing"
)

// SECURITY B-2 / B-12 guard: PROTONMCP_DEBUG output must not leak
// credentials in HTTP headers or JSON bodies even though the
// transport itself dumps raw bytes.

func TestRedactDumpHeaders(t *testing.T) {
	dump := []byte(
		"POST /auth/v4 HTTP/1.1\r\n" +
			"Host: mail-api.proton.me\r\n" +
			"Authorization: Bearer sk_live_abc123\r\n" +
			"Cookie: Session-Id=verysecret; Tag=default\r\n" +
			"X-Pm-Uid: kyt2bhaj27dzjofd\r\n" +
			"Content-Type: application/json\r\n\r\n" +
			"{}")
	got := string(redactDump(dump))
	for _, leak := range []string{"sk_live_abc123", "verysecret", "kyt2bhaj27dzjofd"} {
		if strings.Contains(got, leak) {
			t.Errorf("leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "Authorization: [REDACTED]") {
		t.Errorf("Authorization header not redacted: %q", got)
	}
	if !strings.Contains(got, "Content-Type:") {
		t.Errorf("non-sensitive headers should pass through: %q", got)
	}
}

func TestRedactDumpJSONBody(t *testing.T) {
	dump := []byte(`POST /auth/v4 HTTP/1.1
Host: mail-api.proton.me
Content-Type: application/json

{"Username":"alice","ClientProof":"abc","ClientEphemeral":"def","SRPSession":"opaque"}`)
	got := string(redactDump(dump))
	for _, leak := range []string{`"abc"`, `"def"`} {
		if strings.Contains(got, leak) {
			t.Errorf("body leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, `"Username":"alice"`) {
		t.Errorf("non-sensitive fields should pass through: %q", got)
	}
	if !strings.Contains(got, `"ClientProof": "[REDACTED]"`) {
		t.Errorf("ClientProof not redacted: %q", got)
	}
}

// Regression: a PROTONMCP_DEBUG dump of a real session leaked the user's
// armored PGP private key, RecoverySecret and RecoverySecretSignature.
// /core/v4/users returns all three on every session bootstrap, and none
// were covered by the field list.
func TestRedactDumpUserKeyMaterial(t *testing.T) {
	const privKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ProtonMail\n\nxYYEYuvEQRYJKwYBBAHaRw8BAQdAziVVc0Zz1QRk6CtgWaWD4fDEmsG66kbG\n=zMOS\n-----END PGP PRIVATE KEY BLOCK-----\n`
	dump := []byte(`HTTP/1.1 200 OK
Content-Type: application/json

{"Code":1000,"User":{"ID":"abc","Name":"rdort","Keys":[{"ID":"key-1","Primary":1,` +
		`"RecoverySecret":"s5trHPS08phRECOVER","RecoverySecretSignature":"SIGBLOB",` +
		`"PrivateKey":"` + privKey + `","Fingerprint":"90cc6d32","Active":1}],` +
		`"Email":"rdort@proton.me"}}`)

	got := string(redactDump(dump))
	for _, leak := range []string{
		"s5trHPS08phRECOVER",
		"SIGBLOB",
		"xYYEYuvEQRYJKwYBBAHaRw8BAQdAziVVc0Zz1QRk6CtgWaWD4fDEmsG66kbG",
		"BEGIN PGP PRIVATE KEY BLOCK",
	} {
		if strings.Contains(got, leak) {
			t.Errorf("key material survived redaction: %q in %q", leak, got)
		}
	}

	// Field names and non-sensitive values must still be readable, or the
	// dump stops being useful for debugging.
	for _, keep := range []string{`"PrivateKey"`, `"RecoverySecret"`, `"Fingerprint":"90cc6d32"`, `"Name":"rdort"`} {
		if !strings.Contains(got, keep) {
			t.Errorf("over-redacted, lost %q from %q", keep, got)
		}
	}
}

// The armor sweep is a backstop for a private key arriving under a field
// name that isn't on the list — the failure mode that caused the original
// leak.
func TestRedactDumpArmoredKeyUnderUnknownField(t *testing.T) {
	dump := []byte(`HTTP/1.1 200 OK
Content-Type: application/json

{"SomeFutureField":"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecretkeybytes\n-----END PGP PRIVATE KEY BLOCK-----"}`)

	got := string(redactDump(dump))
	if strings.Contains(got, "secretkeybytes") || strings.Contains(got, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Errorf("armored key under an unknown field survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED PGP PRIVATE KEY]") {
		t.Errorf("expected the armor placeholder, got %q", got)
	}
}

// Public key blocks and signatures are not secrets and are useful when
// debugging key selection — the armor sweep must not eat them.
func TestRedactDumpKeepsPublicKeyBlocks(t *testing.T) {
	dump := []byte(`HTTP/1.1 200 OK
Content-Type: application/json

{"PublicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\npubbytes\n-----END PGP PUBLIC KEY BLOCK-----"}`)

	got := string(redactDump(dump))
	if !strings.Contains(got, "pubbytes") {
		t.Errorf("public key block should pass through: %q", got)
	}
}

func TestRedactDumpResponseBody(t *testing.T) {
	// A /auth/v4 response shape.
	dump := []byte(`HTTP/1.1 200 OK
Set-Cookie: Session-Id=abc; HttpOnly
Content-Type: application/json

{"UID":"kyt2bhaj","AccessToken":"uozazbvw","RefreshToken":"k2fkzwv4","TwoFA":{"Enabled":3}}`)
	got := string(redactDump(dump))
	for _, leak := range []string{"abc", "kyt2bhaj", "uozazbvw", "k2fkzwv4"} {
		if strings.Contains(got, leak) {
			t.Errorf("response leak survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, `"Enabled":3`) {
		t.Errorf("nested non-sensitive value lost: %q", got)
	}
}
