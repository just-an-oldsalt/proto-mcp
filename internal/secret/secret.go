// Package secret holds a small type for sensitive byte material whose
// lifetime needs explicit management.
//
// Use Secret in place of string / []byte for passwords, tokens, and any
// other material that should never appear in logs, error messages, or
// JSON serialization. The type:
//
//   - returns "[REDACTED]" from String / GoString / Format so every fmt
//     verb is safe;
//   - returns an error from MarshalJSON rather than silently leaking a
//     placeholder (so accidental inclusion in a JSON-encoded struct is
//     a loud failure rather than data exfil);
//   - exposes Zero() to overwrite the backing bytes with zeros.
//
// Secret intentionally does NOT use a finalizer; Go has no destructors,
// and relying on GC for credential lifecycle is wrong. Callers must call
// Zero() explicitly when the secret is no longer needed. The convention
// is enforced by review, not the type system.
package secret

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Secret holds sensitive bytes with explicit lifecycle controls.
//
// The zero value is empty and safe to use. Copy semantics share the
// backing []byte: zeroing one copy zeroes the bytes seen by every other
// copy (because they share the slice's backing array), but each copy's
// own slice header is independent. In practice this is fine — once a
// secret has been zeroed, all sharers should already be done with it.
type Secret struct {
	b []byte
}

// New copies the given bytes into a fresh Secret. The caller retains
// ownership of the input slice and is responsible for zeroing it if it
// was holding secret material (Secret cannot zero it for you, because
// it doesn't know the caller's lifetime expectations).
func New(b []byte) Secret {
	if len(b) == 0 {
		return Secret{}
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return Secret{b: cp}
}

// FromString copies a string into a Secret. Prefer New([]byte) for
// terminal-read material — Go strings are immutable and live in
// memory until GC reclaims them, so the original string copy cannot
// be zeroed. FromString is for unavoidable string sources like env
// vars.
func FromString(s string) Secret {
	if s == "" {
		return Secret{}
	}
	return New([]byte(s))
}

// Bytes returns the underlying slice. Callers MUST NOT mutate it or
// hold the reference beyond the Secret's lifetime. Returns nil for
// empty or zeroed secrets.
//
// Bytes is the necessary escape hatch for passing secret material into
// APIs that take []byte (SRP / OpenPGP / HTTP body writers). Keep that
// surface area tiny.
func (s Secret) Bytes() []byte {
	return s.b
}

// Empty reports whether the Secret currently holds no bytes (either
// constructed empty or fully zeroed and cleared).
func (s Secret) Empty() bool {
	return len(s.b) == 0
}

// Zero overwrites the underlying bytes with zeros and detaches the
// slice header. Idempotent. Pointer receiver so callers must hold an
// addressable Secret (which struct fields are, when the struct itself
// is addressable).
func (s *Secret) Zero() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

// String returns a placeholder so fmt.Print(s) / "%v" / "%s" never
// leak. Defined on a value receiver so it applies to both Secret and
// *Secret.
func (Secret) String() string { return redacted }

// GoString returns a placeholder for "%#v".
func (Secret) GoString() string { return "secret.Secret{[REDACTED]}" }

// Format covers every other fmt verb. Without it, "%x" on a value
// receiver would fall back to the default formatter and might expose
// the underlying field.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, redacted)
}

// MarshalJSON refuses to encode a Secret. Returning an error rather
// than a placeholder string means a struct that accidentally contains
// a Secret can't be silently JSON-encoded into a log line.
func (Secret) MarshalJSON() ([]byte, error) {
	return nil, ErrRefusedJSON
}

// ErrRefusedJSON is returned by Secret.MarshalJSON.
var ErrRefusedJSON = errors.New("secret: refusing to marshal Secret to JSON")

const redacted = "[REDACTED]"

// Compile-time guarantees that we still satisfy the formatter interfaces.
var (
	_ json.Marshaler = Secret{}
	_ fmt.Stringer   = Secret{}
	_ fmt.GoStringer = Secret{}
	_ fmt.Formatter  = Secret{}
)
