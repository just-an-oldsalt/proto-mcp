package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewCopies(t *testing.T) {
	src := []byte("hunter2")
	s := New(src)

	if string(s.Bytes()) != "hunter2" {
		t.Errorf("Bytes() = %q, want %q", s.Bytes(), "hunter2")
	}

	// Mutating the caller's source should not affect the Secret —
	// New must copy, not retain the reference.
	for i := range src {
		src[i] = 0
	}
	if string(s.Bytes()) != "hunter2" {
		t.Errorf("after zeroing src, Bytes() = %q, want %q", s.Bytes(), "hunter2")
	}
}

func TestNewEmpty(t *testing.T) {
	s := New(nil)
	if !s.Empty() {
		t.Error("expected Empty() == true for nil input")
	}
	if s.Bytes() != nil {
		t.Errorf("expected nil Bytes(), got %v", s.Bytes())
	}
}

func TestFromString(t *testing.T) {
	s := FromString("hunter2")
	if string(s.Bytes()) != "hunter2" {
		t.Errorf("Bytes() = %q", s.Bytes())
	}
	if s.Empty() {
		t.Error("Empty() == true for non-empty string input")
	}

	if !FromString("").Empty() {
		t.Error("FromString(\"\") should be Empty")
	}
}

func TestZero(t *testing.T) {
	s := FromString("hunter2")
	s.Zero()
	if !s.Empty() {
		t.Errorf("after Zero, Empty() = false, Bytes() = %v", s.Bytes())
	}
	// Idempotent.
	s.Zero()
}

func TestZeroOverwritesSharedBacking(t *testing.T) {
	// A copy of a Secret shares the underlying []byte backing array.
	// Zeroing through one copy must overwrite the bytes visible to
	// the other copy — the bytes are the secret, the headers aren't.
	a := FromString("secret-data")
	b := a // value copy

	// Sanity: both see the bytes initially.
	if string(b.Bytes()) != "secret-data" {
		t.Fatalf("copy didn't share content: %q", b.Bytes())
	}

	a.Zero()

	if !a.Empty() {
		t.Error("a should be Empty after Zero")
	}
	// b's slice header still has the original length but the bytes
	// it points to have been zeroed. Verify each byte is zero.
	for i, by := range b.Bytes() {
		if by != 0 {
			t.Errorf("b.Bytes()[%d] = %d, want 0", i, by)
		}
	}
}

func TestStringRedacts(t *testing.T) {
	s := FromString("hunter2")
	cases := map[string]string{
		"%v":  fmt.Sprintf("%v", s),
		"%s":  fmt.Sprintf("%s", s),
		"%q":  fmt.Sprintf("%q", s),
		"%x":  fmt.Sprintf("%x", s),
		"%#v": fmt.Sprintf("%#v", s),
	}
	for verb, got := range cases {
		if strings.Contains(got, "hunter2") {
			t.Errorf("%s leaked content: %q", verb, got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Errorf("%s did not include REDACTED marker: %q", verb, got)
		}
	}
}

func TestMarshalJSONErrors(t *testing.T) {
	s := FromString("hunter2")

	_, err := json.Marshal(s)
	if err == nil {
		t.Fatal("expected MarshalJSON to error")
	}
	if !errors.Is(err, ErrRefusedJSON) && !strings.Contains(err.Error(), ErrRefusedJSON.Error()) {
		t.Errorf("error doesn't reference ErrRefusedJSON: %v", err)
	}

	// And inside a struct — the encoder must propagate.
	wrapper := struct {
		Public string
		Token  Secret
	}{Public: "ok", Token: s}
	if _, err := json.Marshal(wrapper); err == nil {
		t.Error("expected struct-with-Secret to fail JSON marshal")
	}
}

func TestEmptyZeroValue(t *testing.T) {
	var s Secret
	if !s.Empty() {
		t.Error("zero value should be Empty")
	}
	if s.Bytes() != nil {
		t.Errorf("zero value Bytes() = %v, want nil", s.Bytes())
	}
	// Zero on an empty Secret must not panic.
	s.Zero()
}
