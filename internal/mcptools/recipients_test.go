package mcptools

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// SECURITY D7 — extractSendRecipients normalizes addresses (strips
// display names, explodes multi-address smuggled strings) before the
// allowlist comparison.

func TestExtractSendRecipients_StripsDisplayName(t *testing.T) {
	args := json.RawMessage(`{"subject":"x","to":["Alice <alice@example.com>"]}`)
	got := extractSendRecipients(args)
	want := []string{"alice@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractSendRecipients_ExplodesMultiAddress(t *testing.T) {
	// RFC 5322 address-list smuggling: one entry contains multiple
	// addresses. Without explosion the middleware would compare the
	// raw string against the allowlist (no match → safe but
	// confusing), while a future code path that uses ParseAddressList
	// directly would see both addresses.
	args := json.RawMessage(`{"subject":"x","to":["alice@example.com, mallory@evil.com"]}`)
	got := extractSendRecipients(args)
	sort.Strings(got)
	want := []string{"alice@example.com", "mallory@evil.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractSendRecipients_MergesFields(t *testing.T) {
	args := json.RawMessage(`{
		"subject":"x",
		"to":["alice@example.com"],
		"cc":["bob@example.com"],
		"bcc":["secret@example.com"]
	}`)
	got := extractSendRecipients(args)
	sort.Strings(got)
	want := []string{"alice@example.com", "bob@example.com", "secret@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractSendRecipients_BadInputFailClosed(t *testing.T) {
	// mail.ParseAddressList errors on garbage — we fall back to the
	// raw string so the allowlist still gets to see SOMETHING (and
	// the SDK's own ParseAddress will reject before send). The
	// principle is fail-closed: never return an empty list that
	// would skip the allowlist check.
	args := json.RawMessage(`{"subject":"x","to":["definitely not an address"]}`)
	got := extractSendRecipients(args)
	if len(got) != 1 {
		t.Errorf("expected fallback single-entry slice, got %v", got)
	}
}

func TestNormalizeRecipientList_HandlesNil(t *testing.T) {
	if got := normalizeRecipientList(""); len(got) != 1 || got[0] != "" {
		t.Errorf("empty input: got %v", got)
	}
}
