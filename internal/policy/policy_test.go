package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func TestDefaultPolicyAllowsReadTools(t *testing.T) {
	e, err := New(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	readTools := []string{
		"account_whoami", "mail_list", "mail_search", "mail_read",
		"mail_read_thread", "mail_list_attachments",
		"labels_list", "folders_list", "mail_sync",
	}
	for _, name := range readTools {
		d, _ := e.Decide(name, nil, caller.Caller{})
		if d != DecisionAllow {
			t.Errorf("%s: decision = %s, want allow", name, d)
		}
	}
}

func TestDefaultDenyForUnknownTool(t *testing.T) {
	e, err := New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := e.Decide("never_heard_of_it", nil, caller.Caller{})
	if d != DecisionDeny {
		t.Errorf("unknown tool: decision = %s, want deny (Foundational #4)", d)
	}
}

func TestPhase5StubsPresentAsPrompt(t *testing.T) {
	e, err := New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	promptTools := []string{"mail_send", "mail_reply", "mail_trash"}
	for _, name := range promptTools {
		d, p := e.Decide(name, nil, caller.Caller{})
		if d != DecisionPrompt {
			t.Errorf("%s: decision = %s, want prompt", name, d)
		}
		// Send-family must carry confirm:true so the NSAlert + Touch
		// ID dual prompt fires. Regression-locked.
		if name == "mail_send" && !p.Confirm {
			t.Errorf("mail_send: confirm = false, want true")
		}
	}
}

func TestOverrideReplacesToolBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`
tools:
  mail_list: { decision: deny }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := e.Decide("mail_list", nil, caller.Caller{})
	if d != DecisionDeny {
		t.Errorf("override didn't replace: decision = %s, want deny", d)
	}
	// Untouched tool still allows.
	d, _ = e.Decide("mail_read", nil, caller.Caller{})
	if d != DecisionAllow {
		t.Errorf("untouched tool: decision = %s, want allow", d)
	}
}

func TestInvalidOverrideFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`not: valid: yaml: at all: }`), 0o600); err != nil {
		t.Fatal(err)
	}
	// New() doesn't fail — it logs Warn and proceeds with defaults.
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New should tolerate invalid override: %v", err)
	}
	d, _ := e.Decide("mail_list", nil, caller.Caller{})
	if d != DecisionAllow {
		t.Errorf("after invalid override, decision = %s, want allow (defaults retained)", d)
	}
}

func TestReloadAtomicOnInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// First write a valid override that flips mail_list to deny.
	if err := os.WriteFile(path, []byte(`tools:
  mail_list: { decision: deny }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide("mail_list", nil, caller.Caller{}); d != DecisionDeny {
		t.Fatalf("initial: decision = %s, want deny", d)
	}
	// Now corrupt the file and Reload — old state must persist.
	if err := os.WriteFile(path, []byte(`{{ broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Error("expected Reload to surface the parse error")
	}
	// Pre-Reload state is preserved.
	if d, _ := e.Decide("mail_list", nil, caller.Caller{}); d != DecisionDeny {
		t.Errorf("after failed Reload: decision = %s, want deny (atomic)", d)
	}
}

func TestUnknownDecisionStringIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`tools:
  mail_list: { decision: aloow }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// New() tolerates parse errors on the override (logs Warn).
	// Reload surfaces them so the operator sees their typo.
	e, _ := New(context.Background(), path, nil)
	err := e.Reload()
	if err == nil {
		t.Fatal("expected Reload to reject 'aloow'")
	}
	if !strings.Contains(err.Error(), "aloow") {
		t.Errorf("error should name the offending value: %v", err)
	}
}

func TestSnapshotYAMLIsValid(t *testing.T) {
	e, err := New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.SnapshotYAML()
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through parseDocument; the YAML the CLI prints
	// must be valid YAML the same code can parse back.
	if _, err := parseDocument(out); err != nil {
		t.Errorf("SnapshotYAML output didn't round-trip: %v\n%s", err, out)
	}
}
