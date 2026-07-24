package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for writeConfigAtomic. The file being replaced is
// ~/.claude.json, which holds the user's Claude Code project history
// and preferences alongside our one mcpServers entry — so the write
// path has to be non-destructive under every failure it can hit.

func TestWriteConfigAtomicCreatesNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := []byte(`{"mcpServers":{}}` + "\n")

	if err := writeConfigAtomic(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestWriteConfigAtomicIsOwnerOnly — the file records absolute paths to
// the binaries Claude will execute, so it stays 0600 like the rest of
// our on-disk state.
func TestWriteConfigAtomicIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := writeConfigAtomic(path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

// TestWriteConfigAtomicBacksUpPrevious is the recovery net: if a future
// bug ever writes a config that loses the user's other top-level keys,
// the previous file is still sitting next to it.
func TestWriteConfigAtomicBacksUpPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"projects":{"/tmp/x":{"history":["a"]}}}` + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeConfigAtomic(path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}

	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("no backup written: %v", err)
	}
	if string(bak) != string(original) {
		t.Errorf("backup = %q, want the pre-write contents %q", bak, original)
	}
}

// TestWriteConfigAtomicLeavesNoTempFiles guards against leaking a
// dot-prefixed sibling on every run. Claude Code globs its own config
// directory, and litter there is both confusing and unbounded.
func TestWriteConfigAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	for range 3 {
		if err := writeConfigAtomic(path, []byte("{}\n")); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config.json-") {
			t.Errorf("leaked temp file %s", e.Name())
		}
	}
}

// TestWriteConfigAtomicPreservesTargetOnFailure is the property the
// whole function exists for. A plain os.WriteFile truncates first, so a
// failure mid-write destroys the original. Here the write is aimed at a
// path whose parent directory doesn't exist, forcing CreateTemp to
// fail — the pre-existing file must be exactly as it was.
func TestWriteConfigAtomicPreservesTargetOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := []byte(`{"projects":{"/tmp/x":{"history":["irreplaceable"]}}}` + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// Make the directory read-only so the temp file cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := writeConfigAtomic(path, []byte("{}\n")); err == nil {
		t.Fatal("expected an error when the temp file cannot be created")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("original file is gone after a failed write: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("original was modified by a failed write:\n got %q\nwant %q", got, original)
	}
}

// TestInstallPreservesClaudeCodeStateEndToEnd runs the real installInto
// against a config shaped like Claude Code's, confirming the atomic
// write didn't regress the unknown-key preservation that
// TestConfigPreservesUnknownKeys covers for the marshal layer.
func TestInstallPreservesClaudeCodeStateEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".claude.json")

	original := map[string]any{
		"projects":         map[string]any{"/tmp/proj": map[string]any{"history": []any{"one", "two"}}},
		"numStartups":      float64(42),
		"userID":           "abc123",
		"oauthAccount":     map[string]any{"emailAddress": "user@example.com"},
		"hasCompletedOnbo": true,
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	target := clientTarget{
		id:   "code",
		name: "Claude Code",
		path: func() (string, error) { return cfgPath, nil },
	}
	if err := installInto(target, "/opt/homebrew/bin/protonmcp-shim", nil, false); err != nil {
		t.Fatalf("installInto: %v", err)
	}

	var after map[string]any
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &after); err != nil {
		t.Fatalf("config is not valid JSON after install: %v", err)
	}

	for k, want := range original {
		got, ok := after[k]
		if !ok {
			t.Errorf("install dropped top-level key %q", k)
			continue
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("key %q = %s, want %s", k, gotJSON, wantJSON)
		}
	}

	servers, ok := after["mcpServers"].(map[string]any)
	if !ok {
		t.Fatal("mcpServers missing after install")
	}
	if _, ok := servers["protonmcp"]; !ok {
		t.Error("protonmcp entry not added")
	}
}
