package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigPreservesUnknownKeys verifies that re-encoding a
// claude_desktop_config.json with other top-level keys doesn't lose
// them. Important — Claude Desktop also stores theme prefs, model
// selection, etc. in this file; install/uninstall must touch only
// mcpServers. Same shape applies to Claude Code's ~/.claude.json
// which also stores project history and other user state under
// other top-level keys.
func TestConfigPreservesUnknownKeys(t *testing.T) {
	in := `{
  "theme": "dark",
  "selectedModel": "claude-sonnet-4-6",
  "mcpServers": {
    "filesystem": {"command": "/usr/local/bin/mcp-filesystem", "args": ["/Users/x/Documents"]}
  }
}`
	var c claudeDesktopConfig
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := c.MCPServers["filesystem"]; !ok {
		t.Fatalf("filesystem server lost during parse: %+v", c.MCPServers)
	}

	c.MCPServers["protonmcp"] = mcpServerEntry{
		Type:    "stdio",
		Command: "/usr/local/bin/protonmcp",
		Args:    []string{"serve-stdio"},
	}

	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)

	for _, want := range []string{`"theme":"dark"`, `"selectedModel":"claude-sonnet-4-6"`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost top-level field: %s (have: %s)", want, s)
		}
	}
	if !strings.Contains(s, "mcp-filesystem") {
		t.Errorf("existing server lost: %s", s)
	}
	if !strings.Contains(s, "protonmcp") {
		t.Errorf("protonmcp not added: %s", s)
	}
	// Claude Code requires `"type": "stdio"` on each entry; we
	// always emit it (harmless for Claude Desktop, required for
	// Claude Code).
	if !strings.Contains(s, `"type":"stdio"`) {
		t.Errorf("expected type:stdio on entry; got %s", s)
	}
}

func TestConfigUninstallSkipsWhenAbsent(t *testing.T) {
	in := `{"mcpServers": {"filesystem": {"command": "/x"}}}`
	var c claudeDesktopConfig
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	delete(c.MCPServers, "protonmcp")
	if _, ok := c.MCPServers["filesystem"]; !ok {
		t.Error("non-target server removed")
	}
}

func TestPickTargetsAllByDefault(t *testing.T) {
	got, err := pickTargets("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("all → %d targets, want 2", len(got))
	}

	got, err = pickTargets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("empty → %d targets, want 2", len(got))
	}
}

func TestPickTargetsSpecific(t *testing.T) {
	cases := map[string]string{
		"desktop": "Claude Desktop",
		"code":    "Claude Code",
		"DESKTOP": "Claude Desktop", // case-insensitive
	}
	for in, wantName := range cases {
		got, err := pickTargets(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if len(got) != 1 || got[0].name != wantName {
			t.Errorf("%s → %+v, want single %q", in, got, wantName)
		}
	}
}

func TestPickTargetsRejectsUnknown(t *testing.T) {
	if _, err := pickTargets("vscode"); err == nil {
		t.Error("expected error for unknown client")
	}
}

// TestClaudeCodeConfigPath pins the path so an accidental refactor
// doesn't write to the wrong file.
func TestClaudeCodeConfigPath(t *testing.T) {
	p, err := claudeCodeConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "/.claude.json") {
		t.Errorf("expected ~/.claude.json, got %s", p)
	}
}
