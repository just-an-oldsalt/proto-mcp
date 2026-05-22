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
// mcpServers.
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

	// Add our entry.
	c.MCPServers["protonmcp"] = mcpServerEntry{
		Command: "/usr/local/bin/protonmcp",
		Args:    []string{"serve-stdio"},
	}

	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)

	// Unknown top-level fields round-trip.
	for _, want := range []string{`"theme":"dark"`, `"selectedModel":"claude-sonnet-4-6"`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost top-level field: %s (have: %s)", want, s)
		}
	}
	// Existing server stays.
	if !strings.Contains(s, "mcp-filesystem") {
		t.Errorf("existing server lost: %s", s)
	}
	// Our server present.
	if !strings.Contains(s, "protonmcp") {
		t.Errorf("protonmcp not added: %s", s)
	}
}

func TestConfigUninstallSkipsWhenAbsent(t *testing.T) {
	in := `{"mcpServers": {"filesystem": {"command": "/x"}}}`
	var c claudeDesktopConfig
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	delete(c.MCPServers, "protonmcp") // no-op
	if _, ok := c.MCPServers["filesystem"]; !ok {
		t.Error("non-target server removed")
	}
}
