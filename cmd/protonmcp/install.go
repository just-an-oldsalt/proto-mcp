package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// runInstall writes (or updates) Claude Desktop's
// claude_desktop_config.json so it knows to spawn this binary as an
// MCP server. Idempotent — re-running just updates the path.
//
// Path: ~/Library/Application Support/Claude/claude_desktop_config.json
//
// The file is owned-by-Claude-Desktop in normal use; we read + merge
// the existing content rather than overwriting blindly so we don't
// stomp on other MCP servers the user has configured.
func runInstall(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "print what would be written without changing the file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("install takes no positional arguments; got %v", fs.Args())
	}

	// Path to this binary, absolute.
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary: %w", err)
	}
	binPath, err = filepath.Abs(binPath)
	if err != nil {
		return fmt.Errorf("absolute path: %w", err)
	}

	cfgPath, err := claudeDesktopConfigPath()
	if err != nil {
		return err
	}

	cfg, err := loadClaudeDesktopConfig(cfgPath)
	if err != nil {
		return err
	}
	if cfg.MCPServers == nil {
		cfg.MCPServers = map[string]mcpServerEntry{}
	}
	cfg.MCPServers["protonmcp"] = mcpServerEntry{
		Command: binPath,
		Args:    []string{"serve-stdio"},
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if *dryRun {
		fmt.Println("# Would write to", cfgPath)
		fmt.Println(string(out))
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Installed protonmcp into Claude Desktop config: %s\n", cfgPath)
	fmt.Println("Restart Claude Desktop to pick up the new server.")
	return nil
}

// runUninstall removes our entry from claude_desktop_config.json.
// Idempotent — silent success if we weren't there.
func runUninstall(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("uninstall takes no arguments; got %v", args)
	}
	cfgPath, err := claudeDesktopConfigPath()
	if err != nil {
		return err
	}
	cfg, err := loadClaudeDesktopConfig(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("Claude Desktop config does not exist — nothing to uninstall.")
			return nil
		}
		return err
	}
	if _, ok := cfg.MCPServers["protonmcp"]; !ok {
		fmt.Println("protonmcp not registered in Claude Desktop config — nothing to do.")
		return nil
	}
	delete(cfg.MCPServers, "protonmcp")
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, append(out, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("Removed protonmcp from %s\n", cfgPath)
	return nil
}

// claudeDesktopConfig matches the documented Claude Desktop schema.
// Other top-level keys are preserved verbatim via the extra field.
type claudeDesktopConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers,omitempty"`

	// Extra is everything else in the file — preserved on read /
	// re-emitted on write so we don't stomp on other settings.
	Extra map[string]json.RawMessage `json:"-"`
}

type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// MarshalJSON / UnmarshalJSON preserve unknown top-level fields so
// Claude Desktop's other settings aren't lost when we rewrite.
func (c *claudeDesktopConfig) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if m, ok := raw["mcpServers"]; ok {
		if err := json.Unmarshal(m, &c.MCPServers); err != nil {
			return fmt.Errorf("decode mcpServers: %w", err)
		}
		delete(raw, "mcpServers")
	}
	c.Extra = raw
	return nil
}

func (c claudeDesktopConfig) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range c.Extra {
		out[k] = v
	}
	if len(c.MCPServers) > 0 {
		m, err := json.Marshal(c.MCPServers)
		if err != nil {
			return nil, err
		}
		out["mcpServers"] = m
	}
	return json.Marshal(out)
}

func claudeDesktopConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
}

func loadClaudeDesktopConfig(path string) (claudeDesktopConfig, error) {
	var cfg claudeDesktopConfig
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(data) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
