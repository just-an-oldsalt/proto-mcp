package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Claude clients we know how to install into. Each writes to its
// own config file with the same JSON shape: a top-level mcpServers
// map. Claude Desktop's docs predate the explicit "type": "stdio"
// field; Claude Code's docs require it. Setting the field is
// harmless either way, so we always include it.
//
// Both files are owned by their respective apps in normal use; we
// preserve every top-level key we don't recognise (Claude Code in
// particular stores project history and other settings in the same
// file).

type clientTarget struct {
	id       string // "desktop" / "code"
	name     string // human label
	path     func() (string, error)
}

func clientTargets() []clientTarget {
	return []clientTarget{
		{
			id:   "desktop",
			name: "Claude Desktop",
			path: claudeDesktopConfigPath,
		},
		{
			id:   "code",
			name: "Claude Code",
			path: claudeCodeConfigPath,
		},
	}
}

// runInstall writes (or updates) the MCP server entry in each
// selected client's config so the app launches this binary as an
// MCP server. Idempotent — re-running just updates the path.
//
// --client (desktop|code|all) controls which clients are touched.
// Default "all" — installing to both Claude Desktop and Claude
// Code, which is the multi-client setup the PID-relax work makes
// possible.
func runInstall(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "print what would be written without changing the file")
	client := fs.String("client", "all", "which Claude client to install for: desktop, code, all")
	// Phase 6/B: default is now the shim binary (which connects to
	// the persistent protonmcpd daemon). --transport serve-stdio
	// keeps the v1.0.0-alpha behavior of spawning a fresh
	// serve-stdio per Claude session for users who'd rather not
	// run the daemon.
	transport := fs.String("transport", "shim",
		"MCP server invocation: shim (Claude → protonmcp-shim → daemon) or serve-stdio (Claude → fresh serve-stdio per session)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("install takes no positional arguments; got %v", fs.Args())
	}

	thisBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary: %w", err)
	}
	thisBin, err = filepath.Abs(thisBin)
	if err != nil {
		return fmt.Errorf("absolute path: %w", err)
	}

	cmdPath, cmdArgs, err := transportLaunchSpec(*transport, thisBin)
	if err != nil {
		return err
	}

	targets, err := pickTargets(*client)
	if err != nil {
		return err
	}

	for _, t := range targets {
		if err := installInto(t, cmdPath, cmdArgs, *dryRun); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}
	if !*dryRun {
		fmt.Println("Restart any running Claude clients to pick up the new server.")
		if *transport == "shim" {
			fmt.Println("Also: make sure protonmcpd is running — `protonmcp daemon start` (Phase 6/C).")
		}
	}
	return nil
}

// transportLaunchSpec returns (command, args) for the chosen
// transport. "shim" looks up cmd/protonmcp-shim next to this
// binary (Makefile builds them into the same bin/ directory).
// "serve-stdio" uses this binary with the existing subcommand.
//
// SECURITY-relevant: the shim path comes from `filepath.Dir(thisBin)`,
// not from PATH. A planted protonmcp-shim earlier on PATH cannot
// hijack the install. The downside is we require the user to
// build/install both binaries to the same location.
func transportLaunchSpec(transport, thisBin string) (string, []string, error) {
	switch transport {
	case "shim":
		shim := filepath.Join(filepath.Dir(thisBin), "protonmcp-shim")
		if _, err := os.Stat(shim); err != nil {
			return "", nil, fmt.Errorf(
				"protonmcp-shim not found next to %s — run `make all` (or pass --transport serve-stdio): %w",
				thisBin, err)
		}
		return shim, nil, nil
	case "serve-stdio":
		return thisBin, []string{"serve-stdio"}, nil
	default:
		return "", nil, fmt.Errorf("unknown transport %q; expected: shim, serve-stdio", transport)
	}
}

func installInto(t clientTarget, cmdPath string, cmdArgs []string, dryRun bool) error {
	cfgPath, err := t.path()
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
		Type:    "stdio",
		Command: cmdPath,
		Args:    cmdArgs,
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if dryRun {
		fmt.Printf("# Would write to %s (%s)\n", cfgPath, t.name)
		fmt.Println(string(out))
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Installed protonmcp into %s config: %s\n", t.name, cfgPath)
	return nil
}

// runUninstall removes our entry from the selected client configs.
// Idempotent — silent success per-client when we weren't there.
func runUninstall(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	client := fs.String("client", "all", "which Claude client to uninstall from: desktop, code, all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("uninstall takes no positional arguments; got %v", fs.Args())
	}
	targets, err := pickTargets(*client)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err := uninstallFrom(t); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}
	return nil
}

func uninstallFrom(t clientTarget) error {
	cfgPath, err := t.path()
	if err != nil {
		return err
	}
	cfg, err := loadClaudeDesktopConfig(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("%s: config does not exist — nothing to uninstall.\n", t.name)
			return nil
		}
		return err
	}
	if _, ok := cfg.MCPServers["protonmcp"]; !ok {
		fmt.Printf("%s: protonmcp not registered — nothing to do.\n", t.name)
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
	fmt.Printf("Removed protonmcp from %s: %s\n", t.name, cfgPath)
	return nil
}

func pickTargets(client string) ([]clientTarget, error) {
	all := clientTargets()
	switch strings.ToLower(client) {
	case "all", "":
		return all, nil
	default:
		for _, t := range all {
			if t.id == strings.ToLower(client) {
				return []clientTarget{t}, nil
			}
		}
		return nil, fmt.Errorf("unknown client %q; expected one of: desktop, code, all", client)
	}
}

// claudeDesktopConfig matches the documented Claude Desktop / Claude
// Code schema. Both use a top-level mcpServers map; other top-level
// keys are preserved verbatim via the extra field — Claude Code
// stores project history in the same file, and dropping it would
// stomp on the user's other state.
type claudeDesktopConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers,omitempty"`

	// Extra is everything else in the file — preserved on read /
	// re-emitted on write.
	Extra map[string]json.RawMessage `json:"-"`
}

type mcpServerEntry struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// MarshalJSON / UnmarshalJSON preserve unknown top-level fields so
// neither Claude Desktop's nor Claude Code's other settings get lost
// when we rewrite.
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

// claudeCodeConfigPath is ~/.claude.json — the user-scope MCP
// registration file for the Claude Code CLI. The same JSON shape as
// Claude Desktop's config (top-level mcpServers map); Claude Code
// requires the per-entry "type": "stdio" field, which we set
// unconditionally so the same install logic works for either client.
//
// Note: this file also stores project-local Claude Code state under
// other top-level keys (sessions, project history, user prefs). We
// preserve those via the Extra map on claudeDesktopConfig.
func claudeCodeConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude.json"), nil
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
