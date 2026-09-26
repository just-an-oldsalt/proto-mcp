package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	id   string // "desktop" / "code"
	name string // human label
	path func() (string, error)
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
			fmt.Println("Also: make sure the daemon is running — `protonmcp daemon status`.")
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
	if err := cfg.setServer("protonmcp", mcpServerEntry{
		Type:    "stdio",
		Command: cmdPath,
		Args:    cmdArgs,
	}); err != nil {
		return err
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
	if err := writeConfigAtomic(cfgPath, append(out, '\n')); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Installed protonmcp into %s config: %s\n", t.name, cfgPath)
	return nil
}

// writeConfigAtomic replaces path's contents without ever leaving it
// truncated or half-written.
//
// This matters more than it looks. Claude Code's config is ~/.claude.json,
// which also holds the user's project history, session state, and
// preferences — none of it ours, all of it rewritten wholesale every
// time we add or remove our one mcpServers entry. A plain
// os.WriteFile truncates in place, so an interrupt, a crash, or a full
// disk between truncate and write destroys all of it.
//
// Write to a temp file in the same directory (same filesystem, so the
// rename is atomic), fsync it, keep the previous contents as a
// timestamped backup (see backupConfig), then rename over the target. A reader either sees the old file or the
// new one, never a partial.
func writeConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Removes the temp file on any error path; a no-op once the rename
	// below has moved it away.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	// fsync before rename: without it a crash right after the rename
	// can leave the directory entry pointing at a file whose contents
	// never reached disk.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Best-effort backup of what we're about to replace. Never fatal —
	// failing to back up a file is not a reason to refuse to install,
	// and the atomic rename already guarantees we don't corrupt it.
	backupConfig(path)

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// configBackupsKept is how many timestamped backups backupConfig
// leaves next to a config. ~/.claude.json can run to megabytes, so the
// count is bounded; five covers repeated install / uninstall / setup
// runs without the newest write pushing out the last good copy.
const configBackupsKept = 5

// backupConfig copies path's current contents to
// <path>.bak-<UTC timestamp> and prunes all but the newest
// configBackupsKept of those. Each run gets its own file (O_EXCL, never
// an overwrite), so a second run can no longer replace the only good
// copy the way a single fixed .bak did. A plain .bak left by older
// versions is not touched. Best-effort: every error is ignored.
func backupConfig(path string) {
	prev, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// Fixed-width stamp, so lexical order is chronological order.
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	f, err := os.OpenFile(path+".bak-"+stamp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return
	}
	_, werr := f.Write(prev)
	if cerr := f.Close(); werr != nil || cerr != nil {
		_ = os.Remove(f.Name())
		return
	}

	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := filepath.Base(path) + ".bak-"
	var baks []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), prefix) {
			baks = append(baks, e.Name())
		}
	}
	sort.Strings(baks)
	for len(baks) > configBackupsKept {
		_ = os.Remove(filepath.Join(dir, baks[0]))
		baks = baks[1:]
	}
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
	// Same atomic path as install — uninstall rewrites the whole file
	// too, so it carries the identical risk to the user's other state.
	if err := writeConfigAtomic(cfgPath, append(out, '\n')); err != nil {
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
//
// MCPServers keeps each entry as raw JSON for the same reason. Other
// servers carry fields mcpServerEntry doesn't model (url and headers
// on HTTP servers, cwd, disabled, whatever the clients add next), and
// decoding them through the struct silently dropped those fields
// (#126). Only our own entry goes through mcpServerEntry, via server /
// setServer.
type claudeDesktopConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers,omitempty"`

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

// server decodes the named mcpServers entry. ok is false when there is
// no such entry; err is non-nil when there is one but it can't be read
// as a server object.
func (c claudeDesktopConfig) server(name string) (e mcpServerEntry, ok bool, err error) {
	raw, ok := c.MCPServers[name]
	if !ok {
		return e, false, nil
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, true, fmt.Errorf("decode mcpServers.%s: %w", name, err)
	}
	return e, true, nil
}

// setServer replaces the named mcpServers entry and leaves every other
// entry's raw JSON as it was.
func (c *claudeDesktopConfig) setServer(name string, e mcpServerEntry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode mcpServers.%s: %w", name, err)
	}
	if c.MCPServers == nil {
		c.MCPServers = map[string]json.RawMessage{}
	}
	c.MCPServers[name] = raw
	return nil
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
