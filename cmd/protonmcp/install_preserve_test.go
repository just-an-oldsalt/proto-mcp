package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Regression tests for #126: install / uninstall decoded every
// mcpServers entry through mcpServerEntry and wrote the struct back, so
// any field it doesn't model was dropped. An HTTP server came back as
// {"type":"http","command":""}. Everything here runs against temp
// files; nothing touches the real ~/.claude.json or Claude Desktop
// config.

// preserveFixture has (a) an HTTP server with url + headers, (b) a
// stdio server with cwd, disabled and a field no client has invented
// yet, and (c) unrelated top-level keys.
const preserveFixture = `{
  "numStartups": 7,
  "projects": {"/tmp/proj": {"history": ["one", "two"], "allowedTools": []}},
  "theme": "dark",
  "mcpServers": {
    "remote": {
      "type": "http",
      "url": "https://example.test/mcp",
      "headers": {"Authorization": "Bearer t0ken", "X-Trace": "1"}
    },
    "local": {
      "command": "/bin/x",
      "args": ["--flag"],
      "cwd": "/tmp/work",
      "disabled": true,
      "futureField": {"nested": [1, 2, {"deep": null}]}
    }
  }
}`

func parseJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, data)
	}
	return m
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return parseJSON(t, data)
}

// configBackups lists the timestamped backups next to path, oldest
// first.
func configBackups(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(matches)
	return matches
}

func tempTarget(path string) clientTarget {
	return clientTarget{
		id:   "code",
		name: "Claude Code (test)",
		path: func() (string, error) { return path, nil },
	}
}

func TestInstallUninstallPreservesOtherServerFields(t *testing.T) {
	// Belt and braces: even if some code path fell back to the real
	// config locations, it would land in a temp dir.
	t.Setenv("HOME", t.TempDir())

	cfgPath := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(cfgPath, []byte(preserveFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	want := parseJSON(t, []byte(preserveFixture))
	wantServers := want["mcpServers"].(map[string]any)
	target := tempTarget(cfgPath)

	// Compares everything except our own entry against the fixture.
	checkOthers := func(stage string, got map[string]any) {
		t.Helper()
		for _, k := range []string{"numStartups", "projects", "theme"} {
			if !reflect.DeepEqual(got[k], want[k]) {
				t.Errorf("%s: top-level %q = %#v, want %#v", stage, k, got[k], want[k])
			}
		}
		servers, ok := got["mcpServers"].(map[string]any)
		if !ok {
			t.Fatalf("%s: mcpServers missing: %#v", stage, got)
		}
		for _, name := range []string{"remote", "local"} {
			if !reflect.DeepEqual(servers[name], wantServers[name]) {
				t.Errorf("%s: mcpServers.%s = %#v, want %#v", stage, name, servers[name], wantServers[name])
			}
		}
	}

	if err := installInto(target, "/opt/homebrew/bin/protonmcp-shim", nil, false); err != nil {
		t.Fatalf("installInto: %v", err)
	}
	got := readJSONFile(t, cfgPath)
	checkOthers("after install", got)
	servers := got["mcpServers"].(map[string]any)
	if len(servers) != 3 {
		t.Errorf("after install: %d servers, want 3: %#v", len(servers), servers)
	}
	wantOurs := map[string]any{"type": "stdio", "command": "/opt/homebrew/bin/protonmcp-shim"}
	if !reflect.DeepEqual(servers["protonmcp"], wantOurs) {
		t.Errorf("protonmcp entry = %#v, want %#v", servers["protonmcp"], wantOurs)
	}

	// Re-install with different args replaces only our entry.
	if err := installInto(target, "/usr/local/bin/protonmcp", []string{"serve-stdio"}, false); err != nil {
		t.Fatalf("second installInto: %v", err)
	}
	got = readJSONFile(t, cfgPath)
	checkOthers("after reinstall", got)
	wantOurs = map[string]any{"type": "stdio", "command": "/usr/local/bin/protonmcp", "args": []any{"serve-stdio"}}
	if ours := got["mcpServers"].(map[string]any)["protonmcp"]; !reflect.DeepEqual(ours, wantOurs) {
		t.Errorf("protonmcp entry after reinstall = %#v, want %#v", ours, wantOurs)
	}

	if err := uninstallFrom(target); err != nil {
		t.Fatalf("uninstallFrom: %v", err)
	}
	got = readJSONFile(t, cfgPath)
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("install then uninstall did not round-trip the config:\n got %s\nwant %s", gotJSON, preserveFixture)
	}
}

// TestConfigServerAccessor checks the one typed reader of
// the raw map: our entry decodes, a missing one reports !ok, and a
// malformed one is an error rather than a silent zero value.
func TestConfigServerAccessor(t *testing.T) {
	var c claudeDesktopConfig
	in := `{"mcpServers":{"protonmcp":{"type":"stdio","command":"/x/shim","extra":1},"bad":"nope"}}`
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	e, ok, err := c.server("protonmcp")
	if err != nil || !ok || e.Command != "/x/shim" || e.Type != "stdio" {
		t.Errorf("server(protonmcp) = %+v, %v, %v", e, ok, err)
	}
	if _, ok, err := c.server("missing"); ok || err != nil {
		t.Errorf("server(missing) = %v, %v; want false, nil", ok, err)
	}
	if _, ok, err := c.server("bad"); !ok || err == nil {
		t.Errorf("server(bad) = %v, %v; want true, error", ok, err)
	}
}

// TestWriteConfigAtomicNeverOverwritesBackup is the second half of
// #126: with a single fixed .bak, a second run replaced the only good
// copy. Every write now leaves its own backup.
func TestWriteConfigAtomicNeverOverwritesBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	legacy := []byte("legacy backup from an older version\n")
	if err := os.WriteFile(path+".bak", legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	versions := []string{`{"v":0}`, `{"v":1}`, `{"v":2}`}
	if err := os.WriteFile(path, []byte(versions[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range versions[1:] {
		if err := writeConfigAtomic(path, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}

	baks := configBackups(t, path)
	if len(baks) != 2 {
		t.Fatalf("backups = %v, want 2", baks)
	}
	for i, b := range baks {
		data, err := os.ReadFile(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != versions[i] {
			t.Errorf("backup %d (%s) = %q, want %q", i, filepath.Base(b), data, versions[i])
		}
		info, err := os.Stat(b)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("backup %s mode = %o, want 600", filepath.Base(b), perm)
		}
	}
	if data, err := os.ReadFile(path + ".bak"); err != nil || string(data) != string(legacy) {
		t.Errorf("legacy .bak changed: %q, %v", data, err)
	}
}

// TestWriteConfigAtomicPrunesOldBackups bounds the backups: ~/.claude.json
// can be large, so only the newest configBackupsKept survive.
func TestWriteConfigAtomicPrunesOldBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An unrelated file sharing the prefix-less name must survive.
	other := filepath.Join(dir, "other.json.bak-20000101T000000.000000000Z")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	writes := configBackupsKept + 3
	for i := 1; i <= writes; i++ {
		if err := writeConfigAtomic(path, []byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}

	baks := configBackups(t, path)
	if len(baks) != configBackupsKept {
		t.Fatalf("%d backups, want %d: %v", len(baks), configBackupsKept, baks)
	}
	// The survivors are the newest: contents writes-kept .. writes-1.
	for i, b := range baks {
		data, err := os.ReadFile(b)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprint(writes - configBackupsKept + i); string(data) != want {
			t.Errorf("backup %d = %q, want %q", i, data, want)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("pruning removed an unrelated file: %v", err)
	}
	for _, b := range baks {
		if !strings.HasPrefix(filepath.Base(b), "config.json.bak-") {
			t.Errorf("unexpected backup name %s", b)
		}
	}
}
