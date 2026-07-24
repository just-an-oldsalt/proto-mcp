package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/buildinfo"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/serve"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// `protonmcp doctor` — one command that answers "why isn't this
// working?".
//
// The setup flow is four separate commands (login → backfill → daemon
// install → install), each of which can half-succeed, plus an upgrade
// path that can leave the daemon down. Before doctor, diagnosing that
// meant knowing which of six files to look at. Every check here is
// read-only and non-prompting — in particular the login check uses
// keystore.Exists() rather than resuming the session, so running doctor
// never fires a Touch ID prompt.

// checkState is the outcome of a single check. Ordering matters:
// worse states sort later so the summary can report the worst.
type checkState int

const (
	stateOK checkState = iota
	stateInfo
	stateWarn
	stateFail
)

func (s checkState) marker() string {
	switch s {
	case stateOK:
		return "  ok  "
	case stateInfo:
		return " info "
	case stateWarn:
		return " warn "
	default:
		return " FAIL "
	}
}

type check struct {
	name   string
	state  checkState
	detail string
	// fix is the literal command (or one-line instruction) that
	// resolves this check. Printed in the remediation block so the
	// user never has to go looking in the README.
	fix string
}

type report struct {
	checks []check
}

func (r *report) add(name string, state checkState, detail, fix string) {
	r.checks = append(r.checks, check{name: name, state: state, detail: detail, fix: fix})
}

func (r *report) worst() checkState {
	w := stateOK
	for _, c := range r.checks {
		if c.state > w {
			w = c.state
		}
	}
	return w
}

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to the local mirror (default: the standard location)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("doctor takes no positional arguments; got %v", fs.Args())
	}

	var r report
	checkBinaries(&r)
	checkLogin(&r)
	checkStore(ctx, &r, *dbPath)
	checkDaemon(&r)
	checkIntegrity(&r)
	checkClients(&r)

	fmt.Printf("protonmcp doctor — %s\n\n", buildinfo.String())
	for _, c := range r.checks {
		fmt.Printf("[%s] %-22s %s\n", c.state.marker(), c.name, c.detail)
	}

	// Remediation block: only the checks that need action, in the
	// order they were run, which is also dependency order (you can't
	// usefully backfill before logging in).
	var todo []check
	for _, c := range r.checks {
		if c.state >= stateWarn && c.fix != "" {
			todo = append(todo, c)
		}
	}
	if len(todo) > 0 {
		fmt.Println("\nTo fix:")
		for _, c := range todo {
			fmt.Printf("  %s\n      %s\n", c.name, c.fix)
		}
	}

	switch r.worst() {
	case stateFail:
		fmt.Println("\nSomething is broken — work through the list above, top to bottom.")
		return errors.New("doctor found problems")
	case stateWarn:
		fmt.Println("\nUsable, but not fully set up.")
	default:
		fmt.Println("\nAll good.")
	}
	return nil
}

// checkBinaries verifies the four sibling binaries exist next to this
// one and report a matching version. A version skew here is the
// signature of a partial upgrade — e.g. `brew upgrade` replaced the
// binaries but the daemon still running in memory is the old build.
func checkBinaries(r *report) {
	self, err := os.Executable()
	if err != nil {
		r.add("binaries", stateFail, "cannot locate this binary: "+err.Error(), "")
		return
	}
	dir := filepath.Dir(self)

	mine := buildinfo.Version()
	for _, name := range []string{"protonmcpd", "protonmcp-shim"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			r.add(name, stateFail, "missing at "+p,
				"reinstall: brew reinstall --cask proto-mcp   (or `make all` for a source build)")
			continue
		}
		v, err := binaryVersion(p)
		if err != nil {
			r.add(name, stateWarn, "present but --version failed: "+err.Error(), "")
			continue
		}
		if v != mine {
			r.add(name, stateWarn,
				fmt.Sprintf("version %s, but protonmcp is %s", v, mine),
				"partial upgrade — reinstall, then re-run: protonmcp daemon install")
			continue
		}
		r.add(name, stateOK, "version "+v, "")
	}

	checkHelpers(r, filepath.Join(dir, "protonmcpd"))
}

// checkHelpers asks the real resolvers where the Swift helpers would be
// found for a daemon at daemonPath, rather than guessing a directory.
// The helpers live beside the binaries in a cask install but under
// helpers/ in a source build, and the Touch ID helper additionally has
// to pass an owner-writable-only trust check — a helper that exists but
// is rejected is otherwise invisible until a send prompt fails.
func checkHelpers(r *report, daemonPath string) {
	if p, err := approval.ResolveHelperPath(daemonPath); err != nil {
		r.add("protonmcp-touchid", stateFail, "no trusted helper found",
			"reinstall: brew reinstall --cask proto-mcp   (source build: make touchid)\n"+
				"      note: the helper must not be group- or world-writable")
	} else {
		r.add("protonmcp-touchid", stateOK, p, "")
	}

	if p, ok := serve.ResolveLockwatchPathFrom(daemonPath); ok {
		r.add("protonmcp-lockwatch", stateOK, p, "")
	} else {
		// Not fatal: the idle timer still locks the session, only the
		// screen-lock/sleep trigger is lost.
		r.add("protonmcp-lockwatch", stateWarn,
			"not found — lock-on-screen-lock/sleep is inactive (idle timer still applies)",
			"reinstall: brew reinstall --cask proto-mcp   (source build: make lockwatch)")
	}
}

// binaryVersion shells out to `<bin> --version` and returns just the
// version token. Both protonmcpd and protonmcp-shim print
// "<name> <version> (<details>)".
func binaryVersion(path string) (string, error) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected --version output %q", strings.TrimSpace(string(out)))
	}
	return fields[1], nil
}

// checkLogin reports whether a saved session exists. Uses
// keystore.Exists rather than a resume so doctor never fires a Touch ID
// prompt — a diagnostic command that demands a fingerprint before it
// will tell you what's wrong is a bad diagnostic command.
func checkLogin(r *report) {
	ok, err := keystore.Exists()
	switch {
	case err != nil:
		r.add("login", stateFail, "keychain lookup failed: "+err.Error(),
			"protonmcp login")
	case !ok:
		r.add("login", stateFail, "no saved session in the keychain",
			"protonmcp login")
	default:
		r.add("login", stateOK, "session present in keychain", "")
	}
}

// checkStore opens the local mirror read-only-ish and reports whether
// backfill has run. An empty mirror is the single most common "Claude
// says I have no mail" cause.
func checkStore(ctx context.Context, r *report, dbPath string) {
	path := dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			r.add("local mirror", stateFail, "cannot resolve path: "+err.Error(), "")
			return
		}
		path = p
	}

	if _, err := os.Stat(path); err != nil {
		r.add("local mirror", stateFail, "not created yet ("+path+")",
			"protonmcp backfill")
		return
	}

	st, err := store.Open(path)
	if err != nil {
		r.add("local mirror", stateFail, "cannot open "+path+": "+err.Error(),
			"if the file is corrupt, remove it and re-run: protonmcp backfill")
		return
	}
	defer st.Close()

	var messages int64
	if err := st.DB.QueryRowContext(ctx, "SELECT count(*) FROM messages").Scan(&messages); err != nil {
		r.add("local mirror", stateWarn, "cannot count messages: "+err.Error(), "")
		return
	}

	// ErrNotFound just means backfill hasn't recorded a cursor yet —
	// that's a reportable state, not a failure to read the store.
	cursor, err := st.GetSyncState(ctx, "event_cursor")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		r.add("local mirror", stateWarn, "cannot read sync cursor: "+err.Error(), "")
		return
	}

	switch {
	case messages == 0:
		r.add("local mirror", stateFail, "exists but holds no messages",
			"protonmcp backfill")
	case cursor == "":
		r.add("local mirror", stateWarn,
			fmt.Sprintf("%d messages, but no sync cursor — incremental sync can't resume", messages),
			"protonmcp backfill")
	default:
		r.add("local mirror", stateOK,
			fmt.Sprintf("%d messages, sync cursor set (%s)", messages, path), "")
	}
}

// checkDaemon reuses the same primitives as `daemon status` but folds
// them into a single line plus a targeted fix.
func checkDaemon(r *report) {
	plistPath, _ := daemonPlistPath()
	if _, err := os.Stat(plistPath); err != nil {
		r.add("daemon", stateFail, "LaunchAgent not installed",
			"protonmcp daemon install")
		return
	}
	if !labelLoaded() {
		r.add("daemon", stateFail, "LaunchAgent installed but not loaded by launchd",
			"protonmcp daemon install")
		return
	}
	sockPath, _ := daemonSocketPath()
	if !socketReachable(sockPath) {
		fix := "protonmcp daemon restart"
		if d, err := daemonLogDir(); err == nil {
			fix += "   (if it stays down: tail " + filepath.Join(d, "daemon.log") + ")"
		}
		r.add("daemon", stateFail, "loaded, but the socket isn't accepting connections", fix)
		return
	}
	detail := "running, socket healthy"
	if pid := daemonPID(); pid > 0 {
		detail = fmt.Sprintf("running (pid %d), socket healthy", pid)
	}
	r.add("daemon", stateOK, detail, "")
}

// checkIntegrity compares the recorded SHA-256 against the protonmcpd
// binary sitting on disk right now. A mismatch is what an upgrade
// leaves behind, and it's why the daemon refuses to start — so naming
// it explicitly turns a mystifying outage into a one-line fix.
func checkIntegrity(r *report) {
	dir, err := appSupportDir()
	if err != nil {
		r.add("binary integrity", stateWarn, "cannot resolve app support dir: "+err.Error(), "")
		return
	}
	recPath := filepath.Join(dir, "expected_sha256")
	data, err := os.ReadFile(recPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.add("binary integrity", stateWarn, "no hash recorded yet",
				"protonmcp daemon install")
			return
		}
		r.add("binary integrity", stateWarn, "cannot read "+recPath+": "+err.Error(), "")
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 || len(fields[0]) != 64 {
		r.add("binary integrity", stateWarn, "recorded hash is malformed",
			"protonmcp daemon install")
		return
	}
	recorded, recordedPath := fields[0], fields[1]

	actual, err := sha256File(recordedPath)
	if err != nil {
		r.add("binary integrity", stateFail,
			"recorded binary is gone: "+recordedPath,
			"protonmcp daemon install")
		return
	}
	if actual != recorded {
		r.add("binary integrity", stateWarn,
			"protonmcpd on disk doesn't match the recorded hash (upgraded since install?)",
			"protonmcp daemon install   — re-records the hash and restarts the daemon")
		return
	}
	r.add("binary integrity", stateOK, "recorded hash matches "+recordedPath, "")
}

// checkClients verifies each Claude client config actually references
// protonmcp and that the command it points at still exists. A stale
// path here is what a source-build-then-brew-install leaves behind.
func checkClients(r *report) {
	for _, t := range clientTargets() {
		cfgPath, err := t.path()
		if err != nil {
			r.add(t.name, stateWarn, "cannot resolve config path: "+err.Error(), "")
			continue
		}
		cfg, err := loadClaudeDesktopConfig(cfgPath)
		if err != nil {
			r.add(t.name, stateWarn, "cannot read "+cfgPath+": "+err.Error(), "")
			continue
		}
		entry, ok := cfg.MCPServers["protonmcp"]
		if !ok {
			r.add(t.name, stateWarn, "protonmcp not registered",
				"protonmcp install --client "+t.id)
			continue
		}
		if _, err := os.Stat(entry.Command); err != nil {
			r.add(t.name, stateFail,
				"registered, but points at a missing binary: "+entry.Command,
				"protonmcp install --client "+t.id)
			continue
		}
		r.add(t.name, stateOK, "registered → "+entry.Command, "")
	}
}
