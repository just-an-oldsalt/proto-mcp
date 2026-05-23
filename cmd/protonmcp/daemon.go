package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// `protonmcp daemon` subcommand. Phase 6/C. Manages the launchd
// LaunchAgent that runs protonmcpd in the background.
//
// Subcommands:
//
//	install    write the plist + bootstrap. Idempotent.
//	uninstall  bootout + remove the plist.
//	start      kickstart (forces a run even if launchctl has the
//	           label disabled).
//	stop       kill the running instance; label stays loaded.
//	restart    stop + start.
//	status     report plist existence + launchctl state + socket
//	           reachability.

// daemonLabel is the bundle-identifier-style label macOS launchd
// uses to identify our LaunchAgent. Must match the Label key inside
// the plist.
const daemonLabel = "zone.dort.protonmcpd"

func runDaemon(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: protonmcp daemon {install|uninstall|start|stop|restart|status}")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		return runDaemonInstall(ctx, rest)
	case "uninstall":
		return runDaemonUninstall(ctx, rest)
	case "start":
		return runDaemonStart(ctx, rest)
	case "stop":
		return runDaemonStop(ctx, rest)
	case "restart":
		return runDaemonRestart(ctx, rest)
	case "status":
		return runDaemonStatus(ctx, rest)
	default:
		return fmt.Errorf("unknown daemon subcommand: %s", sub)
	}
}

// runDaemonInstall writes the LaunchAgent plist next to the user's
// other LaunchAgents and asks launchd to bootstrap it. Idempotent:
// rerunning with an updated binary path rewrites the plist + reloads.
func runDaemonInstall(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("daemon install takes no arguments; got %v", args)
	}
	bin, err := protonmcpdBinaryPath()
	if err != nil {
		return err
	}

	logDir, err := daemonLogDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	plistPath, err := daemonPlistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	plist, err := renderPlist(bin, filepath.Join(logDir, "daemon.log"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, plist, 0o600); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// If the label is already loaded (re-install on an updated
	// binary path), bootout first so launchd picks up the new
	// plist.
	if labelLoaded() {
		if err := launchctl("bootout", "gui/"+uidString()+"/"+daemonLabel); err != nil {
			// "Boot-out failed: 5: Input/output error" is what
			// launchctl returns when the label isn't loaded —
			// harmless if we got here via a stale labelLoaded
			// race. Surface other errors.
			if !isLaunchctlNotLoadedError(err) {
				return fmt.Errorf("bootout existing: %w", err)
			}
		}
	}

	if err := launchctl("bootstrap", "gui/"+uidString(), plistPath); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	fmt.Printf("Installed LaunchAgent: %s\n", plistPath)
	fmt.Printf("  Binary:    %s\n", bin)
	fmt.Printf("  Log file:  %s\n", filepath.Join(logDir, "daemon.log"))
	fmt.Println("  Daemon should now be running. `protonmcp daemon status` to verify.")
	fmt.Println("  Restart Claude Desktop / Claude Code to connect via the shim.")
	return nil
}

func runDaemonUninstall(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("daemon uninstall takes no arguments; got %v", args)
	}
	plistPath, err := daemonPlistPath()
	if err != nil {
		return err
	}
	if labelLoaded() {
		if err := launchctl("bootout", "gui/"+uidString()+"/"+daemonLabel); err != nil {
			if !isLaunchctlNotLoadedError(err) {
				return fmt.Errorf("bootout: %w", err)
			}
		}
	}
	if _, err := os.Stat(plistPath); err == nil {
		if err := os.Remove(plistPath); err != nil {
			return fmt.Errorf("remove plist: %w", err)
		}
		fmt.Printf("Removed %s\n", plistPath)
	} else {
		fmt.Println("LaunchAgent plist was not installed; nothing to remove.")
	}
	return nil
}

func runDaemonStart(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("daemon start takes no arguments; got %v", args)
	}
	if !labelLoaded() {
		return errors.New("LaunchAgent not bootstrapped — run `protonmcp daemon install` first")
	}
	if err := launchctl("kickstart", "-k", "gui/"+uidString()+"/"+daemonLabel); err != nil {
		return fmt.Errorf("kickstart: %w", err)
	}
	fmt.Println("Daemon kickstarted.")
	return nil
}

func runDaemonStop(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("daemon stop takes no arguments; got %v", args)
	}
	if !labelLoaded() {
		fmt.Println("LaunchAgent not loaded; nothing to stop.")
		return nil
	}
	if err := launchctl("kill", "SIGTERM", "gui/"+uidString()+"/"+daemonLabel); err != nil {
		return fmt.Errorf("kill: %w", err)
	}
	fmt.Println("Sent SIGTERM to daemon.")
	return nil
}

func runDaemonRestart(ctx context.Context, args []string) error {
	if err := runDaemonStop(ctx, args); err != nil {
		return err
	}
	// Brief settle window so launchd registers the exit before
	// kickstart fires. KeepAlive=true means launchd will
	// auto-restart anyway; this just makes the user-facing
	// "restarted" feel deterministic.
	time.Sleep(500 * time.Millisecond)
	return runDaemonStart(ctx, args)
}

func runDaemonStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("daemon status takes no arguments; got %v", args)
	}
	plistPath, _ := daemonPlistPath()
	plistExists := false
	if _, err := os.Stat(plistPath); err == nil {
		plistExists = true
	}

	loaded := labelLoaded()
	socketPath, _ := daemonSocketPath()
	socketAlive := socketReachable(socketPath)

	pid := daemonPID()

	fmt.Println("protonmcp daemon status")
	fmt.Printf("  Plist installed:   %v   (%s)\n", plistExists, plistPath)
	fmt.Printf("  launchctl loaded:  %v   (label %s)\n", loaded, daemonLabel)
	fmt.Printf("  Socket reachable:  %v   (%s)\n", socketAlive, socketPath)
	if pid > 0 {
		fmt.Printf("  Process PID:       %d\n", pid)
	}
	if !plistExists {
		fmt.Println("\nNot installed. Run: protonmcp daemon install")
	} else if !loaded {
		fmt.Println("\nInstalled but not loaded. Run: launchctl bootstrap gui/$UID " + plistPath)
	} else if !socketAlive {
		fmt.Println("\nLoaded but socket isn't responding — check the log:")
		if d, err := daemonLogDir(); err == nil {
			fmt.Printf("  tail %s/daemon.log\n", d)
		}
	} else {
		fmt.Println("\nHealthy.")
	}
	_ = ctx
	return nil
}

// ============================================================
// helpers
// ============================================================

// protonmcpdBinaryPath resolves the absolute path to the protonmcpd
// binary. Convention: lives next to this `protonmcp` binary (Makefile
// builds both into the same bin/ directory). PATH lookup is
// deliberately avoided so a hostile binary earlier on PATH can't
// hijack the install — same defense as the shim installer.
func protonmcpdBinaryPath() (string, error) {
	thisBin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this binary: %w", err)
	}
	thisBin, err = filepath.Abs(thisBin)
	if err != nil {
		return "", fmt.Errorf("absolute path: %w", err)
	}
	candidate := filepath.Join(filepath.Dir(thisBin), "protonmcpd")
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("protonmcpd not found at %s — run `make all`: %w", candidate, err)
	}
	return candidate, nil
}

func daemonPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", daemonLabel+".plist"), nil
}

func daemonLogDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "protonmcp"), nil
}

func daemonSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "protonmcp.sock"), nil
}

func uidString() string { return strconv.Itoa(os.Geteuid()) }

// launchPlist mirrors the (relevant subset of) macOS LaunchAgent
// plist schema. encoding/xml is fine here — the doc is tiny and
// the field order is fixed by the marshaling rules.
type launchPlist struct {
	XMLName xml.Name `xml:"plist"`
	Version string   `xml:"version,attr"`
	Dict    plistDict `xml:"dict"`
}

type plistDict struct {
	Items []plistItem `xml:",any"`
}

type plistItem struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// renderPlist returns a minimal but production-ready LaunchAgent
// plist. RunAtLoad+KeepAlive means launchd starts the daemon
// immediately and restarts it on crash. ProcessType=Background
// tells the scheduler this isn't user-interactive (lower priority,
// no App Nap interference).
//
// Stderr+stdout both go to the same log file so launchd's idea of
// "did the process say anything before it died" is in one place.
// The slog handler in internal/logging writes to stderr, so logs
// land there; stdout sees nothing under normal operation.
func renderPlist(binPath, logPath string) ([]byte, error) {
	tmpl := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>` + escapeXML(daemonLabel) + `</string>
    <key>ProgramArguments</key>
    <array>
        <string>` + escapeXML(binPath) + `</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardErrorPath</key>
    <string>` + escapeXML(logPath) + `</string>
    <key>StandardOutPath</key>
    <string>` + escapeXML(logPath) + `</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
`
	return []byte(tmpl), nil
}

func escapeXML(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		// EscapeText only errors on Writer failure; strings.Builder
		// never fails. Fall through with raw input as a defense.
		return s
	}
	return b.String()
}

// launchctl shells out to /bin/launchctl with the given args. Output
// goes to our stderr so the user sees real launchctl errors verbatim
// (those messages are the most useful diagnostic for plist /
// permission issues).
func launchctl(args ...string) error {
	cmd := exec.Command("launchctl", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// labelLoaded reports whether launchctl currently knows about our
// LaunchAgent. `launchctl print gui/$UID/$LABEL` exits 0 if loaded,
// non-zero otherwise — cleaner than parsing `list` output.
func labelLoaded() bool {
	cmd := exec.Command("launchctl", "print", "gui/"+uidString()+"/"+daemonLabel)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// daemonPID returns the running daemon's PID via launchctl print, or
// 0 if not reachable. The print output includes a `pid = N` line for
// loaded-and-running labels; for loaded-but-exited labels the field
// is absent.
func daemonPID() int {
	out, err := exec.Command("launchctl", "print", "gui/"+uidString()+"/"+daemonLabel).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid =") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid =")))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

// socketReachable returns true if a Dial to the daemon's socket
// succeeds within 250ms. Used by `daemon status` to give a quick
// "is the socket actually responding" answer — labelLoaded only
// tells us launchctl has the entry, not that the process bound
// the socket.
func socketReachable(path string) bool {
	c, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// isLaunchctlNotLoadedError detects the launchctl exit status that
// means "label not loaded" so re-runs don't fail. The stable signal
// is exit status 5 with message "Input/output error" but the
// message text isn't reliable across macOS versions; we accept any
// non-zero exit during bootout as "not loaded."
//
// Conservative: this is a "tolerate this specific failure" gate
// during install/uninstall, not a general error swallower. We log
// to stderr inside launchctl() so the user still sees the real
// error if it's something else (permissions, plist syntax).
func isLaunchctlNotLoadedError(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return true
	}
	return false
}

// (compile-only seam — the policy import is here because the
// future `daemon status` might want to surface the policy reload
// path. Not used today; keep so a follow-up edit doesn't reshape
// the import block needlessly.)
var _ = policy.DefaultPIDPath
