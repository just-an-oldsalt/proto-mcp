package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// runPolicy is the `protonmcp policy {reload|show|validate}`
// subcommand entry point.
func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: protonmcp policy {reload|show|validate <path>}")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "reload":
		return runPolicyReload(ctx, rest)
	case "show":
		return runPolicyShow(ctx, rest)
	case "validate":
		return runPolicyValidate(ctx, rest)
	default:
		return fmt.Errorf("unknown policy subcommand: %s", sub)
	}
}

// runPolicyReload reads the PID file written by serve-stdio at
// startup and sends SIGHUP to the running daemon. The daemon's HUP
// handler calls policy.Engine.Reload().
func runPolicyReload(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy reload takes no arguments; got %v", args)
	}
	pidPath, err := policy.DefaultPIDPath()
	if err != nil {
		return err
	}
	pid, err := policy.ReadPIDFile(pidPath)
	if err != nil {
		if errors.Is(err, policy.ErrNotRunning) {
			return errors.New("no protonmcp serve-stdio appears to be running")
		}
		return err
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find pid %d: %w", pid, err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	fmt.Printf("sent SIGHUP to protonmcp serve-stdio (pid %d) — check the daemon's logs for reload outcome\n", pid)
	return nil
}

// runPolicyShow prints the currently-effective policy. Loads it the
// same way serve-stdio does (default + user override) so users see
// exactly what's in force.
func runPolicyShow(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy show takes no arguments; got %v", args)
	}
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		return err
	}
	e, err := policy.New(ctx, overridePath, nil)
	if err != nil {
		return err
	}
	out, err := e.SnapshotYAML()
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(out)
	return nil
}

// runPolicyValidate parses a candidate YAML file the same way the
// engine would. Useful for "does my override file have a typo"
// before running `policy reload` against a daemon.
func runPolicyValidate(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: protonmcp policy validate <path>")
	}
	// Construct a candidate engine pointing at the user-supplied
	// path; Reload reads + parses without committing on error.
	e, err := policy.New(ctx, args[0], nil)
	if err != nil {
		return err
	}
	if err := e.Reload(); err != nil {
		return fmt.Errorf("policy %s is invalid: %w", args[0], err)
	}
	fmt.Printf("policy %s parses cleanly\n", args[0])
	return nil
}
