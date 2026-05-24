package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// runLock finds every running protonmcp serve-stdio / protonmcpd
// process and sends it SIGUSR1. The runtime's signal handler zeros
// the in-memory session and flips Runtime.Locked = true; subsequent
// tool calls return "daemon is locked" until `protonmcp unlock`.
//
// Phase 6/E. Same pgrep-by-executable mechanism as `policy reload`
// (SECURITY D9 / D33) — no PID file, no race with stale lock files.
func runLock(_ context.Context, args []string) error {
	return signalRunning("lock", syscall.SIGUSR1, args)
}

// runUnlock sends SIGUSR2 to running daemons. The runtime's handler
// invokes the Swift Touch ID helper via the approval broker, then
// re-runs AcquireSession from the saved Keychain blob.
//
// Note: the Touch ID prompt fires INSIDE the daemon process, not
// here in the CLI. The CLI exits immediately after dispatching the
// signal; the user's macOS biometric prompt comes from the daemon.
// If the Touch ID is denied or the Keychain is empty, the daemon
// logs the failure and stays locked. Run `protonmcp daemon status`
// or watch the audit log to verify the unlock succeeded.
func runUnlock(_ context.Context, args []string) error {
	return signalRunning("unlock", syscall.SIGUSR2, args)
}

func signalRunning(verb string, sig syscall.Signal, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments; got %v", verb, args)
	}
	pids, err := policy.FindRunningPIDs()
	if err != nil {
		if errors.Is(err, policy.ErrNotRunning) {
			return errors.New("no protonmcp serve-stdio or daemon appears to be running")
		}
		return err
	}
	var sent int
	for _, pid := range pids {
		p, perr := os.FindProcess(pid)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "warning: find pid %d: %v\n", pid, perr)
			continue
		}
		if perr := p.Signal(sig); perr != nil {
			fmt.Fprintf(os.Stderr, "warning: signal pid %d: %v\n", pid, perr)
			continue
		}
		fmt.Printf("sent %s to protonmcp pid %d\n", sig, pid)
		sent++
	}
	if sent == 0 {
		return errors.New("no signals delivered (see warnings above)")
	}
	fmt.Printf("%s signal sent to %d instance(s)\n", verb, sent)
	return nil
}
