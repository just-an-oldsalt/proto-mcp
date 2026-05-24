package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

// newStartupGatedAcquire wraps an AcquireSession callback with a
// Touch-ID prompt. Phase 6/E — the application-layer substitute for
// the deferred Keychain ACL.
//
// Why this exists vs. just calling broker.Request: at the point we
// need to gate startup, the broker hasn't been constructed yet
// (broker construction is step 7 in Setup, AcquireSession is step
// 3). We invoke the helper directly with a minimal payload matching
// the helper's stdin JSON contract.
//
// The helper exec is intentionally narrow: empty Args, a fixed
// title/body, and the daemon's own PID as caller. Unlock-driven
// re-acquires hit the SAME wrapper (because rt.acquireSession is
// the gated callback), so SIGUSR2 also Touch-ID-prompts before
// touching the keychain.
func newStartupGatedAcquire(helperPath string, inner func(context.Context) (SessionBundle, error), logger *slog.Logger) func(context.Context) (SessionBundle, error) {
	return func(ctx context.Context) (SessionBundle, error) {
		if err := promptStartupTouchID(ctx, helperPath, logger); err != nil {
			return nil, fmt.Errorf("touch-id startup gate: %w", err)
		}
		return inner(ctx)
	}
}

// startupGateTimeout caps the Touch ID prompt. 60s matches the
// approval broker's per-call timeout doubled — startup is rare and
// the user may need a moment to locate their finger.
const startupGateTimeout = 60 * time.Second

func promptStartupTouchID(ctx context.Context, helperPath string, logger *slog.Logger) error {
	payload, _ := json.Marshal(struct {
		Title   string `json:"title"`
		Body    string `json:"body"`
		Caller  string `json:"caller"`
		Confirm bool   `json:"confirm"`
	}{
		Title:   "Approve protonmcp startup",
		Body:    "Touch ID required to unlock the saved Proton session and start the MCP daemon.",
		Caller:  "protonmcp daemon",
		Confirm: false,
	})

	subCtx, cancel := context.WithTimeout(ctx, startupGateTimeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, helperPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &bytes.Buffer{} // discard helper stdout; never inherit (serve-stdio would corrupt MCP framing)

	err := cmd.Run()
	if err == nil {
		logger.Info("touch-id startup gate approved")
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case 1:
			return errors.New("user canceled startup approval")
		case 2:
			return fmt.Errorf("helper rejected request: %s", stderr.String())
		default:
			return fmt.Errorf("helper exit %d: %s", exitErr.ExitCode(), stderr.String())
		}
	}

	if errors.Is(subCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("startup approval timed out after %s", startupGateTimeout)
	}
	return fmt.Errorf("helper invocation failed: %v", err)
}
