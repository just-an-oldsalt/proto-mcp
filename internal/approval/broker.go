// Package approval drives the Touch ID prompt + NSAlert confirmation
// for tool calls the policy engine has gated.
//
// The Swift helper (helpers/touchid/protonmcp-touchid) does the
// actual UI work; this package execs it with a JSON payload on stdin
// and interprets the exit code:
//
//	0 → approval granted
//	1 → user declined / cancelled / biometric failed
//	2 → malformed stdin (programmer error on our side; surfaces as ErrAuthFailed)
//
// Caching: per-policy TTL is applied here, keyed by
// sha256(tool || pid || args_json) so changing recipients
// invalidates an approval. ttl: 0 bypasses the cache entirely
// (always reprompt) — appropriate for irreversible operations.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// Source identifies how an approval was obtained. Recorded in the
// audit row's approval_source column.
const (
	SourceTouchID = "touchid"
	SourceCached  = "cached"
)

// Request is everything the broker needs to drive a prompt. Title
// and Body are the user-facing strings; the broker passes them
// through to the Swift helper verbatim. Caller MUST format them
// from the tool's args (e.g., "Send mail_send to alice@example.com,
// subject: Re: gear list").
type Request struct {
	Tool   string
	Caller caller.Caller
	Args   json.RawMessage
	Policy policy.ToolPolicy
	Title  string
	Body   string
}

// Broker holds the helper-binary path and the approval cache.
// Construct via New(). Safe for concurrent use; the cache has its
// own lock.
type Broker struct {
	helperPath  string
	cache       *cache
	logger      *slog.Logger
	helperTimeout time.Duration
}

// New constructs a Broker. helperPath should resolve to an
// executable file; if the file doesn't exist OR isn't executable,
// New returns an error so callers (serve-stdio) fail fast at
// startup rather than mid-call.
//
// Use ResolveHelperPath for the standard discovery sequence.
// Invalidate drops every cached approval. SECURITY D14: serve-stdio
// hooks this into the SIGHUP handler after engine.Reload() so a
// policy that newly demands confirm:true (or newly restricts
// allowed_recipients) takes effect immediately, instead of being
// shadowed by a still-valid pre-reload cache entry. Returns the
// number of entries dropped, mostly for log messages.
func (b *Broker) Invalidate() int {
	if b == nil || b.cache == nil {
		return 0
	}
	return b.cache.purge()
}

func New(helperPath string, logger *slog.Logger) (*Broker, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if helperPath == "" {
		return nil, errors.New("approval: helper path is required")
	}
	return &Broker{
		helperPath:    helperPath,
		cache:         newCache(),
		logger:        logger,
		helperTimeout: 30 * time.Second,
	}, nil
}

// Request runs the approval flow per the Request's policy. Returns
// the approval source ("touchid" / "cached") on success, or one of
// the mcperrors sentinels (ErrUserCanceled, ErrAuthFailed) on
// failure.
//
// ctx is honored — cancellation kills the helper subprocess. A
// 30s timeout is also enforced internally so a forgotten Touch ID
// prompt fails fast rather than letting Claude Desktop's ~60s tool
// timeout strand a NULL-outcome audit row.
func (b *Broker) Request(ctx context.Context, r Request) (string, error) {
	ttl := r.Policy.TTLDuration()
	if ttl > 0 {
		key := cacheKey(r.Tool, r.Caller.PID, r.Args)
		if b.cache.hit(key) {
			return SourceCached, nil
		}
		defer func() {
			// Populated only on success.
		}()
		src, err := b.runHelper(ctx, r)
		if err != nil {
			return "", err
		}
		b.cache.set(key, ttl)
		return src, nil
	}

	// ttl == 0 → no caching, always reprompt.
	return b.runHelper(ctx, r)
}

// runHelper execs the Swift helper with the JSON payload on stdin.
// Returns SourceTouchID on exit 0, ErrUserCanceled on exit 1,
// ErrAuthFailed on exit 2 or any other non-zero exit.
func (b *Broker) runHelper(ctx context.Context, r Request) (string, error) {
	payload, err := json.Marshal(struct {
		Title   string `json:"title"`
		Body    string `json:"body"`
		Caller  string `json:"caller"`
		Confirm bool   `json:"confirm"`
	}{
		Title:   r.Title,
		Body:    r.Body,
		Caller:  r.Caller.String(),
		Confirm: r.Policy.Confirm,
	})
	if err != nil {
		return "", fmt.Errorf("approval: marshal request: %w", err)
	}

	subCtx, cancel := context.WithTimeout(ctx, b.helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, b.helperPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Stdout from the helper is unused (it's a UI tool) but we
	// capture it to avoid the default of inheriting our stdout —
	// which for serve-stdio is the JSON-RPC stream to Claude
	// Desktop. Letting Swift print into that would corrupt MCP
	// framing.
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err == nil {
		return SourceTouchID, nil
	}

	// ExitError carries the helper's exit code. Map per spec.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case 1:
			return "", mcperrors.ErrUserCanceled
		case 2:
			return "", fmt.Errorf("%w: helper rejected stdin (programmer error): %s",
				mcperrors.ErrAuthFailed, stderr.String())
		default:
			return "", fmt.Errorf("%w: helper exit %d: %s",
				mcperrors.ErrAuthFailed, exitErr.ExitCode(), stderr.String())
		}
	}

	// Context timeout / non-exit error.
	if subCtx.Err() == context.DeadlineExceeded {
		b.logger.Warn("approval helper timed out",
			"tool", r.Tool, "timeout", b.helperTimeout)
		return "", mcperrors.ErrUserCanceled
	}
	return "", fmt.Errorf("%w: %v", mcperrors.ErrAuthFailed, err)
}

// ResolveHelperPath finds the touchid binary using the standard
// discovery sequence:
//
//  1. Sibling of the running binary: <dir(argv[0])>/helpers/touchid/protonmcp-touchid
//  2. Phase-7 packaged app: /Applications/protonmcp.app/Contents/MacOS/protonmcp-touchid
//  3. Test override: PROTONMCP_TOUCHID environment variable
//
// Returns "" + error if none exist. Callers should treat that as
// a startup failure (broker can't function without it).
//
// Defined as a function rather than a method so cmd/protonmcp can
// call it independently — e.g., for diagnostic CLI subcommands.
func ResolveHelperPath(argv0 string) (string, error) {
	return resolveHelperPath(argv0)
}
