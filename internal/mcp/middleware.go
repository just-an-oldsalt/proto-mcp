package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/redact"
)

// firstDisallowedRecipient returns "" if every recipient in extracted
// matches at least one entry in allowed; otherwise returns the first
// non-matching address. Allowed entries can be either a full address
// ("alice@example.com") or a domain suffix ("@example.com" matches
// any address ending in @example.com).
func firstDisallowedRecipient(extracted, allowed []string) string {
	if len(allowed) == 0 {
		return ""
	}
	full := map[string]struct{}{}
	var domains []string
	for _, a := range allowed {
		if strings.HasPrefix(a, "@") {
			domains = append(domains, strings.ToLower(a))
		} else {
			full[strings.ToLower(a)] = struct{}{}
		}
	}
	for _, addr := range extracted {
		lower := strings.ToLower(addr)
		if _, ok := full[lower]; ok {
			continue
		}
		matched := false
		for _, d := range domains {
			if strings.HasSuffix(lower, d) {
				matched = true
				break
			}
		}
		if !matched {
			return addr
		}
	}
	return ""
}

// Middleware wires together the audit log, policy engine, and
// approval broker around every tool call. It's an implementation
// detail of Server — exposed as a type so the wrapped call can be
// unit-tested in isolation without spinning up an NDJSON loop.
//
// Construction via WithPolicy / WithAudit / WithApproval options on
// mcp.New. All three are optional; when any of them is nil the
// corresponding pipeline stage is skipped:
//
//	policy   nil → every tool implicitly DecisionAllow
//	audit    nil → no audit row written
//	approval nil → DecisionPrompt becomes DecisionDeny (the safe
//	               fallback — if there's no broker we can't ask the
//	               user, so we refuse)
//
// This shape preserves Phase-3 test behavior (mcp.New(logger) with
// no options is unchanged) while letting serve-stdio inject the
// full pipeline.
type Middleware struct {
	policy    *policy.Engine
	audit     *audit.Writer
	broker    *approval.Broker
	resolver  *caller.Resolver
	rate      *rateLimiter
	lockState func() (bool, string) // Phase 6/E — nil = unlockable
}

func (m *Middleware) ensureRate() {
	if m.rate == nil {
		m.rate = newRateLimiter()
	}
}

// runTool is the per-call pipeline that replaces the inline
// t.Handler(...) call at the bottom of handleToolsCall.
//
//	1. Resolve caller identity (cached for the life of the
//	   process).
//	2. Begin an audit row with redacted args + the upcoming
//	   policy decision.
//	3. Ask the policy engine. deny → fill row, return ErrorResult.
//	4. If prompt → ask the broker. ErrUserCanceled / ErrAuthFailed
//	   → fill row, return ErrorResult.
//	5. Run the tool handler. recover() in the defer converts panics
//	   to outcome=error so a buggy handler can't crash the daemon.
//	6. Complete the audit row.
//
// The function NEVER returns a *Error for tool-execution failures —
// those land in ToolResult.isError so the LLM sees the message,
// per the spec.
func (m *Middleware) runTool(ctx context.Context, t Tool, args json.RawMessage, logger Logger) (result *ToolResult, jrErr *Error) {
	var (
		callerInfo     caller.Caller
		auditID        int64
		outcome        = audit.OutcomeError // pessimistic default — flip on success
		errMsg         string
		approvalSource string
		started        = time.Now()
	)

	// SECURITY D20 — per-connection caller takes precedence over
	// the process-wide Resolver. The daemon's accept loop stashes
	// the peer's PID/UID/binary via caller.WithCaller(ctx, peer)
	// after LOCAL_PEERCRED / LOCAL_PEERPID lookups, so each
	// connection's audit row records the real connecting client
	// rather than the daemon's own PID.
	//
	// Resolver remains as the fallback for serve-stdio, where
	// there's exactly one parent (the spawning Claude client)
	// and the process-lifetime cache is the right semantics.
	if c := caller.FromContext(ctx); c.PID != 0 {
		callerInfo = c
	} else if m.resolver != nil {
		callerInfo = m.resolver.Resolve()
	}

	// Phase 6/E — locked daemon refuses every tool call until
	// `protonmcp unlock` (or SIGUSR2). The check happens BEFORE
	// the audit row so a locked-daemon flood doesn't write a
	// row per attempt — only the first attempt per second is
	// logged (logger.Warn-rate-limited at the caller level if
	// needed). For now we log every locked call at Warn — the
	// daemon is presumed to lock infrequently.
	if m.lockState != nil {
		if locked, reason := m.lockState(); locked {
			logger.Warn("tool call refused: daemon locked",
				"tool", t.Name, "reason", reason,
				"caller_pid", callerInfo.PID)
			return ErrorResult("daemon is locked (%s); run `protonmcp unlock` to resume", reason), nil
		}
	}

	if m.audit != nil {
		auditID = m.audit.Begin(ctx, &audit.Entry{
			Caller:         callerInfo,
			Tool:           t.Name,
			ArgsJSON:       redact.JSON(args),
			PolicyDecision: "",
		})
	}

	defer func() {
		if r := recover(); r != nil {
			outcome = audit.OutcomeError
			errMsg = fmt.Sprintf("handler panic: %v", r)
			logger.Warn("tool handler panicked",
				"tool", t.Name, "panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
			result = ErrorResult("%s crashed: %v", t.Name, r)
			jrErr = nil
		}
		if m.audit != nil {
			m.audit.Complete(ctx, auditID, outcome, approvalSource, errMsg, time.Since(started))
		}
	}()

	// Policy stage.
	decision := policy.DecisionAllow
	var pol *policy.ToolPolicy
	if m.policy != nil {
		decision, pol = m.policy.Decide(t.Name, args, callerInfo)
	}
	if m.audit != nil && auditID != 0 {
		// Backfill the decision now that we have it. We do this in
		// the same UPDATE Complete uses; minor inefficiency vs
		// holding decision aside and writing once, but the audit
		// row reflects the decision even if a panic happens before
		// Complete runs.
		_ = updateDecision(ctx, m.audit, auditID, string(decision))
	}

	// Phase 5/D — rate limit check happens BEFORE recipient
	// allowlist and BEFORE approval. A flood of denied calls
	// doesn't burn through approval prompts; a flood of
	// approval-prompted calls doesn't bypass rate limits. Order:
	// rate → recipients → broker → handler.
	if pol != nil && pol.RateLimit != "" {
		m.ensureRate()
		key := t.Name + "|" + strconv.Itoa(callerInfo.PID)
		if ok, reason := m.rate.Allow(key, pol.RateLimit); !ok {
			outcome = audit.OutcomeDenied
			errMsg = reason
			return ErrorResult("%s denied: %s", t.Name, reason), nil
		}
	}

	// Phase 5/D — recipient allowlist. Tool registers a Recipients
	// extractor; middleware compares against pol.AllowedRecipients.
	// Empty allowlist (zero or nil) = no restriction. Domain entries
	// start with "@" (e.g. "@example.com" matches alice@example.com).
	if pol != nil && len(pol.AllowedRecipients) > 0 && t.Recipients != nil {
		extracted := t.Recipients(args)
		if bad := firstDisallowedRecipient(extracted, pol.AllowedRecipients); bad != "" {
			outcome = audit.OutcomeDenied
			errMsg = "recipient " + bad + " not on allowlist"
			return ErrorResult("%s denied: recipient %s not on allowlist", t.Name, bad), nil
		}
	}

	switch decision {
	case policy.DecisionDeny:
		outcome = audit.OutcomeDenied
		errMsg = "policy denied"
		return ErrorResult("tool %s denied by policy", t.Name), nil
	case policy.DecisionPrompt:
		if m.broker == nil {
			// No broker configured but policy says prompt → safe
			// fallback is deny. Better than letting an unsafe op
			// through silently.
			outcome = audit.OutcomeDenied
			errMsg = "approval broker unavailable"
			logger.Warn("tool requires approval but no broker is configured",
				"tool", t.Name)
			return ErrorResult("tool %s requires approval but the approval broker is not available", t.Name), nil
		}
		// Phase 5/D — per-tool prompt body. Send-family tools build
		// a literal "To: ... Subject: ..." string so the user reads
		// exactly what they're approving in the NSAlert.
		title, body := defaultPromptTitle(t.Name), defaultPromptBody(t.Name, args, pol)
		if t.PromptBody != nil {
			title, body = t.PromptBody(args)
		}
		src, perr := m.broker.Request(ctx, approval.Request{
			Tool:   t.Name,
			Caller: callerInfo,
			Args:   args,
			Policy: *pol,
			Title:  title,
			Body:   body,
		})
		if perr != nil {
			outcome = audit.OutcomeDenied
			errMsg = perr.Error()
			if errors.Is(perr, mcperrors.ErrUserCanceled) {
				return ErrorResult("user canceled %s", t.Name), nil
			}
			return ErrorResult("approval failed: %v", perr), nil
		}
		approvalSource = src
	case policy.DecisionAllow:
		approvalSource = "policy"
	}

	// Handler.
	res, herr := t.Handler(Context{
		Std: ctx,
		Caller: CallerInfo{
			PID:    callerInfo.PID,
			UID:    callerInfo.UID,
			Binary: callerInfo.Binary,
		},
	}, args)
	if herr != nil {
		var jr *Error
		if errors.As(herr, &jr) {
			outcome = audit.OutcomeError
			errMsg = herr.Error()
			return nil, jr
		}
		outcome = audit.OutcomeError
		errMsg = herr.Error()
		logger.Warn("tool execution failed", "tool", t.Name, "err", herr.Error())
		return ErrorResult("%s failed: %v", t.Name, herr), nil
	}
	if res == nil {
		outcome = audit.OutcomeError
		errMsg = "tool returned nil result with no error"
		return nil, NewError(CodeInternalError,
			fmt.Sprintf("tool %s returned nil result with no error", t.Name))
	}
	outcome = audit.OutcomeOK
	return res, nil
}

// Logger is the minimal subset of *slog.Logger the middleware uses.
// Defined here so the middleware doesn't depend on the concrete
// logger type (makes tests trivial — pass any slog.Logger).
type Logger interface {
	Warn(msg string, args ...any)
}

// defaultPromptTitle / defaultPromptBody build the strings shown to
// the user when a tool is gated by prompt. Both run through
// SanitizePromptText (below) — SECURITY D21 / D23.
//
// Per-tool PromptBody implementations (in internal/mcptools) MUST
// also route their output through SanitizePromptText. The send-family
// builds the recipient list from raw LLM input, so the choke point
// for the NSAlert content is essential.
func defaultPromptTitle(tool string) string {
	return SanitizePromptText("Approve "+tool+"?", 120)
}

func defaultPromptBody(tool string, args json.RawMessage, _ *policy.ToolPolicy) string {
	if len(args) == 0 {
		return SanitizePromptText(tool+" was requested by an MCP client.", 4000)
	}
	return SanitizePromptText(
		tool+" was requested by an MCP client with args:\n"+string(redact.JSON(args)),
		4000,
	)
}

// SanitizePromptText is the single chokepoint for any text the
// approval broker is about to feed into NSAlert. SECURITY D21 +
// D23: LLM-supplied content (recipients, subject) routes verbatim
// into a macOS dialog, exposing the user to:
//
//  1. Terminal-escape / control-character corruption — same C0/C1
//     range internal/sanitize.Text already strips on the read path.
//  2. RTL-override / bidi spoofing — characters like U+202E flip
//     visual rendering so "alice@example.com" can read as
//     "moc.live@ecila". Strip them.
//  3. Zero-width joiners hiding additional content.
//  4. AppKit OOM from multi-MB strings. Cap.
//  5. Look-alike Unicode glyphs (Cyrillic 'а' vs Latin 'a').
//     NFKC normalization folds many compatibility forms; not a
//     full homograph defense (those need explicit allowlisting)
//     but cheap and helps.
//
// Exported so internal/mcptools' per-tool PromptBody builders can
// call it without re-implementing the same logic.
func SanitizePromptText(in string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 4000
	}
	in = norm.NFKC.String(in)
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20:
			// C0 controls — drop.
		case r >= 0x7f && r <= 0x9f:
			// DEL + C1 controls — drop.
		case r == 0x200e || r == 0x200f, // LRM / RLM
			r == 0x202a, r == 0x202b, r == 0x202c, r == 0x202d, r == 0x202e, // bidi embed / override
			r == 0x2066, r == 0x2067, r == 0x2068, r == 0x2069: // bidi isolate
			// Drop bidi-control codepoints entirely.
		case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff:
			// Zero-width joiners / non-joiners / BOM — drop.
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	r := []rune(out)
	if len(r) > maxRunes {
		out = string(r[:maxRunes]) + "…[truncated]"
	}
	return out
}

// updateDecision backfills policy_decision into the audit row that
// Begin created with an empty decision. Defined here rather than on
// audit.Writer because it's specific to the middleware's pipeline
// (audit doesn't know about policy.Decision strings).
func updateDecision(ctx context.Context, w *audit.Writer, id int64, decision string) error {
	return w.SetDecision(ctx, id, decision)
}
