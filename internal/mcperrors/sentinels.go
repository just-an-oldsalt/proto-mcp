// Package mcperrors defines the sentinel error set shared across
// the policy engine, audit log, approval broker, and MCP middleware.
//
// Closes M-4 / M-5 from the SECURITY re-audits. Prior to this
// package, every wrapped error was identified by string content,
// which forced consumers to fmt.Sprintf-match for classification —
// brittle and easy to reopen on every new code path.
//
// Imported by:
//
//	internal/approval — broker returns ErrUserCanceled on exit 1,
//	                    ErrAuthFailed on exit 2.
//	internal/audit    — outcome classification from error type.
//	internal/policy   — Decide returns ErrPolicyDenied via the
//	                    middleware when a tool is denied.
//	internal/mcp      — middleware maps these to ToolResult.isError
//	                    text vs JSON-RPC error responses.
//
// This package imports nothing — keep it that way. Cycles are
// impossible if there are no inbound imports.
package mcperrors

import "errors"

var (
	// ErrUserCanceled is returned when a Touch ID / NSAlert prompt
	// is dismissed by the user (or times out from inactivity).
	// Treated as a tool-execution failure that surfaces to the LLM,
	// not a server-internal error.
	ErrUserCanceled = errors.New("user canceled approval")

	// ErrAuthFailed is returned when biometric authentication fails
	// for non-user reasons: helper binary crashed, LAContext
	// unavailable on this hardware, exit code outside the expected
	// 0/1/2 range. Distinguished from ErrUserCanceled so the audit
	// log can show "authentication failure" vs "user said no".
	ErrAuthFailed = errors.New("biometric authentication failed")

	// ErrNetwork wraps transient network failures from go-proton-api
	// calls inside tool handlers. Phase 5 write tools will use this
	// to drive retry-with-backoff in the daemon's outer loop.
	ErrNetwork = errors.New("network error during tool execution")

	// ErrUnlockFailed is returned when the user's keyring can't be
	// unlocked — wrong mailbox password, key material missing, etc.
	// Phase 4 doesn't trigger this directly but the middleware
	// classification layer needs to recognize it for audit outcomes.
	ErrUnlockFailed = errors.New("mailbox unlock failed")

	// ErrPolicyDenied is returned by the MCP middleware when the
	// policy engine refuses a tool call. Distinct from
	// ErrUserCanceled — the user wasn't prompted; the policy said
	// no before we'd even ask.
	ErrPolicyDenied = errors.New("policy denied tool call")
)
