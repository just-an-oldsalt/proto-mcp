// Command protonmcp is the entry point for the Proton MCP project.
//
// Current subcommands:
//
//	whoami    Log in and print an account summary.
//	backfill  Drain message metadata into the local SQLite mirror.
//
// Later subcommands (setup, daemon, status, lock, unlock, audit ...) will
// be added as the build plan in TODO.html progresses.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/cli"
	"github.com/just-an-oldsalt/proto-mcp/internal/logging"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// secretEnvNames are the environment variables that may carry credential
// material. Once collectCredentials has copied any of them into a Secret,
// the underlying env entry is unset so it doesn't sit in `ps eww` /
// /proc/<pid>/environ for the lifetime of the process.
var secretEnvNames = []string{
	"PROTONMCP_PASSWORD",
	"PROTONMCP_MAILBOX_PASSWORD",
	"PROTONMCP_TOTP",
}

func main() {
	// Owner-only umask so every file the process creates (store.db,
	// future audit logs, body cache) is 0o600 / 0o700 by default.
	// SECURITY M-3. Note: macOS doesn't enforce umask on Keychain
	// items — those are protected by Keychain ACL instead.
	syscall.Umask(0o077)

	// Install the redacting slog logger before anything else so any
	// stderr log calls that follow are filtered. SECURITY Foundational #2.
	logging.Setup(os.Stderr)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	// SIGTERM / SIGINT cancel ctx (clean shutdown). SIGHUP is NOT in
	// this list (Phase 4 / SECURITY B-15): serve-stdio installs its
	// own HUP handler for policy reload, and short-lived CLI
	// subcommands fall back to the kernel default (process
	// termination) — equivalent to today's behavior for those.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "login":
		err = requireNoArgs("login", args)
		if err == nil {
			err = runLogin(ctx, args)
		}
	case "logout":
		err = requireNoArgs("logout", args)
		if err == nil {
			err = runLogout(ctx, args)
		}
	case "inspect":
		err = requireNoArgs("inspect", args)
		if err == nil {
			err = runInspect(ctx, args)
		}
	case "whoami":
		err = requireNoArgs("whoami", args)
		if err == nil {
			err = runWhoami(ctx)
		}
	case "backfill":
		err = runBackfill(ctx, args)
	case "read":
		err = runRead(ctx, args)
	case "search":
		err = runSearch(ctx, args)
	case "sync":
		err = runSync(ctx, args)
	case "serve-stdio":
		err = runServeStdio(ctx, args)
	case "install":
		err = runInstall(ctx, args)
	case "uninstall":
		err = runUninstall(ctx, args)
	case "policy":
		err = runPolicy(ctx, args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `protonmcp — Proton MCP daemon (pre-alpha)

Usage:
  protonmcp <command> [options]

Commands:
  login      Run the full Proton login flow and save the session to the
             macOS Keychain so other subcommands can resume silently.
  logout     Revoke the server-side session and delete the Keychain entry.
  whoami     Print an account summary. Resumes the saved session if one
             exists; otherwise falls back to the full login flow once.
  backfill   Drain message metadata into the local SQLite mirror. Same
             session-resume behavior as whoami.
             Flags: --db <path>, --yes (skip confirm), --limit <n>.
  read       Print a single decrypted message (text + sanitized HTML)
             as JSON. Served from local cache when possible.
             Flags: --db <path>, --refresh (ignore cache).
  search     Run a query against the local mirror. DSL:
             from:alice  to:bob  subject:"gear list"  in:inbox
             before:2026-01-01  after:2025-12-01  has:attachment
             plus bare full-text terms.
             Flags: --db <path>, --limit n, --offset n.
  sync       Drain pending events into the local mirror (incremental
             update from the last stored event cursor). Phase 6's
             daemon will call this on its own cadence; the CLI is for
             one-shot manual updates.
             Flags: --db <path>.
  serve-stdio
             Run as a Model Context Protocol server over stdin/stdout
             (JSON-RPC, NDJSON framed). What Claude Desktop spawns to
             talk to the read tools. Don't run by hand; use install
             to register with Claude Desktop instead.
             Flags: --db <path>.
  install    Register protonmcp in Claude Desktop's config so the
             desktop app launches it as an MCP server. Idempotent.
             Flags: --dry-run (print what would be written).
  uninstall  Remove protonmcp from Claude Desktop's config.
  policy     Inspect or hot-reload the policy engine.
             Subcommands:
               reload                  Send SIGHUP to a running serve-stdio
                                       (it reloads ~/Library/Application
                                       Support/protonmcp/policy.yaml).
               show                    Print the currently-effective policy.
               validate <path>         Parse a candidate policy file without
                                       touching the live daemon.
  help       Show this help.

The session is persisted in the macOS Keychain (service
"zone.dort.protonmcp") so credential prompts only happen on first
run or after logout / token expiry. Passwords are entered on
echo-off /dev/tty.

Environment (override prompts; useful for scripting). Secret-bearing
vars are consumed and unset early so they do not survive in the
process environment:
  PROTONMCP_EMAIL              Proton login email.
  PROTONMCP_PASSWORD           Login password.
  PROTONMCP_MAILBOX_PASSWORD   Only for legacy two-password accounts.
  PROTONMCP_TOTP               Required if the account has TOTP 2FA.`)
}

// collectCredentials assembles a Credentials value from environment
// variables, prompting interactively for anything still empty. The
// prompts respect ctx — Ctrl-C / SIGTERM closes /dev/tty and returns
// ctx.Err() instead of hanging in a kernel read.
//
// Secret-bearing env entries are unset immediately after copying into a
// Secret so they don't linger in the process environment. AskTOTP and
// AskMailboxPassword are wired so that login can request those mid-flow
// only when the server actually needs them.
func collectCredentials(ctx context.Context) (*protonclient.Credentials, error) {
	creds := &protonclient.Credentials{
		Email: os.Getenv("PROTONMCP_EMAIL"),
		AskTOTP: func(ctx context.Context) (secret.Secret, error) {
			v, err := cli.PromptLine(ctx, "TOTP code: ")
			if err != nil {
				return secret.Secret{}, err
			}
			return secret.FromString(v), nil
		},
		AskMailboxPassword: func(ctx context.Context) (secret.Secret, error) {
			return cli.PromptSecret(ctx, "Mailbox password (two-password mode): ")
		},
	}

	if v := os.Getenv("PROTONMCP_PASSWORD"); v != "" {
		creds.Password = secret.FromString(v)
	}
	if v := os.Getenv("PROTONMCP_MAILBOX_PASSWORD"); v != "" {
		creds.MailboxPassword = secret.FromString(v)
	}
	if v := os.Getenv("PROTONMCP_TOTP"); v != "" {
		creds.TOTP = secret.FromString(v)
	}
	for _, n := range secretEnvNames {
		_ = os.Unsetenv(n)
	}

	if creds.Email == "" {
		v, err := cli.PromptLine(ctx, "Proton email: ")
		if err != nil {
			return nil, fmt.Errorf("read email: %w", err)
		}
		creds.Email = v
	}
	if creds.Password.Empty() {
		s, err := cli.PromptSecret(ctx, "Password: ")
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		creds.Password = s
	}
	if creds.Email == "" || creds.Password.Empty() {
		return nil, errors.New("email and password are required")
	}
	return creds, nil
}

func runWhoami(ctx context.Context) error {
	acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	start := time.Now()
	bundle, err := acquireSession(acquireCtx)
	if err != nil {
		return err
	}
	defer bundle.Close()
	defer bundle.Session.Close()

	sess := bundle.Session
	primary, _ := sess.PrimaryAddress()
	fmt.Println("Authenticated:")
	fmt.Printf("  User ID:        %s\n", sess.User.ID)
	fmt.Printf("  Display name:   %s\n", coalesce(sess.User.DisplayName, sess.User.Name, "(none)"))
	fmt.Printf("  Primary email:  %s\n", primary.Email)
	fmt.Printf("  Addresses:      %d\n", len(sess.Addresses))
	fmt.Printf("  Password mode:  %s\n", passwordModeLabel(sess.PasswordMode))
	fmt.Printf("  2FA:            %s\n", twoFALabel(sess.TwoFA))
	fmt.Printf("  Storage:        %.2f MiB / %.2f MiB used\n",
		float64(sess.User.UsedSpace)/1024/1024,
		float64(sess.User.MaxSpace)/1024/1024,
	)
	fmt.Printf("  Login + unlock: %s\n", time.Since(start).Round(time.Millisecond))
	fmt.Printf("  Client header:  %s   (impersonating Proton Bridge; see TODO open question #7)\n",
		protonclient.AppVersion)
	return nil
}

// requireNoArgs fails with a clear error if extra positional arguments
// were passed to a subcommand that takes none. Better than silently
// discarding via `_ = args` — the latter hides typos like
// `protonmcp whoami --json` (intended a flag, got swallowed).
// SECURITY L-3.
func requireNoArgs(cmd string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("subcommand %q takes no arguments; got %v", cmd, args)
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func passwordModeLabel(m gpa.PasswordMode) string {
	switch m {
	case gpa.OnePasswordMode:
		return "one-password"
	case gpa.TwoPasswordMode:
		return "two-password"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

func twoFALabel(s gpa.TwoFAStatus) string {
	switch s {
	case 0:
		return "disabled"
	case gpa.HasTOTP:
		return "TOTP"
	case gpa.HasFIDO2:
		return "FIDO2"
	case gpa.HasFIDO2AndTOTP:
		return "FIDO2 + TOTP"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}
