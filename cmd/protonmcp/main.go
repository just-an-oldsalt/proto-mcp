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
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "whoami":
		err = runWhoami(ctx)
	case "backfill":
		err = runBackfill(ctx, args)
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
  whoami     Log in and print account summary.
  backfill   Drain message metadata into the local SQLite mirror.
             Flags: --db <path>, --yes (skip confirm), --limit <n>.
  help       Show this help.

All commands prompt interactively for missing credentials; passwords use
echo-off /dev/tty.

Environment (override prompts; useful for scripting):
  PROTONMCP_EMAIL              Proton login email.
  PROTONMCP_PASSWORD           Login password.
  PROTONMCP_MAILBOX_PASSWORD   Only for legacy two-password accounts.
  PROTONMCP_TOTP               Required if the account has TOTP 2FA.`)
}

// collectCredentials assembles a Credentials value from environment
// variables, prompting interactively for anything still empty. The
// AskTOTP / AskMailboxPassword callbacks are wired to interactive
// prompts so login can request those mid-flow only when the server
// actually needs them.
func collectCredentials() (protonclient.Credentials, error) {
	creds := protonclient.Credentials{
		Email:           os.Getenv("PROTONMCP_EMAIL"),
		Password:        os.Getenv("PROTONMCP_PASSWORD"),
		MailboxPassword: os.Getenv("PROTONMCP_MAILBOX_PASSWORD"),
		TOTP:            os.Getenv("PROTONMCP_TOTP"),
		AskTOTP: func() (string, error) {
			return cli.PromptLine("TOTP code: ")
		},
		AskMailboxPassword: func() (string, error) {
			return cli.PromptSecret("Mailbox password (two-password mode): ")
		},
	}
	if creds.Email == "" {
		v, err := cli.PromptLine("Proton email: ")
		if err != nil {
			return creds, fmt.Errorf("read email: %w", err)
		}
		creds.Email = v
	}
	if creds.Password == "" {
		v, err := cli.PromptSecret("Password: ")
		if err != nil {
			return creds, fmt.Errorf("read password: %w", err)
		}
		creds.Password = v
	}
	if creds.Email == "" || creds.Password == "" {
		return creds, errors.New("email and password are required")
	}
	return creds, nil
}

func runWhoami(ctx context.Context) error {
	creds, err := collectCredentials()
	if err != nil {
		return err
	}

	mgr := protonclient.NewManager("")
	defer mgr.Close()

	loginCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	start := time.Now()
	sess, err := protonclient.Login(loginCtx, mgr, creds)
	if err != nil {
		return err
	}
	defer sess.Close(context.Background())

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
	return nil
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
