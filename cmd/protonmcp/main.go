// Command protonmcp is the entry point for the Proton MCP project.
//
// At this stage it only implements `whoami`, which performs an SRP login
// against Proton Mail using env-var credentials, unlocks the user keyring,
// and prints a small account summary. This validates the auth path before
// any of the daemon, IPC, or MCP scaffolding is in place.
//
// Later subcommands (setup, daemon, status, lock, unlock, audit ...) will
// be added as the build plan in TODO.md progresses.
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

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	_ = args

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "whoami":
		if err := runWhoami(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `protonmcp — Proton MCP daemon (pre-alpha)

Usage:
  protonmcp <command>

Commands:
  whoami    Log in via env-var credentials and print account summary.
  help      Show this help.

Environment (for whoami):
  PROTONMCP_EMAIL              Required. Proton login email.
  PROTONMCP_PASSWORD           Required. Login password.
  PROTONMCP_MAILBOX_PASSWORD   Optional. Only for legacy two-password accounts.
  PROTONMCP_TOTP               Optional. Required if the account has TOTP 2FA.`)
}

func runWhoami(ctx context.Context) error {
	creds := protonclient.Credentials{
		Email:           os.Getenv("PROTONMCP_EMAIL"),
		Password:        os.Getenv("PROTONMCP_PASSWORD"),
		MailboxPassword: os.Getenv("PROTONMCP_MAILBOX_PASSWORD"),
		TOTP:            os.Getenv("PROTONMCP_TOTP"),
	}
	if creds.Email == "" || creds.Password == "" {
		return errors.New("PROTONMCP_EMAIL and PROTONMCP_PASSWORD must be set")
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
