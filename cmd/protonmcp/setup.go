package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/cli"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// `protonmcp setup` — the whole first-run flow as one command.
//
// The four steps have always existed; what didn't was anything tying
// them together. A user pasting four commands from the README gets no
// indication of how far along they are, no explanation of why step two
// takes minutes, and — if step three fails — no idea whether it is safe
// to re-run step two. Each step is also independently re-runnable, so
// the common recovery ("just do it again") silently redid a twenty-
// minute mailbox drain.
//
// setup runs them in dependency order, skips what is already done,
// explains each step before it happens, and finishes with the same
// checks `protonmcp doctor` runs. It is safe to re-run at any point.

// setupStep is one unit of the flow. done() reports whether the step
// can be skipped; run() performs it.
type setupStep struct {
	title string
	// why explains, in one sentence a non-technical user can act on,
	// what this step does and what to expect while it runs.
	why  string
	done func() (bool, string)
	run  func(ctx context.Context) error
}

func runSetup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to the local mirror (default: the standard location)")
	force := fs.Bool("force", false, "re-run every step even if it looks complete")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("setup takes no positional arguments; got %v", fs.Args())
	}

	backfillArgs := []string{}
	if *dbPath != "" {
		backfillArgs = append(backfillArgs, "--db", *dbPath)
	}

	steps := []setupStep{
		{
			title: "Sign in to Proton",
			why: "Asks for your Proton email, password, and 2FA code, then unlocks\n" +
				"your mail keys. The session is stored in the macOS Keychain, so\n" +
				"this only happens once.",
			done: func() (bool, string) {
				ok, err := keystore.Exists()
				if err != nil || !ok {
					return false, ""
				}
				return true, "already signed in"
			},
			run: func(ctx context.Context) error { return runLogin(ctx, nil) },
		},
		{
			title: "Copy your mailbox index",
			why: "Downloads the subject, sender, and date of every message into a\n" +
				"local database so search and listing are instant and work offline.\n" +
				"Message bodies are fetched later, as needed. On a large mailbox\n" +
				"this can take several minutes — it only runs once.",
			done: func() (bool, string) { return backfillDone(ctx, *dbPath) },
			run:  func(ctx context.Context) error { return runBackfill(ctx, backfillArgs) },
		},
		{
			title: "Start the background service",
			why: "Registers a login item that keeps one unlocked session shared by\n" +
				"Claude Desktop and Claude Code, and starts it now.",
			done: func() (bool, string) {
				if p, err := daemonPlistPath(); err == nil {
					if _, serr := os.Stat(p); serr == nil && labelLoaded() {
						if sock, serr := daemonSocketPath(); serr == nil && socketReachable(sock) {
							return true, "already running"
						}
					}
				}
				return false, ""
			},
			run: func(ctx context.Context) error { return runDaemonInstall(ctx, nil) },
		},
		{
			title: "Connect Claude",
			why: "Adds proto-mcp to Claude Desktop and Claude Code so the mail tools\n" +
				"appear in both.",
			done: func() (bool, string) {
				for _, t := range clientTargets() {
					p, err := t.path()
					if err != nil {
						return false, ""
					}
					cfg, err := loadClaudeDesktopConfig(p)
					if err != nil {
						return false, ""
					}
					if _, ok := cfg.MCPServers["protonmcp"]; !ok {
						return false, ""
					}
				}
				return true, "already connected"
			},
			run: func(ctx context.Context) error { return runInstall(ctx, nil) },
		},
	}

	fmt.Println("proto-mcp setup")
	fmt.Println()
	fmt.Println("This connects your Proton mailbox to Claude. Four steps, and you can")
	fmt.Println("stop and re-run this at any time — it picks up where it left off.")
	fmt.Println()

	for i, s := range steps {
		label := fmt.Sprintf("Step %d of %d: %s", i+1, len(steps), s.title)
		fmt.Println(label)
		fmt.Println(strings.Repeat("─", len([]rune(label))))

		if !*force {
			if ok, note := s.done(); ok {
				fmt.Printf("  Skipped — %s.\n\n", note)
				continue
			}
		}

		fmt.Println(indent(s.why, "  "))
		fmt.Println()

		if err := s.run(ctx); err != nil {
			// Stop at the first failure rather than cascading into
			// steps that depend on it. Re-running setup resumes here.
			fmt.Fprintf(os.Stderr, "\nStep %d failed: %v\n\n", i+1, err)
			fmt.Fprintln(os.Stderr, "Nothing after this step ran. Fix the problem above, then run")
			fmt.Fprintln(os.Stderr, "`protonmcp setup` again — completed steps are skipped.")
			return errors.New("setup incomplete")
		}
		fmt.Println()
	}

	fmt.Println("Checking everything…")
	fmt.Println()
	if err := runDoctor(ctx, doctorArgs(*dbPath)); err != nil {
		fmt.Fprintln(os.Stderr,
			"\nSetup finished but some checks did not pass. Work through the list above.")
		return err
	}

	fmt.Println()
	fmt.Println("Setup complete. One last thing:")
	fmt.Println()
	fmt.Println("  Quit and reopen Claude Desktop and Claude Code.")
	fmt.Println()
	fmt.Println("They only read the tool list at startup, so the mail tools won't")
	fmt.Println("appear until you restart them. Then try asking Claude:")
	fmt.Println()
	fmt.Println("    \"What's in my inbox from this week?\"")
	return nil
}

func doctorArgs(dbPath string) []string {
	if dbPath == "" {
		return nil
	}
	return []string{"--db", dbPath}
}

// backfillDone reports whether the local mirror already holds messages.
// A store that exists but is empty counts as not done — that is what a
// backfill interrupted partway through leaves behind, and re-running it
// is both safe and what the user wants.
func backfillDone(ctx context.Context, dbPath string) (bool, string) {
	path := dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return false, ""
		}
		path = p
	}
	if _, err := os.Stat(path); err != nil {
		return false, ""
	}
	st, err := store.Open(path)
	if err != nil {
		return false, ""
	}
	defer st.Close()

	var n int64
	if err := st.DB.QueryRowContext(ctx, "SELECT count(*) FROM messages").Scan(&n); err != nil {
		return false, ""
	}
	if n == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("%d messages already copied", n)
}

// indent prefixes every line of s, so multi-line explanations line up
// under their step heading.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

// confirm asks a yes/no question, defaulting to no. Unused by the happy
// path today but kept alongside the wizard: any step that grows a
// destructive branch should ask before taking it.
func confirm(ctx context.Context, question string) (bool, error) {
	ans, err := cli.PromptLine(ctx, question+" [y/N]: ")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(ans), "y"), nil
}
