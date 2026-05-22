// Package cli holds small helpers for the protonmcp command-line entry
// points. Right now that's just TTY-aware credential prompts.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// ErrNoTTY is returned by the prompt helpers when /dev/tty isn't available
// (e.g. running under a non-interactive launchd session).
var ErrNoTTY = errors.New("no controlling tty available for interactive prompt")

// openTTY opens /dev/tty for read+write. Going direct to /dev/tty
// (instead of os.Stdin) lets the caller still pipe data on stdin
// without confusing the interactive prompts — useful when chaining a
// password manager later.
func openTTY() (*os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	return f, nil
}

// watchCancel spawns a goroutine that closes the tty as soon as ctx is
// cancelled. Closing the underlying fd unblocks any in-flight Read /
// term.ReadPassword call so Ctrl-C actually returns control to the
// caller. The watcher exits when stop is closed (the prompt finished
// normally) so it never leaks.
//
// Returns a function the prompt must call before returning so the
// goroutine cleans itself up.
func watchCancel(ctx context.Context, tty *os.File) func() {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Closing forces the in-flight Read to return EOF / error.
			_ = tty.Close()
		case <-stop:
		}
	}()
	return func() { close(stop) }
}

// PromptLine writes label to /dev/tty and returns the next line of
// input with echo enabled. Trailing CR/LF is stripped. Use for non-
// secret fields (email, TOTP, yes/no answers).
//
// If ctx is cancelled while waiting for input, the tty is closed and
// PromptLine returns ctx.Err() rather than a confusing read error.
func PromptLine(ctx context.Context, label string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()
	stop := watchCancel(ctx, tty)
	defer stop()

	if _, err := io.WriteString(tty, label); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	r := bufio.NewReader(tty)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// PromptSecret writes label to /dev/tty and reads a line with echo
// off, returning the result wrapped in a secret.Secret. The underlying
// term.ReadPassword buffer is zeroed before return so the password
// material doesn't sit on the heap waiting for GC.
//
// As with PromptLine, ctx cancellation closes the tty and surfaces
// ctx.Err() — Ctrl-C escapes the prompt cleanly.
func PromptSecret(ctx context.Context, label string) (secret.Secret, error) {
	tty, err := openTTY()
	if err != nil {
		return secret.Secret{}, err
	}
	defer tty.Close()
	stop := watchCancel(ctx, tty)
	defer stop()

	if _, err := io.WriteString(tty, label); err != nil {
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, err
	}
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		zero(pw)
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, err
	}
	s := secret.New(pw)
	zero(pw)
	return s, nil
}

// zero overwrites b with zeros. Defined here so PromptSecret doesn't
// reach into another package for a three-line loop.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
