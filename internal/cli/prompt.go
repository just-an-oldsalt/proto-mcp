// Package cli holds small helpers for the protonmcp command-line entry
// points. Right now that's just TTY-aware credential prompts.
package cli

import (
	"bufio"
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

// openTTY opens /dev/tty for read+write. Going direct to /dev/tty (instead of
// os.Stdin) lets the caller still pipe data on stdin without confusing the
// interactive prompts — useful when chaining a password manager later.
func openTTY() (*os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	return f, nil
}

// PromptLine writes label to /dev/tty and returns the next line of input
// with echo enabled. Trailing CR/LF is stripped. Use for non-secret
// fields (email, TOTP, yes/no answers).
func PromptLine(label string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()

	if _, err := io.WriteString(tty, label); err != nil {
		return "", err
	}
	r := bufio.NewReader(tty)
	line, err := r.ReadString('\n')
	// Tighten: surface any non-EOF error even when we got partial data.
	// Previously the predicate silently swallowed read errors that
	// happened to coincide with non-empty lines (SECURITY L-1).
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// PromptSecret writes label to /dev/tty and reads a line with echo off,
// returning the result wrapped in a secret.Secret. The underlying
// term.ReadPassword buffer is zeroed before return so the password
// material doesn't sit on the heap waiting for GC.
//
// A newline is written to the tty after the read so the next output
// starts on a fresh line.
func PromptSecret(label string) (secret.Secret, error) {
	tty, err := openTTY()
	if err != nil {
		return secret.Secret{}, err
	}
	defer tty.Close()

	if _, err := io.WriteString(tty, label); err != nil {
		return secret.Secret{}, err
	}
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		zero(pw)
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
