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
)

// ErrNoTTY is returned by the prompt helpers when /dev/tty isn't available
// (e.g. running under a non-interactive launchd session).
var ErrNoTTY = errors.New("no controlling tty available for interactive prompt")

// tty opens /dev/tty for read+write. Going direct to /dev/tty (instead of
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
// with echo enabled. Trailing CR/LF is stripped.
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
	if err != nil && (line == "" || err != io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// PromptSecret writes label to /dev/tty and reads a line with echo off.
// A newline is written after the read so the next output starts on a
// fresh line.
func PromptSecret(label string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()

	if _, err := io.WriteString(tty, label); err != nil {
		return "", err
	}
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
