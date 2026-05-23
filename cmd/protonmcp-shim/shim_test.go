package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketPathHasExpectedShape(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "Application Support/protonmcp/protonmcp.sock") {
		t.Errorf("unexpected default socket path: %s", p)
	}
}

// TestEmitDaemonUnavailableError checks the JSON-RPC error frame we
// emit when the daemon isn't reachable. It must be valid NDJSON
// (one line, ends with \n) and include the dial error so the user
// can act on it.
func TestEmitDaemonUnavailableError(t *testing.T) {
	// Redirect os.Stdout to a temp file for inspection. The
	// emitDaemonUnavailableError function writes directly to it.
	tmp, err := os.CreateTemp(t.TempDir(), "stdout*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	orig := os.Stdout
	os.Stdout = tmp
	defer func() { os.Stdout = orig }()

	emitDaemonUnavailableError("/tmp/test.sock", net.ErrClosed)
	tmp.Sync()
	_ = tmp.Close()

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		t.Error("error frame must end with newline (NDJSON framing)")
	}
	if !strings.Contains(s, `"jsonrpc":"2.0"`) {
		t.Errorf("missing JSON-RPC envelope: %s", s)
	}
	if !strings.Contains(s, "/tmp/test.sock") {
		t.Errorf("missing socket path: %s", s)
	}
	if !strings.Contains(s, `"data":{"dial_error":`) {
		t.Errorf("missing structured dial_error: %s", s)
	}
}

// TestShortSocketPathConstraint sanity-checks that the default
// socket path fits within macOS's 104-char sockaddr_un limit. If
// this ever fails for some path-config reason, the shim would also
// fail to connect and we'd want to know first.
func TestShortSocketPathConstraint(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 104 {
		t.Errorf("default socket path %d chars > 104 (sockaddr_un limit): %s", len(p), p)
	}
	// Sanity: the path is rooted under the user's home dir.
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(p, filepath.Clean(home)) {
		t.Errorf("default socket path not under home: %s (home=%s)", p, home)
	}
}
