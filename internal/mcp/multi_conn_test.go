package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Phase 6/A — the daemon model serves multiple connections from one
// Server. Before the connState refactor, the `initialized` flag was
// on the Server itself, so a second connection would see the first
// connection's handshake state. These tests guard against that
// regression.

// dialUnix is a tiny helper that connects to a temp Unix socket and
// runs an NDJSON conversation: write `msg`, read one response line.
func dialUnix(t *testing.T, path string, msg string) string {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64*1024)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

// TestMultiConnectionInitializeIndependent is the core regression
// guard: two clients each do their own initialize handshake, and
// the second's `not initialized` state isn't shadowed by the first.
func TestMultiConnectionInitializeIndependent(t *testing.T) {
	srv := New(nil)
	srv.Register(Tool{
		Name:        "ping_tool",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(_ Context, _ json.RawMessage) (*ToolResult, error) {
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})

	// Listen on a temp socket. macOS caps sockaddr_un.sun_path at
	// 104 chars, so the default t.TempDir() (which embeds the full
	// test name) blows the limit. Use a short /tmp path instead.
	sockPath := shortSockPath(t)
	addr, _ := net.ResolveUnixAddr("unix", sockPath)
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One goroutine per accepted connection — same shape as the
	// daemon's acceptLoop.
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}(c)
		}
	}()

	// Connection A: try tools/list BEFORE initialize. Must fail
	// with "server not initialized".
	respA := dialUnix(t, sockPath,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if !contains(respA, `"server not initialized"`) {
		t.Errorf("conn A pre-init tools/list should fail; got %s", respA)
	}

	// Connection B: full initialize then tools/list. Must succeed.
	// We read line-by-line because each write triggers a response
	// and a single Read() only catches the first response chunk.
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n"))
	_, _ = c.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))
	_, _ = c.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Read until we see ping_tool or timeout.
	allB := readLinesUntil(c, `"ping_tool"`, 2*time.Second)
	if !contains(allB, `"ping_tool"`) {
		t.Errorf("conn B post-init tools/list should include ping_tool; got %s", allB)
	}

	// Connection C: brand-new, no handshake. Should STILL get
	// "server not initialized" — proving B's initialized state
	// didn't leak.
	respC := dialUnix(t, sockPath,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if !contains(respC, `"server not initialized"`) {
		t.Errorf("conn C inherited initialized state from conn B (the bug Phase 6/A fixed); got %s", respC)
	}
}

// TestConcurrentInitializeNoRace exercises the per-conn handshake
// state under -race. Twenty parallel "initialize" handshakes should
// all complete cleanly.
func TestConcurrentInitializeNoRace(t *testing.T) {
	srv := New(nil)
	srv.Register(Tool{
		Name:        "ping_tool",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(_ Context, _ json.RawMessage) (*ToolResult, error) {
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})

	sockPath := shortSockPath(t)
	addr, _ := net.ResolveUnixAddr("unix", sockPath)
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}(c)
		}
	}()

	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", sockPath)
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer c.Close()
			_, _ = c.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n"))
			buf := make([]byte, 8192)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(buf); err != nil && err != io.EOF {
				t.Errorf("read: %v", err)
			}
		}()
	}
	wg.Wait()
}

// shortSockPath returns a Unix socket path under /tmp that's
// guaranteed to fit in sockaddr_un.sun_path (104 chars on macOS).
// t.TempDir() is too long for this constraint because it embeds the
// full test name. We register the file for cleanup with t.Cleanup
// since /tmp won't be auto-removed.
func shortSockPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("/tmp", "mcp*.sock")
	if err != nil {
		t.Fatalf("temp sock: %v", err)
	}
	p := f.Name()
	_ = f.Close()
	_ = os.Remove(p) // listener wants to create it
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// readLinesUntil drains the connection until `needle` appears OR
// the deadline fires. Returns whatever was read.
func readLinesUntil(c net.Conn, needle string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	_ = c.SetReadDeadline(deadline)
	var got []byte
	buf := make([]byte, 8192)
	for time.Now().Before(deadline) {
		n, err := c.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if contains(string(got), needle) {
				return string(got)
			}
		}
		if err != nil {
			break
		}
	}
	return string(got)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
