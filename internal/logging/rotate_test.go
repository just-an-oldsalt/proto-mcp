package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatorRotatesAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	r, err := NewRotator(path, 100, 3)
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer r.Close()

	// 90 bytes — no rotation.
	if _, err := r.Write(bytes.Repeat([]byte("a"), 90)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); !os.IsNotExist(err) {
		t.Fatalf("expected no .1 yet; stat err = %v", err)
	}

	// Next 20 bytes crosses the threshold → rotate BEFORE writing.
	if _, err := r.Write(bytes.Repeat([]byte("b"), 20)); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	// .1 now holds the original 90 'a's; current holds the 20 'b's.
	dotOne, err := os.ReadFile(filepath.Join(dir, "audit.log.1"))
	if err != nil {
		t.Fatalf("read .1: %v", err)
	}
	if !bytes.Equal(dotOne, bytes.Repeat([]byte("a"), 90)) {
		t.Errorf(".1 content unexpected: got %d bytes, first %q…",
			len(dotOne), string(dotOne[:min(20, len(dotOne))]))
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if !bytes.Equal(current, bytes.Repeat([]byte("b"), 20)) {
		t.Errorf("current content unexpected: got %d bytes, %q",
			len(current), string(current))
	}
}

func TestRotatorDropsOldestGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")

	// 3 generations, threshold 10 bytes → 4 rotations should leave
	// .1/.2/.3 and have evicted the original first generation.
	r, err := NewRotator(path, 10, 3)
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer r.Close()

	// Write 11 bytes, four times. Each write rotates before
	// itself, so we end up with:
	//   write 1: 'a' × 11 → no rotation (file was empty)
	//                       wait — 0 + 11 > 10, so rotates first;
	//                       .1 is empty (current was empty), current=‘a’×11
	//
	// Simpler: write 11 bytes, then 11, then 11, then 11.
	for _, c := range []byte{'a', 'b', 'c', 'd'} {
		if _, err := r.Write(bytes.Repeat([]byte{c}, 11)); err != nil {
			t.Fatalf("write %c: %v", c, err)
		}
	}
	// After 4 writes: current=‘d’ × 11. .1=‘c’ × 11. .2=‘b’ × 11.
	// .3=‘a’ × 11. Original empty file was evicted past .3.
	// And .4 must NOT exist (maxGenerations = 3).
	if _, err := os.Stat(filepath.Join(dir, "log.4")); !os.IsNotExist(err) {
		t.Errorf("expected no .4; stat err = %v", err)
	}
	for i, want := range map[int]byte{1: 'c', 2: 'b', 3: 'a'} {
		got, err := os.ReadFile(filepath.Join(dir, "log."+itoa(i)))
		if err != nil {
			t.Fatalf("read .%d: %v", i, err)
		}
		if len(got) != 11 || got[0] != want {
			t.Errorf(".%d: want %d × %q, got %d × %q", i, 11, want, len(got), got[0])
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("d"), 11)) {
		t.Errorf("current: want 11 × d, got %d × %q", len(got), got[0])
	}
}

func TestRotatorReopenPicksUpExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	if err := os.WriteFile(path, []byte("preexisting "), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRotator(path, 100, 3)
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer r.Close()

	if _, err := r.Write([]byte("appended")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "preexisting appended") {
		t.Errorf("expected append to existing file; got %q", got)
	}
}

func TestRotatorCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRotator(filepath.Join(dir, "log"), 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second close should be no-op: %v", err)
	}
	if _, err := r.Write([]byte("after close")); err == nil {
		t.Error("write after close should fail")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
