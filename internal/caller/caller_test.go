package caller

import (
	"os"
	"strings"
	"testing"
)

func TestResolveCaches(t *testing.T) {
	r := New()
	a := r.Resolve()
	b := r.Resolve()
	if a != b {
		t.Errorf("cached results diverged: %+v vs %+v", a, b)
	}
	if a.PID != os.Getppid() {
		t.Errorf("PID = %d, want %d", a.PID, os.Getppid())
	}
	if a.UID != os.Getuid() {
		t.Errorf("UID = %d, want %d", a.UID, os.Getuid())
	}
}

// TestStringFallback locks in the display format. The audit log row
// and slog attributes use this string, so test fleet should catch
// changes that would alter log output unexpectedly.
func TestStringFallback(t *testing.T) {
	c := Caller{PID: 42, Binary: ""}
	if got := c.String(); got != "pid 42" {
		t.Errorf("unresolved binary: got %q, want %q", got, "pid 42")
	}
	c = Caller{PID: 42, Binary: "/usr/local/bin/protonmcp"}
	if got := c.String(); !strings.Contains(got, "protonmcp") || !strings.Contains(got, "42") {
		t.Errorf("resolved: got %q", got)
	}
}

func TestBasenameOf(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/foo":      "foo",
		"foo":                     "foo",
		"/single":                 "single",
		"/path/with/many/parts/x": "x",
	}
	for in, want := range cases {
		if got := basenameOf(in); got != want {
			t.Errorf("basenameOf(%q) = %q, want %q", in, got, want)
		}
	}
}
