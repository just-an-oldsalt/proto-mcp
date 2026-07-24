package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// backfillDone drives whether `protonmcp setup` re-runs a mailbox
// drain that can take many minutes. Getting it wrong in either
// direction is user-visible: a false positive skips a backfill the user
// needs, a false negative repeats one they already sat through.

func TestBackfillDoneMissingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	if done, _ := backfillDone(context.Background(), path); done {
		t.Error("reported done for a store that does not exist")
	}
}

// TestBackfillDoneEmptyStore covers the interrupted-backfill case: the
// migrations ran and the file exists, but no messages landed. Treating
// that as complete would leave the user with an empty mailbox in Claude
// and no indication why.
func TestBackfillDoneEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	st.Close()

	if done, note := backfillDone(context.Background(), path); done {
		t.Errorf("reported done for an empty store (note: %q)", note)
	}
}

func TestBackfillDonePopulatedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.DB.Exec(
		`INSERT INTO messages (id, thread_id, subject, date) VALUES ('m1', 't1', 'hello', 0)`,
	); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	done, note := backfillDone(context.Background(), path)
	if !done {
		t.Fatal("reported not-done for a store holding a message")
	}
	if !strings.Contains(note, "1 message") {
		t.Errorf("note = %q, want it to mention the message count", note)
	}
}

// TestIndentPreservesBlankLines keeps the step explanations from
// growing trailing whitespace on their blank lines, which shows up as
// stray spaces in a terminal.
func TestIndentPreservesBlankLines(t *testing.T) {
	got := indent("first\n\nsecond", "  ")
	want := "  first\n\n  second"
	if got != want {
		t.Errorf("indent() = %q, want %q", got, want)
	}
}

// TestDoctorArgsThreadsDBPath — setup must hand doctor the same --db it
// used, or the final verification checks a different store than the one
// it just populated and reports a false failure.
func TestDoctorArgsThreadsDBPath(t *testing.T) {
	if got := doctorArgs(""); got != nil {
		t.Errorf("doctorArgs(\"\") = %v, want nil", got)
	}
	got := doctorArgs("/tmp/x.db")
	want := []string{"--db", "/tmp/x.db"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("doctorArgs = %v, want %v", got, want)
	}
}
