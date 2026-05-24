package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadExpectedSha256(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name     string
		body     string
		wantHash string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "shasum_format",
			body:     "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  /usr/local/bin/protonmcpd\n",
			wantHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			wantPath: "/usr/local/bin/protonmcpd",
		},
		{
			name:     "tab_separator",
			body:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\t/Users/x/bin/protonmcpd",
			wantHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			wantPath: "/Users/x/bin/protonmcpd",
		},
		{
			name:    "short_hash",
			body:    "abc123  /bin/x\n",
			wantErr: true,
		},
		{
			name:    "no_separator",
			body:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
			wantErr: true,
		},
		{
			name:    "empty",
			body:    "",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".txt")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			gotHash, gotPath, err := readExpectedSha256(path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error; got hash=%q path=%q", gotHash, gotPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotHash != tc.wantHash {
				t.Errorf("hash = %q, want %q", gotHash, tc.wantHash)
			}
			if gotPath != tc.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tc.wantPath)
			}
		})
	}
}

func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256("hello") is a well-known fixed value.
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256File(hello) = %s, want %s", got, want)
	}
}

func TestReadExpectedSha256MissingFile(t *testing.T) {
	_, _, err := readExpectedSha256(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("want os.IsNotExist err; got %v", err)
	}
}
