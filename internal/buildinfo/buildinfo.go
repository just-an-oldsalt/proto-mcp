// Package buildinfo carries the version identity stamped into the
// binaries at link time.
//
// Every shipped binary needs to be able to answer "what are you?" —
// for bug reports, for confirming an upgrade actually took, and for
// `protonmcp doctor` to spot a protonmcp/protonmcpd version skew after
// a partial upgrade.
//
// The values below are set with -ldflags -X by the Makefile:
//
//	go build -ldflags "-X github.com/just-an-oldsalt/proto-mcp/internal/buildinfo.version=1.0.2 ..."
//
// A plain `go build ./...` or `go install` leaves them empty, so
// Version/Commit fall back to the VCS metadata the Go toolchain embeds
// in every binary automatically (debug.ReadBuildInfo). That way even an
// unstamped developer build reports something truthful rather than
// "unknown".
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Linker-set values. Do not read these directly — use Version(),
// Commit(), and Date(), which apply the ReadBuildInfo fallback.
var (
	version string
	commit  string
	date    string
)

// devVersion is what an unstamped build with no VCS metadata reports.
// Deliberately not "unknown": it tells the reader the binary was built
// straight from a working tree rather than cut from a release tag.
const devVersion = "dev"

// dirtySuffix marks a build made from a working tree with uncommitted
// changes. Matches what `git describe --dirty` emits.
const dirtySuffix = "-dirty"

var resolved = sync.OnceValue(func() info {
	i := info{version: version, commit: commit, date: date}

	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.commit == "" {
					i.commit = shortCommit(s.Value)
				}
			case "vcs.time":
				if i.date == "" {
					i.date = s.Value
				}
			case "vcs.modified":
				i.dirty = s.Value == "true"
			}
		}
		// Module version — set for `go install module@version`
		// builds, "(devel)" when built from a working tree.
		if i.version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			i.version = bi.Main.Version
		}
	}

	if i.version == "" {
		i.version = devVersion
	}
	return i
})

type info struct {
	version string
	commit  string
	date    string
	dirty   bool
}

// Version returns the release version, e.g. "1.0.2". Falls back to the
// module version for `go install` builds and to "dev" for an unstamped
// working-tree build.
func Version() string { return resolved().version }

// Commit returns the short git SHA the binary was built from, or "" if
// the build carried no VCS metadata.
func Commit() string { return resolved().commit }

// Date returns the RFC-3339 commit timestamp, or "" if unknown. The
// Makefile stamps the *commit* date rather than the wall-clock build
// time so repeated builds of the same commit stay byte-identical.
func Date() string { return resolved().date }

// Dirty reports whether the working tree had uncommitted changes at
// build time. Only known for toolchain-embedded VCS metadata.
func Dirty() bool { return resolved().dirty }

// String renders the one-line version banner, e.g.
//
//	1.0.2 (a1b2c3d, 2026-07-24T10:11:12Z, go1.26.4, darwin/arm64)
//
// Used by `protonmcp version`, the daemon's startup log line, and the
// doctor report.
func String() string {
	i := resolved()

	var b strings.Builder
	b.WriteString(i.version)
	// `git describe --dirty` already carries the suffix, and the
	// toolchain's vcs.modified flag reports the same fact — append only
	// if the stamped version didn't say it first, or a working-tree
	// build reads "1.0.2-dirty-dirty".
	if i.dirty && !strings.HasSuffix(i.version, dirtySuffix) {
		b.WriteString(dirtySuffix)
	}

	var parts []string
	if i.commit != "" {
		parts = append(parts, i.commit)
	}
	if i.date != "" {
		parts = append(parts, i.date)
	}
	parts = append(parts, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)

	b.WriteString(" (")
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString(")")
	return b.String()
}

// shortCommit truncates a full 40-char git SHA to the conventional
// 7-char short form. Anything already shorter is returned as-is, so a
// Makefile that stamps `git rev-parse --short HEAD` isn't re-truncated.
func shortCommit(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
