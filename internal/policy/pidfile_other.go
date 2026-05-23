//go:build !darwin

package policy

// procExeFor on non-macOS platforms returns "" (can't determine).
// Linux CI exercises this branch for the vulncheck job; the
// matchesExecutable caller treats empty as "don't include." Since
// the project is macOS-only, that's the right default — Linux is
// only here to satisfy `go build` on CI Linux runners.
func procExeFor(_ int) string {
	return ""
}
