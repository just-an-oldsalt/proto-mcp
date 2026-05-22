package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// resolveHelperPath walks the three candidate locations in order:
//
//  1. PROTONMCP_TOUCHID env var (test override / dev convenience).
//  2. Sibling of argv[0]: helpers/touchid/protonmcp-touchid relative
//     to filepath.Dir(argv[0]).
//  3. /Applications/protonmcp.app/Contents/MacOS/protonmcp-touchid
//     (Phase 7 packaged app).
//
// Returns the first existing executable path. If none exist, returns
// an error listing all the locations tried so the user knows where
// to put the binary.
func resolveHelperPath(argv0 string) (string, error) {
	var candidates []string

	if env := os.Getenv("PROTONMCP_TOUCHID"); env != "" {
		candidates = append(candidates, env)
	}

	if argv0 != "" {
		abs, err := filepath.Abs(argv0)
		if err == nil {
			sib := filepath.Join(filepath.Dir(abs), "helpers", "touchid", "protonmcp-touchid")
			candidates = append(candidates, sib)
			// Also check a "two levels up" location for the
			// common "binary at bin/protonmcp, helper at
			// helpers/touchid/protonmcp-touchid" dev layout.
			twoUp := filepath.Join(filepath.Dir(filepath.Dir(abs)), "helpers", "touchid", "protonmcp-touchid")
			candidates = append(candidates, twoUp)
		}
	}

	candidates = append(candidates,
		"/Applications/protonmcp.app/Contents/MacOS/protonmcp-touchid")

	for _, c := range candidates {
		if isExecutable(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("touchid helper not found; tried: %v", candidates)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return false
	}
	// Bit 0o111 covers user/group/other execute. We don't check for
	// 0o100-only (user-execute only) because dev builds typically
	// have 0o755 and packaged apps have 0o755 too.
	return fi.Mode().Perm()&0o111 != 0
}

// (touch a sentinel error here to anchor the doc comment in path.go)
var _ = errors.New
