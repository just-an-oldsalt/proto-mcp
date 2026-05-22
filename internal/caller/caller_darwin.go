//go:build darwin

package caller

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
#include <errno.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// resolveBinary returns the absolute path of the binary running with
// the given PID. macOS's libproc.proc_pidpath is the canonical API —
// /proc doesn't exist on macOS, and `ps -o comm=` would require
// shell-out which is slower and more brittle.
//
// Returns an empty string + nil error if the PID is gone or we lack
// permission to query it (which can happen with sandboxed parents).
// Audit log handles empty binary as "unknown caller" — that's the
// correct behavior, not a fatal error.
func resolveBinary(pid int) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n, err := C.proc_pidpath(
		C.int(pid),
		unsafe.Pointer(&buf[0]),
		C.uint32_t(len(buf)),
	)
	if n <= 0 {
		// errno may be ESRCH (pid gone) or EPERM (can't query) —
		// both are non-fatal; we return empty string.
		if err != nil && !errors.Is(err, nil) {
			_ = err // silenced; the caller treats empty Binary as unknown
		}
		return "", nil
	}
	return string(buf[:n]), nil
}
