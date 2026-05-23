//go:build !darwin

package caller

import (
	"errors"
	"net"
)

// PeerCred is a stub on non-macOS platforms. The project is
// macOS-only; this exists so `go build` succeeds on the Linux CI
// runners used for vulncheck.
func PeerCred(_ net.Conn) (Caller, error) {
	return Caller{}, errors.New("caller.PeerCred: unsupported on this platform")
}
