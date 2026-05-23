//go:build darwin

package caller

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// PeerCred returns the connected peer's identity for a Unix-domain
// connection. Combines macOS's three relevant socket options:
//
//	LOCAL_PEEREUID / LOCAL_PEERGID (via Getpeereid) → uid + gid
//	LOCAL_PEERPID                                   → pid
//
// Plus proc_pidpath to resolve the executable for the audit row's
// caller_binary field.
//
// SECURITY D20: the daemon needs this so its audit log records the
// real connecting client (Claude Desktop / Code) rather than its
// own PID/UID. Without it, the audit row's caller fields are
// useless for distinguishing connections in a multi-client setup.
//
// Returns an error if the conn isn't a *net.UnixConn (TCP would
// have no peer creds — and shouldn't reach here anyway, since
// internal/mcp/trustguard.go panics on net.Listen("tcp")).
func PeerCred(conn net.Conn) (Caller, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Caller{}, errors.New("caller.PeerCred: conn is not *net.UnixConn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Caller{}, fmt.Errorf("syscall conn: %w", err)
	}

	// macOS socket-option constants. Stable in /usr/include/sys/un.h
	// + /usr/include/sys/socket.h.
	const (
		SOL_LOCAL      = 0
		LOCAL_PEERPID  = 2
		LOCAL_PEERCRED = 1
	)

	var (
		uid     uint32
		pid     int32
		callErr error
	)
	rcErr := raw.Control(func(fd uintptr) {
		// LOCAL_PEERCRED returns the peer's full Xucred. We only
		// use .Uid; .Groups is also available if we ever need
		// group-membership checks.
		xucred, gerr := unix.GetsockoptXucred(int(fd), SOL_LOCAL, LOCAL_PEERCRED)
		if gerr != nil {
			callErr = fmt.Errorf("LOCAL_PEERCRED: %w", gerr)
			return
		}
		uid = xucred.Uid

		// LOCAL_PEERPID is a separate option (peer PID). Just an
		// int; no wrapper struct needed.
		p, perr := unix.GetsockoptInt(int(fd), SOL_LOCAL, LOCAL_PEERPID)
		if perr != nil {
			callErr = fmt.Errorf("LOCAL_PEERPID: %w", perr)
			return
		}
		pid = int32(p)
	})
	if rcErr != nil {
		return Caller{}, fmt.Errorf("control: %w", rcErr)
	}
	if callErr != nil {
		return Caller{}, callErr
	}

	bin, _ := resolveBinary(int(pid))
	return Caller{
		PID:    int(pid),
		UID:    int(uid),
		Binary: bin,
	}, nil
}

// ensure syscall is used somewhere so the import isn't dropped
// when the file gets refactored.
var _ = syscall.SOCK_STREAM
