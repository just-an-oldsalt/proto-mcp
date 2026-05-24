//go:build darwin

package keystore

/*
#cgo CFLAGS: -mmacosx-version-min=11.0
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include "access_control_darwin.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// saveProtected writes the keychain item with SecAccessControl set
// to userPresence. Phase 7/D — D37 fix. Reads of the resulting item
// trigger Touch ID (or passcode fallback per D30) at the OS level;
// writes (this function) record the policy but do not prompt.
//
// service / account / label are UTF-8 strings the cgo side wraps
// into CFStrings without requiring NUL-termination on this side.
//
// Returns nil on success, or an error wrapping the OSStatus from
// Security.framework. The most common non-zero results:
//
//   -25291  errSecAllocate         (allocation failure — usually OOM)
//   -25308  errSecInteractionNotAllowed (keychain locked, e.g. screen lock)
//   -25300  errSecItemNotFound     (update on missing item — shouldn't happen)
//
// A full OSStatus reference: <https://www.osstatus.com/>
func saveProtected(service, account, label string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("keystore: refusing to save empty data via protected path")
	}
	status := C.protonmcpSaveProtected(
		cstr(service), C.int(len(service)),
		cstr(account), C.int(len(account)),
		cstr(label), C.int(len(label)),
		// CFData copies the bytes internally; no lifetime concern
		// from the Go side after the call returns.
		unsafe.Pointer(&data[0]), C.int(len(data)),
	)
	if status != 0 {
		return fmt.Errorf("keystore: SecItem (Add|Update) returned OSStatus %d (see https://www.osstatus.com/ for the human name)", int(status))
	}
	return nil
}

// cstr returns a *C.char pointing at the Go string's bytes.
// Safe for the duration of the cgo call because cgo pins the
// argument across the call boundary; the C side copies bytes
// into CFString immediately.
//
// The string can be empty: returns a valid pointer to a one-byte
// region (cgo gives us at least that for empty strings).
func cstr(s string) *C.char {
	if len(s) == 0 {
		// Returning nil here causes CFStringCreateWithBytes to
		// build an empty string, which is what we want.
		return nil
	}
	// unsafe.Pointer of the first byte; cgo handles pinning for
	// the duration of the call.
	return (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
}

// saveProtectedSupported is true on darwin; the non-darwin stub
// returns false. Callers query this to fall back to plain
// (non-ACL) save on platforms that can't satisfy the contract.
const saveProtectedSupported = true
