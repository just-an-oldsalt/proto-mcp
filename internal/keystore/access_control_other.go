//go:build !darwin

package keystore

import "errors"

// saveProtected on non-darwin returns an error indicating the
// platform doesn't support the macOS-specific SecAccessControl
// path. Callers should fall back to the plain Save().
//
// proto-mcp is macOS-only by design (LaunchAgent, Touch ID
// helper, Keychain integration are all macOS APIs). The non-
// darwin stub exists so unit tests compile on Linux CI without
// requiring cgo or platform-specific build tags.
func saveProtected(_, _, _ string, _ []byte) error {
	return errors.New("keystore: protected save is darwin-only")
}

const saveProtectedSupported = false
