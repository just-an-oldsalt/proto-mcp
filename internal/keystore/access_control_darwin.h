// Phase 7/D — Keychain ACL via cgo. Closes D37.
//
// Wraps Security.framework's SecItemAdd / SecItemUpdate with a
// SecAccessControl that requires biometric (Touch ID) or passcode
// presence to READ the item. Writes (this function) do NOT prompt
// — the ACL records the policy; the prompt fires on every Load.
//
// kSecAttrAccessControl conflicts with kSecAttrAccessible (Apple
// docs: set one or the other, not both). We use ACL only here;
// keybase/go-keychain's plain AccessibleWhenUnlocked path lives
// in keystore.go as the v3 fallback.

#ifndef PROTONMCP_ACCESS_CONTROL_H
#define PROTONMCP_ACCESS_CONTROL_H

#include <CoreFoundation/CoreFoundation.h>

// protonmcpSaveProtected adds (or replaces) a Keychain generic-
// password item whose ACL requires user-presence (Touch ID or
// passcode) for subsequent reads.
//
// Inputs are UTF-8 char* + length pairs (no CFString allocation in
// Go); the C side wraps them into CoreFoundation types internally.
//
// Returns the OSStatus from SecItemAdd / SecItemUpdate:
//   0           (errSecSuccess)        wrote successfully
//   -25299      (errSecDuplicateItem)  caller bug — we handle dup internally
//   -25308      (errSecInteractionNotAllowed) keychain locked
//   negative    other Security framework error code
int protonmcpSaveProtected(
    const char *service, int serviceLen,
    const char *account, int accountLen,
    const char *label,   int labelLen,
    const void *data,    int dataLen
);

#endif
