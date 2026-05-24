// Phase 7/D — Keychain ACL implementation. See access_control_darwin.h
// for the public signature + design notes.

#include "access_control_darwin.h"
#include <Security/Security.h>

// makeCFString converts a length-bounded UTF-8 buffer into a
// CFString without requiring NUL termination on the Go side.
// Caller owns the returned CF object (CFRelease).
static CFStringRef makeCFString(const char *buf, int len) {
    return CFStringCreateWithBytes(
        kCFAllocatorDefault,
        (const UInt8 *)buf,
        (CFIndex)len,
        kCFStringEncodingUTF8,
        false
    );
}

int protonmcpSaveProtected(
    const char *service, int serviceLen,
    const char *account, int accountLen,
    const char *label,   int labelLen,
    const void *data,    int dataLen
) {
    CFStringRef cfService = makeCFString(service, serviceLen);
    CFStringRef cfAccount = makeCFString(account, accountLen);
    CFStringRef cfLabel   = makeCFString(label,   labelLen);
    CFDataRef   cfData    = CFDataCreate(kCFAllocatorDefault,
                                          (const UInt8 *)data,
                                          (CFIndex)dataLen);

    // SecAccessControl with user-presence: Touch ID (preferred) or
    // device passcode (fallback). Same shape D30/Phase-7A landed on
    // for the LAContext helper, so the user UX is consistent.
    //
    // We anchor the ACL to kSecAttrAccessibleWhenUnlocked — the item
    // is only available while the user is logged in AND the keychain
    // is unlocked, AND the presence check passes. Anything stricter
    // (ThisDeviceOnly variants) prevents Time Machine restores from
    // bringing the item to a new Mac, which we'd rather support.
    CFErrorRef aclErr = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlocked,
        kSecAccessControlUserPresence,
        &aclErr
    );
    if (acl == NULL) {
        if (aclErr) CFRelease(aclErr);
        CFRelease(cfService);
        CFRelease(cfAccount);
        CFRelease(cfLabel);
        CFRelease(cfData);
        return -25291; // errSecAllocate; ACL build failed
    }

    // Build the add-attribute dictionary. kSecAttrSynchronizable is
    // explicitly false so the item never lands in iCloud Keychain.
    const void *addKeys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecAttrLabel,
        kSecValueData,
        kSecAttrAccessControl,
        kSecAttrSynchronizable,
    };
    const void *addVals[] = {
        kSecClassGenericPassword,
        cfService,
        cfAccount,
        cfLabel,
        cfData,
        acl,
        kCFBooleanFalse,
    };
    CFDictionaryRef addAttrs = CFDictionaryCreate(
        kCFAllocatorDefault,
        addKeys, addVals, 7,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemAdd(addAttrs, NULL);

    if (status == errSecDuplicateItem) {
        // Item exists from a prior save. SecItemUpdate replaces the
        // value AND swaps in the new ACL — exactly the migration
        // path from v3-without-ACL to v4-with-ACL.
        const void *qKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
        const void *qVals[] = { kSecClassGenericPassword, cfService, cfAccount };
        CFDictionaryRef query = CFDictionaryCreate(
            kCFAllocatorDefault,
            qKeys, qVals, 3,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );

        const void *uKeys[] = {
            kSecValueData,
            kSecAttrLabel,
            kSecAttrAccessControl,
        };
        const void *uVals[] = { cfData, cfLabel, acl };
        CFDictionaryRef update = CFDictionaryCreate(
            kCFAllocatorDefault,
            uKeys, uVals, 3,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );

        status = SecItemUpdate(query, update);

        CFRelease(query);
        CFRelease(update);
    }

    CFRelease(addAttrs);
    CFRelease(acl);
    CFRelease(cfService);
    CFRelease(cfAccount);
    CFRelease(cfLabel);
    CFRelease(cfData);

    return (int)status;
}
