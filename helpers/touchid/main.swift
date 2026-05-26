// protonmcp-touchid — single-prompt Touch ID helper for proto-mcp.
//
// Spec:
//   - Read one JSON object from stdin (single line or multi-line).
//   - Run LAContext.evaluatePolicy(.deviceOwnerAuthentication) with
//     the body text (plus caller info, when present) as the
//     localizedReason. The biometric IS the confirmation — no
//     separate NSAlert step.
//   - Exit 0 on biometric/password success, 1 on deny/cancel/
//     auth-fail, 2 on stdin parse error.
//
// History: earlier versions of this helper showed an NSAlert FIRST
// when policy had confirm:true, then the Touch ID prompt — same
// body text shown twice with one extra click. Collapsed to a single
// prompt; the `confirm` field on the request is now accepted for
// backwards compat but does not gate a second dialog.
//
// Distribution: ad-hoc signed by swiftc on the dev machine. Phase 7
// adds Developer ID signing + notarization + NSFaceIDUsageDescription
// in an Info.plist when we bundle this as a .app.

import Foundation
import LocalAuthentication

struct Request: Codable {
    let title: String
    let body: String
    let caller: String?
    let confirm: Bool?
}

let data = FileHandle.standardInput.readDataToEndOfFile()
guard let req = try? JSONDecoder().decode(Request.self, from: data) else {
    FileHandle.standardError.write(Data("malformed stdin\n".utf8))
    exit(2)
}

// D30 (Phase 7/A): use .deviceOwnerAuthentication instead of
// .deviceOwnerAuthenticationWithBiometrics so the system falls back
// to the user's login password when biometric hardware is missing
// or disabled (Mac Mini, a Mac with a broken Touch ID sensor, Screen
// Sharing). Without this fallback, every prompted tool was simply
// inoperable on those Macs. Touch ID still runs FIRST on hardware
// that has it.
let ctx = LAContext()
var laError: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &laError) else {
    // Neither biometric NOR password available — extremely rare
    // (only happens with no user account configured for the local
    // session). Treat as deny.
    FileHandle.standardError.write(Data("authentication not available: \(laError?.localizedDescription ?? "unknown")\n".utf8))
    exit(1)
}

// Compose the reason text. macOS's Touch ID dialog renders this
// just below the lock icon; multi-line is supported but kept short.
// Caller info appended on a final line so the user can see which
// process is asking.
var reason = req.body
if let caller = req.caller, !caller.isEmpty {
    reason += "\n\nRequested by: \(caller)"
}

let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalErr in
    ok = success
    if !success, let e = evalErr {
        FileHandle.standardError.write(Data("evaluatePolicy: \(e.localizedDescription)\n".utf8))
    }
    sem.signal()
}
sem.wait()
exit(ok ? 0 : 1)
