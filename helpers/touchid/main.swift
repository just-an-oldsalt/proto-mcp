// protonmcp-touchid — Touch ID + NSAlert helper for proto-mcp.
//
// Spec:
//   - Read one JSON object from stdin (single line or multi-line).
//   - If confirm: true, show NSAlert with the literal title + body.
//     If user cancels there, exit 1 immediately (skip biometrics).
//   - Otherwise (or if user clicked Send), run LAContext with
//     deviceOwnerAuthenticationWithBiometrics. Localized reason is
//     body. Window is brought to front via NSApp.activate.
//   - Exit 0 on biometric success, 1 on deny/cancel/auth-fail,
//     2 on stdin parse error.
//
// Distribution: ad-hoc signed by swiftc on the dev machine. Phase 7
// adds Developer ID signing + notarization + NSFaceIDUsageDescription
// in an Info.plist when we bundle this as a .app.

import Foundation
import LocalAuthentication
import AppKit

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

// AppKit needs an NSApplication for NSAlert. Without this the alert
// silently no-ops and exits with the wrong code. -.regular keeps us
// in the Dock briefly; for a one-shot prompt that's tolerable.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

if req.confirm == true {
    let alert = NSAlert()
    alert.messageText = req.title
    alert.informativeText = req.body
    if let caller = req.caller, !caller.isEmpty {
        alert.informativeText += "\n\nRequested by: \(caller)"
    }
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Send")
    alert.addButton(withTitle: "Cancel")

    NSApp.activate(ignoringOtherApps: true)
    let response = alert.runModal()
    if response != .alertFirstButtonReturn {
        exit(1)  // user clicked Cancel (or closed the sheet)
    }
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

let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: req.body) { success, evalErr in
    ok = success
    if !success, let e = evalErr {
        FileHandle.standardError.write(Data("evaluatePolicy: \(e.localizedDescription)\n".utf8))
    }
    sem.signal()
}
sem.wait()
exit(ok ? 0 : 1)
