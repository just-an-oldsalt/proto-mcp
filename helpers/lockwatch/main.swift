// protonmcp-lockwatch — screen-lock / sleep monitor for proto-mcp.
//
// Watches two macOS distributed notifications and writes a line to
// stdout when either fires:
//
//   "screen_locked\n"   — com.apple.screenIsLocked posted by loginwindow
//   "sleep\n"           — NSWorkspaceWillSleepNotification (system sleep)
//
// The daemon spawns this helper as a managed subprocess, reads
// stdout line-by-line, and calls Runtime.Lock with the corresponding
// reason. Phase 7/A.
//
// Design notes:
//
//   * One process per daemon. Helper exits when stdin closes
//     (daemon shutdown), or on its own SIGTERM. Daemon respawns it
//     on exit via a small Go-side restart loop (idleTracker
//     companion goroutine).
//
//   * Distributed notifications are global per user session. macOS
//     posts com.apple.screenIsLocked from loginwindow when the
//     screen locks for ANY reason (Cmd-Ctrl-Q, sleep+wake, lid
//     close, screen-saver-with-password, etc). The screen-unlock
//     notification (com.apple.screenIsUnlocked) is observed but not
//     emitted — the spec is "manual unlock via Touch ID" only.
//
//   * NSWorkspace sleep notification is in the WORKSPACE
//     notification center, not the distributed center. They're
//     different APIs.
//
//   * Stdout is line-buffered. Each notification handler writes one
//     line + flushes. fflush(stdout) is not in Swift; we use
//     FileHandle.standardOutput.write + explicit \n.
//
// Distribution: ad-hoc signed by swiftc on the dev machine. Phase
// 7/C will Developer-ID-sign this alongside the rest.

import Foundation
import AppKit

let stdout = FileHandle.standardOutput
let stderr = FileHandle.standardError

func emit(_ s: String) {
    if let data = (s + "\n").data(using: .utf8) {
        stdout.write(data)
    }
}

func warn(_ s: String) {
    if let data = (s + "\n").data(using: .utf8) {
        stderr.write(data)
    }
}

// Distributed center — screen lock / unlock signals come from
// loginwindow via the per-user distributed notification system.
let distCenter = DistributedNotificationCenter.default()

let screenLockObserver = distCenter.addObserver(
    forName: NSNotification.Name("com.apple.screenIsLocked"),
    object: nil,
    queue: .main
) { _ in
    emit("screen_locked")
}

// Optional: track screen-unlock so we know when to bump activity.
// We don't lock OR unlock on this — manual `protonmcp unlock` is the
// only path back. But emitting the line lets the daemon log it.
let screenUnlockObserver = distCenter.addObserver(
    forName: NSNotification.Name("com.apple.screenIsUnlocked"),
    object: nil,
    queue: .main
) { _ in
    emit("screen_unlocked")
}

// Workspace notifications — sleep / wake fire here, not the
// distributed center.
let wsCenter = NSWorkspace.shared.notificationCenter
let sleepObserver = wsCenter.addObserver(
    forName: NSWorkspace.willSleepNotification,
    object: nil,
    queue: .main
) { _ in
    emit("sleep")
}

let wakeObserver = wsCenter.addObserver(
    forName: NSWorkspace.didWakeNotification,
    object: nil,
    queue: .main
) { _ in
    emit("wake")
}

// Suppress unused-variable warnings; the observer tokens keep the
// closures alive for the process lifetime.
_ = screenLockObserver
_ = screenUnlockObserver
_ = sleepObserver
_ = wakeObserver

// Exit cleanly when the parent closes our stdin (daemon shutdown).
// We background-read stdin in a thread; an EOF stops the run loop.
DispatchQueue.global().async {
    let stdin = FileHandle.standardInput
    while true {
        let chunk = stdin.availableData
        if chunk.isEmpty {
            // EOF — parent went away.
            warn("stdin closed; lockwatch exiting")
            CFRunLoopStop(CFRunLoopGetMain())
            return
        }
    }
}

// SIGTERM → graceful exit. signal() via libc; Swift's Process API is
// for spawning, not for installing a handler in our own process.
signal(SIGTERM) { _ in
    CFRunLoopStop(CFRunLoopGetMain())
}

warn("lockwatch ready")
CFRunLoopRun()
