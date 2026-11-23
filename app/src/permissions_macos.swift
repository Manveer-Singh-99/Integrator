//
//  permissions_macos.swift
//  Integrator Setup & Permissions Assistant - macOS Native TCC & Privacy FFI Bridge
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This module provides the native macOS C-ABI FFI bridge for querying and requesting
//  operating system privacy permissions managed by macOS Transparency, Consent, and Control
//  (TCC) across Accessibility, Input Monitoring, Screen Recording, and Camera capture.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `app/src/setup.rs`: Invokes `@_cdecl` entry points during launch health checks,
//    on-demand permission audits, and user-initiated permission request flows.
//
//  Downstream Callees:
//  - `ApplicationServices`: `AXIsProcessTrusted()`, `AXIsProcessTrustedWithOptions(_:)`.
//  - `CoreGraphics`: `CGPreflightListenEventAccess()`, `CGRequestListenEventAccess()`,
//    `CGPreflightScreenCaptureAccess()`, `CGRequestScreenCaptureAccess()`.
//  - `AVFoundation`: `AVCaptureDevice.authorizationStatus(for:)`,
//    `AVCaptureDevice.requestAccess(for:completionHandler:)`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Preflight status checks (`*_granted`, `*_status`) are thread-safe and non-blocking,
//    suitable for synchronous invocation from Rust worker threads.
//  - Interactive request triggers (`*_request`) may present native macOS system permission
//    dialogs or dispatch asynchronous TCC prompts without blocking the main UI runloop.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - OS Availability Guards: `CGPreflightListenEventAccess` and `CGPreflightScreenCaptureAccess`
//    are gated with `if #available(macOS 10.15, *)` to guarantee symbol availability across
//    deployment targets.
//  - Bundle Plist Guard: `integrator_mac_perm_camera_request` verifies the presence of a
//    non-empty `NSCameraUsageDescription` in `Bundle.main` prior to invoking AVFoundation,
//    preventing TCC `SIGABRT` termination when invoked from unbundled CLI test binaries.
//

import AppKit
import ApplicationServices
import AVFoundation
import CoreGraphics
import Foundation
import LocalAuthentication

/// Info.plist key required by macOS TCC before requesting video capture authorization.
private let kCameraUsageDescriptionKey: String = "NSCameraUsageDescription"

/// Maximum wait timeout in seconds when awaiting an interactive AVFoundation camera prompt.
private let kCameraPromptTimeoutSec: Int = 15

/// Maximum wait timeout in seconds when awaiting an interactive macOS Touch ID biometric prompt.
private let kTouchIdPromptTimeoutSec: Int = 45

/// Fallback reason string displayed in the macOS Touch ID sheet when caller passes an empty reason.
private let kTouchIdDefaultPromptReason: String = "authenticate a remote Touch ID challenge from your paired Windows PC"

/// Queries whether the current process is trusted for macOS Accessibility (`AXIsProcessTrusted`).
///
/// Accessibility is required for Quartz `CGEventTap` cursor capture, edge hop detection,
/// and synthetic mouse/keyboard event injection in the Universal Input KVM subsystem.
///
/// - Returns: `true` if Accessibility permission is currently granted; otherwise `false`.
@_cdecl("integrator_mac_perm_accessibility_granted")
public func integrator_mac_perm_accessibility_granted() -> Bool {
    return AXIsProcessTrusted()
}

/// Prompts the user with the native macOS Accessibility trust dialog via `AXIsProcessTrustedWithOptions`.
///
/// - Returns: `true` if the process is already trusted; `false` if the user must still toggle
///   Integrator ON in System Settings -> Privacy & Security -> Accessibility.
@_cdecl("integrator_mac_perm_accessibility_request")
public func integrator_mac_perm_accessibility_request() -> Bool {
    let promptKey = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
    let options = [promptKey: true] as CFDictionary
    return AXIsProcessTrustedWithOptions(options)
}

/// Queries whether the current process has macOS Input Monitoring permission (`CGPreflightListenEventAccess`).
///
/// Input Monitoring is required on macOS 10.15+ to listen to global keyboard and mouse events
/// across background applications.
///
/// - Returns: `true` if Input Monitoring permission is granted; otherwise `false`.
@_cdecl("integrator_mac_perm_input_monitoring_granted")
public func integrator_mac_perm_input_monitoring_granted() -> Bool {
    if #available(macOS 10.15, *) {
        return CGPreflightListenEventAccess()
    } else {
        return AXIsProcessTrusted()
    }
}

/// Triggers the native macOS Input Monitoring permission prompt via `CGRequestListenEventAccess`.
///
/// - Returns: `true` if Input Monitoring access is granted; otherwise `false`.
@_cdecl("integrator_mac_perm_input_monitoring_request")
public func integrator_mac_perm_input_monitoring_request() -> Bool {
    if #available(macOS 10.15, *) {
        return CGRequestListenEventAccess()
    } else {
        return integrator_mac_perm_accessibility_request()
    }
}

/// Queries whether the current process has macOS Screen Recording permission (`CGPreflightScreenCaptureAccess`).
///
/// Screen Recording is required when the Mac acts as an extended display streaming host.
///
/// - Returns: `true` if Screen Recording permission is granted; otherwise `false`.
@_cdecl("integrator_mac_perm_screen_recording_granted")
public func integrator_mac_perm_screen_recording_granted() -> Bool {
    if #available(macOS 10.15, *) {
        return CGPreflightScreenCaptureAccess()
    } else {
        return true
    }
}

/// Triggers the native macOS Screen Recording permission prompt via `CGRequestScreenCaptureAccess`.
///
/// - Returns: `true` if Screen Recording access is granted; otherwise `false`.
@_cdecl("integrator_mac_perm_screen_recording_request")
public func integrator_mac_perm_screen_recording_request() -> Bool {
    if #available(macOS 10.15, *) {
        return CGRequestScreenCaptureAccess()
    } else {
        return true
    }
}

/// Queries the current macOS TCC authorization status for video camera capture.
///
/// - Returns:
///   - `0`: `.notDetermined` (user has not yet been prompted).
///   - `1`: `.restricted` or `.denied` (user must enable in System Settings).
///   - `2`: `.authorized` (permission granted).
@_cdecl("integrator_mac_perm_camera_status")
public func integrator_mac_perm_camera_status() -> Int32 {
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized:
        return 2
    case .denied, .restricted:
        return 1
    case .notDetermined:
        return 0
    @unknown default:
        return 1
    }
}

/// Requests macOS video camera access via `AVCaptureDevice.requestAccess(for: .video)` if the
/// bundle defines `NSCameraUsageDescription` and the status is `.notDetermined`.
@_cdecl("integrator_mac_perm_camera_request")
public func integrator_mac_perm_camera_request() {
    guard AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined else {
        return
    }
    guard let desc = Bundle.main.object(forInfoDictionaryKey: kCameraUsageDescriptionKey) as? String,
          !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
        return
    }
    let sem = DispatchSemaphore(value: 0)
    AVCaptureDevice.requestAccess(for: .video) { _ in
        sem.signal()
    }
    _ = sem.wait(timeout: .now() + .seconds(kCameraPromptTimeoutSec))
}

/// Checks whether physical Apple Touch ID Secure Enclave biometric authentication is available
/// and enrolled on this Mac (`LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`).
///
/// - Returns: `true` if Touch ID hardware is present, enrolled, and ready; otherwise `false`.
@_cdecl("integrator_mac_touchid_available")
public func integrator_mac_touchid_available() -> Bool {
    let context = LAContext()
    var authError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
        return false
    }
    return context.biometryType == .touchID
}

/// Copies a human-readable UTF-8 error message into a caller-allocated C character buffer.
private func writeCStringBuffer(_ text: String, into buf: UnsafeMutablePointer<CChar>?, cap: Int) {
    guard let buf = buf, cap > 1 else { return }
    let utf8 = Array(text.utf8)
    let copyLen = min(utf8.count, cap - 1)
    for i in 0..<copyLen {
        buf[i] = CChar(bitPattern: utf8[i])
    }
    buf[copyLen] = 0
}

/// Presents the native macOS Touch ID fingerprint authentication sheet backed by the Apple Secure Enclave.
///
/// - Parameters:
///   - reasonPtr: NUL-terminated UTF-8 reason string displayed inside the macOS Touch ID sheet.
///   - outErrorBuf: Optional caller-allocated UTF-8 buffer receiving a failure explanation.
///   - outErrorCap: Capacity in bytes of `outErrorBuf`.
/// - Returns:
///   - `1`: Biometric Touch ID match succeeded.
///   - `0`: User cancelled or authentication failed.
///   - `-1`: Touch ID hardware unavailable or not enrolled on this Mac.
@_cdecl("integrator_mac_touchid_authenticate")
public func integrator_mac_touchid_authenticate(
    reasonPtr: UnsafePointer<CChar>?,
    outErrorBuf: UnsafeMutablePointer<CChar>?,
    outErrorCap: Int
) -> Int32 {
    let reason: String
    if let reasonPtr = reasonPtr {
        let parsed = String(cString: reasonPtr).trimmingCharacters(in: .whitespacesAndNewlines)
        reason = parsed.isEmpty ? kTouchIdDefaultPromptReason : parsed
    } else {
        reason = kTouchIdDefaultPromptReason
    }

    let context = LAContext()
    context.localizedFallbackTitle = ""
    var preflightError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &preflightError) else {
        let msg = preflightError?.localizedDescription ?? "Touch ID is not available or not enrolled on this Mac."
        writeCStringBuffer(msg, into: outErrorBuf, cap: outErrorCap)
        return -1
    }

    // Bring Integrator to foreground on main thread so the Touch ID system sheet is immediately visible
    DispatchQueue.main.async {
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    let sem = DispatchSemaphore(value: 0)
    var authSuccess: Bool = false
    var evalErrorMsg: String = ""

    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evalError in
        authSuccess = success
        if let evalError = evalError {
            evalErrorMsg = evalError.localizedDescription
        }
        sem.signal()
    }

    let waitResult = sem.wait(timeout: .now() + .seconds(kTouchIdPromptTimeoutSec))
    if waitResult == .timedOut {
        context.invalidate()
        writeCStringBuffer("Touch ID biometric prompt timed out after \(kTouchIdPromptTimeoutSec)s.", into: outErrorBuf, cap: outErrorCap)
        return 0
    }

    if authSuccess {
        writeCStringBuffer("", into: outErrorBuf, cap: outErrorCap)
        return 1
    } else {
        let msg = evalErrorMsg.isEmpty ? "Touch ID verification was cancelled or did not match." : evalErrorMsg
        writeCStringBuffer(msg, into: outErrorBuf, cap: outErrorCap)
        return 0
    }
}

/// Presents an explicit modal consent dialog asking the local user if they allow the remote peer
/// to activate and stream the Mac camera, with a configurable timeout and granular scope options.
///
/// - Parameters:
///   - peerNamePtr: UTF-8 C string of the remote peer hostname or device identifier.
///   - timeoutSec: Maximum seconds before prompt automatically dismisses and denies.
/// - Returns:
///   - `1`: Allow Once (single stream)
///   - `2`: Allow for this Session
///   - `3`: Always Allow (persistent)
// MARK: - Non-blocking Scoped Camera Consent Coordinator

private final class MacPromptCoordinator: NSObject {
    private let lock = NSLock()
    private var completed = false
    private var completion: ((Int32) -> Void)?
    weak var window: NSWindow?
    private var timer: DispatchSourceTimer?

    init(completion: @escaping (Int32) -> Void) {
        self.completion = completion
        super.init()
    }

    func attachTimer(timer: DispatchSourceTimer) {
        self.timer = timer
    }

    func finish(with result: Int32) {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return }
        completed = true
        timer?.cancel()
        timer = nil
        let comp = self.completion
        self.completion = nil
        DispatchQueue.main.async { [weak window] in
            window?.orderOut(nil)
        }
        g_macPromptLock.lock()
        if g_activeMacPromptCoordinator === self {
            g_activeMacPromptCoordinator = nil
        }
        g_macPromptLock.unlock()
        comp?(result)
    }

    @objc func buttonTapped(_ sender: NSButton) {
        let tag = sender.tag
        let decision: Int32
        switch tag {
        case 1: decision = 2  // ActiveSession
        case 2: decision = 1  // AllowOnce
        case 3: decision = 3  // AlwaysAllow
        case 4: decision = 0  // Deny
        case 5: decision = -1 // DenyAndBlock
        default: decision = 0
        }
        finish(with: decision)
    }
}

private var g_activeMacPromptCoordinator: MacPromptCoordinator?
private let g_macPromptLock = NSLock()

/// Cancels any currently pending macOS camera consent dialog immediately.
@_cdecl("integrator_mac_cancel_camera_consent_prompt")
public func integrator_mac_cancel_camera_consent_prompt() {
    g_macPromptLock.lock()
    let coord = g_activeMacPromptCoordinator
    g_macPromptLock.unlock()
    coord?.finish(with: 0)
}

/// Prompts the local Mac user for camera streaming consent using non-blocking AppKit presentation.
/// Never invokes synchronous `runModal()`; main-thread event dispatch continues uninterrupted.
///
/// Returns:
///   - `1`: Allow Once (Single continuous stream)
///   - `2`: Allow for Active Session
///   - `3`: Always Allow (Remember persistently)
///   - `0`: Denied, timed out, or cancelled
///   - `-1`: Deny and Block persistently
@_cdecl("integrator_mac_prompt_camera_consent_scoped")
public func integrator_mac_prompt_camera_consent_scoped(
    peerNamePtr: UnsafePointer<CChar>?,
    timeoutSec: Int32
) -> Int32 {
    let peerName: String
    if let ptr = peerNamePtr {
        peerName = String(cString: ptr)
    } else {
        peerName = "Paired Workstation"
    }

    let effectiveTimeout = timeoutSec > 0 ? Int(timeoutSec) : 30
    let sem = DispatchSemaphore(value: 0)
    var selectedOption: Int32 = 0

    let coordinator = MacPromptCoordinator { result in
        selectedOption = result
        sem.signal()
    }

    g_macPromptLock.lock()
    g_activeMacPromptCoordinator = coordinator
    g_macPromptLock.unlock()

    DispatchQueue.main.async {
        _ = NSApplication.shared
        let alert = NSAlert()
        alert.messageText = "Remote Camera Access Request"
        alert.informativeText = "\(peerName) is requesting to access and stream your Mac camera.\n\nChoose an authorization scope:"
        alert.alertStyle = .warning

        // Button 1: Allow for Session (tag: 1)
        let b1 = alert.addButton(withTitle: "Allow for Session")
        b1.tag = 1
        b1.target = coordinator
        b1.action = #selector(MacPromptCoordinator.buttonTapped(_:))

        // Button 2: Allow Once (tag: 2)
        let b2 = alert.addButton(withTitle: "Allow Once")
        b2.tag = 2
        b2.target = coordinator
        b2.action = #selector(MacPromptCoordinator.buttonTapped(_:))

        // Button 3: Always Allow (tag: 3)
        let b3 = alert.addButton(withTitle: "Always Allow")
        b3.tag = 3
        b3.target = coordinator
        b3.action = #selector(MacPromptCoordinator.buttonTapped(_:))

        // Button 4: Deny (tag: 4)
        let b4 = alert.addButton(withTitle: "Deny")
        b4.tag = 4
        b4.target = coordinator
        b4.action = #selector(MacPromptCoordinator.buttonTapped(_:))

        // Button 5: Deny & Block (tag: 5)
        let b5 = alert.addButton(withTitle: "Deny & Block")
        b5.tag = 5
        b5.target = coordinator
        b5.action = #selector(MacPromptCoordinator.buttonTapped(_:))

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.main)
        timer.schedule(deadline: .now() + .seconds(effectiveTimeout))
        timer.setEventHandler {
            coordinator.finish(with: 0) // Timeout: Deny
        }
        coordinator.attachTimer(timer: timer)
        timer.resume()

        let window = alert.window
        coordinator.window = window

        if let targetWindow = NSApp?.keyWindow ?? NSApp?.mainWindow {
            alert.beginSheetModal(for: targetWindow) { response in
                let decision: Int32
                switch response {
                case .alertFirstButtonReturn: decision = 2
                case .alertSecondButtonReturn: decision = 1
                case .alertThirdButtonReturn: decision = 3
                case NSApplication.ModalResponse(rawValue: 1004): decision = -1
                default: decision = 0
                }
                coordinator.finish(with: decision)
            }
        } else {
            window.level = .floating
            window.center()
            window.makeKeyAndOrderFront(nil)
            NSApp?.activate(ignoringOtherApps: true)
        }
    }

    let waitResult = sem.wait(timeout: .now() + .seconds(effectiveTimeout + 2))
    if waitResult == .timedOut {
        coordinator.finish(with: 0)
        return 0
    }
    return selectedOption
}

/// Presents an explicit modal consent dialog asking the local user if they allow the remote peer
/// to activate and stream the Mac camera.
///
/// - Parameters:
///   - peerNamePtr: UTF-8 C string of the remote peer hostname or device identifier.
/// - Returns: `true` if the local user explicitly clicked "Allow", `false` if denied or cancelled.
@_cdecl("integrator_mac_prompt_camera_consent")
public func integrator_mac_prompt_camera_consent(peerNamePtr: UnsafePointer<CChar>?) -> Bool {
    let res = integrator_mac_prompt_camera_consent_scoped(peerNamePtr: peerNamePtr, timeoutSec: 30)
    return res > 0
}
