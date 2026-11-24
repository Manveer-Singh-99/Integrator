//
//  permissions_macos.swift
//  Integrator Setup & Permissions Assistant - macOS Native TCC, Touch ID & Privacy FFI Bridge
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This module provides the native macOS C-ABI FFI bridge for querying and requesting
//  operating system privacy permissions managed by macOS Transparency, Consent, and Control
//  (TCC) across Accessibility, Input Monitoring, Screen Recording, and Camera capture,
//  plus Apple Secure Enclave biometric authentication (Touch ID) and explicit session-scoped
//  remote camera access consent prompts (`NSAlert` sheet / floating panel).
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `app/src/setup.rs`: Invokes permission preflight/request `@_cdecl` entry points during
//    launch health checks, on-demand permission audits, and guided permission requests.
//  - `app/src/trust.rs`: Invokes `integrator_mac_touchid_available` and
//    `integrator_mac_touchid_authenticate` for cross-device Windows Hello / Passkey approval.
//  - `app/src/camera/mod.rs`: Invokes `integrator_mac_prompt_camera_consent_scoped` and
//    `integrator_mac_cancel_camera_consent_prompt` for explicit local camera consent leases.
//
//  Downstream Callees:
//  - `ApplicationServices`: `AXIsProcessTrusted()`, `AXIsProcessTrustedWithOptions(_:)`.
//  - `CoreGraphics`: `CGPreflightListenEventAccess()`, `CGRequestListenEventAccess()`,
//    `CGPreflightScreenCaptureAccess()`, `CGRequestScreenCaptureAccess()`.
//  - `AVFoundation`: `AVCaptureDevice.authorizationStatus(for:)`,
//    `AVCaptureDevice.requestAccess(for:completionHandler:)`.
//  - `LocalAuthentication`: `LAContext` Secure Enclave Touch ID evaluation.
//  - `AppKit`: Non-blocking `NSAlert` (`beginSheetModal` or retained floating window).
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Preflight status checks (`*_granted`, `*_status`, `touchid_available`) are thread-safe
//    and non-blocking for direct synchronous invocation from Rust threads.
//  - Blocking FFI prompts (`touchid_authenticate`, `prompt_camera_consent_scoped`,
//    `perm_camera_request`) never block `Thread.isMainThread`: Touch ID and consent prompts
//    guard against main-thread deadlock and present AppKit UI on `DispatchQueue.main`.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Fail-Closed Main-Thread & Timeout Semantics: Touch ID and scoped camera consent prompts
//    default to denial (`0`) on timeout, cancellation, preemption, or invalid calling thread.
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

/// Default timeout in seconds when awaiting an explicit macOS camera consent dialog response.
private let kCameraConsentDefaultTimeoutSec: Int = 30

/// Thread-safe synchronization container bridging `LAContext.evaluatePolicy` callbacks across timeout boundaries.
private final class TouchIdEvalBox: @unchecked Sendable {
    /// Lock protecting `success` and `errorMessage`.
    private let lock = NSLock()
    /// Whether biometric authentication succeeded.
    private var success = false
    /// Localized diagnostic string supplied on biometric failure or cancellation.
    private var errorMessage = ""

    /// Stores the asynchronous LocalAuthentication outcome safely from any callback thread.
    func set(success: Bool, errorMessage: String) {
        lock.lock()
        self.success = success
        self.errorMessage = errorMessage
        lock.unlock()
    }

    /// Reads the stored biometric authentication result and error diagnostic atomically.
    func get() -> (Bool, String) {
        lock.lock()
        let res = (success, errorMessage)
        lock.unlock()
        return res
    }
}

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
///
/// Never blocks the main AppKit thread; dispatches asynchronously when invoked on `Thread.isMainThread`.
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
    if Thread.isMainThread {
        AVCaptureDevice.requestAccess(for: .video) { _ in }
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

/// Copies a human-readable UTF-8 error message into a caller-allocated NUL-terminated C character buffer.
///
/// - Parameters:
///   - text: Error string (truncated safely to `cap - 1` UTF-8 bytes without splitting multi-byte scalars).
///   - buf: Destination C character buffer; no-op if `nil` or `cap <= 0`.
///   - cap: Capacity of `buf` in bytes including trailing NUL byte.
private func writeCStringBuffer(_ text: String, into buf: UnsafeMutablePointer<CChar>?, cap: Int) {
    guard let buf = buf, cap > 0 else { return }
    if cap == 1 {
        buf[0] = 0
        return
    }
    let utf8 = Array(text.utf8)
    let copyLen = min(utf8.count, cap - 1)
    for i in 0..<copyLen {
        buf[i] = CChar(bitPattern: utf8[i])
    }
    buf[copyLen] = 0
}

/// Presents the native macOS Touch ID fingerprint authentication sheet backed by the Apple Secure Enclave.
///
/// Must be called from a background worker thread (returns `0` fail-closed if invoked synchronously on
/// `Thread.isMainThread` so AppKit never deadlocks).
///
/// - Parameters:
///   - reasonPtr: NUL-terminated UTF-8 reason string displayed inside the macOS Touch ID sheet.
///   - outErrorBuf: Optional caller-allocated UTF-8 buffer receiving a failure explanation.
///   - outErrorCap: Capacity in bytes of `outErrorBuf`.
/// - Returns:
///   - `1`: Biometric Touch ID match succeeded.
///   - `0`: User cancelled, authentication failed, or called on main thread.
///   - `-1`: Touch ID hardware unavailable or not enrolled on this Mac.
@_cdecl("integrator_mac_touchid_authenticate")
public func integrator_mac_touchid_authenticate(
    reasonPtr: UnsafePointer<CChar>?,
    outErrorBuf: UnsafeMutablePointer<CChar>?,
    outErrorCap: Int
) -> Int32 {
    if Thread.isMainThread {
        writeCStringBuffer("Touch ID verification cannot block the main AppKit UI thread.", into: outErrorBuf, cap: outErrorCap)
        return 0
    }

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
    let evalBox = TouchIdEvalBox()

    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evalError in
        evalBox.set(success: success, errorMessage: evalError?.localizedDescription ?? "")
        sem.signal()
    }

    let waitResult = sem.wait(timeout: .now() + .seconds(kTouchIdPromptTimeoutSec))
    if waitResult == .timedOut {
        context.invalidate()
        writeCStringBuffer("Touch ID biometric prompt timed out after \(kTouchIdPromptTimeoutSec)s.", into: outErrorBuf, cap: outErrorCap)
        return 0
    }

    let (authSuccess, evalErrorMsg) = evalBox.get()
    if authSuccess {
        writeCStringBuffer("", into: outErrorBuf, cap: outErrorCap)
        return 1
    } else {
        let msg = evalErrorMsg.isEmpty ? "Touch ID verification was cancelled or did not match." : evalErrorMsg
        writeCStringBuffer(msg, into: outErrorBuf, cap: outErrorCap)
        return 0
    }
}

// MARK: - Non-blocking Scoped Camera Consent Coordinator

/// Coordinates the lifecycle, timeout timer, sheet/window dismissal, and single-shot result delivery
/// for the non-blocking AppKit remote camera authorization dialog.
private final class MacPromptCoordinator: NSObject, @unchecked Sendable {
    /// Mutex guarding `completed`, `resultValue`, `timer`, and `completion`.
    private let lock = NSLock()
    /// Prevents double completion when button tap, sheet completion, timer, or cancel race.
    private var completed = false
    /// Recorded user authorization scope decision (`0` = Denied until resolved).
    private var resultValue: Int32 = 0
    /// One-shot completion callback invoked at most once upon prompt resolution.
    private var completion: ((Int32) -> Void)?
    /// Retained `NSAlert` instance kept alive for standalone floating alerts without an attached sheet.
    var retainedAlert: NSAlert?
    /// Weak reference to the alert window displayed onscreen.
    weak var window: NSWindow?
    /// Weak reference to the parent `NSWindow` when presented via `beginSheetModal`.
    weak var parentSheetWindow: NSWindow?
    /// Main-queue expiration timer auto-denying the request if the user does not respond in time.
    private var timer: DispatchSourceTimer?

    /// Creates a new coordinator with the given single-shot completion callback.
    init(completion: @escaping (Int32) -> Void) {
        self.completion = completion
        super.init()
    }

    /// Attaches the expiration timeout source created on `DispatchQueue.main`.
    func attachTimer(timer: DispatchSourceTimer) {
        lock.lock()
        self.timer = timer
        lock.unlock()
    }

    /// Returns the resolved authorization scope code safely from any thread.
    func currentResult() -> Int32 {
        lock.lock()
        let v = resultValue
        lock.unlock()
        return v
    }

    /// Completes the prompt once with `result`, cancels the timeout timer, dismisses the UI cleanly
    /// on the main thread, and invokes the caller completion callback.
    func finish(with result: Int32) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        resultValue = result
        let activeTimer = self.timer
        self.timer = nil
        let comp = self.completion
        self.completion = nil
        let win = self.window
        let parent = self.parentSheetWindow
        self.retainedAlert = nil
        lock.unlock()

        activeTimer?.cancel()

        DispatchQueue.main.async {
            if let parent = parent, let win = win, win.sheetParent === parent {
                parent.endSheet(win, returnCode: .cancel)
            } else {
                win?.orderOut(nil)
            }
        }
        g_macPromptLock.lock()
        if g_activeMacPromptCoordinator === self {
            g_activeMacPromptCoordinator = nil
        }
        g_macPromptLock.unlock()
        comp?(result)
    }

    /// Target-action handler attached to buttons when the alert runs as a standalone floating panel.
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

/// Currently displayed camera consent prompt coordinator (used for remote cancellation or preemption).
private var g_activeMacPromptCoordinator: MacPromptCoordinator?

/// Lock protecting `g_activeMacPromptCoordinator`.
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
/// Must be called from a background worker thread (returns `0` fail-closed if called on `Thread.isMainThread`).
///
/// - Parameters:
///   - peerNamePtr: NUL-terminated UTF-8 C string of the remote peer display name.
///   - timeoutSec: Maximum seconds before prompt automatically dismisses and denies (defaults to 30 when `<= 0`).
/// - Returns:
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
    if Thread.isMainThread {
        return 0
    }

    let peerName: String
    if let ptr = peerNamePtr {
        let parsed = String(cString: ptr).trimmingCharacters(in: .whitespacesAndNewlines)
        peerName = parsed.isEmpty ? "Paired Workstation" : parsed
    } else {
        peerName = "Paired Workstation"
    }

    let effectiveTimeout = timeoutSec > 0 ? Int(timeoutSec) : kCameraConsentDefaultTimeoutSec
    let sem = DispatchSemaphore(value: 0)

    let coordinator = MacPromptCoordinator { _ in
        sem.signal()
    }

    // Cancel any orphaned prior prompt before installing the new active coordinator.
    g_macPromptLock.lock()
    let previous = g_activeMacPromptCoordinator
    g_activeMacPromptCoordinator = coordinator
    g_macPromptLock.unlock()
    previous?.finish(with: 0)

    DispatchQueue.main.async {
        _ = NSApplication.shared
        let alert = NSAlert()
        alert.messageText = "Remote Camera Access Request"
        alert.informativeText = "\(peerName) is requesting to access and stream your Mac camera.\n\nChoose an authorization scope:"
        alert.alertStyle = .warning

        let b1 = alert.addButton(withTitle: "Allow for Session")
        b1.tag = 1
        let b2 = alert.addButton(withTitle: "Allow Once")
        b2.tag = 2
        let b3 = alert.addButton(withTitle: "Always Allow")
        b3.tag = 3
        let b4 = alert.addButton(withTitle: "Deny")
        b4.tag = 4
        let b5 = alert.addButton(withTitle: "Deny & Block")
        b5.tag = 5

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.main)
        timer.schedule(deadline: .now() + .seconds(effectiveTimeout))
        timer.setEventHandler {
            coordinator.finish(with: 0) // Timeout: Deny
        }
        coordinator.attachTimer(timer: timer)
        timer.resume()

        let window = alert.window
        coordinator.window = window
        coordinator.retainedAlert = alert

        if let targetWindow = NSApp?.keyWindow ?? NSApp?.mainWindow {
            // Preserve NSAlert's native sheet button handling so endSheet fires cleanly without stranding parent window.
            coordinator.parentSheetWindow = targetWindow
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
            // Standalone floating alert: route button actions directly through coordinator.
            for btn in [b1, b2, b3, b4, b5] {
                btn.target = coordinator
                btn.action = #selector(MacPromptCoordinator.buttonTapped(_:))
            }
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
    return coordinator.currentResult()
}

/// Presents an explicit modal consent dialog asking the local user if they allow the remote peer
/// to activate and stream the Mac camera.
///
/// - Parameters:
///   - peerNamePtr: UTF-8 C string of the remote peer hostname or device identifier.
/// - Returns: `true` if the local user explicitly clicked an Allow option, `false` if denied or cancelled.
@_cdecl("integrator_mac_prompt_camera_consent")
public func integrator_mac_prompt_camera_consent(peerNamePtr: UnsafePointer<CChar>?) -> Bool {
    let res = integrator_mac_prompt_camera_consent_scoped(
        peerNamePtr: peerNamePtr,
        timeoutSec: Int32(kCameraConsentDefaultTimeoutSec)
    )
    return res > 0
}
