//
//  kvm_macos.swift
//  Integrator Universal Input KVM - macOS Native Quartz & AppKit Driver
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file provides the native macOS implementation for hardware input capture, cursor
//  virtualization, synthetic Quartz injection, and cross-screen drag-and-drop bridging for
//  the Integrator Universal Input KVM subsystem.
//
//  Key Subsystem Capabilities:
//  - Quartz Event Tap (`CGEventTap`): Captures pointer moves, drags, clicks, scroll wheel deltas,
//    and keyboard transitions at the `kCGHIDEventTap` level on a dedicated high-priority Mach port
//    run-loop thread.
//  - Background Cursor Hiding & Warping: Uses private CoreGraphics WindowServer connection properties
//    (`CGSSetConnectionProperty("SetsCursorInBackground")`) and `CGAssociateMouseAndMouseCursorPosition`
//    to seamlessly hide and park the macOS cursor while the user is actively controlling the
//    paired Windows workstation.
//  - IOKit HID Hardware State Synchronization: Interacts directly with the IOKit HID System
//    (`IOHIDSetModifierLockState`, `IOHIDGetModifierLockState`) to synchronize physical Caps Lock
//    LED and latch states between macOS and Windows keyboards.
//  - Liquid Glass Drag Ghost HUD: Renders an AppKit floating translucent panel (`NSVisualEffectView`
//    with `.hudWindow` material) displaying live file transfer badges, thumbnails, and progress
//    during cross-screen file drags.
//  - macOS Sequoia Native `NSDraggingSession` Ingestion: Intercepts active file drags from Finder
//    or other macOS applications via `NSPasteboard(name: .drag)` and synthesizes native drag-and-drop
//    sessions onto local target applications upon remote handoff.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `src/kvm/macos_backend.rs`: Rust FFI bridge that invokes `@_cdecl` entry points:
//    - `integrator_kvm_macos_start_tap`: Starts the Mach port event tap run-loop thread.
//    - `integrator_kvm_macos_stop_tap`: Teardown and unregistration of the tap.
//    - `integrator_kvm_macos_set_controlling`: Toggles background parking and cursor hiding.
//    - `integrator_kvm_macos_inject_*`: Synthesizes remote inputs into the local Quartz event stream.
//    - `integrator_kvm_macos_show_drag_ghost` / `hide_drag_ghost`: Controls the floating HUD badge.
//    - `integrator_kvm_macos_begin_native_drag`: Initiates native AppKit drag sessions.
//
//  Downstream Callees:
//  - CoreGraphics Quartz Services (`CGEventTapCreate`, `CGEventPost`, `CGWarpMouseCursorPosition`).
//  - AppKit (`NSPanel`, `NSVisualEffectView`, `NSDraggingSession`, `NSWorkspace`).
//  - IOKit Framework (`IOServiceGetMatchingService`, `IOHIDSetModifierLockState`).
//  - C FFI Callbacks to Rust: `KvmEventCallback` (`on_cg_event`) and `KvmDragEndedCallback`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Mach Port Run-Loop Thread: The `CGEventTap` executes on a dedicated `Thread` named
//    `"Integrator.KvmEventTap"` with `.userInteractive` QoS. It runs an independent `CFRunLoop`
//    to guarantee zero latency drops or dropped frames even if the main thread is busy.
//  - AppKit UI Thread: All `NSPanel`, `NSWindow`, and `NSView` mutations are dispatched
//    asynchronously to `DispatchQueue.main`.
//  - Synchronization: Thread safety across the C FFI boundary is enforced using discrete locks:
//    - `gStateLock`: Protects atomic flags, callback pointers, and modifier key tracking.
//    - `gTapLifecycleLock`: Guards tap thread startup and shutdown.
//    - `gHidLock`: Guards shared IOKit HID connection handles.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Event Tagging (`kIntegratorEventTag = 0x494E5447`): Every synthetic event posted by Integrator
//    has its `eventSourceUserData` field tagged with "INTG". The `CGEventTap` callback checks this
//    field and immediately passes tagged events through, preventing infinite feedback loops.
//  - Accessibility Permission Verification: `AXIsProcessTrusted()` is verified before creating the
//    tap, preventing crashes or OS security exceptions.
//  - Watchdog Protection: The native drag injector window uses a 600ms `DispatchWorkItem` watchdog
//    that automatically tears down the transparent capture window if an aborted drag occurs,
//    ensuring the desktop never gets blocked by orphan invisible windows.
//

import AppKit
import ApplicationServices
import CoreGraphics
import Foundation
import IOKit
import IOKit.hid

/// Tag attached to all synthetic CGEvents injected by Integrator ("INTG" in ASCII hex: 0x494E5447).
/// Allows the CGEventTap to immediately distinguish injected events from physical user inputs.
private let kIntegratorEventTag: Int64 = 0x494E5447

/// Default fallback X coordinate in Quartz points used when parking the hidden cursor.
private let kDefaultParkX: Double = 400.0

/// Default fallback Y coordinate in Quartz points used when parking the hidden cursor.
private let kDefaultParkY: Double = 300.0

/// Conversion scale factor between Quartz pixel scroll deltas and normalized KVM scroll units.
private let kScrollWheelScaleFactor: Double = 12.0

/// Maximum absolute pixel scroll delta permitted per injected Quartz scroll wheel event.
private let kMaxScrollDelta: Double = 4000.0

/// Synchronous main-thread timeout in milliseconds when probing `NSPasteboard(name: .drag)`.
private let kDragProbeTimeoutMs: Int = 120

/// Synchronous main-thread timeout in milliseconds when rendering a dragged file's PNG icon.
private let kIconGenTimeoutMs: Int = 80

/// Watchdog timeout in milliseconds after which an unstarted native drag capture window auto-dismisses.
private let kDragWatchdogTimeoutMs: Int = 600

/// Startup handshake timeout in seconds while waiting for the `CGEventTap` thread to initialize.
private let kTapStartupTimeoutSec: Int = 2

/// C-ABI callback signatures implemented in Rust (`app/src/kvm/macos_backend.rs`).
///
/// Event kinds:
/// - 1 = MouseMoveAbsOrDelta (x, y, dx, dy, leftHeldMask)
/// - 2 = MouseButton (button: 0=left, 1=right, 2=middle; pressed: 0/1)
/// - 3 = MouseScroll (dx, dy)
/// - 4 = KeyEvent (keyCode, pressed: 0/1, cgFlagsRaw)
/// - 5 = FlagsChanged (keyCode, 0, cgFlagsRaw)
///
/// Return values from Rust:
/// - 0 = Pass through natively to local macOS applications.
/// - 1 = Swallow event (`kCGEventNull`).
/// - 2 = Swallow event and warp cursor to center park position.
public typealias KvmEventCallback = @convention(c) (
    Int32,      // kind
    Double,     // a (x or dx or button or keyCode)
    Double,     // b (y or dy or pressed)
    Double,     // c (dx or flags)
    Double,     // d (dy)
    UInt64      // extra flags / buttonMask
) -> Int32

/// C-ABI callback signature invoked when an AppKit dragging session completes or cancels.
public typealias KvmDragEndedCallback = @convention(c) (Bool, UnsafePointer<CChar>?) -> Void

/// Generic thread-safe container protected by an internal `NSLock`.
private final class SafeBox<T>: @unchecked Sendable {
    /// Lock guarding access to `value`.
    private let lock = NSLock()
    /// Stored value exchanged across thread boundaries.
    private var value: T?

    /// Stores `newValue` atomically under `lock`.
    func set(_ newValue: T?) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    /// Reads the stored value atomically under `lock`.
    func get() -> T? {
        lock.lock()
        let v = value
        lock.unlock()
        return v
    }
}

/// Thread-safe synchronization lock protecting KVM runtime flags, callbacks, and modifier tracking state.
private let gStateLock = NSLock()
/// Serialization lock protecting `CGEventTap` thread creation and teardown (`start_tap` / `stop_tap`).
private let gTapLifecycleLock = NSLock()
/// Lock guarding the shared IOKit HID system connection (`gHidConn`).
private let gHidLock = NSLock()

/// Active Rust callback invoked on captured physical HID events.
private var gKvmCallback: KvmEventCallback? = nil
/// Active Rust callback invoked when a synthesized AppKit dragging session ends or times out.
private var gDragEndedCallback: KvmDragEndedCallback? = nil

/// Active Mach port `CGEventTap` reference (`nil` when stopped).
private var gEventTap: CFMachPort? = nil
/// Dedicated high-priority worker `Thread` executing the event tap `CFRunLoop`.
private var gTapThread: Thread? = nil
/// `CFRunLoop` associated with `gTapThread` (stopped cleanly during teardown).
private var gTapRunLoop: CFRunLoop? = nil

/// True while macOS is actively controlling the remote Windows workstation (local cursor parked/hidden).
private var gControllingPeer: Bool = false
/// Tracks whether `CGDisplayHideCursor` has been invoked on the main thread (balanced with `ShowCursor`).
private var gCursorHidden: Bool = false
/// Drag pasteboard change count recorded on `.leftMouseDown` to detect genuine user drags.
private var gDragChangeCountAtDown: Int = -1

/// X coordinate in Quartz points where the local cursor stays parked while controlling remote peer.
private var gParkX: Double = kDefaultParkX
/// Y coordinate in Quartz points where the local cursor stays parked while controlling remote peer.
private var gParkY: Double = kDefaultParkY
/// Monotonic `CFAbsoluteTimeGetCurrent()` timestamp when controlling mode was most recently entered.
private var gControllingEnteredAt: Double = 0.0

/// Remote-held state for Left Shift (`virtualKey 56`), cleared on disconnect.
private var gRemoteShiftLeft: Bool = false
/// Remote-held state for Right Shift (`virtualKey 60`), cleared on disconnect.
private var gRemoteShiftRight: Bool = false
/// Remote-held state for Left Control (`virtualKey 59`), cleared on disconnect.
private var gRemoteCtrlLeft: Bool = false
/// Remote-held state for Right Control (`virtualKey 62`), cleared on disconnect.
private var gRemoteCtrlRight: Bool = false
/// Remote-held state for Left Option/Alt (`virtualKey 58`), cleared on disconnect.
private var gRemoteAltLeft: Bool = false
/// Remote-held state for Right Option/Alt (`virtualKey 61`), cleared on disconnect.
private var gRemoteAltRight: Bool = false
/// Remote-held state for Left Command/Meta (`virtualKey 55`), cleared on disconnect.
private var gRemoteMetaLeft: Bool = false
/// Remote-held state for Right Command/Meta (`virtualKey 54`), cleared on disconnect.
private var gRemoteMetaRight: Bool = false

/// True once an `atexit` handler restoring mouse-cursor association has been registered.
private var gAtExitRegistered: Bool = false
/// Cached IOKit HID system parameter connection handle (`0` until lazily opened).
private var gHidConn: io_connect_t = 0

/// One-time process-wide configuration of the private WindowServer `SetsCursorInBackground` connection
/// property so `CGDisplayHideCursor` succeeds even while Integrator is not the frontmost app.
private let gConfigureBgCursorOnce: Void = {
    typealias CGSDefaultConnFn = @convention(c) () -> UInt32
    typealias CGSSetConnPropFn = @convention(c) (UInt32, UInt32, CFString, CFTypeRef) -> Int32
    guard let handle = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_LAZY
    ),
    let connSym = dlsym(handle, "CGSMainConnectionID"),
    let propSym = dlsym(handle, "CGSSetConnectionProperty")
    else { return }
    let cid = unsafeBitCast(connSym, to: CGSDefaultConnFn.self)()
    let setProp = unsafeBitCast(propSym, to: CGSSetConnPropFn.self)
    _ = setProp(cid, cid, "SetsCursorInBackground" as CFString, kCFBooleanTrue)
}()

/// Ensures WindowServer background cursor hiding is initialized atomically before any cursor hide call.
private func enableBackgroundCursorHiding() {
    _ = gConfigureBgCursorOnce
}

/// Executes a closure with a valid IOKit HID System connection handle under `gHidLock`.
private func withHidConnection<T>(_ body: (io_connect_t) -> T?) -> T? {
    gHidLock.lock()
    defer { gHidLock.unlock() }
    if gHidConn == 0 {
        let mainPort: mach_port_t = 0
        let service = IOServiceGetMatchingService(
            mainPort,
            IOServiceMatching(kIOHIDSystemClass)
        )
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        var conn: io_connect_t = 0
        guard IOServiceOpen(
            service,
            mach_task_self_,
            UInt32(kIOHIDParamConnectType),
            &conn
        ) == KERN_SUCCESS else {
            return nil
        }
        gHidConn = conn
    }
    return body(gHidConn)
}

/// Toggles the macOS hardware Caps Lock modifier lock state via IOKit HID.
///
/// - Returns: Resulting Caps Lock state (`true` if ON), or `nil` if IOKit query/update failed.
private func toggleMacCapsLock() -> Bool? {
    return withHidConnection { conn in
        var cur = false
        guard IOHIDGetModifierLockState(conn, Int32(kIOHIDCapsLockState), &cur) == KERN_SUCCESS else {
            IOServiceClose(conn)
            gHidConn = 0
            return nil
        }
        let next = !cur
        if IOHIDSetModifierLockState(conn, Int32(kIOHIDCapsLockState), next) == KERN_SUCCESS {
            return next
        }
        IOServiceClose(conn)
        gHidConn = 0
        return nil
    }
}

/// Queries whether the macOS hardware Caps Lock is currently locked on.
///
/// Resets any stale `gHidConn` handle if WindowServer restarted across fast user switch or sleep.
private func currentMacCapsLockOn() -> Bool {
    return withHidConnection { conn in
        var cur = false
        if IOHIDGetModifierLockState(conn, Int32(kIOHIDCapsLockState), &cur) == KERN_SUCCESS {
            return cur
        }
        IOServiceClose(conn)
        gHidConn = 0
        return false
    } ?? false
}

/// Captures all currently held synthetic remote modifier key codes and resets their tracking state.
private func snapshotAndClearRemoteModKeysLocked() -> [UInt16] {
    var downCodes: [UInt16] = []
    if gRemoteShiftLeft { downCodes.append(56) }
    if gRemoteShiftRight { downCodes.append(60) }
    if gRemoteCtrlLeft { downCodes.append(59) }
    if gRemoteCtrlRight { downCodes.append(62) }
    if gRemoteAltLeft { downCodes.append(58) }
    if gRemoteAltRight { downCodes.append(61) }
    if gRemoteMetaLeft { downCodes.append(55) }
    if gRemoteMetaRight { downCodes.append(54) }
    gRemoteShiftLeft = false
    gRemoteShiftRight = false
    gRemoteCtrlLeft = false
    gRemoteCtrlRight = false
    gRemoteAltLeft = false
    gRemoteAltRight = false
    gRemoteMetaLeft = false
    gRemoteMetaRight = false
    return downCodes
}

// MARK: - Virtual Desktop & Multi-Monitor Screen Geometry

/// Queries the unified virtual desktop bounds across all active displays in Quartz global coordinates.
///
/// Supports both single-display Macs and multi-monitor Mac desktop/laptop workstations (including
/// secondary monitors arranged to the left or above the primary display with negative `x`/`y` origins).
@_cdecl("integrator_kvm_macos_screen_rect")
public func integrator_kvm_macos_screen_rect(
    outX: UnsafeMutablePointer<Double>?,
    outY: UnsafeMutablePointer<Double>?,
    outW: UnsafeMutablePointer<Double>?,
    outH: UnsafeMutablePointer<Double>?
) {
    var displayCount: UInt32 = 0
    var unionBounds = CGDisplayBounds(CGMainDisplayID())
    if CGGetActiveDisplayList(0, nil, &displayCount) == .success, displayCount > 1 {
        let maxDisplays = min(displayCount, 32)
        var activeDisplays = [CGDirectDisplayID](repeating: 0, count: Int(maxDisplays))
        var actualCount: UInt32 = 0
        if CGGetActiveDisplayList(maxDisplays, &activeDisplays, &actualCount) == .success, actualCount > 0 {
            var combined = CGRect.null
            for idx in 0..<Int(actualCount) {
                let b = CGDisplayBounds(activeDisplays[idx])
                if b.width > 0 && b.height > 0 {
                    combined = combined.isNull ? b : combined.union(b)
                }
            }
            if !combined.isNull && combined.width > 0 && combined.height > 0 {
                unionBounds = combined
            }
        }
    }
    outX?.pointee = Double(unionBounds.origin.x)
    outY?.pointee = Double(unionBounds.origin.y)
    outW?.pointee = Double(unionBounds.size.width)
    outH?.pointee = Double(unionBounds.size.height)
}

// MARK: - Cursor Visibility & Warp

/// Sets the controlling mode on macOS. When controlling, parks and hides the local cursor.
///
/// - Parameters:
///   - controlling: `true` when Mac is actively controlling Windows (hide/park cursor); `false` to restore.
///   - parkX: Quartz X coordinate where hidden cursor remains parked while controlling Windows.
///   - parkY: Quartz Y coordinate where hidden cursor remains parked while controlling Windows.
///   - restoreX: Quartz X coordinate to warp local cursor back to upon returning control to Mac.
///   - restoreY: Quartz Y coordinate to warp local cursor back to upon returning control to Mac.
@_cdecl("integrator_kvm_macos_set_controlling")
public func integrator_kvm_macos_set_controlling(
    controlling: Bool,
    parkX: Double,
    parkY: Double,
    restoreX: Double,
    restoreY: Double
) {
    let px = parkX.isFinite ? parkX : kDefaultParkX
    let py = parkY.isFinite ? parkY : kDefaultParkY
    let rx = restoreX.isFinite ? restoreX : px
    let ry = restoreY.isFinite ? restoreY : py

    gStateLock.lock()
    gControllingPeer = controlling
    gParkX = px
    gParkY = py
    if controlling {
        gControllingEnteredAt = CFAbsoluteTimeGetCurrent()
    }
    gStateLock.unlock()

    if controlling {
        enableBackgroundCursorHiding()
        CGAssociateMouseAndMouseCursorPosition(boolean_t(0))
        CGWarpMouseCursorPosition(CGPoint(x: px, y: py))
        DispatchQueue.main.async {
            gStateLock.lock()
            let stillControlling = gControllingPeer
            let needHide = stillControlling && !gCursorHidden
            if needHide {
                gCursorHidden = true
            }
            gStateLock.unlock()
            if needHide {
                CGDisplayHideCursor(CGMainDisplayID())
            }
        }
    } else {
        CGWarpMouseCursorPosition(CGPoint(x: rx, y: ry))
        CGAssociateMouseAndMouseCursorPosition(boolean_t(1))
        DispatchQueue.main.async {
            gStateLock.lock()
            let stillNotControlling = !gControllingPeer
            let needShow = stillNotControlling && gCursorHidden
            if needShow {
                gCursorHidden = false
            }
            gStateLock.unlock()
            if needShow {
                CGDisplayShowCursor(CGMainDisplayID())
            }
        }
    }
}

/// Sets the controlled mode on macOS. When entering, shows the cursor and warps to entry coordinates;
/// when leaving controlled mode, releases any tracked synthetic remote modifier keys.
///
/// - Parameters:
///   - controlled: `true` while remote peer is injecting cursor/keyboard events into this Mac.
///   - entryX: Quartz entry cursor X coordinate when entering controlled mode.
///   - entryY: Quartz entry cursor Y coordinate when entering controlled mode.
@_cdecl("integrator_kvm_macos_set_controlled")
public func integrator_kvm_macos_set_controlled(controlled: Bool, entryX: Double, entryY: Double) {
    var modsToRelease: [UInt16] = []
    gStateLock.lock()
    if !controlled {
        modsToRelease = snapshotAndClearRemoteModKeysLocked()
    }
    gStateLock.unlock()

    if !modsToRelease.isEmpty {
        let src = CGEventSource(stateID: .hidSystemState)
        for kc in modsToRelease {
            if let ev = CGEvent(keyboardEventSource: src, virtualKey: kc, keyDown: false) {
                ev.type = .flagsChanged
                ev.flags = [.maskNonCoalesced]
                ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
                ev.post(tap: .cghidEventTap)
            }
        }
    }

    if controlled && entryX.isFinite && entryY.isFinite {
        CGAssociateMouseAndMouseCursorPosition(boolean_t(1))
        DispatchQueue.main.async {
            gStateLock.lock()
            let needShow = gCursorHidden
            if needShow {
                gCursorHidden = false
            }
            gStateLock.unlock()
            if needShow {
                CGDisplayShowCursor(CGMainDisplayID())
            }
            CGWarpMouseCursorPosition(CGPoint(x: entryX, y: entryY))
        }
    }
}

// MARK: - Drag Source Probe (`NSPasteboard(name: .drag)`)

/// Inspects the active AppKit drag pasteboard to retrieve the list of file paths being dragged.
@_cdecl("integrator_kvm_macos_probe_drag_paths")
public func integrator_kvm_macos_probe_drag_paths() -> UnsafeMutablePointer<CChar>? {
    let resultBox = SafeBox<String>()
    let sem = DispatchSemaphore(value: 0)
    let work = {
        let pb = NSPasteboard(name: .drag)
        let currentCount = pb.changeCount
        gStateLock.lock()
        let downCount = gDragChangeCountAtDown
        gStateLock.unlock()

        if currentCount != downCount {
            let opts: [NSPasteboard.ReadingOptionKey: Any] = [.urlReadingFileURLsOnly: true]
            if let urls = pb.readObjects(forClasses: [NSURL.self], options: opts) as? [URL] {
                let paths = urls.filter { $0.isFileURL }.map { $0.path }
                if !paths.isEmpty,
                   let data = try? JSONSerialization.data(withJSONObject: paths),
                   let str = String(data: data, encoding: .utf8)
                {
                    resultBox.set(str)
                }
            }
        }
        sem.signal()
    }
    if Thread.isMainThread {
        work()
    } else {
        DispatchQueue.main.async(execute: work)
        _ = sem.wait(timeout: .now() + .milliseconds(kDragProbeTimeoutMs))
    }
    guard let s = resultBox.get() else { return nil }
    return strdup(s)
}

/// Injects synthetic Escape key to cancel Finder's local drag session after cross-screen handoff.
@_cdecl("integrator_kvm_macos_cancel_local_drag")
public func integrator_kvm_macos_cancel_local_drag() {
    let src = CGEventSource(stateID: .hidSystemState)
    if let down = CGEvent(keyboardEventSource: src, virtualKey: 53, keyDown: true) {
        down.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        down.post(tap: .cghidEventTap)
    }
    if let up = CGEvent(keyboardEventSource: src, virtualKey: 53, keyDown: false) {
        up.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        up.post(tap: .cghidEventTap)
    }
}

/// Generates a Base64-encoded PNG thumbnail icon for the specified file.
@_cdecl("integrator_kvm_macos_icon_png_b64")
public func integrator_kvm_macos_icon_png_b64(pathPtr: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let pathPtr = pathPtr else { return nil }
    let path = String(cString: pathPtr)
    guard !path.isEmpty, FileManager.default.fileExists(atPath: path) else { return nil }

    let resultBox = SafeBox<String>()
    let sem = DispatchSemaphore(value: 0)
    let work = {
        let icon = NSWorkspace.shared.icon(forFile: path)
        let targetSize = NSSize(width: 48, height: 48)
        let img = NSImage(size: targetSize, flipped: false) { rect in
            icon.draw(in: rect, from: .zero, operation: .copy, fraction: 1.0)
            return true
        }
        if let tiff = img.tiffRepresentation,
           let rep = NSBitmapImageRep(data: tiff),
           let png = rep.representation(using: .png, properties: [:])
        {
            if png.count <= 48_000 {
                resultBox.set(png.base64EncodedString())
            }
        }
        sem.signal()
    }
    if Thread.isMainThread {
        work()
    } else {
        DispatchQueue.main.async(execute: work)
        _ = sem.wait(timeout: .now() + .milliseconds(kIconGenTimeoutMs))
    }
    guard let out = resultBox.get() else { return nil }
    return strdup(out)
}

/// Frees heap-allocated C strings returned to Rust.
@_cdecl("integrator_kvm_macos_free_str")
public func integrator_kvm_macos_free_str(ptr: UnsafeMutablePointer<CChar>?) {
    if let p = ptr {
        free(p)
    }
}

// MARK: - Synthetic Input Injection

/// Injects synthetic pointer movement into Quartz at absolute coordinates `(x, y)`.
@_cdecl("integrator_kvm_macos_inject_mouse_move")
public func integrator_kvm_macos_inject_mouse_move(x: Double, y: Double, leftHeld: Bool) {
    guard x.isFinite, y.isFinite else { return }
    let pt = CGPoint(x: x, y: y)
    CGWarpMouseCursorPosition(pt)
    let src = CGEventSource(stateID: .hidSystemState)
    let evType: CGEventType = leftHeld ? .leftMouseDragged : .mouseMoved
    if let ev = CGEvent(mouseEventSource: src, mouseType: evType, mouseCursorPosition: pt, mouseButton: .left) {
        ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        ev.post(tap: .cghidEventTap)
    }
}

/// Injects synthetic mouse button transitions into Quartz.
@_cdecl("integrator_kvm_macos_inject_mouse_button")
public func integrator_kvm_macos_inject_mouse_button(button: Int32, pressed: Bool, x: Double, y: Double) {
    guard x.isFinite, y.isFinite else { return }
    let pt = CGPoint(x: x, y: y)
    CGWarpMouseCursorPosition(pt)
    let src = CGEventSource(stateID: .hidSystemState)
    let cgBtn: CGMouseButton
    let evType: CGEventType
    switch button {
    case 0:
        cgBtn = .left
        evType = pressed ? .leftMouseDown : .leftMouseUp
    case 1:
        cgBtn = .right
        evType = pressed ? .rightMouseDown : .rightMouseUp
    default:
        cgBtn = .center
        evType = pressed ? .otherMouseDown : .otherMouseUp
    }
    if let ev = CGEvent(mouseEventSource: src, mouseType: evType, mouseCursorPosition: pt, mouseButton: cgBtn) {
        ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        ev.post(tap: .cghidEventTap)
    }
}

/// Injects synthetic scroll wheel deltas into Quartz.
@_cdecl("integrator_kvm_macos_inject_scroll")
public func integrator_kvm_macos_inject_scroll(dx: Double, dy: Double) {
    let safeDx = dx.isFinite ? Swift.max(-kMaxScrollDelta, Swift.min(kMaxScrollDelta, dx * kScrollWheelScaleFactor)) : 0.0
    let safeDy = dy.isFinite ? Swift.max(-kMaxScrollDelta, Swift.min(kMaxScrollDelta, dy * kScrollWheelScaleFactor)) : 0.0
    let pxY = Int32(safeDy.rounded())
    let pxX = Int32(safeDx.rounded())
    if pxX == 0 && pxY == 0 { return }
    let src = CGEventSource(stateID: .hidSystemState)
    if let ev = CGEvent(scrollWheelEvent2Source: src, units: .pixel, wheelCount: 2, wheel1: pxY, wheel2: pxX, wheel3: 0) {
        ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        ev.post(tap: .cghidEventTap)
    }
}

/// Injects a synthetic keyboard key transition into Quartz, managing CapsLock and modifier tracking.
@_cdecl("integrator_kvm_macos_inject_key")
public func integrator_kvm_macos_inject_key(keyCode: UInt16, pressed: Bool, shift: Bool, ctrl: Bool, alt: Bool, meta: Bool) {
    let src = CGEventSource(stateID: .hidSystemState)

    // CapsLock (macOS virtualKey 57) must toggle the IOHID CapsLock lock state + emit flagsChanged.
    if keyCode == 57 {
        guard pressed else { return }
        let newCaps = toggleMacCapsLock() ?? !currentMacCapsLockOn()
        gStateLock.lock()
        let sOn = shift || gRemoteShiftLeft || gRemoteShiftRight
        let cOn = ctrl || gRemoteCtrlLeft || gRemoteCtrlRight
        let aOn = alt || gRemoteAltLeft || gRemoteAltRight
        let mOn = meta || gRemoteMetaLeft || gRemoteMetaRight
        gStateLock.unlock()

        if let ev = CGEvent(keyboardEventSource: src, virtualKey: 57, keyDown: true) {
            ev.type = .flagsChanged
            var flags: CGEventFlags = [.maskNonCoalesced]
            if newCaps { flags.insert(.maskAlphaShift) }
            if sOn { flags.insert(.maskShift) }
            if cOn { flags.insert(.maskControl) }
            if aOn { flags.insert(.maskAlternate) }
            if mOn { flags.insert(.maskCommand) }
            ev.flags = flags
            ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
            ev.post(tap: .cghidEventTap)
        }
        return
    }

    let isModifierKey: Bool
    gStateLock.lock()
    switch keyCode {
    case 56: gRemoteShiftLeft = pressed; isModifierKey = true
    case 60: gRemoteShiftRight = pressed; isModifierKey = true
    case 59: gRemoteCtrlLeft = pressed; isModifierKey = true
    case 62: gRemoteCtrlRight = pressed; isModifierKey = true
    case 58: gRemoteAltLeft = pressed; isModifierKey = true
    case 61: gRemoteAltRight = pressed; isModifierKey = true
    case 55: gRemoteMetaLeft = pressed; isModifierKey = true
    case 54: gRemoteMetaRight = pressed; isModifierKey = true
    default: isModifierKey = false
    }
    let effectiveShift = shift || gRemoteShiftLeft || gRemoteShiftRight
    let effectiveCtrl = ctrl || gRemoteCtrlLeft || gRemoteCtrlRight
    let effectiveAlt = alt || gRemoteAltLeft || gRemoteAltRight
    let effectiveMeta = meta || gRemoteMetaLeft || gRemoteMetaRight
    gStateLock.unlock()

    guard let ev = CGEvent(keyboardEventSource: src, virtualKey: keyCode, keyDown: pressed) else {
        return
    }
    if isModifierKey {
        ev.type = .flagsChanged
    }

    var flags: CGEventFlags = [.maskNonCoalesced]
    if ev.flags.contains(.maskAlphaShift) || currentMacCapsLockOn() {
        flags.insert(.maskAlphaShift)
    }
    if ev.flags.contains(.maskNumericPad) {
        flags.insert(.maskNumericPad)
    }
    if ev.flags.contains(.maskSecondaryFn) {
        flags.insert(.maskSecondaryFn)
    }
    if effectiveShift { flags.insert(.maskShift) }
    if effectiveCtrl { flags.insert(.maskControl) }
    if effectiveAlt { flags.insert(.maskAlternate) }
    if effectiveMeta { flags.insert(.maskCommand) }

    ev.flags = flags
    ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
    ev.post(tap: .cghidEventTap)
}

// MARK: - Translucent Liquid Glass Floating Drag Ghost Badge

/// Cached borderless AppKit panel rendering the translucent Liquid Glass drag-and-drop HUD badge.
private var gGhostPanel: NSPanel? = nil
/// Primary title label (dragged file name or item summary) inside `gGhostPanel`.
private var gGhostTitleLabel: NSTextField? = nil
/// Secondary subtitle label (operation / transfer hint) inside `gGhostPanel`.
private var gGhostSubtitleLabel: NSTextField? = nil
/// Thumbnail or SF Symbol icon view inside `gGhostPanel`.
private var gGhostIconView: NSImageView? = nil

/// Creates or returns the cached translucent floating HUD panel on the AppKit main thread.
private func ensureGhostPanel() -> NSPanel {
    if let existing = gGhostPanel {
        return existing
    }
    let panel = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: 256, height: 54),
        styleMask: [.borderless, .nonactivatingPanel],
        backing: .buffered,
        defer: false
    )
    panel.level = .statusBar
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.ignoresMouseEvents = true
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
    panel.sharingType = .none

    let glass = NSVisualEffectView(frame: NSRect(x: 0, y: 0, width: 256, height: 54))
    glass.material = .hudWindow
    glass.blendingMode = .behindWindow
    glass.state = .active
    glass.wantsLayer = true
    glass.layer?.cornerRadius = 14
    glass.layer?.cornerCurve = .continuous
    glass.layer?.borderWidth = 1.0
    glass.layer?.borderColor = NSColor.white.withAlphaComponent(0.24).cgColor

    let iconView = NSImageView(frame: NSRect(x: 12, y: 11, width: 32, height: 32))
    iconView.image = NSImage(systemSymbolName: "doc.on.doc.fill", accessibilityDescription: nil)
    iconView.contentTintColor = .controlAccentColor
    glass.addSubview(iconView)
    gGhostIconView = iconView

    let titleField = NSTextField(labelWithString: "Transferring...")
    titleField.frame = NSRect(x: 52, y: 27, width: 192, height: 17)
    titleField.font = NSFont.systemFont(ofSize: 12.5, weight: .semibold)
    titleField.textColor = .labelColor
    titleField.lineBreakMode = .byTruncatingMiddle
    glass.addSubview(titleField)
    gGhostTitleLabel = titleField

    let subField = NSTextField(labelWithString: "Universal Control • Copy")
    subField.frame = NSRect(x: 52, y: 10, width: 192, height: 14)
    subField.font = NSFont.systemFont(ofSize: 10.5, weight: .regular)
    subField.textColor = .secondaryLabelColor
    subField.lineBreakMode = .byTruncatingTail
    glass.addSubview(subField)
    gGhostSubtitleLabel = subField

    panel.contentView = glass
    gGhostPanel = panel
    return panel
}

/// Converts Quartz top-left global coordinates to AppKit bottom-left global screen coordinates.
///
/// Both coordinate spaces anchor at the primary display (`CGMainDisplayID()`): Quartz Y increases downward
/// from the top edge of the primary display while AppKit Y increases upward from its bottom edge, so
/// `primaryHeight - cgY` remains exact across all multi-monitor arrangements including negative origins.
private func cgPointToAppKitScreenOrigin(cgX: Double, cgY: Double) -> NSPoint {
    let mainH = Double(CGDisplayBounds(CGMainDisplayID()).size.height)
    return NSPoint(x: cgX + 18.0, y: (mainH - cgY) - 62.0)
}

/// Shows the floating translucent drag ghost HUD at Quartz coordinates `(cgX, cgY)`.
///
/// - Parameters:
///   - cgX: Horizontal pointer coordinate in global Quartz points.
///   - cgY: Vertical pointer coordinate in global Quartz points.
///   - titlePtr: Optional NUL-terminated UTF-8 title string (`"Universal Drag"` default).
///   - subtitlePtr: Optional NUL-terminated UTF-8 subtitle string.
///   - iconB64Ptr: Optional NUL-terminated Base64 PNG thumbnail (`<= 80,000` chars).
@_cdecl("integrator_kvm_macos_show_drag_ghost")
public func integrator_kvm_macos_show_drag_ghost(
    cgX: Double,
    cgY: Double,
    titlePtr: UnsafePointer<CChar>?,
    subtitlePtr: UnsafePointer<CChar>?,
    iconB64Ptr: UnsafePointer<CChar>?
) {
    guard cgX.isFinite, cgY.isFinite else { return }
    let title = titlePtr.map { String(cString: $0) } ?? "Universal Drag"
    let subtitle = subtitlePtr.map { String(cString: $0) } ?? "Streaming securely..."
    let iconB64 = iconB64Ptr.map { String(cString: $0) }

    DispatchQueue.main.async {
        let panel = ensureGhostPanel()
        gGhostTitleLabel?.stringValue = title
        gGhostSubtitleLabel?.stringValue = subtitle
        if let b64 = iconB64, b64.count <= 80_000, let raw = Data(base64Encoded: b64), let img = NSImage(data: raw) {
            gGhostIconView?.contentTintColor = nil
            gGhostIconView?.image = img
        } else {
            gGhostIconView?.contentTintColor = .controlAccentColor
            gGhostIconView?.image = NSImage(systemSymbolName: "tray.and.arrow.down.fill", accessibilityDescription: nil)
        }
        panel.setFrameOrigin(cgPointToAppKitScreenOrigin(cgX: cgX, cgY: cgY))
        panel.orderFrontRegardless()
    }
}

/// Moves the active drag ghost HUD window to updated pointer coordinates.
@_cdecl("integrator_kvm_macos_move_drag_ghost")
public func integrator_kvm_macos_move_drag_ghost(cgX: Double, cgY: Double) {
    guard cgX.isFinite, cgY.isFinite else { return }
    DispatchQueue.main.async {
        guard let panel = gGhostPanel, panel.isVisible else { return }
        panel.setFrameOrigin(cgPointToAppKitScreenOrigin(cgX: cgX, cgY: cgY))
    }
}

/// Hides and orders out the drag ghost HUD window.
@_cdecl("integrator_kvm_macos_hide_drag_ghost")
public func integrator_kvm_macos_hide_drag_ghost() {
    DispatchQueue.main.async {
        gGhostPanel?.orderOut(nil)
    }
}

// MARK: - Native Sequoia `NSDraggingSession` Bridge

/// Invisible drag source view that initiates a native AppKit `NSDraggingSession` upon synthetic mouse drag.
private final class IntegratorDragSourceView: NSView, NSDraggingSource {
    /// Local staged file URLs handed off to the native CoreDrag session (capped at 64 items onscreen).
    var fileURLs: [URL] = []
    /// Cross-machine drag transfer session identifier echoed back on completion.
    var sessionId: String = ""
    /// Monotonic token preventing an older aborted drag watchdog from cancelling a newer session.
    var sessionToken: UInt64 = 0
    /// Guards against initiating more than one `NSDraggingSession` per capture cycle.
    var sessionStarted = false
    /// Timeout watchdog dismissing the invisible capture window if dragging fails to begin within 600ms.
    var watchdogWorkItem: DispatchWorkItem? = nil
    /// Weak reference back to the temporary transparent host `NSWindow`.
    weak var hostWindow: NSWindow?

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseDown(with event: NSEvent) {
        // Focus-free initiation
    }

    override func mouseDragged(with event: NSEvent) {
        if sessionStarted || fileURLs.isEmpty { return }
        sessionStarted = true
        watchdogWorkItem?.cancel()
        watchdogWorkItem = nil

        var items: [NSDraggingItem] = []
        for (idx, url) in fileURLs.prefix(64).enumerated() {
            let item = NSDraggingItem(pasteboardWriter: url as NSURL)
            let offset = CGFloat(Swift.min(idx, 4)) * 3.0
            item.setDraggingFrame(
                NSRect(x: 16 + offset, y: 16 - offset, width: 44, height: 44),
                contents: NSWorkspace.shared.icon(forFile: url.path)
            )
            items.append(item)
        }

        _ = beginDraggingSession(with: items, event: event, source: self)
        // Release mouse capture immediately so CoreDrag hands tracking globally to real target windows
        DispatchQueue.main.async {
            self.hostWindow?.ignoresMouseEvents = true
            self.hostWindow?.orderOut(nil)
            gGhostPanel?.orderOut(nil)
        }
    }

    /// Declares `.copy` as the allowed cross-machine drag operation mask.
    func draggingSession(
        _ session: NSDraggingSession,
        sourceOperationMaskFor context: NSDraggingContext
    ) -> NSDragOperation {
        return .copy
    }

    /// Reports drop acceptance or cancellation back to Rust via `gDragEndedCallback`.
    func draggingSession(
        _ session: NSDraggingSession,
        endedAt screenPoint: NSPoint,
        operation: NSDragOperation
    ) {
        let accepted = !operation.isEmpty
        gStateLock.lock()
        let cb = gDragEndedCallback
        gStateLock.unlock()
        if let cb = cb {
            sessionId.withCString { sid in
                cb(accepted, sid)
            }
        }
    }
}

/// Cached invisible window hosting `IntegratorDragSourceView` for synthetic CoreDrag initiation.
private var gDragInjectorWindow: NSWindow? = nil
/// Cached drag source view inside `gDragInjectorWindow`.
private var gDragInjectorView: IntegratorDragSourceView? = nil
/// Monotonically incremented drag generation counter distinguishing overlapping drag sessions.
private var gDragSessionSeq: UInt64 = 0

/// Begins a native macOS AppKit `NSDraggingSession` using staged payload files.
///
/// - Parameters:
///   - pathsJsonPtr: NUL-terminated UTF-8 JSON array of existing local file paths.
///   - sessionIdPtr: Optional NUL-terminated session ID echoed to `gDragEndedCallback`.
///   - cgX: Quartz cursor X coordinate where drag initiation begins.
///   - cgY: Quartz cursor Y coordinate where drag initiation begins.
@_cdecl("integrator_kvm_macos_begin_native_drag")
public func integrator_kvm_macos_begin_native_drag(
    pathsJsonPtr: UnsafePointer<CChar>?,
    sessionIdPtr: UnsafePointer<CChar>?,
    cgX: Double,
    cgY: Double
) {
    guard cgX.isFinite, cgY.isFinite,
          let pathsJsonPtr = pathsJsonPtr,
          let data = String(cString: pathsJsonPtr).data(using: .utf8),
          let paths = try? JSONSerialization.jsonObject(with: data) as? [String],
          !paths.isEmpty
    else { return }

    let sid = sessionIdPtr.map { String(cString: $0) } ?? ""
    let urls = paths.compactMap { path -> URL? in
        guard !path.isEmpty, !path.contains("\0"), FileManager.default.fileExists(atPath: path) else { return nil }
        return URL(fileURLWithPath: path)
    }
    guard !urls.isEmpty else { return }

    DispatchQueue.main.async {
        let win: NSWindow
        let view: IntegratorDragSourceView
        if let w = gDragInjectorWindow, let v = gDragInjectorView {
            win = w
            view = v
        } else {
            win = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 96, height: 96),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            win.level = .floating
            win.isOpaque = false
            // Crucial on macOS Sequoia: non-zero alpha required or WindowServer marks window click-through!
            win.backgroundColor = NSColor(white: 0.5, alpha: 0.01)
            win.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            win.sharingType = .none
            view = IntegratorDragSourceView(frame: NSRect(x: 0, y: 0, width: 96, height: 96))
            view.hostWindow = win
            win.contentView = view
            gDragInjectorWindow = win
            gDragInjectorView = view
        }

        view.watchdogWorkItem?.cancel()
        gDragSessionSeq &+= 1
        let myToken = gDragSessionSeq

        let mainH = Double(CGDisplayBounds(CGMainDisplayID()).size.height)
        let appKitOrigin = NSPoint(x: cgX - 48.0, y: (mainH - cgY) - 48.0)
        view.fileURLs = urls
        view.sessionId = sid
        view.sessionToken = myToken
        view.sessionStarted = false
        win.setFrameOrigin(appKitOrigin)
        win.ignoresMouseEvents = false
        win.orderFrontRegardless()

        // Watchdog guarantees the invisible capture window never stays click-blocking onscreen
        // if synthetic events fail or drag is aborted before mouseDragged fires.
        let watchdog = DispatchWorkItem {
            guard view.sessionToken == myToken && !view.sessionStarted else { return }
            win.ignoresMouseEvents = true
            win.orderOut(nil)
            gGhostPanel?.orderOut(nil)
            gStateLock.lock()
            let cb = gDragEndedCallback
            gStateLock.unlock()
            if let cb = cb {
                sid.withCString { sptr in
                    cb(false, sptr)
                }
            }
        }
        view.watchdogWorkItem = watchdog
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(kDragWatchdogTimeoutMs), execute: watchdog)

        DispatchQueue.global(qos: .userInteractive).asyncAfter(deadline: .now() + .milliseconds(16)) {
            let src = CGEventSource(stateID: .hidSystemState)
            let pDown = CGPoint(x: cgX, y: cgY)
            let pDrag = CGPoint(x: cgX + 6.0, y: cgY)
            if let down = CGEvent(mouseEventSource: src, mouseType: .leftMouseDown, mouseCursorPosition: pDown, mouseButton: .left) {
                down.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
                down.post(tap: .cghidEventTap)
            }
            usleep(12_000)
            if let drag = CGEvent(mouseEventSource: src, mouseType: .leftMouseDragged, mouseCursorPosition: pDrag, mouseButton: .left) {
                drag.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
                drag.post(tap: .cghidEventTap)
            }
        }
    }
}

// MARK: - CGEventTap Hook Thread

/// Thread-safe startup coordinator preventing a timed-out `start_tap` thread from leaving an orphan tap active.
private final class TapStartupCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private var timedOut = false
    private var started = false

    func markTimedOut() {
        lock.lock()
        timedOut = true
        lock.unlock()
    }

    func finishIfActive(started ok: Bool) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if timedOut {
            return false
        }
        started = ok
        return true
    }

    func wasStarted() -> Bool {
        lock.lock()
        let v = started
        lock.unlock()
        return v
    }
}

/// Low-level Mach port callback for the Quartz Event Tap.
private func handleTapEvent(
    proxy: CGEventTapProxy,
    type: CGEventType,
    event: CGEvent
) -> Unmanaged<CGEvent>? {
    if type == .tapDisabledByTimeout {
        gStateLock.lock()
        let tap = gEventTap
        gStateLock.unlock()
        if let tap = tap {
            CGEvent.tapEnable(tap: tap, enable: true)
        }
        return Unmanaged.passUnretained(event)
    }
    if type == .tapDisabledByUserInput {
        return Unmanaged.passUnretained(event)
    }

    // Pass self-injected synthetic CGEvents through cleanly
    if event.getIntegerValueField(.eventSourceUserData) == kIntegratorEventTag {
        return Unmanaged.passUnretained(event)
    }

    if type == .leftMouseDown {
        // Track NSPasteboard(name: .drag) changeCount at press start (non-blocking)
        DispatchQueue.main.async {
            let cnt = NSPasteboard(name: .drag).changeCount
            gStateLock.lock()
            gDragChangeCountAtDown = cnt
            gStateLock.unlock()
        }
    }

    gStateLock.lock()
    let cb = gKvmCallback
    gStateLock.unlock()
    guard let cb = cb else {
        return Unmanaged.passUnretained(event)
    }

    let loc = event.location
    let mask = event.flags.rawValue
    var decision: Int32 = 0

    switch type {
    case .mouseMoved, .leftMouseDragged, .rightMouseDragged, .otherMouseDragged:
        var dx = event.getDoubleValueField(.mouseEventDeltaX)
        var dy = event.getDoubleValueField(.mouseEventDeltaY)
        gStateLock.lock()
        let controllingNow = gControllingPeer
        let enteredAt = gControllingEnteredAt
        gStateLock.unlock()
        if controllingNow && (CFAbsoluteTimeGetCurrent() - enteredAt) < 0.08 {
            if abs(dx) > 220.0 || abs(dy) > 220.0 {
                dx = 0.0
                dy = 0.0
            }
        }
        let leftDown: UInt64 = (type == .leftMouseDragged) ? 1 : 0
        decision = cb(1, Double(loc.x), Double(loc.y), dx, dy, leftDown)

    case .leftMouseDown:
        decision = cb(2, 0.0, 1.0, Double(loc.x), Double(loc.y), mask)
    case .leftMouseUp:
        decision = cb(2, 0.0, 0.0, Double(loc.x), Double(loc.y), mask)
    case .rightMouseDown:
        decision = cb(2, 1.0, 1.0, Double(loc.x), Double(loc.y), mask)
    case .rightMouseUp:
        decision = cb(2, 1.0, 0.0, Double(loc.x), Double(loc.y), mask)
    case .otherMouseDown:
        decision = cb(2, 2.0, 1.0, Double(loc.x), Double(loc.y), mask)
    case .otherMouseUp:
        decision = cb(2, 2.0, 0.0, Double(loc.x), Double(loc.y), mask)

    case .scrollWheel:
        let dy = Double(event.getDoubleValueField(.scrollWheelEventPointDeltaAxis1)) / kScrollWheelScaleFactor
        let dx = Double(event.getDoubleValueField(.scrollWheelEventPointDeltaAxis2)) / kScrollWheelScaleFactor
        decision = cb(3, dx, dy, 0.0, 0.0, mask)

    case .keyDown:
        let kc = Double(event.getIntegerValueField(.keyboardEventKeycode))
        decision = cb(4, kc, 1.0, 0.0, 0.0, mask)
    case .keyUp:
        let kc = Double(event.getIntegerValueField(.keyboardEventKeycode))
        decision = cb(4, kc, 0.0, 0.0, 0.0, mask)
    case .flagsChanged:
        let kc = Double(event.getIntegerValueField(.keyboardEventKeycode))
        decision = cb(5, kc, 0.0, 0.0, 0.0, mask)

    default:
        break
    }

    if decision == 2 {
        gStateLock.lock()
        let px = gParkX
        let py = gParkY
        gStateLock.unlock()
        if abs(loc.x - px) > 3.0 || abs(loc.y - py) > 3.0 {
            CGWarpMouseCursorPosition(CGPoint(x: px, y: py))
        }
        return nil
    } else if decision == 1 {
        return nil
    }
    return Unmanaged.passUnretained(event)
}

/// Checks whether the Quartz Event Tap is currently enabled and Accessibility is trusted.
@_cdecl("integrator_kvm_macos_is_tap_active")
public func integrator_kvm_macos_is_tap_active() -> Bool {
    gStateLock.lock()
    let tap = gEventTap
    gStateLock.unlock()
    guard let tap = tap else { return false }
    return CGEvent.tapIsEnabled(tap: tap) && AXIsProcessTrusted()
}

/// Prompts the user for Accessibility permission if not already granted.
@_cdecl("integrator_kvm_macos_request_accessibility")
public func integrator_kvm_macos_request_accessibility() -> Bool {
    if AXIsProcessTrusted() {
        return true
    }
    let promptWork = {
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(opts)
    }
    if Thread.isMainThread {
        promptWork()
    } else {
        DispatchQueue.main.async(execute: promptWork)
    }
    return AXIsProcessTrusted()
}

/// Starts the Mach port event tap run-loop thread and registers the Quartz callback.
///
/// - Parameters:
///   - cb: Function pointer receiving HID events from the dedicated tap thread.
///   - dragEndedCb: Function pointer invoked upon AppKit dragging session completion or abort.
/// - Returns: `true` if the `CGEventTap` initialized cleanly within 2 seconds; `false` otherwise.
@_cdecl("integrator_kvm_macos_start_tap")
public func integrator_kvm_macos_start_tap(
    cb: KvmEventCallback?,
    dragEndedCb: KvmDragEndedCallback?
) -> Bool {
    gTapLifecycleLock.lock()
    defer { gTapLifecycleLock.unlock() }

    gStateLock.lock()
    gKvmCallback = cb
    gDragEndedCallback = dragEndedCb
    let alreadyTap = gEventTap
    let reg = gAtExitRegistered
    if !reg {
        gAtExitRegistered = true
    }
    gStateLock.unlock()

    enableBackgroundCursorHiding()
    if !reg {
        atexit {
            CGAssociateMouseAndMouseCursorPosition(boolean_t(1))
        }
    }

    if let tap = alreadyTap {
        CGEvent.tapEnable(tap: tap, enable: true)
        return CGEvent.tapIsEnabled(tap: tap) && AXIsProcessTrusted()
    }

    let sem = DispatchSemaphore(value: 0)
    let startup = TapStartupCoordinator()

    let thread = Thread {
        let maskList: [CGEventType] = [
            .mouseMoved, .leftMouseDragged, .rightMouseDragged, .otherMouseDragged,
            .leftMouseDown, .leftMouseUp,
            .rightMouseDown, .rightMouseUp,
            .otherMouseDown, .otherMouseUp,
            .scrollWheel, .keyDown, .keyUp, .flagsChanged,
        ]
        var mask: CGEventMask = 0
        for t in maskList {
            mask |= (1 << t.rawValue)
        }

        let callback: CGEventTapCallBack = { proxy, type, event, _ in
            return handleTapEvent(proxy: proxy, type: type, event: event)
        }

        guard let tap = CGEvent.tapCreate(
            tap: .cghidEventTap,
            place: .headInsertEventTap,
            options: .defaultTap,
            eventsOfInterest: mask,
            callback: callback,
            userInfo: nil
        ), let src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0) else {
            _ = startup.finishIfActive(started: false)
            sem.signal()
            return
        }

        let rl = CFRunLoopGetCurrent()
        gStateLock.lock()
        guard startup.finishIfActive(started: true) else {
            gStateLock.unlock()
            CGEvent.tapEnable(tap: tap, enable: false)
            CFMachPortInvalidate(tap)
            sem.signal()
            return
        }
        gEventTap = tap
        gTapRunLoop = rl
        gStateLock.unlock()

        CFRunLoopAddSource(rl, src, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)
        sem.signal()
        CFRunLoopRun()

        gStateLock.lock()
        if gTapRunLoop === rl {
            gTapRunLoop = nil
            gEventTap = nil
        }
        gStateLock.unlock()
    }
    thread.name = "Integrator.KvmEventTap"
    thread.qualityOfService = .userInteractive
    gStateLock.lock()
    gTapThread = thread
    gStateLock.unlock()
    thread.start()

    let waitRes = sem.wait(timeout: .now() + .seconds(kTapStartupTimeoutSec))
    if waitRes == .timedOut {
        startup.markTimedOut()
    }
    let started = startup.wasStarted()
    if !started {
        gStateLock.lock()
        gTapThread = nil
        gStateLock.unlock()
    }
    return started
}

/// Disables and removes the Quartz Event Tap, releases any held remote modifier keys,
/// restores mouse cursor association, and stops its background run loop.
@_cdecl("integrator_kvm_macos_stop_tap")
public func integrator_kvm_macos_stop_tap() {
    gTapLifecycleLock.lock()
    defer { gTapLifecycleLock.unlock() }

    gStateLock.lock()
    let tap = gEventTap
    let rl = gTapRunLoop
    let modsToRelease = snapshotAndClearRemoteModKeysLocked()
    let wasCursorHidden = gCursorHidden
    gControllingPeer = false
    gCursorHidden = false
    gEventTap = nil
    gTapRunLoop = nil
    gTapThread = nil
    gKvmCallback = nil
    gDragEndedCallback = nil
    gStateLock.unlock()

    // Ensure no synthetic remote modifier keys stay latched if the KVM session shuts down mid-keypress.
    if !modsToRelease.isEmpty {
        let src = CGEventSource(stateID: .hidSystemState)
        for kc in modsToRelease {
            if let ev = CGEvent(keyboardEventSource: src, virtualKey: kc, keyDown: false) {
                ev.type = .flagsChanged
                ev.flags = [.maskNonCoalesced]
                ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
                ev.post(tap: .cghidEventTap)
            }
        }
    }

    if let tap = tap {
        CGEvent.tapEnable(tap: tap, enable: false)
        CFMachPortInvalidate(tap)
    }
    if let rl = rl {
        CFRunLoopStop(rl)
    }
    CGAssociateMouseAndMouseCursorPosition(boolean_t(1))
    if wasCursorHidden {
        DispatchQueue.main.async {
            CGDisplayShowCursor(CGMainDisplayID())
        }
    }
}
