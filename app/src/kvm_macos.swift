import AppKit
import ApplicationServices
import CoreGraphics
import Foundation
import IOKit
import IOKit.hid

// Tag attached to all synthetic CGEvents injected by Integrator so our CGEventTap
// passes them through immediately without re-capturing or feedback-looping.
private let kIntegratorEventTag: Int64 = 0x494E5447 // "INTG"

// Callback signatures implemented in Rust (`app/src/kvm/macos_backend.rs`)
// Event types:
//   1 = MouseMoveAbsOrDelta (x, y, dx, dy, buttonMask)
//   2 = MouseButton (button: 0=left,1=right,2=middle; pressed: 0/1)
//   3 = MouseScroll (dx, dy)
//   4 = KeyEvent (keyCode, pressed: 0/1, cgFlagsRaw)
//   5 = FlagsChanged (keyCode, 0, cgFlagsRaw)
// Returns: 0 = pass through natively, 1 = swallow event, 2 = swallow and warp cursor to center (park_x, park_y)
public typealias KvmEventCallback = @convention(c) (
    Int32,      // kind
    Double,     // a (x or dx or button or keyCode)
    Double,     // b (y or dy or pressed)
    Double,     // c (dx or flags)
    Double,     // d (dy)
    UInt64      // extra flags / buttonMask
) -> Int32

public typealias KvmDragEndedCallback = @convention(c) (Bool, UnsafePointer<CChar>?) -> Void

private final class SafeBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?

    func set(_ newValue: T?) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func get() -> T? {
        lock.lock()
        let v = value
        lock.unlock()
        return v
    }
}

private let gStateLock = NSLock()
private let gTapLifecycleLock = NSLock()
private let gHidLock = NSLock()

private var gKvmCallback: KvmEventCallback? = nil
private var gDragEndedCallback: KvmDragEndedCallback? = nil

private var gEventTap: CFMachPort? = nil
private var gTapThread: Thread? = nil
private var gTapRunLoop: CFRunLoop? = nil
private var gControllingPeer: Bool = false
private var gCursorHidden: Bool = false
private var gDragChangeCountAtDown: Int = -1

private var gParkX: Double = 400.0
private var gParkY: Double = 300.0
private var gControllingEnteredAt: Double = 0.0

private var gRemoteShiftLeft: Bool = false
private var gRemoteShiftRight: Bool = false
private var gRemoteCtrlLeft: Bool = false
private var gRemoteCtrlRight: Bool = false
private var gRemoteAltLeft: Bool = false
private var gRemoteAltRight: Bool = false
private var gRemoteMetaLeft: Bool = false
private var gRemoteMetaRight: Bool = false

private var gBgCursorConfigured: Bool = false
private var gCoreGraphicsHandle: UnsafeMutableRawPointer? = nil
private var gAtExitRegistered: Bool = false
private var gHidConn: io_connect_t = 0

private func enableBackgroundCursorHiding() {
    gStateLock.lock()
    let already = gBgCursorConfigured
    if !already {
        gBgCursorConfigured = true
    }
    gStateLock.unlock()
    if already { return }

    typealias CGSDefaultConnFn = @convention(c) () -> UInt32
    typealias CGSSetConnPropFn = @convention(c) (UInt32, UInt32, CFString, CFTypeRef) -> Int32
    if gCoreGraphicsHandle == nil {
        gCoreGraphicsHandle = dlopen(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
            RTLD_LAZY
        )
    }
    guard let handle = gCoreGraphicsHandle,
          let connSym = dlsym(handle, "CGSMainConnectionID"),
          let propSym = dlsym(handle, "CGSSetConnectionProperty")
    else { return }
    let cid = unsafeBitCast(connSym, to: CGSDefaultConnFn.self)()
    let setProp = unsafeBitCast(propSym, to: CGSSetConnPropFn.self)
    _ = setProp(cid, cid, "SetsCursorInBackground" as CFString, kCFBooleanTrue)
}

private func withHidConnection<T>(_ body: (io_connect_t) -> T?) -> T? {
    gHidLock.lock()
    defer { gHidLock.unlock() }
    if gHidConn == 0 {
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
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
        return nil
    }
}

private func currentMacCapsLockOn() -> Bool {
    return withHidConnection { conn in
        var cur = false
        if IOHIDGetModifierLockState(conn, Int32(kIOHIDCapsLockState), &cur) == KERN_SUCCESS {
            return cur
        }
        return false
    } ?? false
}

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

// MARK: - Primary Screen Geometry

@_cdecl("integrator_kvm_macos_screen_rect")
public func integrator_kvm_macos_screen_rect(
    outX: UnsafeMutablePointer<Double>?,
    outY: UnsafeMutablePointer<Double>?,
    outW: UnsafeMutablePointer<Double>?,
    outH: UnsafeMutablePointer<Double>?
) {
    let bounds = CGDisplayBounds(CGMainDisplayID())
    outX?.pointee = Double(bounds.origin.x)
    outY?.pointee = Double(bounds.origin.y)
    outW?.pointee = Double(bounds.size.width)
    outH?.pointee = Double(bounds.size.height)
}

// MARK: - Cursor Visibility & Warp

@_cdecl("integrator_kvm_macos_set_controlling")
public func integrator_kvm_macos_set_controlling(
    controlling: Bool,
    parkX: Double,
    parkY: Double,
    restoreX: Double,
    restoreY: Double
) {
    let px = parkX.isFinite ? parkX : 400.0
    let py = parkY.isFinite ? parkY : 300.0
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
        _ = sem.wait(timeout: .now() + .milliseconds(120))
    }
    guard let s = resultBox.get() else { return nil }
    return strdup(s)
}

@_cdecl("integrator_kvm_macos_cancel_local_drag")
public func integrator_kvm_macos_cancel_local_drag() {
    // Inject tagged Escape key so Finder exits its local CoreDrag cleanly after handoff
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
        _ = sem.wait(timeout: .now() + .milliseconds(80))
    }
    guard let out = resultBox.get() else { return nil }
    return strdup(out)
}

@_cdecl("integrator_kvm_macos_free_str")
public func integrator_kvm_macos_free_str(ptr: UnsafeMutablePointer<CChar>?) {
    if let p = ptr {
        free(p)
    }
}

// MARK: - Synthetic Input Injection

@_cdecl("integrator_kvm_macos_inject_mouse_move")
public func integrator_kvm_macos_inject_mouse_move(x: Double, y: Double, leftHeld: Bool) {
    guard x.isFinite, y.isFinite else { return }
    let pt = CGPoint(x: x, y: y)
    let src = CGEventSource(stateID: .hidSystemState)
    let evType: CGEventType = leftHeld ? .leftMouseDragged : .mouseMoved
    if let ev = CGEvent(mouseEventSource: src, mouseType: evType, mouseCursorPosition: pt, mouseButton: .left) {
        ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        ev.post(tap: .cghidEventTap)
    }
}

@_cdecl("integrator_kvm_macos_inject_mouse_button")
public func integrator_kvm_macos_inject_mouse_button(button: Int32, pressed: Bool, x: Double, y: Double) {
    guard x.isFinite, y.isFinite else { return }
    let pt = CGPoint(x: x, y: y)
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

@_cdecl("integrator_kvm_macos_inject_scroll")
public func integrator_kvm_macos_inject_scroll(dx: Double, dy: Double) {
    let safeDx = dx.isFinite ? Swift.max(-4000.0, Swift.min(4000.0, dx * 12.0)) : 0.0
    let safeDy = dy.isFinite ? Swift.max(-4000.0, Swift.min(4000.0, dy * 12.0)) : 0.0
    let pxY = Int32(safeDy.rounded())
    let pxX = Int32(safeDx.rounded())
    if pxX == 0 && pxY == 0 { return }
    let src = CGEventSource(stateID: .hidSystemState)
    if let ev = CGEvent(scrollWheelEvent2Source: src, units: .pixel, wheelCount: 2, wheel1: pxY, wheel2: pxX, wheel3: 0) {
        ev.setIntegerValueField(.eventSourceUserData, value: kIntegratorEventTag)
        ev.post(tap: .cghidEventTap)
    }
}

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

private var gGhostPanel: NSPanel? = nil
private var gGhostTitleLabel: NSTextField? = nil
private var gGhostSubtitleLabel: NSTextField? = nil
private var gGhostIconView: NSImageView? = nil

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

private func cgPointToAppKitScreenOrigin(cgX: Double, cgY: Double) -> NSPoint {
    let mainH = Double(CGDisplayBounds(CGMainDisplayID()).size.height)
    return NSPoint(x: cgX + 18.0, y: (mainH - cgY) - 62.0)
}

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

@_cdecl("integrator_kvm_macos_move_drag_ghost")
public func integrator_kvm_macos_move_drag_ghost(cgX: Double, cgY: Double) {
    guard cgX.isFinite, cgY.isFinite else { return }
    DispatchQueue.main.async {
        guard let panel = gGhostPanel, panel.isVisible else { return }
        panel.setFrameOrigin(cgPointToAppKitScreenOrigin(cgX: cgX, cgY: cgY))
    }
}

@_cdecl("integrator_kvm_macos_hide_drag_ghost")
public func integrator_kvm_macos_hide_drag_ghost() {
    DispatchQueue.main.async {
        gGhostPanel?.orderOut(nil)
    }
}

// MARK: - Native Sequoia `NSDraggingSession` Bridge

private final class IntegratorDragSourceView: NSView, NSDraggingSource {
    var fileURLs: [URL] = []
    var sessionId: String = ""
    var sessionToken: UInt64 = 0
    var sessionStarted = false
    var watchdogWorkItem: DispatchWorkItem? = nil
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

    func draggingSession(
        _ session: NSDraggingSession,
        sourceOperationMaskFor context: NSDraggingContext
    ) -> NSDragOperation {
        return .copy
    }

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

private var gDragInjectorWindow: NSWindow? = nil
private var gDragInjectorView: IntegratorDragSourceView? = nil
private var gDragSessionSeq: UInt64 = 0

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
        guard !path.isEmpty, FileManager.default.fileExists(atPath: path) else { return nil }
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
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(600), execute: watchdog)

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
        let dy = Double(event.getDoubleValueField(.scrollWheelEventPointDeltaAxis1)) / 12.0
        let dx = Double(event.getDoubleValueField(.scrollWheelEventPointDeltaAxis2)) / 12.0
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

@_cdecl("integrator_kvm_macos_is_tap_active")
public func integrator_kvm_macos_is_tap_active() -> Bool {
    gStateLock.lock()
    let tap = gEventTap
    gStateLock.unlock()
    guard let tap = tap else { return false }
    return CGEvent.tapIsEnabled(tap: tap) && AXIsProcessTrusted()
}

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
    let startResult = SafeBox<Bool>()

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
        ) else {
            startResult.set(false)
            sem.signal()
            return
        }

        let rl = CFRunLoopGetCurrent()
        gStateLock.lock()
        gEventTap = tap
        gTapRunLoop = rl
        gStateLock.unlock()

        let src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
        CFRunLoopAddSource(rl, src, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)
        startResult.set(true)
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

    _ = sem.wait(timeout: .now() + .seconds(2))
    let started = startResult.get() ?? false
    if !started {
        gStateLock.lock()
        gTapThread = nil
        gStateLock.unlock()
    }
    return started
}

@_cdecl("integrator_kvm_macos_stop_tap")
public func integrator_kvm_macos_stop_tap() {
    gTapLifecycleLock.lock()
    defer { gTapLifecycleLock.unlock() }

    gStateLock.lock()
    let tap = gEventTap
    let rl = gTapRunLoop
    gEventTap = nil
    gTapRunLoop = nil
    gTapThread = nil
    gKvmCallback = nil
    gDragEndedCallback = nil
    gStateLock.unlock()

    if let tap = tap {
        CGEvent.tapEnable(tap: tap, enable: false)
        CFMachPortInvalidate(tap)
    }
    if let rl = rl {
        CFRunLoopStop(rl)
    }
    CGAssociateMouseAndMouseCursorPosition(boolean_t(1))
}
