//
//  touchbar_hud.swift
//  Integrator TouchBar HUD - Liquid Glass Controls & Telemetry Streamer
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file provides the native macOS TouchBar (`NSTouchBar`) HUD controller for MacBook Pro
//  models, implementing tactile hardware-level monitoring, remote clipboard paste interception,
//  and interactive liquid-glass controls.
//
//  Key Subsystem Capabilities:
//  - Viscous Liquid Glass Pill Views (`GoopyLiquidGlassPillView`): Implements squishy, rubber-band
//    drag-stretch physics with Spring animations, Frosted HUD blur materials (`NSVisualEffectView`
//    with `.hudWindow`), and continuous corner curves.
//  - Live Telemetry Streamer: Displays real-time GPU metrics from the connected Windows 11 host
//    (GPU temperature °C, clock speed MHz, power consumption W, VRAM utilization %, display latency ms,
//    and frame rates).
//  - Remote File Paste Interceptor (`PasteboardShortcutInterceptor`): Installs a passive `CGEventTap`
//    listening for `Cmd+V`. When a remote file announcement is pending, it intercepts the shortcut,
//    updates the TouchBar with a haptic pulse, and triggers asynchronous zero-RAM streaming via
//    `trigger_rust_remote_paste()`.
//  - In-App Pasteboard Native File Helper: Implements `read_pasteboard_files_in_app` and
//    `write_pasteboard_files_in_app` using `\0`-delimited UTF-8 byte arrays directly on the main
//    AppKit thread, avoiding external helper process spawn latency.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `src/clipboard/service.rs`: Invokes C-ABI functions:
//    - `notify_touchbar_remote_file`: Announces pending remote files on TouchBar.
//    - `update_touchbar_paste_progress`: Telemeters transfer % and MB/s stream velocity.
//    - `reset_touchbar_paste_progress`: Clears transfer indicators upon completion.
//  - `src/clipboard/file_helper.rs`: Calls `read_pasteboard_files_in_app` and `write_pasteboard_files_in_app`.
//
//  Downstream Callees:
//  - AppKit TouchBar Framework (`NSTouchBar`, `NSTouchBarItem`, `NSCustomTouchBarItem`).
//  - Quartz Core Graphics (`CGEventTapCreate`, `CGEventPost`).
//  - Rust FFI: Calls `trigger_rust_remote_paste()` to initiate asynchronous file streaming.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - AppKit Main Thread: All TouchBar UI item creation and label updates execute on `DispatchQueue.main`.
//  - Shortcut Interceptor RunLoop: The `CGEventTap` executes on a dedicated Mach port `Thread`.
//  - Async Rust Handoff: Shortcut triggers dispatch to `DispatchQueue.global(qos: .userInitiated)`
//    before invoking `trigger_rust_remote_paste()`, ensuring the UI thread is never blocked.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Stale Paste Expiration: In-flight paste sessions automatically expire after 60 seconds if
//    the remote host fails to stream data, unblocking future paste shortcuts.
//  - Buffer Capacity Verification: `read_pasteboard_files_in_app` strictly verifies output buffer
//    capacities before copying NUL-delimited bytes, returning `-1` on overflow.
//

import AppKit
import Foundation
import IOKit

// MARK: - RPC Data Models
struct GpuTelemetryData: Codable {
    let gpu_name: String
    let temperature_c: UInt32
    let power_usage_watts: Float
    let gpu_utilization_percent: UInt32
    let memory_utilization_percent: UInt32
    let memory_used_mb: UInt64
    let memory_total_mb: UInt64
    let core_clock_mhz: UInt32
}

struct DisplayRpcResponseData: Codable {
    let success: Bool
    let message: String
    let is_active: Bool
    let active_mode: String?
    let gpu_telemetry: GpuTelemetryData?
}

// MARK: - Goopy Liquid Glass Pill View (Viscous Squishy + Drag-Stretch Physics)
class GoopyLiquidGlassPillView: NSView {
    let visualEffectView = NSVisualEffectView()
    let label = NSTextField(labelWithString: "")
    var accentColor: NSColor = .systemGreen {
        didSet { updateRestingStyle() }
    }
    var onTap: (() -> Void)?

    private var initialTouchPoint: CGPoint = .zero
    private var isHeld: Bool = false
    private let pillWidth: CGFloat

    init(text: String, accent: NSColor, width: CGFloat = 88) {
        self.pillWidth = width
        self.accentColor = accent
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: 30))
        setup(text: text)
    }

    required init?(coder: NSCoder) {
        self.pillWidth = 88
        super.init(coder: coder)
    }

    override var intrinsicContentSize: NSSize {
        return NSSize(width: pillWidth, height: 30)
    }

    func setup(text: String) {
        wantsLayer = true
        layer?.masksToBounds = false
        allowedTouchTypes = [.direct]

        // 1. Frosted Glass Blur Backdrop
        visualEffectView.frame = bounds
        visualEffectView.autoresizingMask = [.width, .height]
        visualEffectView.material = .hudWindow
        visualEffectView.blendingMode = .withinWindow
        visualEffectView.state = .active
        visualEffectView.wantsLayer = true
        visualEffectView.layer?.cornerRadius = 9
        visualEffectView.layer?.masksToBounds = true
        addSubview(visualEffectView)

        // 2. High-Legibility Monospace Centered Typography via AutoLayout
        label.translatesAutoresizingMaskIntoConstraints = false
        label.alignment = .center
        label.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .bold)
        label.textColor = .white
        label.backgroundColor = .clear
        label.isBezeled = false
        label.isEditable = false
        label.isSelectable = false
        label.maximumNumberOfLines = 1
        label.lineBreakMode = .byTruncatingTail
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        label.stringValue = text
        addSubview(label)

        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 6),
            label.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -6)
        ])

        updateRestingStyle()
    }

    func setText(_ newText: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.stringValue = newText
        }
    }

    func setAccent(_ color: NSColor) {
        DispatchQueue.main.async { [weak self] in
            self?.accentColor = color
        }
    }

    func updateRestingStyle() {
        guard !isHeld else { return }
        layer?.shadowColor = accentColor.cgColor
        layer?.shadowOffset = .zero
        layer?.shadowRadius = 6.0
        layer?.shadowOpacity = 0.0

        visualEffectView.layer?.borderWidth = 0.5
        visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.18).cgColor
        visualEffectView.layer?.backgroundColor = accentColor.withAlphaComponent(0.12).cgColor
    }

    // MARK: - Direct Touch & Mouse Interaction
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { return true }
    override var acceptsFirstResponder: Bool { return true }

    override func touchesBegan(with event: NSEvent) {
        guard let touch = event.touches(matching: .began, in: self).first else { return }
        beginInteraction(at: touch.location(in: self))
    }

    override func touchesMoved(with event: NSEvent) {
        guard isHeld, let touch = event.touches(matching: .moved, in: self).first else { return }
        updateDragStretch(currentPoint: touch.location(in: self))
    }

    override func touchesEnded(with event: NSEvent) {
        endInteraction(triggerTap: true)
    }

    override func touchesCancelled(with event: NSEvent) {
        endInteraction(triggerTap: false)
    }

    override func mouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        beginInteraction(at: pt)
    }

    override func mouseDragged(with event: NSEvent) {
        guard isHeld else { return }
        let pt = convert(event.locationInWindow, from: nil)
        updateDragStretch(currentPoint: pt)
    }

    override func mouseUp(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let inside = bounds.contains(pt)
        endInteraction(triggerTap: inside)
    }

    // MARK: - Goopy Liquid Physics Engine
    private func beginInteraction(at point: CGPoint) {
        guard !isHeld else { return }
        isHeld = true
        initialTouchPoint = point

        NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)

        // Faint diffuse overall glow applied to whole button (NO solid border)
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.10
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            self.layer?.shadowColor = self.accentColor.cgColor
            self.layer?.shadowRadius = 14.0
            self.layer?.shadowOpacity = 0.60
            self.layer?.transform = CATransform3DScale(CATransform3DIdentity, 0.94, 0.90, 1.0)
            self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.24).cgColor
            self.visualEffectView.layer?.borderWidth = 0.6
            self.visualEffectView.layer?.borderColor = self.accentColor.withAlphaComponent(0.30).cgColor
        }
    }

    private func updateDragStretch(currentPoint: CGPoint) {
        let deltaX = currentPoint.x - initialTouchPoint.x
        let deltaY = currentPoint.y - initialTouchPoint.y
        let distance = hypot(deltaX, deltaY)

        if distance < 1.5 {
            self.layer?.transform = CATransform3DScale(CATransform3DIdentity, 0.94, 0.90, 1.0)
            return
        }

        let angle = atan2(deltaY, deltaX)
        // Viscous elongation along drag axis; perpendicular necking preserving volume
        let stretch = 1.0 + min(distance / 50.0, 0.85)
        let pinch = max(1.0 / sqrt(stretch), 0.60)
        let dragX = deltaX * 0.42
        let dragY = deltaY * 0.42

        var t = CATransform3DIdentity
        let w = bounds.width
        let h = bounds.height
        t = CATransform3DTranslate(t, w / 2.0, h / 2.0, 0)
        t = CATransform3DTranslate(t, dragX, dragY, 0)
        t = CATransform3DRotate(t, angle, 0, 0, 1)
        t = CATransform3DScale(t, stretch, pinch, 1.0)
        t = CATransform3DRotate(t, -angle, 0, 0, 1)
        t = CATransform3DTranslate(t, -w / 2.0, -h / 2.0, 0)

        CATransaction.begin()
        CATransaction.setDisableActions(true)
        self.layer?.transform = t
        self.layer?.shadowRadius = 14.0 + min(distance / 5.0, 8.0)
        CATransaction.commit()
    }

    private func endInteraction(triggerTap: Bool) {
        guard isHeld else { return }
        isHeld = false

        NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)

        let currentT = self.layer?.transform ?? CATransform3DIdentity
        // High-viscosity jelly recoil spring animation
        let spring = CASpringAnimation(keyPath: "transform")
        spring.mass = 0.8
        spring.stiffness = 260.0
        spring.damping = 9.5
        spring.initialVelocity = 26.0
        spring.fromValue = NSValue(caTransform3D: currentT)
        spring.toValue = NSValue(caTransform3D: CATransform3DIdentity)
        spring.duration = spring.settlingDuration

        self.layer?.transform = CATransform3DIdentity
        self.layer?.add(spring, forKey: "goopySnapBack")

        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.35
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            self.layer?.shadowOpacity = 0.0
            self.layer?.shadowRadius = 6.0
            self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.12).cgColor
            self.visualEffectView.layer?.borderWidth = 0.5
            self.visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.18).cgColor
        }

        if triggerTap {
            onTap?()
        }
    }
}

// MARK: - Touch Bar Controller (Singleton within Main App)
@objc public class TouchBarHudController: NSObject, NSTouchBarDelegate {
    public static let shared = TouchBarHudController()

    private static let rpcPort: UInt16 = 58281
    private let stateLock = NSLock()

    private var _isActive: Bool = false
    public var isActive: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive
    }

    private var _peerIp: String? = nil
    var peerIp: String? {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _peerIp
        }
        set {
            stateLock.lock()
            _peerIp = Self.normalizedIp(newValue)
            stateLock.unlock()
        }
    }

    private var _generation: UInt64 = 0
    private var isPollingInFlight: Bool = false
    private var lastKnownGpuName: String? = nil
    private var pendingPasteText: String? = nil

    private func isGenerationCurrent(_ gen: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive && _generation == gen
    }

    var touchBar: NSTouchBar?
    var pollTimer: Timer?

    // Goopy Liquid Glass Pill Views
    var viewGpu: GoopyLiquidGlassPillView?
    var viewTemp: GoopyLiquidGlassPillView?
    var viewPower: GoopyLiquidGlassPillView?
    var viewClock: GoopyLiquidGlassPillView?
    var viewVram: GoopyLiquidGlassPillView?
    var viewUtil: GoopyLiquidGlassPillView?
    var viewPaste: GoopyLiquidGlassPillView?

    private static func normalizedIp(_ raw: String?) -> String? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        var addr4 = in_addr()
        var addr6 = in6_addr()
        if inet_pton(AF_INET, trimmed, &addr4) == 1 || inet_pton(AF_INET6, trimmed, &addr6) == 1 {
            return trimmed
        }
        return nil
    }

    private static let cachedTouchBarSupported: Bool = {
        let presentSelPlacement = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        let presentSelLegacy = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
        let hasModalApi =
            (NSTouchBar.responds(to: presentSelPlacement) && class_getClassMethod(NSTouchBar.self, presentSelPlacement) != nil) ||
            (NSTouchBar.responds(to: presentSelLegacy) && class_getClassMethod(NSTouchBar.self, presentSelLegacy) != nil)
        guard hasModalApi else { return false }

        if !NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.controlstrip").isEmpty {
            return true
        }

        if let dfrHandle = dlopen("/System/Library/PrivateFrameworks/DFRFoundation.framework/DFRFoundation", RTLD_LAZY) {
            defer { dlclose(dfrHandle) }
            if let dfrSym = dlsym(dfrHandle, "DFRGetScreenSize") {
                typealias DfrSizeFn = @convention(c) () -> CGSize
                let fn = unsafeBitCast(dfrSym, to: DfrSizeFn.self)
                let size = fn()
                if size.width > 0 && size.height > 0 {
                    return true
                }
            }
        }

        let mainPort: mach_port_t = 0
        if let matchDispdfr = IOServiceNameMatching("dispdfr") {
            let service = IOServiceGetMatchingService(mainPort, matchDispdfr)
            if service != 0 {
                IOObjectRelease(service)
                return true
            }
        }

        if let matchDfr = IOServiceMatching("AppleDFR") {
            let service = IOServiceGetMatchingService(mainPort, matchDfr)
            if service != 0 {
                IOObjectRelease(service)
                return true
            }
        }

        return false
    }()

    /// Detects whether this Mac has Touch Bar hardware / ControlStrip / DFR runtime
    /// and NSTouchBar system-modal presentation support (cached after first probe).
    public static func isTouchBarSupported() -> Bool {
        return cachedTouchBarSupported
    }

    private static func formatByteSize(_ totalBytes: UInt64) -> String {
        let bytes = Double(totalBytes)
        let gb = 1024.0 * 1024.0 * 1024.0
        let mb = 1024.0 * 1024.0
        let kb = 1024.0
        if bytes >= gb {
            return String(format: "%.1f GB", bytes / gb)
        }
        if bytes >= 10.0 * mb {
            return String(format: "%.0f MB", bytes / mb)
        }
        if bytes >= mb {
            return String(format: "%.1f MB", bytes / mb)
        }
        if totalBytes >= 1024 {
            return String(format: "%.0f KB", bytes / kb)
        }
        return "\(totalBytes) B"
    }

    public func showRemotePasteButton(name: String, totalBytes: UInt64) {
        guard Self.isTouchBarSupported() else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let sizeStr = Self.formatByteSize(totalBytes)
            let btnText = "📥 Paste \(name) (\(sizeStr))"
            self.pendingPasteText = btnText

            if !self.isActive {
                self.activateOnMainThread()
            }

            if let existing = self.viewPaste {
                existing.setText(btnText)
                existing.setAccent(NSColor.systemCyan)
                existing.isHidden = false
            }

            if let tb = self.touchBar {
                let idPaste = NSTouchBarItem.Identifier("paste_remote")
                if !tb.defaultItemIdentifiers.contains(idPaste) {
                    var items = tb.defaultItemIdentifiers
                    items.insert(idPaste, at: 0)
                    tb.defaultItemIdentifiers = items
                }
            }
        }
    }

    public func updatePasteProgress(percent: Float, mbPerSec: Float) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let view = self.viewPaste else { return }
            view.setText(String(format: "📥 %.0f%% • %.0f MB/s", percent, mbPerSec))
            view.setAccent(NSColor.systemGreen)
        }
    }

    public func resetPasteButton() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.pendingPasteText = nil
            if let tb = self.touchBar {
                let idPaste = NSTouchBarItem.Identifier("paste_remote")
                tb.defaultItemIdentifiers.removeAll { $0 == idPaste }
            }
            self.viewPaste?.isHidden = true
        }
    }

    private override init() {
        super.init()
    }

    public func launch_touchbar_hud(peerIp: String? = nil) {
        start(peerIp: peerIp)
    }

    public func start(peerIp: String? = nil) {
        guard Self.isTouchBarSupported() else {
            NSLog("ℹ️ [TouchBarHud] Touch Bar DF/NSTouchBar support not detected on this Mac; skipping HUD launch.")
            return
        }

        if let raw = peerIp {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                self.peerIp = nil
            } else if let normalized = Self.normalizedIp(trimmed) {
                self.peerIp = normalized
            } else {
                NSLog("⚠️ [TouchBarHud] Ignoring invalid peer IP argument; refusing launch.")
                self.peerIp = nil
                return
            }
        } else {
            self.peerIp = nil
        }

        let block = { [weak self] in
            guard let self = self else { return }
            if self.isActive {
                self.queryTelemetry()
                return
            }
            self.activateOnMainThread()
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func activateOnMainThread() {
        guard Self.isTouchBarSupported() else { return }
        guard !self.isActive else { return }
        guard self.setupTouchBar() else { return }

        stateLock.lock()
        _generation &+= 1
        _isActive = true
        stateLock.unlock()

        self.startPolling()
        NSLog("🚀 Integrator Touch Bar GPU HUD active.")
    }

    public func dismiss() {
        let block = { [weak self] in
            guard let self = self else { return }
            self.stateLock.lock()
            let wasActive = self._isActive
            self._isActive = false
            self._generation &+= 1
            self.stateLock.unlock()

            guard wasActive || self.touchBar != nil || self.pollTimer != nil else { return }

            self.pollTimer?.invalidate()
            self.pollTimer = nil

            if let tb = self.touchBar {
                let sel = NSSelectorFromString("dismissSystemModalTouchBar:")
                if NSTouchBar.responds(to: sel),
                   let method = class_getClassMethod(NSTouchBar.self, sel) {
                    typealias DismissFunc = @convention(c) (AnyClass, Selector, AnyObject) -> Void
                    let imp = method_getImplementation(method)
                    let fn = unsafeBitCast(imp, to: DismissFunc.self)
                    fn(NSTouchBar.self, sel, tb)
                }
            }

            self.touchBar = nil
            self.viewGpu = nil
            self.viewTemp = nil
            self.viewPower = nil
            self.viewClock = nil
            self.viewVram = nil
            self.viewUtil = nil
            self.viewPaste = nil
            NSLog("🚀 Integrator Touch Bar GPU HUD dismissed.")
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    @discardableResult
    func setupTouchBar() -> Bool {
        guard Self.isTouchBarSupported() else { return false }

        let tb = NSTouchBar()
        tb.delegate = self

        tb.defaultItemIdentifiers = [
            NSTouchBarItem.Identifier("gpu"),
            NSTouchBarItem.Identifier("temp"),
            NSTouchBarItem.Identifier("power"),
            NSTouchBarItem.Identifier("clock"),
            NSTouchBarItem.Identifier("vram"),
            NSTouchBarItem.Identifier("util")
        ]

        // Placement: 0 (NSTouchBarPlacementDefault) keeps the native macOS Control Strip intact.
        let sel = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        if NSTouchBar.responds(to: sel),
           let method = class_getClassMethod(NSTouchBar.self, sel) {
            self.touchBar = tb
            typealias PresentFunc = @convention(c) (AnyClass, Selector, AnyObject, Int64, AnyObject?) -> Void
            let imp = method_getImplementation(method)
            let fn = unsafeBitCast(imp, to: PresentFunc.self)
            fn(NSTouchBar.self, sel, tb, 0, nil)
            NSLog("🚀 Integrator Touch Bar GPU HUD presented (placement 0, Control Strip preserved)")
            return true
        }

        let sel2 = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
        if NSTouchBar.responds(to: sel2),
           let method2 = class_getClassMethod(NSTouchBar.self, sel2) {
            self.touchBar = tb
            typealias PresentFunc2 = @convention(c) (AnyClass, Selector, AnyObject, AnyObject?) -> Void
            let imp2 = method_getImplementation(method2)
            let fn2 = unsafeBitCast(imp2, to: PresentFunc2.self)
            fn2(NSTouchBar.self, sel2, tb, nil)
            NSLog("🚀 Integrator Touch Bar GPU HUD presented (legacy modal API)")
            return true
        }

        return false
    }

    public func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        let item = NSCustomTouchBarItem(identifier: identifier)
        switch identifier.rawValue {
        case "gpu":
            let v = GoopyLiquidGlassPillView(text: "Peer Offline", accent: .systemGray, width: 118)
            self.viewGpu = v
            item.view = v
            item.visibilityPriority = .high
        case "temp":
            let v = GoopyLiquidGlassPillView(text: "🌡️ --°C", accent: .systemGray, width: 74)
            self.viewTemp = v
            item.view = v
            item.visibilityPriority = .high
        case "power":
            let v = GoopyLiquidGlassPillView(text: "⚡ --W", accent: .systemGray, width: 72)
            self.viewPower = v
            item.view = v
            item.visibilityPriority = .low
        case "clock":
            let v = GoopyLiquidGlassPillView(text: "🚀 -- MHz", accent: .systemGray, width: 86)
            self.viewClock = v
            item.view = v
            item.visibilityPriority = .low
        case "vram":
            let v = GoopyLiquidGlassPillView(text: "💾 -- / -- GB", accent: .systemGray, width: 102)
            self.viewVram = v
            item.view = v
            item.visibilityPriority = .normal
        case "util":
            let v = GoopyLiquidGlassPillView(text: "📊 --% GPU", accent: .systemGray, width: 82)
            self.viewUtil = v
            item.view = v
            item.visibilityPriority = .high
        case "paste_remote":
            let initialText = self.pendingPasteText ?? "📥 Paste"
            let v = GoopyLiquidGlassPillView(text: initialText, accent: NSColor.systemCyan, width: 155)
            v.onTap = { [weak v] in
                v?.setText("⏳ Streaming...")
                DispatchQueue.global(qos: .userInitiated).async {
                    trigger_rust_remote_paste()
                }
            }
            self.viewPaste = v
            item.view = v
            item.visibilityPriority = .high
        default:
            return nil
        }
        return item
    }

    func startPolling() {
        self.pollTimer?.invalidate()
        queryTelemetry()
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.queryTelemetry()
        }
        RunLoop.main.add(timer, forMode: .common)
        self.pollTimer = timer
    }

    func queryTelemetry() {
        stateLock.lock()
        guard _isActive, !isPollingInFlight else {
            stateLock.unlock()
            return
        }
        let gen = _generation
        isPollingInFlight = true
        stateLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            defer {
                self.stateLock.lock()
                self.isPollingInFlight = false
                self.stateLock.unlock()
            }
            guard self.isGenerationCurrent(gen) else { return }

            guard let host = self.peerIp else {
                self.updateOfflineUi(statusText: "Peer Offline", expectedGeneration: gen)
                return
            }

            guard let response = self.sendRpcRequest(host: host, port: Self.rpcPort, requestJson: "\"GetGpuTelemetry\"") else {
                self.updateOfflineUi(statusText: "Peer Offline", expectedGeneration: gen)
                return
            }
            guard self.isGenerationCurrent(gen) else { return }

            if response.success, let telemetry = response.gpu_telemetry {
                self.updateUi(with: telemetry, expectedGeneration: gen)
            } else {
                self.updateOfflineUi(statusText: "Telemetry N/A", expectedGeneration: gen)
            }
        }
    }

    private func sendRpcRequest(host: String, port: UInt16, requestJson: String) -> DisplayRpcResponseData? {
        let _ = port
        let _ = requestJson
        let bufCap = 65_536
        var outBuf = [UInt8](repeating: 0, count: bufCap)
        let n = host.withCString { cHost -> Int in
            outBuf.withUnsafeMutableBufferPointer { bufPtr -> Int in
                fetch_rust_gpu_telemetry_json(cHost, bufPtr.baseAddress, bufCap)
            }
        }
        guard n > 0 && n <= bufCap else { return nil }
        let respData = Data(outBuf.prefix(n))
        guard let decoded = try? JSONDecoder().decode(DisplayRpcResponseData.self, from: respData) else {
            return nil
        }
        if let t = decoded.gpu_telemetry, !t.power_usage_watts.isFinite {
            return nil
        }
        return decoded
    }

    private func compactGpuName(_ raw: String) -> String {
        var name = raw
            .replacingOccurrences(of: "(R)", with: "")
            .replacingOccurrences(of: "(TM)", with: "")
            .replacingOccurrences(of: "®", with: "")
            .replacingOccurrences(of: "™", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        while name.contains("  ") {
            name = name.replacingOccurrences(of: "  ", with: " ")
        }

        if name.isEmpty {
            return "GPU"
        }

        let removableSuffixes = [" Laptop GPU", " Graphics"]
        for suffix in removableSuffixes where name.count > 14 && name.hasSuffix(suffix) {
            name = String(name.dropLast(suffix.count)).trimmingCharacters(in: .whitespaces)
        }

        let removablePrefixes = ["NVIDIA ", "GeForce ", "AMD ", "Radeon ", "Intel "]
        for prefix in removablePrefixes where name.count > 14 && name.hasPrefix(prefix) {
            name = String(name.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        }

        let maxChars = 14
        if name.count > maxChars {
            return String(name.prefix(maxChars - 1)) + "…"
        }
        return name
    }

    func updateOfflineUi(statusText: String = "Peer Offline", expectedGeneration: UInt64? = nil) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if let gen = expectedGeneration {
                guard self.isGenerationCurrent(gen) else { return }
            } else {
                guard self.isActive else { return }
            }
            self.viewGpu?.setText(statusText)
            self.viewGpu?.setAccent(.systemGray)

            self.viewTemp?.setText("🌡️ --°C")
            self.viewTemp?.setAccent(.systemGray)

            self.viewPower?.setText("⚡ --W")
            self.viewPower?.setAccent(.systemGray)

            self.viewClock?.setText("🚀 -- MHz")
            self.viewClock?.setAccent(.systemGray)

            self.viewVram?.setText("💾 -- / -- GB")
            self.viewVram?.setAccent(.systemGray)

            self.viewUtil?.setText("📊 --% GPU")
            self.viewUtil?.setAccent(.systemGray)
        }
    }

    func updateUi(with t: GpuTelemetryData, expectedGeneration: UInt64? = nil) {
        self.stateLock.lock()
        self.lastKnownGpuName = t.gpu_name
        self.stateLock.unlock()

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if let gen = expectedGeneration {
                guard self.isGenerationCurrent(gen) else { return }
            } else {
                guard self.isActive else { return }
            }
            let hasLiveCounters =
                t.temperature_c > 0 ||
                t.power_usage_watts > 0.05 ||
                t.core_clock_mhz > 0 ||
                t.gpu_utilization_percent > 0

            // 0. Dynamic GPU Name (compactly truncated for Touch Bar width)
            if let v = self.viewGpu {
                v.setText("🎮 \(self.compactGpuName(t.gpu_name))")
                v.setAccent(NSColor(red: 0.25, green: 0.72, blue: 0.95, alpha: 1.0))
            }

            // 1. Temperature with Dynamic Thermal Color
            if let v = self.viewTemp {
                if t.temperature_c > 0 {
                    v.setText("🌡️ \(t.temperature_c)°C")
                    if t.temperature_c < 55 {
                        v.setAccent(NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0))
                    } else if t.temperature_c < 75 {
                        v.setAccent(NSColor(red: 0.95, green: 0.55, blue: 0.1, alpha: 1.0))
                    } else {
                        v.setAccent(NSColor(red: 0.95, green: 0.2, blue: 0.2, alpha: 1.0))
                    }
                } else {
                    v.setText("🌡️ --°C")
                    v.setAccent(.systemGray)
                }
            }

            // 2. Power Draw
            if let v = self.viewPower {
                if t.power_usage_watts > 0.05 {
                    v.setText(String(format: "⚡ %.1fW", t.power_usage_watts))
                    v.setAccent(NSColor(red: 0.95, green: 0.65, blue: 0.1, alpha: 1.0))
                } else {
                    v.setText("⚡ --W")
                    v.setAccent(.systemGray)
                }
            }

            // 3. Core Clock
            if let v = self.viewClock {
                if t.core_clock_mhz > 0 {
                    v.setText("🚀 \(t.core_clock_mhz) MHz")
                    v.setAccent(NSColor(red: 0.05, green: 0.7, blue: 0.85, alpha: 1.0))
                } else {
                    v.setText("🚀 -- MHz")
                    v.setAccent(.systemGray)
                }
            }

            // 4. VRAM Usage
            if let v = self.viewVram {
                if t.memory_total_mb > 0 {
                    let totalGb = Double(t.memory_total_mb) / 1024.0
                    if t.memory_used_mb > 0 || hasLiveCounters {
                        let usedGb = Double(t.memory_used_mb) / 1024.0
                        v.setText(String(format: "💾 %.1f/%.1f GB", usedGb, totalGb))
                    } else {
                        v.setText(String(format: "💾 --/%.1f GB", totalGb))
                    }
                    v.setAccent(NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0))
                } else if t.memory_used_mb > 0 {
                    let usedGb = Double(t.memory_used_mb) / 1024.0
                    v.setText(String(format: "💾 %.1f GB", usedGb))
                    v.setAccent(NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0))
                } else {
                    v.setText("💾 -- GB")
                    v.setAccent(.systemGray)
                }
            }

            // 5. Utilization
            if let v = self.viewUtil {
                if hasLiveCounters {
                    v.setText("📊 \(t.gpu_utilization_percent)% GPU")
                    v.setAccent(NSColor(red: 0.65, green: 0.35, blue: 0.95, alpha: 1.0))
                } else {
                    v.setText("📊 --% GPU")
                    v.setAccent(.systemGray)
                }
            }
        }
    }

    public func updateUiExplicit(temp: UInt32, power: Float, clock: UInt32, vramUsed: UInt64, vramTotal: UInt64, util: UInt32) {
        stateLock.lock()
        let gpuName = lastKnownGpuName ?? "Remote GPU"
        stateLock.unlock()

        let memPercent: UInt32
        if vramTotal > 0 {
            let pct = (Double(vramUsed) * 100.0) / Double(vramTotal)
            memPercent = UInt32(min(100.0, max(0.0, pct)))
        } else {
            memPercent = 0
        }

        let t = GpuTelemetryData(
            gpu_name: gpuName,
            temperature_c: temp,
            power_usage_watts: power.isFinite ? power : 0.0,
            gpu_utilization_percent: util,
            memory_utilization_percent: memPercent,
            memory_used_mb: vramUsed,
            memory_total_mb: vramTotal,
            core_clock_mhz: clock
        )
        updateUi(with: t)
    }
}

// MARK: - C FFI Interface for Main App Integration
@_cdecl("init_touchbar_in_app")
public func init_touchbar_in_app(peerIpPtr: UnsafePointer<CChar>?) {
    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : nil
    TouchBarHudController.shared.launch_touchbar_hud(peerIp: peerIp)
}

@_cdecl("dismiss_touchbar_in_app")
public func dismiss_touchbar_in_app() {
    TouchBarHudController.shared.dismiss()
}

@_cdecl("is_touchbar_active_in_app")
public func is_touchbar_active_in_app() -> Bool {
    return TouchBarHudController.shared.isActive
}

@_cdecl("update_touchbar_telemetry_in_app")
public func update_touchbar_telemetry_in_app(
    temp: UInt32,
    power: Float,
    clock: UInt32,
    vramUsed: UInt64,
    vramTotal: UInt64,
    util: UInt32
) {
    TouchBarHudController.shared.updateUiExplicit(
        temp: temp,
        power: power,
        clock: clock,
        vramUsed: vramUsed,
        vramTotal: vramTotal,
        util: util
    )
}

private var touchBarCliSignalSources: [DispatchSourceSignal] = []

@_cdecl("run_touchbar_cli_loop")
public func run_touchbar_cli_loop(peerIpPtr: UnsafePointer<CChar>?) {
    guard TouchBarHudController.isTouchBarSupported() else {
        NSLog("ℹ️ [TouchBarHud] Touch Bar DF/NSTouchBar support not detected on this Mac; exiting CLI loop.")
        return
    }

    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : nil
    let initMain = {
        let app = NSApplication.shared
        if app.activationPolicy() == .prohibited {
            app.setActivationPolicy(.accessory)
        }
        TouchBarHudController.shared.launch_touchbar_hud(peerIp: peerIp)
    }
    if Thread.isMainThread {
        initMain()
    } else {
        DispatchQueue.main.sync(execute: initMain)
    }

    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    touchBarCliSignalSources.forEach { $0.cancel() }
    touchBarCliSignalSources.removeAll()

    for sig in [SIGINT, SIGTERM] {
        let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        src.setEventHandler {
            TouchBarHudController.shared.dismiss()
            CFRunLoopStop(CFRunLoopGetMain())
        }
        src.resume()
        touchBarCliSignalSources.append(src)
    }

    CFRunLoopRun()
    touchBarCliSignalSources.forEach { $0.cancel() }
    touchBarCliSignalSources.removeAll()
}

// MARK: - On-Demand Remote Paste & Telemetry C FFI Bridge
@_silgen_name("trigger_rust_remote_paste")
func trigger_rust_remote_paste()

@_silgen_name("fetch_rust_gpu_telemetry_json")
func fetch_rust_gpu_telemetry_json(_ peerIp: UnsafePointer<CChar>?, _ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int

@_cdecl("notify_touchbar_remote_file")
public func notify_touchbar_remote_file(namePtr: UnsafePointer<CChar>?, totalBytes: UInt64) {
    guard let namePtr = namePtr else { return }
    let name = String(cString: namePtr)
    TouchBarHudController.shared.showRemotePasteButton(name: name, totalBytes: totalBytes)
}

@_cdecl("update_touchbar_paste_progress")
public func update_touchbar_paste_progress(percent: Float, mbPerSec: Float) {
    PasteboardShortcutInterceptor.shared.touchPasteActivity()
    TouchBarHudController.shared.updatePasteProgress(percent: percent, mbPerSec: mbPerSec)
}

@_cdecl("reset_touchbar_paste_progress")
public func reset_touchbar_paste_progress() {
    PasteboardShortcutInterceptor.shared.isPasting = false
    TouchBarHudController.shared.resetPasteButton()
}

// MARK: - Native Finder Cmd+V Shortcut Interceptor
public class PasteboardShortcutInterceptor: NSObject {
    public static let shared = PasteboardShortcutInterceptor()

    private let lock = NSLock()
    private var _hasPendingRemoteFile: Bool = false
    private var _isPasting: Bool = false
    private var _pasteStartedAt: Date? = nil
    private var eventTap: CFMachPort?
    private var runLoopSource: CFRunLoopSource?

    public var hasPendingRemoteFile: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _hasPendingRemoteFile
        }
        set {
            lock.lock()
            _hasPendingRemoteFile = newValue
            if !newValue {
                _isPasting = false
                _pasteStartedAt = nil
            }
            lock.unlock()
        }
    }

    public var isPasting: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            expireStalePastingLocked()
            return _isPasting
        }
        set {
            lock.lock()
            _isPasting = newValue
            _pasteStartedAt = newValue ? Date() : nil
            lock.unlock()
        }
    }

    func touchPasteActivity() {
        lock.lock()
        if _isPasting {
            _pasteStartedAt = Date()
        }
        lock.unlock()
    }

    private func expireStalePastingLocked() {
        if _isPasting, let started = _pasteStartedAt, Date().timeIntervalSince(started) > 30.0 {
            _isPasting = false
            _pasteStartedAt = nil
        }
    }

    private override init() {
        super.init()
    }

    public func start() {
        let block = { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let alreadyStarted = self.eventTap != nil
            self.lock.unlock()
            guard !alreadyStarted else { return }

            if !AXIsProcessTrusted() {
                NSLog("ℹ️ [PasteboardShortcutInterceptor] Accessibility permissions not granted. Using automatic background stream & native pasteboard registration.")
                return
            }

            let mask = (1 << CGEventType.keyDown.rawValue)
            guard let tap = CGEvent.tapCreate(
                tap: .cgSessionEventTap,
                place: .headInsertEventTap,
                options: .defaultTap,
                eventsOfInterest: CGEventMask(mask),
                callback: { (proxy, type, event, refcon) -> Unmanaged<CGEvent>? in
                    return PasteboardShortcutInterceptor.shared.handleEvent(proxy: proxy, type: type, event: event)
                },
                userInfo: nil
            ) else {
                NSLog("ℹ️ [PasteboardShortcutInterceptor] Could not create CGEventTap; falling back to direct clipboard registration.")
                return
            }

            let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
            self.lock.lock()
            self.eventTap = tap
            self.runLoopSource = source
            self.lock.unlock()

            CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
            CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
            CGEvent.tapEnable(tap: tap, enable: true)
            NSLog("🎯 [PasteboardShortcutInterceptor] Native Finder Cmd+V interceptor active")
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func isPasteShortcutEvent(_ event: CGEvent) -> Bool {
        let flags = event.flags
        guard flags.contains(.maskCommand),
              !flags.contains(.maskAlternate),
              !flags.contains(.maskControl) else {
            return false
        }
        if let nsEvent = NSEvent(cgEvent: event),
           let chars = nsEvent.charactersIgnoringModifiers?.lowercased(),
           !chars.isEmpty {
            return chars == "v"
        }
        return event.getIntegerValueField(.keyboardEventKeycode) == 9
    }

    func handleEvent(proxy: CGEventTapProxy, type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        if type == .tapDisabledByTimeout {
            lock.lock()
            let tap = eventTap
            lock.unlock()
            if let tap = tap {
                CGEvent.tapEnable(tap: tap, enable: true)
            }
            return Unmanaged.passUnretained(event)
        }
        if type == .tapDisabledByUserInput {
            NSLog("ℹ️ [PasteboardShortcutInterceptor] CGEventTap disabled by user input / permission change; not forcing re-enable.")
            return Unmanaged.passUnretained(event)
        }

        guard type == .keyDown else {
            return Unmanaged.passUnretained(event)
        }

        if isPasteShortcutEvent(event) {
            let frontApp = NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? ""
            lock.lock()
            expireStalePastingLocked()
            let pending = _hasPendingRemoteFile
            let pasting = _isPasting
            lock.unlock()

            if pending && !pasting && frontApp == "com.apple.finder" {
                NSLog("🎯 [PasteboardShortcutInterceptor] Intercepting Cmd+V in Finder! Streaming remote files...")
                triggerPaste()
                return nil // Intercept & swallow event so Finder does not paste stale text clippings or beep!
            }
        }

        return Unmanaged.passUnretained(event)
    }

    func triggerPaste() {
        lock.lock()
        expireStalePastingLocked()
        guard _hasPendingRemoteFile && !_isPasting else {
            lock.unlock()
            return
        }
        _isPasting = true
        _pasteStartedAt = Date()
        lock.unlock()

        DispatchQueue.main.async {
            NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
            TouchBarHudController.shared.viewPaste?.setText("⏳ Streaming...")
            TouchBarHudController.shared.viewPaste?.setAccent(NSColor.systemGreen)
        }

        DispatchQueue.global(qos: .userInitiated).async {
            trigger_rust_remote_paste()
        }
    }
}

// MARK: - C FFI Interface for Shortcut Interceptor & Pasteboard
@_cdecl("init_shortcut_interceptor")
public func init_shortcut_interceptor() {
    PasteboardShortcutInterceptor.shared.start()
}

@_cdecl("set_has_pending_remote_file")
public func set_has_pending_remote_file(pending: Bool) {
    PasteboardShortcutInterceptor.shared.hasPendingRemoteFile = pending
}

private func onMainPasteboardSync<T>(_ work: () -> T) -> T {
    if Thread.isMainThread || !(NSApp?.isRunning ?? false) {
        return work()
    }
    return DispatchQueue.main.sync(execute: work)
}

@_cdecl("clear_pasteboard_in_app")
public func clear_pasteboard_in_app() {
    onMainPasteboardSync {
        NSPasteboard.general.clearContents()
    }
}

/// Reads file URLs from `NSPasteboard.general` into `outBuf` as `\0`-delimited UTF-8 paths.
/// Returns `0` when no file URLs are present, `-1` when `outBuf` is invalid or `cap` is too small,
/// or the exact byte count written into `outBuf`.
@_cdecl("read_pasteboard_files_in_app")
public func read_pasteboard_files_in_app(_ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int {
    guard let outBuf = outBuf, cap > 0 else { return -1 }
    let ordered: [String] = onMainPasteboardSync {
        let pb = NSPasteboard.general
        let options: [NSPasteboard.ReadingOptionKey: Any] = [
            .urlReadingFileURLsOnly: true
        ]
        guard let urls = pb.readObjects(forClasses: [NSURL.self], options: options) as? [URL], !urls.isEmpty else {
            return []
        }
        var seen = Set<String>()
        var result: [String] = []
        for url in urls {
            guard url.isFileURL else { continue }
            let path = url.path
            guard !path.isEmpty, !path.contains("\0") else { continue }
            if seen.insert(path).inserted {
                result.append(path)
            }
        }
        return result
    }
    if ordered.isEmpty {
        return 0
    }
    var bytes: [UInt8] = []
    for (idx, path) in ordered.enumerated() {
        if idx > 0 {
            bytes.append(0)
        }
        bytes.append(contentsOf: path.utf8)
    }
    if bytes.isEmpty {
        return 0
    }
    guard bytes.count <= cap else {
        return -1
    }
    for i in 0..<bytes.count {
        outBuf[i] = bytes[i]
    }
    return bytes.count
}

/// Writes `\0`-delimited UTF-8 file paths in `pathsPtr[0..<len]` onto `NSPasteboard.general`.
@_cdecl("write_pasteboard_files_in_app")
public func write_pasteboard_files_in_app(_ pathsPtr: UnsafePointer<UInt8>?, _ len: Int) -> Bool {
    guard let pathsPtr = pathsPtr, len > 0 else { return false }
    let buf = UnsafeBufferPointer(start: pathsPtr, count: len)
    var seen = Set<String>()
    var urls: [NSURL] = []
    for slice in buf.split(separator: 0, omittingEmptySubsequences: true) {
        let path = String(decoding: slice, as: UTF8.self)
        guard !path.isEmpty else { continue }
        if seen.insert(path).inserted {
            urls.append(URL(fileURLWithPath: path) as NSURL)
        }
    }
    guard !urls.isEmpty else { return false }
    return onMainPasteboardSync {
        let pb = NSPasteboard.general
        pb.clearContents()
        return pb.writeObjects(urls)
    }
}

