import AppKit
import Foundation

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
        label.stringValue = text
        addSubview(label)

        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor)
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
        endInteraction()
    }

    override func touchesCancelled(with event: NSEvent) {
        endInteraction()
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
        endInteraction()
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

    private func endInteraction() {
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

        onTap?()
    }
}

// MARK: - Touch Bar Controller (Singleton within Main App)
@objc public class TouchBarHudController: NSObject, NSTouchBarDelegate {
    public static let shared = TouchBarHudController()

    public private(set) var isActive: Bool = false
    var touchBar: NSTouchBar?
    var peerIp: String = "10.99.99.1"
    var pollTimer: Timer?

    // Goopy Liquid Glass Pill Views
    var viewTemp: GoopyLiquidGlassPillView?
    var viewPower: GoopyLiquidGlassPillView?
    var viewClock: GoopyLiquidGlassPillView?
    var viewVram: GoopyLiquidGlassPillView?
    var viewUtil: GoopyLiquidGlassPillView?
    var viewPaste: GoopyLiquidGlassPillView?

    public func showRemotePasteButton(name: String, totalBytes: UInt64) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let mb = Double(totalBytes) / (1024.0 * 1024.0)
            let sizeStr = mb >= 1024.0 ? String(format: "%.1f GB", mb / 1024.0) : String(format: "%.0f MB", mb)
            let btnText = "📥 Paste \(name) (\(sizeStr))"

            if !self.isActive {
                self.start(peerIp: self.peerIp)
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
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let view = self.viewPaste else { return }
            view.setText(String(format: "📥 %.0f%% • %.0f MB/s", percent, mbPerSec))
            view.setAccent(NSColor.systemGreen)
        }
    }

    public func resetPasteButton() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
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

    public func start(peerIp: String = "10.99.99.1") {
        self.peerIp = peerIp
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            guard !self.isActive else { return }
            self.isActive = true
            self.setupTouchBar()
            self.startPolling()
            print("🚀 NVIDIA Goopy Liquid Glass HUD started directly within main app process.")
        }
    }

    public func dismiss() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isActive else { return }
            self.isActive = false
            self.pollTimer?.invalidate()
            self.pollTimer = nil
            if let tb = self.touchBar {
                let sel = NSSelectorFromString("dismissSystemModalTouchBar:")
                if NSTouchBar.responds(to: sel) {
                    typealias DismissFunc = @convention(c) (AnyClass, Selector, AnyObject) -> Void
                    let method = class_getClassMethod(NSTouchBar.self, sel)!
                    let imp = method_getImplementation(method)
                    let fn = unsafeBitCast(imp, to: DismissFunc.self)
                    fn(NSTouchBar.self, sel, tb)
                }
            }
            self.touchBar = nil
            print("🚀 NVIDIA Goopy Liquid Glass HUD dismissed.")
        }
    }

    func setupTouchBar() {
        let tb = NSTouchBar()
        tb.delegate = self

        // Exclusively render the 5 performance metric pills
        tb.defaultItemIdentifiers = [
            NSTouchBarItem.Identifier("temp"),
            NSTouchBarItem.Identifier("power"),
            NSTouchBarItem.Identifier("clock"),
            NSTouchBarItem.Identifier("vram"),
            NSTouchBarItem.Identifier("util")
        ]
        self.touchBar = tb

        // Placement: 0 (NSTouchBarPlacementDefault) keeps the native macOS Control Strip intact!
        let sel = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        if NSTouchBar.responds(to: sel) {
            typealias PresentFunc = @convention(c) (AnyClass, Selector, AnyObject, Int64, AnyObject?) -> Void
            let method = class_getClassMethod(NSTouchBar.self, sel)!
            let imp = method_getImplementation(method)
            let fn = unsafeBitCast(imp, to: PresentFunc.self)
            fn(NSTouchBar.self, sel, tb, 0, nil)
            print("🚀 NVIDIA Goopy Liquid Glass HUD presented (placement 0, Control Strip Preserved)")
        } else {
            let sel2 = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
            typealias PresentFunc2 = @convention(c) (AnyClass, Selector, AnyObject, AnyObject?) -> Void
            let method2 = class_getClassMethod(NSTouchBar.self, sel2)!
            let imp2 = method_getImplementation(method2)
            let fn2 = unsafeBitCast(imp2, to: PresentFunc2.self)
            fn2(NSTouchBar.self, sel2, tb, nil)
        }
    }

    public func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        let item = NSCustomTouchBarItem(identifier: identifier)
        switch identifier.rawValue {
        case "temp":
            let v = GoopyLiquidGlassPillView(text: "🌡️ --°C", accent: NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0), width: 85)
            self.viewTemp = v
            item.view = v
        case "power":
            let v = GoopyLiquidGlassPillView(text: "⚡ --W", accent: NSColor(red: 0.95, green: 0.65, blue: 0.1, alpha: 1.0), width: 85)
            self.viewPower = v
            item.view = v
        case "clock":
            let v = GoopyLiquidGlassPillView(text: "🚀 -- MHz", accent: NSColor(red: 0.05, green: 0.7, blue: 0.85, alpha: 1.0), width: 98)
            self.viewClock = v
            item.view = v
        case "vram":
            let v = GoopyLiquidGlassPillView(text: "💾 -- / 8.1 GB", accent: NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0), width: 110)
            self.viewVram = v
            item.view = v
        case "util":
            let v = GoopyLiquidGlassPillView(text: "📊 --% GPU", accent: NSColor(red: 0.65, green: 0.35, blue: 0.95, alpha: 1.0), width: 88)
            self.viewUtil = v
            item.view = v
        case "paste_remote":
            let v = GoopyLiquidGlassPillView(text: "📥 Paste", accent: NSColor.systemCyan, width: 170)
            v.onTap = {
                v.setText("⏳ Streaming...")
                trigger_rust_remote_paste()
            }
            self.viewPaste = v
            item.view = v
        default:
            return nil
        }
        return item
    }

    func startPolling() {
        queryTelemetry()
        self.pollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.queryTelemetry()
        }
    }

    func queryTelemetry() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self, self.isActive else { return }

            let host = self.peerIp
            let port: UInt16 = 58281

            var clientSocket: Int32 = -1
            clientSocket = socket(AF_INET, SOCK_STREAM, 0)
            guard clientSocket >= 0 else { return }

            var timeout = timeval(tv_sec: 1, tv_usec: 0)
            setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

            var serverAddr = sockaddr_in()
            serverAddr.sin_family = sa_family_t(AF_INET)
            serverAddr.sin_port = port.bigEndian
            inet_pton(AF_INET, host, &serverAddr.sin_addr)

            let connectRes = withUnsafePointer(to: &serverAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(clientSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            guard connectRes == 0 else {
                close(clientSocket)
                return
            }

            let reqJson = "\"GetGpuTelemetry\"".data(using: .utf8)!
            var lenBigEndian = UInt32(reqJson.count).bigEndian

            send(clientSocket, &lenBigEndian, 4, 0)
            reqJson.withUnsafeBytes { rawPtr in
                _ = send(clientSocket, rawPtr.baseAddress, reqJson.count, 0)
            }

            var respLenBigEndian: UInt32 = 0
            let rcvLen = recv(clientSocket, &respLenBigEndian, 4, 0)
            guard rcvLen == 4 else {
                close(clientSocket)
                return
            }

            let respLen = Int(UInt32(bigEndian: respLenBigEndian))
            guard respLen > 0 && respLen < 65536 else {
                close(clientSocket)
                return
            }

            var respData = Data(count: respLen)
            var totalRead = 0
            while totalRead < respLen {
                let bytesLeft = respLen - totalRead
                let n = respData.withUnsafeMutableBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return 0 }
                    return recv(clientSocket, base.advanced(by: totalRead), bytesLeft, 0)
                }
                if n <= 0 { break }
                totalRead += n
            }
            close(clientSocket)

            guard totalRead == respLen else { return }

            if let decoded = try? JSONDecoder().decode(DisplayRpcResponseData.self, from: respData),
               let t = decoded.gpu_telemetry {
                self.updateUi(with: t)
            }
        }
    }

    func updateUi(with t: GpuTelemetryData) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            // 1. Temperature with Dynamic Thermal Color
            if let v = self.viewTemp {
                v.setText("🌡️ \(t.temperature_c)°C")
                if t.temperature_c < 55 {
                    v.setAccent(NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0)) // Emerald
                } else if t.temperature_c < 75 {
                    v.setAccent(NSColor(red: 0.95, green: 0.55, blue: 0.1, alpha: 1.0)) // Amber
                } else {
                    v.setAccent(NSColor(red: 0.95, green: 0.2, blue: 0.2, alpha: 1.0)) // Ruby
                }
            }

            // 2. Power Draw
            if let v = self.viewPower {
                v.setText(String(format: "⚡ %.1fW", t.power_usage_watts))
            }

            // 3. Core Clock
            if let v = self.viewClock {
                v.setText("🚀 \(t.core_clock_mhz) MHz")
            }

            // 4. VRAM Usage
            if let v = self.viewVram {
                let usedGb = Float(t.memory_used_mb) / 1024.0
                let totalGb = Float(t.memory_total_mb) / 1024.0
                v.setText(String(format: "💾 %.1f/%.1f GB", usedGb, totalGb))
            }

            // 5. Utilization
            if let v = self.viewUtil {
                v.setText("📊 \(t.gpu_utilization_percent)% GPU")
            }
        }
    }

    public func updateUiExplicit(temp: UInt32, power: Float, clock: UInt32, vramUsed: UInt64, vramTotal: UInt64, util: UInt32) {
        let t = GpuTelemetryData(
            gpu_name: "NVIDIA GeForce RTX 5070 Laptop GPU",
            temperature_c: temp,
            power_usage_watts: power,
            gpu_utilization_percent: util,
            memory_utilization_percent: vramTotal > 0 ? UInt32((vramUsed * 100) / vramTotal) : 0,
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
    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : "10.99.99.1"
    TouchBarHudController.shared.start(peerIp: peerIp)
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

@_cdecl("run_touchbar_cli_loop")
public func run_touchbar_cli_loop(peerIpPtr: UnsafePointer<CChar>?) {
    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : "10.99.99.1"
    TouchBarHudController.shared.start(peerIp: peerIp)

    signal(SIGINT) { _ in
        TouchBarHudController.shared.dismiss()
        CFRunLoopStop(CFRunLoopGetMain())
        exit(0)
    }
    signal(SIGTERM) { _ in
        TouchBarHudController.shared.dismiss()
        CFRunLoopStop(CFRunLoopGetMain())
        exit(0)
    }

    CFRunLoopRun()
}

// MARK: - On-Demand Remote Paste C FFI Bridge
@_silgen_name("trigger_rust_remote_paste")
func trigger_rust_remote_paste()

@_cdecl("notify_touchbar_remote_file")
public func notify_touchbar_remote_file(namePtr: UnsafePointer<CChar>?, totalBytes: UInt64) {
    guard let namePtr = namePtr else { return }
    let name = String(cString: namePtr)
    TouchBarHudController.shared.showRemotePasteButton(name: name, totalBytes: totalBytes)
}

@_cdecl("update_touchbar_paste_progress")
public func update_touchbar_paste_progress(percent: Float, mbPerSec: Float) {
    TouchBarHudController.shared.updatePasteProgress(percent: percent, mbPerSec: mbPerSec)
}

@_cdecl("reset_touchbar_paste_progress")
public func reset_touchbar_paste_progress() {
    TouchBarHudController.shared.resetPasteButton()
}

// MARK: - Native Finder Cmd+V Shortcut Interceptor
public class PasteboardShortcutInterceptor: NSObject {
    public static let shared = PasteboardShortcutInterceptor()

    public var hasPendingRemoteFile: Bool = false
    public var isPasting: Bool = false
    private var eventTap: CFMachPort?
    private var runLoopSource: CFRunLoopSource?

    private override init() {
        super.init()
    }

    public func start() {
        let block = { [weak self] in
            guard let self = self, self.eventTap == nil else { return }

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

            self.eventTap = tap
            let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
            self.runLoopSource = source
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

    func handleEvent(proxy: CGEventTapProxy, type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            if let tap = eventTap {
                CGEvent.tapEnable(tap: tap, enable: true)
            }
            return Unmanaged.passUnretained(event)
        }

        guard type == .keyDown else {
            return Unmanaged.passUnretained(event)
        }

        let keyCode = event.getIntegerValueField(.keyboardEventKeycode)
        let flags = event.flags

        // KeyCode 9 is 'v' / 'V'
        if keyCode == 9 && flags.contains(.maskCommand) && !flags.contains(.maskAlternate) && !flags.contains(.maskControl) {
            let frontApp = NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? ""
            NSLog("🎯 [PasteboardShortcutInterceptor] Cmd+V pressed. frontApp=%@, hasPending=%d, isPasting=%d", frontApp, hasPendingRemoteFile ? 1 : 0, isPasting ? 1 : 0)
            if hasPendingRemoteFile && !isPasting {
                if frontApp == "com.apple.finder" {
                    NSLog("🎯 [PasteboardShortcutInterceptor] Intercepting Cmd+V in Finder! Streaming remote files...")
                    triggerPaste()
                    return nil // Intercept & swallow event so Finder does not paste stale text clippings or beep!
                }
            }
        }

        return Unmanaged.passUnretained(event)
    }

    func triggerPaste() {
        guard !isPasting else { return }
        isPasting = true

        DispatchQueue.main.async {
            NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
            TouchBarHudController.shared.viewPaste?.setText("⏳ Streaming...")
            TouchBarHudController.shared.viewPaste?.setAccent(NSColor.systemGreen)
        }

        trigger_rust_remote_paste()
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
    if !pending {
        PasteboardShortcutInterceptor.shared.isPasting = false
    }
}

@_cdecl("clear_pasteboard_in_app")
public func clear_pasteboard_in_app() {
    NSPasteboard.general.clearContents()
}
