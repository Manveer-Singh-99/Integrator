import AppKit
import Foundation

// Structure to decode GPU Telemetry JSON from RPC
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

/// Custom Liquid Glass Pill View for Touch Bar
class LiquidGlassPillView: NSView {
    let visualEffectView = NSVisualEffectView()
    let label = NSTextField(labelWithString: "")
    var accentColor: NSColor = .systemGreen {
        didSet { updateGlow() }
    }

    init(text: String, accent: NSColor, width: CGFloat = 85) {
        self.accentColor = accent
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: 30))
        setup(text: text)
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
    }

    func setup(text: String) {
        wantsLayer = true
        layer?.cornerRadius = 9
        layer?.masksToBounds = true

        // 1. Frosted Glass Blur Effect
        visualEffectView.frame = bounds
        visualEffectView.autoresizingMask = [.width, .height]
        visualEffectView.material = .hudWindow
        visualEffectView.blendingMode = .withinWindow
        visualEffectView.state = .active
        visualEffectView.wantsLayer = true
        visualEffectView.layer?.cornerRadius = 9
        visualEffectView.layer?.masksToBounds = true
        addSubview(visualEffectView)

        // 2. Liquid Glass Border & Specular Edge Highlight
        visualEffectView.layer?.borderWidth = 0.8
        visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.22).cgColor
        visualEffectView.layer?.backgroundColor = NSColor(white: 0.1, alpha: 0.45).cgColor

        // 3. Monospace High-Legibility Typography
        label.frame = bounds
        label.autoresizingMask = [.width, .height]
        label.alignment = .center
        label.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .semibold)
        label.textColor = .white
        label.stringValue = text
        addSubview(label)

        updateGlow()
    }

    func setText(_ newText: String) {
        label.stringValue = newText
    }

    func setAccent(_ color: NSColor) {
        self.accentColor = color
    }

    func updateGlow() {
        visualEffectView.layer?.borderColor = accentColor.withAlphaComponent(0.4).cgColor
        visualEffectView.layer?.backgroundColor = accentColor.withAlphaComponent(0.14).cgColor
    }
}

class TouchBarHudController: NSObject, NSTouchBarDelegate {
    var touchBar: NSTouchBar?
    var peerIp: String = "10.99.99.1"
    var pollTimer: Timer?
    var isRunning: Bool = true
    
    // Liquid Glass Item Views
    var viewTemp: LiquidGlassPillView?
    var viewPower: LiquidGlassPillView?
    var viewClock: LiquidGlassPillView?
    var viewVram: LiquidGlassPillView?
    var viewUtil: LiquidGlassPillView?
    
    init(peerIp: String = "10.99.99.1") {
        self.peerIp = peerIp
        super.init()
    }
    
    func start() {
        setupTouchBar()
        startPolling()
    }
    
    func setupTouchBar() {
        let tb = NSTouchBar()
        tb.delegate = self
        
        // Exclusively render the 5 performance metric pills
        // (RTX 5070 title and Close button removed as requested)
        tb.defaultItemIdentifiers = [
            NSTouchBarItem.Identifier("temp"),
            NSTouchBarItem.Identifier("power"),
            NSTouchBarItem.Identifier("clock"),
            NSTouchBarItem.Identifier("vram"),
            NSTouchBarItem.Identifier("util")
        ]
        self.touchBar = tb
        
        // Present with placement: 0 (NSTouchBarPlacementDefault)
        // This keeps the native macOS Control Strip on the right completely intact!
        let sel = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        if NSTouchBar.responds(to: sel) {
            typealias PresentFunc = @convention(c) (AnyClass, Selector, AnyObject, Int64, AnyObject?) -> Void
            let method = class_getClassMethod(NSTouchBar.self, sel)!
            let imp = method_getImplementation(method)
            let fn = unsafeBitCast(imp, to: PresentFunc.self)
            fn(NSTouchBar.self, sel, tb, 0, nil) // placement 0 preserves macOS Control Strip
            print("🚀 NVIDIA Liquid Glass Performance HUD presented (Native macOS Control Strip Preserved)")
        } else {
            let sel2 = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
            typealias PresentFunc2 = @convention(c) (AnyClass, Selector, AnyObject, AnyObject?) -> Void
            let method2 = class_getClassMethod(NSTouchBar.self, sel2)!
            let imp2 = method_getImplementation(method2)
            let fn2 = unsafeBitCast(imp2, to: PresentFunc2.self)
            fn2(NSTouchBar.self, sel2, tb, nil)
            print("🚀 NVIDIA Liquid Glass Performance HUD presented via fallback")
        }
    }
    
    func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        let item = NSCustomTouchBarItem(identifier: identifier)
        switch identifier.rawValue {
        case "temp":
            let v = LiquidGlassPillView(text: "🌡️ --°C", accent: NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0), width: 82)
            self.viewTemp = v
            item.view = v
        case "power":
            let v = LiquidGlassPillView(text: "⚡ --W", accent: NSColor(red: 0.95, green: 0.65, blue: 0.1, alpha: 1.0), width: 80)
            self.viewPower = v
            item.view = v
        case "clock":
            let v = LiquidGlassPillView(text: "🚀 -- MHz", accent: NSColor(red: 0.05, green: 0.7, blue: 0.85, alpha: 1.0), width: 92)
            self.viewClock = v
            item.view = v
        case "vram":
            let v = LiquidGlassPillView(text: "💾 -- / 8.1 GB", accent: NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0), width: 105)
            self.viewVram = v
            item.view = v
        case "util":
            let v = LiquidGlassPillView(text: "📊 --% GPU", accent: NSColor(red: 0.65, green: 0.35, blue: 0.95, alpha: 1.0), width: 85)
            self.viewUtil = v
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
            guard let self = self, self.isRunning else { return }
            
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
                DispatchQueue.main.async { [weak self] in
                    self?.updateUi(with: t)
                }
            }
        }
    }
    
    func updateUi(with t: GpuTelemetryData) {
        // 1. Temperature with Dynamic Thermal Color
        if let v = self.viewTemp {
            v.setText("🌡️ \(t.temperature_c)°C")
            if t.temperature_c < 55 {
                v.setAccent(NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0)) // Emerald Green
            } else if t.temperature_c < 75 {
                v.setAccent(NSColor(red: 0.95, green: 0.55, blue: 0.1, alpha: 1.0)) // Amber Gold
            } else {
                v.setAccent(NSColor(red: 0.95, green: 0.2, blue: 0.2, alpha: 1.0)) // Ruby Red
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
    
    func dismiss() {
        self.isRunning = false
        self.pollTimer?.invalidate()
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
        print("Touch Bar HUD dismissed.")
        exit(0)
    }
}

// Entry Point
let peerIp = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "10.99.99.1"
let app = NSApplication.shared
let controller = TouchBarHudController(peerIp: peerIp)
controller.start()

signal(SIGINT) { _ in controller.dismiss() }
signal(SIGTERM) { _ in controller.dismiss() }

app.run()
