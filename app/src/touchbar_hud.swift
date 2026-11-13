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

class TouchBarHudController: NSObject, NSTouchBarDelegate {
    var touchBar: NSTouchBar?
    var peerIp: String = "10.99.99.1"
    var pollTimer: Timer?
    var isRunning: Bool = true
    
    // Touch Bar UI Item References
    var btnGpu: NSButton?
    var btnTemp: NSButton?
    var btnPower: NSButton?
    var btnClock: NSButton?
    var btnVram: NSButton?
    var btnUtil: NSButton?
    
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
        tb.defaultItemIdentifiers = [
            NSTouchBarItem.Identifier("gpu"),
            NSTouchBarItem.Identifier("temp"),
            NSTouchBarItem.Identifier("power"),
            NSTouchBarItem.Identifier("clock"),
            NSTouchBarItem.Identifier("vram"),
            NSTouchBarItem.Identifier("util"),
            NSTouchBarItem.Identifier("close")
        ]
        self.touchBar = tb
        
        // Present as System-Modal Touch Bar across all spaces
        let sel = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        if NSTouchBar.responds(to: sel) {
            typealias PresentFunc = @convention(c) (AnyClass, Selector, AnyObject, Int64, AnyObject?) -> Void
            let method = class_getClassMethod(NSTouchBar.self, sel)!
            let imp = method_getImplementation(method)
            let fn = unsafeBitCast(imp, to: PresentFunc.self)
            fn(NSTouchBar.self, sel, tb, 1, nil)
            print("🚀 NVIDIA Performance HUD presented on physical OLED Touch Bar!")
        } else {
            let sel2 = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
            typealias PresentFunc2 = @convention(c) (AnyClass, Selector, AnyObject, AnyObject?) -> Void
            let method2 = class_getClassMethod(NSTouchBar.self, sel2)!
            let imp2 = method_getImplementation(method2)
            let fn2 = unsafeBitCast(imp2, to: PresentFunc2.self)
            fn2(NSTouchBar.self, sel2, tb, nil)
            print("🚀 NVIDIA Performance HUD presented on physical Touch Bar via fallback!")
        }
    }
    
    func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        let item = NSCustomTouchBarItem(identifier: identifier)
        switch identifier.rawValue {
        case "gpu":
            let btn = NSButton(title: "🎮 RTX 5070", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.46, green: 0.73, blue: 0.0, alpha: 1.0) // NVIDIA Green
            self.btnGpu = btn
            item.view = btn
        case "temp":
            let btn = NSButton(title: "🌡️ --°C", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.2, green: 0.6, blue: 0.3, alpha: 1.0)
            self.btnTemp = btn
            item.view = btn
        case "power":
            let btn = NSButton(title: "⚡ -- W", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.85, green: 0.65, blue: 0.1, alpha: 1.0)
            self.btnPower = btn
            item.view = btn
        case "clock":
            let btn = NSButton(title: "🚀 -- MHz", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.2, green: 0.6, blue: 0.85, alpha: 1.0)
            self.btnClock = btn
            item.view = btn
        case "vram":
            let btn = NSButton(title: "💾 -- / 8 GB", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.3, green: 0.4, blue: 0.9, alpha: 1.0)
            self.btnVram = btn
            item.view = btn
        case "util":
            let btn = NSButton(title: "📊 --%", target: nil, action: nil)
            btn.bezelColor = NSColor(red: 0.65, green: 0.3, blue: 0.85, alpha: 1.0)
            self.btnUtil = btn
            item.view = btn
        case "close":
            let btn = NSButton(title: "✕", target: self, action: #selector(closeTouchBar))
            btn.bezelColor = NSColor(red: 0.7, green: 0.2, blue: 0.2, alpha: 1.0)
            item.view = btn
        default:
            return nil
        }
        return item
    }
    
    func startPolling() {
        // Initial fetch
        queryTelemetry()
        
        // Repeating timer every 1.0 second
        self.pollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.queryTelemetry()
        }
    }
    
    func queryTelemetry() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self, self.isRunning else { return }
            
            // Query telemetry via socket to 10.99.99.1:58281
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
            
            // Request payload: "\"GetGpuTelemetry\""
            let reqJson = "\"GetGpuTelemetry\"".data(using: .utf8)!
            var lenBigEndian = UInt32(reqJson.count).bigEndian
            
            // Send length prefix (4 bytes) + JSON
            send(clientSocket, &lenBigEndian, 4, 0)
            reqJson.withUnsafeBytes { rawPtr in
                _ = send(clientSocket, rawPtr.baseAddress, reqJson.count, 0)
            }
            
            // Read response length prefix (4 bytes)
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
            
            // Read response buffer
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
            
            // Decode JSON
            if let decoded = try? JSONDecoder().decode(DisplayRpcResponseData.self, from: respData),
               let t = decoded.gpu_telemetry {
                DispatchQueue.main.async { [weak self] in
                    self?.updateUi(with: t)
                }
            }
        }
    }
    
    func updateUi(with t: GpuTelemetryData) {
        // Temperature badge
        if let btn = self.btnTemp {
            btn.title = "🌡️ \(t.temperature_c)°C"
            if t.temperature_c < 55 {
                btn.bezelColor = NSColor(red: 0.1, green: 0.7, blue: 0.3, alpha: 1.0)
            } else if t.temperature_c < 75 {
                btn.bezelColor = NSColor(red: 0.9, green: 0.5, blue: 0.1, alpha: 1.0)
            } else {
                btn.bezelColor = NSColor(red: 0.9, green: 0.2, blue: 0.2, alpha: 1.0)
            }
        }
        
        // Power badge
        if let btn = self.btnPower {
            btn.title = String(format: "⚡ %.1fW", t.power_usage_watts)
        }
        
        // Core Clock
        if let btn = self.btnClock {
            btn.title = "🚀 \(t.core_clock_mhz) MHz"
        }
        
        // VRAM
        if let btn = self.btnVram {
            let usedGb = Float(t.memory_used_mb) / 1024.0
            let totalGb = Float(t.memory_total_mb) / 1024.0
            btn.title = String(format: "💾 %.1f/%.1f GB", usedGb, totalGb)
        }
        
        // Utilization
        if let btn = self.btnUtil {
            btn.title = "📊 \(t.gpu_utilization_percent)%"
        }
    }
    
    @objc func closeTouchBar() {
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
        print("Touch Bar HUD dismissed cleanly.")
        exit(0)
    }
}

// Entry Point
let peerIp = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "10.99.99.1"
let app = NSApplication.shared
let controller = TouchBarHudController(peerIp: peerIp)
controller.start()

// Register signal handlers for clean exit
signal(SIGINT) { _ in
    controller.closeTouchBar()
}
signal(SIGTERM) { _ in
    controller.closeTouchBar()
}

app.run()
