import AppKit
import Foundation
import SwiftUI

// MARK: - Rust Core C-ABI Declarations

@_silgen_name("integrator_core_invoke")
private func rustCoreInvoke(
    _ method: UnsafePointer<CChar>,
    _ paramsJson: UnsafePointer<CChar>
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("integrator_core_free_string")
private func rustCoreFreeString(_ ptr: UnsafeMutablePointer<CChar>?)

@_silgen_name("integrator_core_tray_action")
private func rustCoreTrayAction(_ action: UnsafePointer<CChar>)

@_silgen_name("integrator_core_shutdown")
private func rustCoreShutdown()

typealias RustUiCallback = @convention(c) (
    UnsafePointer<CChar>?,
    UnsafePointer<CChar>?
) -> Void

@_silgen_name("integrator_core_set_ui_callback")
private func rustCoreSetUiCallback(_ cb: RustUiCallback?)

// MARK: - Codable Data Models (mirror Rust Core BridgeStatus & RPC payloads)

private struct RpcEnvelope<T: Decodable>: Decodable {
    let ok: Bool
    let data: T?
    let error: String?
}

struct PrimaryDisplayInfo: Codable, Hashable {
    var width: UInt32 = 0
    var height: UInt32 = 0
    var fps: UInt32 = 60
    var scale_factor: Double = 2.0
}

struct GpuDeviceInfo: Codable, Identifiable, Hashable {
    var id: String { "\(index)-\(name)" }
    var index: UInt32
    var name: String
    var vendor: String
    var is_discrete: Bool
    var vram_mb: UInt64?
}

struct DisplayGeometryModel: Codable, Hashable {
    var width: UInt32
    var height: UInt32
    var fps: UInt32
}

struct LocalInterfaceModel: Codable, Identifiable, Hashable {
    var id: String { "\(name)-\(ip)" }
    var name: String
    var friendly_name: String?
    var ip: String
    var netmask: String?
    var broadcast: String?
    var cidr_prefix: UInt8?
    var transport: String?
    var link_speed_mbps: UInt32?
    var description: String?
}

struct PendingPeerModel: Codable, Identifiable, Hashable {
    var id: String { device_id }
    var device_id: String
    var hostname: String
    var ip: String
    var is_direct_cable: Bool
    var trusted: Bool
    var blocked: Bool
}

struct TrustedPeerModel: Codable, Identifiable, Hashable {
    var id: String { device_id }
    var device_id: String
    var hostname: String
    var last_ip: String
    var paired_at_epoch: UInt64?
    var via_direct_cable: Bool
    var ed25519_pubkey_hex: String?
    var key_id_hex: String?
}

struct DiscoveredPeerModel: Codable, Identifiable, Hashable {
    var id: String { "\(device_id)-\(ip)" }
    var device_id: String
    var hostname: String
    var os: String
    var hardware_model: String
    var ip: String
    var local_ip_used: String?
    var transport_label: String
    var is_direct_cable: Bool
    var link_speed_mbps: UInt32?
    var link_description: String
    var rtt_ms: Double?
    var display: DisplayGeometryModel
    var gpus: [String]
    var share_name: String?
    var trusted: Bool
    var blocked: Bool
}

struct TrustSnapshotModel: Codable, Hashable {
    var pairing_pin: String
    var auto_trust_direct_cable: Bool
    var require_pairing_on_lan: Bool
    var pending_peers: [PendingPeerModel]
    var trusted_peers: [TrustedPeerModel]
    var blocked_device_ids: [String]
}

struct StorageStatusModel: Codable, Hashable {
    var is_mounted: Bool
    var mount_path: String
    var remote_ip: String
    var remote_share: String
    var message: String
}

struct AudioRoutingStatusModel: Codable, Hashable {
    var topology: String
    var latency_ms: Float
    var sample_rate: UInt32
    var bit_depth: UInt8
    var is_active: Bool
}

struct FeatureFlagsModel: Codable, Hashable {
    var display: Bool
    var input_kvm: Bool
    var clipboard: Bool
    var dragdrop: Bool
    var truetone: Bool
    var touchbar: Bool
    var storage: Bool
    var audio: Bool
    var benchmark: Bool? = true
}

struct KvmLayoutConfigModel: Codable, Hashable {
    var peer_edge: String
    var alignment_offset: Float
    var hop_delay_ms: UInt32
    var dead_corners: Bool
    var modifier_translation: Bool
    var precision_touchpad: Bool
    var ghost_thumbnail: Bool
    var qos_clamp: Bool
    var drop_folder: String
    var updated_at_ms: UInt64
}

struct KvmStatusSnapshotModel: Codable, Hashable {
    var enabled: Bool
    var dragdrop_enabled: Bool
    var hook_active: Bool?
    var role: String
    var connected_peer_ip: String?
    var peer_os: String?
    var peer_width: UInt32
    var peer_height: UInt32
    var active_drag_label: String?
    var layout: KvmLayoutConfigModel
}

struct LogEntryModel: Codable, Identifiable, Hashable {
    var id: String { "\(ts_ms)-\(level)-\(message)" }
    var ts_ms: UInt64
    var level: String
    var message: String
}

private struct RenderedLogEntry: Identifiable {
    let id: String
    let entry: LogEntryModel
}

struct SpeedTestResultModel: Codable, Hashable {
    var max_gbps: Double
    var upload_gbps: Double
    var upload_mb_s: Double
    var download_gbps: Double
    var download_mb_s: Double
    var latency_ms: Double
    var summary: String
}

struct GpuTelemetryModel: Codable, Hashable {
    var gpu_name: String
    var temperature_c: UInt32
    var power_usage_watts: Float
    var core_clock_mhz: UInt32
    var memory_used_mb: UInt64
    var memory_total_mb: UInt64
    var memory_utilization_percent: UInt32
    var gpu_utilization_percent: UInt32
}

struct BridgeStatusModel: Codable {
    var device_id: String
    var hostname: String
    var os: String
    var local_os: String
    var hardware_model: String
    var cpu_brand: String
    var primary_display: PrimaryDisplayInfo
    var local_gpus: [GpuDeviceInfo]
    var local_share_names: [String]
    var has_touch_bar: Bool

    var peer_connected: Bool
    var peer_trusted: Bool
    var peer_device_id: String?
    var peer_ip: String?
    var peer_os: String?
    var peer_name: String?
    var peer_hardware_model: String?
    var peer_display: DisplayGeometryModel?
    var peer_gpus: [String]
    var peer_share_name: String?
    var peer_local_ip_used: String?
    var transport_label: String
    var is_direct_cable: Bool
    var link_speed_mbps: UInt32?
    var link_description: String
    var rtt_ms: Double?
    var link_speed: String
    var link_type: String

    var display_active: Bool
    var active_mode: String?
    var is_windows_master: Bool
    var encode_gpu: String
    var decode_gpu: String
    var gpu_controls_supported: Bool
    var touchbar_active: Bool

    var ambient_supported: Bool
    var ambient_lux: Float?
    var ambient_cct: UInt32?

    var storage_mounted: Bool
    var storage_status: StorageStatusModel
    var preferred_peer_share: String?

    var audio_status: AudioRoutingStatusModel
    var feature_flags: FeatureFlagsModel
    var kvm: KvmStatusSnapshotModel

    var local_interfaces: [LocalInterfaceModel]
    var manual_peer_ips: [String]
    var discovered_peers: [DiscoveredPeerModel]
    var trust: TrustSnapshotModel

    var autostart_enabled: Bool
    var recent_logs: [LogEntryModel]
}

// MARK: - ViewModel

enum NavSection: String, CaseIterable, Identifiable {
    case all = "All Modules"
    case display = "Display & GPU"
    case input = "Input & Clipboard"
    case network = "Network & Trust"
    case system = "System & Audio"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .all: return "square.grid.2x2"
        case .display: return "display.2"
        case .input: return "cursorarrow.motionlines"
        case .network: return "network"
        case .system: return "terminal"
        }
    }
}

struct ToastBanner: Identifiable {
    let id = UUID()
    let kind: String
    let message: String
}

@MainActor
final class IntegratorViewModel: ObservableObject {
    static let shared = IntegratorViewModel()

    @Published var section: NavSection = .all
    @Published var status: BridgeStatusModel? = nil
    @Published var speedResult: SpeedTestResultModel? = nil
    @Published var gpuTelemetry: GpuTelemetryModel? = nil
    @Published var toast: ToastBanner? = nil
    @Published var isRunningSpeedTest = false
    @Published var isBusy = false

    // Local interactive form states
    @Published var selectedEncodeGpu: String = "auto"
    @Published var selectedDecodeGpu: String = "auto"
    @Published var encodeGpuDirty: Bool = false
    @Published var decodeGpuDirty: Bool = false
    @Published var manualIpInput: String = ""
    @Published var pairPinInputs: [String: String] = [:]
    @Published var preferredShareInput: String = ""
    @Published var preferredShareDirty: Bool = false
    @Published var trueToneCct: Double = 6500
    @Published var trueToneComp: Double = 1.0

    // Editable KVM Layout draft synced with server
    private var kvmLayoutDirty = false
    private var isApplyingRemoteLayout = false
    private var lastServerLayoutUpdatedMs: UInt64 = 0
    @Published var kvmLayout = KvmLayoutConfigModel(
        peer_edge: "right",
        alignment_offset: 0.0,
        hop_delay_ms: 40,
        dead_corners: true,
        modifier_translation: true,
        precision_touchpad: true,
        ghost_thumbnail: true,
        qos_clamp: true,
        drop_folder: "downloads",
        updated_at_ms: 0
    ) {
        didSet {
            if !isApplyingRemoteLayout {
                kvmLayoutDirty = true
            }
        }
    }

    private var pollTimer: Timer? = nil
    private var isPollingPaused: Bool = false
    private var isRefreshInFlight: Bool = false

    func startPolling() {
        isPollingPaused = false
        refresh()
        schedulePollTimer()
    }

    func setPollingPaused(_ paused: Bool) {
        isPollingPaused = paused
        if paused {
            pollTimer?.invalidate()
            pollTimer = nil
        } else {
            refresh()
            schedulePollTimer()
        }
    }

    func stopPolling() {
        isPollingPaused = true
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func schedulePollTimer() {
        pollTimer?.invalidate()
        guard !isPollingPaused else { return }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isPollingPaused else { return }
                self.refresh()
            }
        }
    }

    func showToast(_ kind: String, _ msg: String) {
        toast = ToastBanner(kind: kind, message: msg)
        let capturedId = toast?.id
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) { [weak self] in
            if self?.toast?.id == capturedId {
                self?.toast = nil
            }
        }
    }

    static func gpuVendorTag(for gpu: GpuDeviceInfo) -> String {
        let combined = "\(gpu.vendor) \(gpu.name)".lowercased()
        if combined.contains("nvidia") || combined.contains("geforce") || combined.contains("rtx") || combined.contains("gtx") || combined.contains("quadro") {
            return "nvidia"
        }
        if combined.contains("amd") || combined.contains("radeon") {
            return "amd"
        }
        if combined.contains("intel") || combined.contains("arc") || combined.contains("iris") || combined.contains("uhd") {
            return "intel"
        }
        if combined.contains("apple") {
            return "apple"
        }
        return gpu.is_discrete ? "discrete" : "integrated"
    }

    static func gpuPickerOptions(from gpus: [GpuDeviceInfo]) -> [(tag: String, label: String)] {
        var options: [(tag: String, label: String)] = [("auto", "Auto (Recommended)")]
        var usedTags: Set<String> = ["auto"]
        for g in gpus {
            if g.vendor == "System" && g.name == "Default System GPU" {
                continue
            }
            let baseTag = gpuVendorTag(for: g)
            let tag = usedTags.contains(baseTag) ? g.name : baseTag
            if usedTags.insert(tag).inserted {
                options.append((tag, g.name))
            }
        }
        return options
    }

    static func resolveGpuSelection(_ raw: String, gpus: [GpuDeviceInfo]) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "auto" }
        let lower = trimmed.lowercased()
        let options = gpuPickerOptions(from: gpus)
        if let exact = options.first(where: { $0.tag.lowercased() == lower }) {
            return exact.tag
        }
        if let byName = options.first(where: { $0.label.lowercased() == lower }) {
            return byName.tag
        }
        return "auto"
    }

    func refresh() {
        guard !isRefreshInFlight else { return }
        isRefreshInFlight = true
        invoke("get_bridge_status", params: "{}", as: BridgeStatusModel.self) { [weak self] res in
            guard let self = self else { return }
            self.isRefreshInFlight = false
            switch res {
            case .success(let model):
                self.status = model
                if !self.kvmLayoutDirty {
                    self.isApplyingRemoteLayout = true
                    self.kvmLayout = model.kvm.layout
                    self.lastServerLayoutUpdatedMs = model.kvm.layout.updated_at_ms
                    self.kvmLayoutDirty = false
                    self.isApplyingRemoteLayout = false
                }
                if !self.encodeGpuDirty {
                    self.selectedEncodeGpu = Self.resolveGpuSelection(model.encode_gpu, gpus: model.local_gpus)
                }
                if !self.decodeGpuDirty {
                    self.selectedDecodeGpu = Self.resolveGpuSelection(model.decode_gpu, gpus: model.local_gpus)
                }
                if !self.preferredShareDirty {
                    self.preferredShareInput = model.preferred_peer_share ?? ""
                }
                for peer in model.discovered_peers where peer.trusted {
                    self.pairPinInputs.removeValue(forKey: peer.ip)
                }
            case .failure(let err):
                self.showToast("error", err.message)
            }
        }
    }

    func runAction(
        _ method: String,
        params: [String: Any] = [:],
        refreshAfter: Bool = true,
        suppressDataToast: Bool = false,
        successToast: String? = nil
    ) {
        let jsonStr: String
        if let data = try? JSONSerialization.data(withJSONObject: params),
           let s = String(data: data, encoding: .utf8)
        {
            jsonStr = s
        } else {
            jsonStr = "{}"
        }
        invokeRaw(method, params: jsonStr) { [weak self] ok, dataJson, errMsg in
            guard let self = self else { return }
            if !ok {
                self.showToast("error", errMsg ?? "Command failed")
            } else if let custom = successToast {
                self.showToast("success", custom)
            } else if !suppressDataToast, let str = Self.decodeStringResult(dataJson) {
                self.showToast("success", str)
            }
            if refreshAfter {
                self.refresh()
            }
        }
    }

    func toggleFeature(_ feature: String, enabled: Bool) {
        runAction("set_feature_flag", params: ["feature": feature, "enabled": enabled])
    }

    func syncKvmLayout() {
        isApplyingRemoteLayout = true
        kvmLayout.updated_at_ms = UInt64(Date().timeIntervalSince1970 * 1000)
        kvmLayoutDirty = false
        isApplyingRemoteLayout = false
        guard let encoded = try? JSONEncoder().encode(kvmLayout),
              let dict = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        else { return }
        runAction("set_kvm_layout", params: ["layout": dict])
    }

    func updateEdgeAndSyncPreservingDirty(_ edge: String) {
        let baseLayout = status?.kvm.layout ?? kvmLayout
        var payload = baseLayout
        payload.peer_edge = edge
        payload.updated_at_ms = UInt64(Date().timeIntervalSince1970 * 1000)

        let wasDirty = kvmLayoutDirty
        isApplyingRemoteLayout = true
        kvmLayout.peer_edge = edge
        isApplyingRemoteLayout = false
        kvmLayoutDirty = wasDirty

        guard let encoded = try? JSONEncoder().encode(payload),
              let dict = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        else { return }
        runAction("set_kvm_layout", params: ["layout": dict])
    }

    func runSpeedBenchmark() {
        isRunningSpeedTest = true
        invoke("run_speed_test", params: "{}", as: SpeedTestResultModel.self) { [weak self] res in
            self?.isRunningSpeedTest = false
            switch res {
            case .success(let r):
                self?.speedResult = r
                self?.showToast("success", r.summary)
            case .failure(let e):
                self?.showToast("error", e.message)
            }
        }
    }

    func queryGpuTelemetry() {
        invokeOptional("get_gpu_telemetry", params: "{}", as: GpuTelemetryModel.self) { [weak self] res in
            switch res {
            case .success(let t):
                self?.gpuTelemetry = t
                if t == nil {
                    self?.showToast("info", "No discrete telemetry returned by peer")
                }
            case .failure(let e):
                self?.showToast("error", e.message)
            }
        }
    }

    private static func decodeStringResult(_ data: Data?) -> String? {
        guard let data = data,
              let s = try? JSONDecoder().decode(String.self, from: data)
        else { return nil }
        return s
    }

    private func invoke<T: Decodable>(
        _ method: String,
        params: String,
        as type: T.Type,
        completion: @escaping @MainActor (Result<T, RpcErrorMessage>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let rawPtr = method.withCString { mPtr in
                params.withCString { pPtr in
                    rustCoreInvoke(mPtr, pPtr)
                }
            }
            guard let ptr = rawPtr else {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Empty native response"))) }
                return
            }
            let str = String(cString: ptr)
            rustCoreFreeString(ptr)
            guard let data = str.data(using: .utf8) else {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Invalid UTF-8 response"))) }
                return
            }
            do {
                let env = try JSONDecoder().decode(RpcEnvelope<T>.self, from: data)
                if env.ok, let d = env.data {
                    Task { @MainActor in completion(.success(d)) }
                } else {
                    Task { @MainActor in completion(.failure(RpcErrorMessage(env.error ?? "Command failed"))) }
                }
            } catch {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Decode error: \(error.localizedDescription)"))) }
            }
        }
    }

    private func invokeOptional<T: Decodable>(
        _ method: String,
        params: String,
        as type: T.Type,
        completion: @escaping @MainActor (Result<T?, RpcErrorMessage>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let rawPtr = method.withCString { mPtr in
                params.withCString { pPtr in
                    rustCoreInvoke(mPtr, pPtr)
                }
            }
            guard let ptr = rawPtr else {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Empty native response"))) }
                return
            }
            let str = String(cString: ptr)
            rustCoreFreeString(ptr)
            guard let data = str.data(using: .utf8) else {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Invalid UTF-8 response"))) }
                return
            }
            do {
                let env = try JSONDecoder().decode(RpcEnvelope<T>.self, from: data)
                if env.ok {
                    Task { @MainActor in completion(.success(env.data)) }
                } else {
                    Task { @MainActor in completion(.failure(RpcErrorMessage(env.error ?? "Command failed"))) }
                }
            } catch {
                Task { @MainActor in completion(.failure(RpcErrorMessage("Decode error: \(error.localizedDescription)"))) }
            }
        }
    }

    private func invokeRaw(
        _ method: String,
        params: String,
        completion: @escaping @MainActor (Bool, Data?, String?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let rawPtr = method.withCString { mPtr in
                params.withCString { pPtr in
                    rustCoreInvoke(mPtr, pPtr)
                }
            }
            guard let ptr = rawPtr else {
                Task { @MainActor in completion(false, nil, "Null native pointer") }
                return
            }
            let str = String(cString: ptr)
            rustCoreFreeString(ptr)
            guard let data = str.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                Task { @MainActor in completion(false, nil, "Invalid JSON payload") }
                return
            }
            let ok = (obj["ok"] as? Bool) ?? false
            let err = obj["error"] as? String
            var dataBytes: Data? = nil
            if let d = obj["data"] {
                dataBytes = try? JSONSerialization.data(withJSONObject: d, options: [.fragmentsAllowed])
            }
            Task { @MainActor in completion(ok, dataBytes, err) }
        }
    }
}

struct RpcErrorMessage: Error, LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

// MARK: - Liquid Glass Styling Modifiers

private struct LiquidGlassCardModifier: ViewModifier {
    var cornerRadius: CGFloat = 16

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            content
                .padding(16)
                .glassEffect(.regular, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        } else {
            content
                .padding(16)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .stroke(Color.primary.opacity(0.14), lineWidth: 1)
                )
        }
        #else
        content
            .padding(16)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(Color.primary.opacity(0.14), lineWidth: 1)
            )
        #endif
    }
}

private struct LiquidGlassSidebarModifier: ViewModifier {
    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        } else {
            content
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(Color.primary.opacity(0.12), lineWidth: 1)
                )
        }
        #else
        content
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Color.primary.opacity(0.12), lineWidth: 1)
            )
        #endif
    }
}

private struct StatusPill: View {
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text(text)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
        }
        .fixedSize(horizontal: true, vertical: false)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(color.opacity(0.16), in: Capsule())
        .overlay(Capsule().stroke(color.opacity(0.35), lineWidth: 0.75))
    }
}

private struct CardHeader: View {
    let icon: String
    let title: String
    let pillText: String
    let pillColor: Color
    var toggleBinding: Binding<Bool>? = nil
    var toggleDisabled: Bool = false

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28)
                .background(Color.accentColor.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))

            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.88)

            Spacer(minLength: 4)

            StatusPill(text: pillText, color: pillColor)

            if let binding = toggleBinding {
                Toggle("", isOn: binding)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .disabled(toggleDisabled)
            }
        }
    }
}

// MARK: - Main Dashboard View

struct MainDashboardView: View {
    @ObservedObject var vm: IntegratorViewModel

    private var s: BridgeStatusModel? { vm.status }
    private var flags: FeatureFlagsModel {
        s?.feature_flags ?? FeatureFlagsModel(
            display: true, input_kvm: true, clipboard: true, dragdrop: true,
            truetone: true, touchbar: true, storage: true, audio: true
        )
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            VisualEffectBackdrop(material: .underWindowBackground, blendingMode: .behindWindow)
                .ignoresSafeArea()

            HStack(spacing: 14) {
                sidebar
                    .frame(width: 228)

                VStack(spacing: 12) {
                    topBar

                    ScrollView {
                        LazyVGrid(
                            columns: [
                                GridItem(.flexible(minimum: 310), spacing: 14, alignment: .top),
                                GridItem(.flexible(minimum: 310), spacing: 14, alignment: .top),
                            ],
                            alignment: .leading,
                            spacing: 14
                        ) {
                            if show(.display) {
                                extendedDisplayCard
                            }
                            if show(.input) {
                                kvmLayoutCard
                                dragDropCard
                                clipboardCard
                            }
                            if show(.network) {
                                discoveryTrustCard
                                routeSpeedCard
                                sharedStorageCard
                            }
                            if show(.display) {
                                trueToneCard
                                touchBarCard
                            }
                            if show(.system) {
                                audioCard
                                systemLifecycleCard
                                logsCard
                            }
                        }
                        .padding(.bottom, 16)
                    }
                }
            }
            .padding(14)

            if let t = vm.toast {
                HStack(spacing: 8) {
                    Image(systemName: t.kind == "error" ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(t.kind == "error" ? .red : .green)
                    Text(t.message)
                        .font(.subheadline.weight(.medium))
                        .lineLimit(2)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .modifier(LiquidGlassCardModifier(cornerRadius: 12))
                .padding(20)
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: vm.toast?.id)
        .onAppear { vm.startPolling() }
    }

    private func show(_ target: NavSection) -> Bool {
        vm.section == .all || vm.section == target
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "link.circle.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Integrator")
                        .font(.title3.bold())
                    Text("v2.0 SECURITY")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, 4)

            Divider().opacity(0.3)

            VStack(spacing: 4) {
                ForEach(NavSection.allCases) { item in
                    Button {
                        vm.section = item
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: item.icon)
                                .frame(width: 18)
                            Text(item.rawValue)
                                .font(.subheadline.weight(vm.section == item ? .semibold : .regular))
                            Spacer()
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(
                            vm.section == item
                                ? Color.accentColor.opacity(0.22)
                                : Color.clear,
                            in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }

            Spacer()

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 7) {
                    Circle()
                        .fill(s?.peer_connected == true ? .green : .orange)
                        .frame(width: 8, height: 8)
                    Text(s?.peer_name ?? "Discovering Peer...")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                }
                Text(s?.link_description ?? "Awaiting Ethernet / TB / USB-C / Wi-Fi beacon")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)

                HStack(spacing: 6) {
                    StatusPill(
                        text: s?.link_speed ?? "--",
                        color: s?.is_direct_cable == true ? .cyan : .blue
                    )
                    if s?.peer_trusted == true {
                        StatusPill(text: "Verified v2.0", color: .green)
                    }
                }
            }
            .padding(12)
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12))
        }
        .padding(14)
        .modifier(LiquidGlassSidebarModifier())
    }

    // MARK: - Top Bar

    private var topBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(s?.hostname ?? "Workstation")
                    .font(.title2.bold())
                Text("\(s?.hardware_model ?? "macOS") • Device \(String((s?.device_id ?? "--").prefix(8)))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            StatusPill(
                text: s?.peer_connected == true ? "Peer Linked" : "Searching",
                color: s?.peer_connected == true ? .green : .orange
            )

            Button { vm.refresh() } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }

            Button { vm.runAction("open_cache_folder", refreshAfter: false) } label: {
                Label("Open Cache", systemImage: "folder")
            }

            Button { vm.runAction("hide_window", refreshAfter: false) } label: {
                Label("Hide", systemImage: "minus.rectangle")
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .modifier(LiquidGlassCardModifier(cornerRadius: 14))
    }

    // MARK: - Card 1: Extended Screen & GPU

    private var extendedDisplayCard: some View {
        let gpuOptions = IntegratorViewModel.gpuPickerOptions(from: s?.local_gpus ?? [])
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "display.2",
                title: "Extended Screen & GPU Acceleration",
                pillText: s?.display_active == true ? (s?.active_mode ?? "Active") : "Standby",
                pillColor: s?.display_active == true ? .green : .secondary,
                toggleBinding: Binding(
                    get: { flags.display },
                    set: { vm.toggleFeature("display", enabled: $0) }
                )
            )

            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Encode GPU").font(.caption).foregroundStyle(.secondary)
                    Picker("", selection: Binding(
                        get: { vm.selectedEncodeGpu },
                        set: {
                            vm.selectedEncodeGpu = $0
                            vm.encodeGpuDirty = true
                        }
                    )) {
                        ForEach(gpuOptions, id: \.tag) { opt in
                            Text(opt.label).tag(opt.tag)
                        }
                    }
                    .labelsHidden()
                    .disabled(!(s?.gpu_controls_supported ?? false))
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Decode GPU").font(.caption).foregroundStyle(.secondary)
                    Picker("", selection: Binding(
                        get: { vm.selectedDecodeGpu },
                        set: {
                            vm.selectedDecodeGpu = $0
                            vm.decodeGpuDirty = true
                        }
                    )) {
                        ForEach(gpuOptions, id: \.tag) { opt in
                            Text(opt.label).tag(opt.tag)
                        }
                    }
                    .labelsHidden()
                    .disabled(!(s?.gpu_controls_supported ?? false))
                }
            }

            if let t = vm.gpuTelemetry {
                HStack(spacing: 12) {
                    Label("\(t.gpu_name)", systemImage: "cpu")
                    Label("\(t.temperature_c)°C", systemImage: "thermometer")
                    Label("\(t.gpu_utilization_percent)%", systemImage: "gauge")
                    Label("\(t.memory_used_mb)/\(t.memory_total_mb) MB", systemImage: "memorychip")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
                Text(s?.gpu_controls_supported == true
                     ? "DirectX / NVENC / Moonlight hardware routing ready."
                     : (s?.cpu_brand.localizedCaseInsensitiveContains("Apple") == true
                        ? "Apple Silicon Unified Memory & VideoToolbox active."
                        : "macOS VideoToolbox hardware encoding active."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    Button { vm.runAction("toggle_mac_to_pc") } label: {
                        Text("Extend Mac -> PC").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.display)

                    Button { vm.runAction("toggle_pc_to_mac") } label: {
                        Text("Extend PC -> Mac").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(!flags.display)
                }
                HStack(spacing: 8) {
                    Button("Apply GPU") {
                        vm.encodeGpuDirty = false
                        vm.decodeGpuDirty = false
                        vm.runAction("set_gpu_preferences", params: [
                            "encodeGpu": vm.selectedEncodeGpu,
                            "decodeGpu": vm.selectedDecodeGpu
                        ])
                    }
                    .buttonStyle(.bordered)
                    .disabled(!(s?.gpu_controls_supported ?? false))
                    Button("Query GPU") { vm.queryGpuTelemetry() }
                        .buttonStyle(.bordered)
                    Spacer()
                }
            }
            Spacer(minLength: 0)
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 2: Universal Input KVM & Interactive Desk Layout

    private var kvmLayoutCard: some View {
        let kvm = s?.kvm
        let hookActive = kvm?.hook_active ?? true
        let roleText: String
        let roleColor: Color
        if !flags.input_kvm {
            roleText = "Disabled"
            roleColor = .secondary
        } else if !hookActive {
            roleText = "Accessibility Off"
            roleColor = .orange
        } else {
            roleText = switch kvm?.role ?? "idle" {
            case "controlling": "Controlling Peer"
            case "controlled": "Controlled by Peer"
            default: kvm?.connected_peer_ip != nil ? "Linked • Ready" : "Awaiting Peer"
            }
            roleColor = kvm?.connected_peer_ip != nil ? .green : .orange
        }

        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "cursorarrow.and.square.on.square.dashed",
                title: "Universal Input KVM & Desk Layout",
                pillText: roleText,
                pillColor: roleColor,
                toggleBinding: Binding(
                    get: { flags.input_kvm },
                    set: { vm.toggleFeature("input_kvm", enabled: $0) }
                )
            )

            if flags.input_kvm && !hookActive {
                HStack(spacing: 8) {
                    Label("macOS Accessibility permission is needed to capture & inject mouse/keyboard events.", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                    Spacer()
                    Button("Grant Access") { vm.runAction("request_kvm_accessibility") }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                }
                .padding(8)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }

            // Interactive 2D Desk Placement Schematic
            VStack(spacing: 8) {
                edgeButton("Top", edge: "top")
                HStack(spacing: 10) {
                    edgeButton("Left", edge: "left")
                    deskMonitorSchematic
                    edgeButton("Right", edge: "right")
                }
                edgeButton("Bottom", edge: "bottom")
            }
            .padding(10)
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12))

            VStack(spacing: 8) {
                HStack {
                    Text("Alignment Offset")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Slider(
                        value: Binding(
                            get: { Double(vm.kvmLayout.alignment_offset) },
                            set: { vm.kvmLayout.alignment_offset = Float($0) }
                        ),
                        in: -0.5...0.5,
                        step: 0.05
                    )
                    Text(String(format: "%+.2f", vm.kvmLayout.alignment_offset))
                        .font(.caption.monospacedDigit())
                        .frame(width: 44, alignment: .trailing)
                }

                HStack {
                    Text("Edge Hop Delay")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Slider(
                        value: Binding(
                            get: { Double(vm.kvmLayout.hop_delay_ms) },
                            set: { vm.kvmLayout.hop_delay_ms = UInt32($0) }
                        ),
                        in: 0...250,
                        step: 10
                    )
                    Text("\(vm.kvmLayout.hop_delay_ms) ms")
                        .font(.caption.monospacedDigit())
                        .frame(width: 50, alignment: .trailing)
                }

                HStack(spacing: 12) {
                    Toggle("Corner Guard", isOn: $vm.kvmLayout.dead_corners)
                    Toggle("⌘ <-> Ctrl", isOn: $vm.kvmLayout.modifier_translation)
                    Toggle("Trackpad", isOn: $vm.kvmLayout.precision_touchpad)
                }
                .font(.caption)
                .toggleStyle(.checkbox)
            }

            HStack(spacing: 8) {
                Button("Save & Sync Layout") { vm.syncKvmLayout() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.input_kvm)
                Button("Release Lock") { vm.runAction("release_kvm_control") }
                    .buttonStyle(.bordered)
                Spacer()
                Text("Panic: Ctrl+Alt+Shift+Esc")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    private func edgeButton(_ title: String, edge: String) -> some View {
        let active = vm.kvmLayout.peer_edge == edge
        return Button(title) {
            vm.updateEdgeAndSyncPreservingDirty(edge)
        }
        .buttonStyle(.bordered)
        .tint(active ? .accentColor : .secondary)
        .controlSize(.small)
    }

    private var deskMonitorSchematic: some View {
        let edge = vm.kvmLayout.peer_edge
        let peerName = s?.peer_name ?? "Peer PC"
        let localName = s?.hostname ?? "This Mac"
        let localBox = monitorTile(localName, accent: true)
        let peerBox = monitorTile(peerName, accent: false)

        return Group {
            switch edge {
            case "left":
                HStack(spacing: 6) { peerBox; localBox }
            case "top":
                VStack(spacing: 6) { peerBox; localBox }
            case "bottom":
                VStack(spacing: 6) { localBox; peerBox }
            default:
                HStack(spacing: 6) { localBox; peerBox }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 74)
    }

    private func monitorTile(_ label: String, accent: Bool) -> some View {
        Text(label)
            .font(.caption.weight(.semibold))
            .lineLimit(1)
            .padding(.horizontal, 10)
            .padding(.vertical, 10)
            .frame(minWidth: 82)
            .background(
                (accent ? Color.accentColor.opacity(0.24) : Color.secondary.opacity(0.18)),
                in: RoundedRectangle(cornerRadius: 8)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(accent ? Color.accentColor.opacity(0.6) : Color.primary.opacity(0.16), lineWidth: 1)
            )
    }

    // MARK: - Card 3: Cross-Screen Drag & Drop

    private var dragDropCard: some View {
        let activeLabel = s?.kvm.active_drag_label
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "arrow.up.right.and.arrow.down.left.rectangle",
                title: "Cross-Screen Drag & Drop",
                pillText: !flags.input_kvm
                    ? "Requires KVM"
                    : (activeLabel != nil ? "Transferring" : (flags.dragdrop ? "Ready" : "Off")),
                pillColor: !flags.input_kvm ? .orange : (flags.dragdrop ? .green : .secondary),
                toggleBinding: Binding(
                    get: { flags.dragdrop && flags.input_kvm },
                    set: { vm.toggleFeature("dragdrop", enabled: $0) }
                ),
                toggleDisabled: !flags.input_kvm
            )

            if !flags.input_kvm {
                Label("Enable Universal Input KVM to use Cross-Screen Drag & Drop.", systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack(spacing: 14) {
                Toggle("Translucent Ghost Badge", isOn: $vm.kvmLayout.ghost_thumbnail)
                Toggle("QoS Clamp", isOn: $vm.kvmLayout.qos_clamp)
            }
            .font(.caption)
            .toggleStyle(.checkbox)

            HStack {
                Text("Fallback Drop Folder").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Picker("", selection: $vm.kvmLayout.drop_folder) {
                    Text("Downloads").tag("downloads")
                    Text("Desktop").tag("desktop")
                    Text("Clipboard Cache").tag("cache")
                }
                .labelsHidden()
                .frame(width: 150)
            }

            HStack {
                Button("Save Drop Prefs") { vm.syncKvmLayout() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.input_kvm || !flags.dragdrop)
                Button("Open Cache") { vm.runAction("open_cache_folder", refreshAfter: false) }
                    .buttonStyle(.bordered)
                Spacer()
                if let label = activeLabel {
                    Text("Active: \(label)").font(.caption).foregroundStyle(.tint)
                }
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 4: Universal Clipboard

    private var clipboardCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "doc.on.clipboard",
                title: "Universal Clipboard",
                pillText: !flags.input_kvm ? "Requires KVM" : (flags.clipboard ? "Encrypted Sync" : "Off"),
                pillColor: !flags.input_kvm ? .orange : (flags.clipboard ? .green : .secondary),
                toggleBinding: Binding(
                    get: { flags.clipboard && flags.input_kvm },
                    set: { vm.toggleFeature("clipboard", enabled: $0) }
                ),
                toggleDisabled: !flags.input_kvm
            )

            if !flags.input_kvm {
                Label("Enable Universal Input KVM to unlock Universal Clipboard.", systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            Text("Zero-RAM ChaCha20 file streaming with per-file & manifest SHA-256 verification and atomic isolated staging.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 8) {
                Button("Paste Remote Item") { vm.runAction("paste_remote") }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.input_kvm || !flags.clipboard)
                Button("Open Cache") { vm.runAction("open_cache_folder", refreshAfter: false) }
                    .buttonStyle(.bordered)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 5: Peer Discovery & v2.0 Trust

    private var discoveryTrustCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "lock.shield",
                title: "Peer Discovery & v2.0 Trust",
                pillText: "PIN: \(s?.trust.pairing_pin ?? "------")",
                pillColor: .cyan
            )

            HStack(spacing: 8) {
                Text("Pairing PIN:")
                    .font(.caption).foregroundStyle(.secondary)
                Text(s?.trust.pairing_pin ?? "------")
                    .font(.system(.title3, design: .monospaced).bold())
                Spacer()
                Button("Regenerate PIN") {
                    vm.runAction("regenerate_pairing_pin", suppressDataToast: true, successToast: "Pairing PIN rotated")
                }
                .buttonStyle(.bordered)
            }

            HStack(spacing: 8) {
                TextField("Manual Peer IPv4 (e.g. 10.99.99.1)", text: $vm.manualIpInput)
                    .textFieldStyle(.roundedBorder)
                Button("Add IP") {
                    let ip = vm.manualIpInput.trimmingCharacters(in: .whitespaces)
                    guard !ip.isEmpty else { return }
                    vm.manualIpInput = ""
                    vm.runAction("add_manual_peer_ip", params: ["ip": ip])
                }
                .buttonStyle(.bordered)
            }

            if let manualIps = s?.manual_peer_ips, !manualIps.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(manualIps, id: \.self) { ip in
                            HStack(spacing: 4) {
                                Text(ip).font(.caption2.monospaced())
                                Button {
                                    vm.runAction("remove_manual_peer_ip", params: ["ip": ip])
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.caption2)
                                }
                                .buttonStyle(.plain)
                                .accessibilityLabel("Remove manual IP \(ip)")
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Color.primary.opacity(0.08), in: Capsule())
                        }
                    }
                }
            }

            ForEach(s?.discovered_peers ?? []) { peer in
                let pinDraft = (vm.pairPinInputs[peer.ip] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(peer.hostname).font(.subheadline.weight(.semibold))
                        Text("(\(peer.ip))").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        StatusPill(
                            text: peer.trusted ? "Trusted" : (peer.blocked ? "Blocked" : "Unpaired"),
                            color: peer.trusted ? .green : (peer.blocked ? .red : .orange)
                        )
                    }
                    HStack(spacing: 6) {
                        if peer.blocked {
                            Button("Unblock") {
                                vm.runAction("untrust_or_block_peer", params: ["deviceId": peer.device_id, "block": false])
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        } else if !peer.trusted {
                            TextField(
                                "6-digit PIN",
                                text: Binding(
                                    get: { vm.pairPinInputs[peer.ip] ?? "" },
                                    set: { vm.pairPinInputs[peer.ip] = $0 }
                                )
                            )
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 110)

                            Button("Pair v2.0") {
                                let pin = (vm.pairPinInputs[peer.ip] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                                vm.pairPinInputs.removeValue(forKey: peer.ip)
                                vm.runAction("pair_with_peer", params: ["ip": peer.ip, "pin": pin])
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                            .disabled(pinDraft.count != 6)

                            Button("Block") {
                                vm.pairPinInputs.removeValue(forKey: peer.ip)
                                vm.runAction("untrust_or_block_peer", params: ["deviceId": peer.device_id, "block": true])
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        } else {
                            Button("Untrust") {
                                vm.runAction("untrust_or_block_peer", params: ["deviceId": peer.device_id, "block": false])
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            Button("Block") {
                                vm.runAction("untrust_or_block_peer", params: ["deviceId": peer.device_id, "block": true])
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        Spacer()
                        Text(peer.transport_label).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                .padding(10)
                .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }

            ForEach(s?.trust.trusted_peers.filter { tp in
                !(s?.discovered_peers ?? []).contains(where: { $0.device_id == tp.device_id && $0.trusted })
            } ?? []) { tp in
                HStack(spacing: 8) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(tp.hostname) (Pinned Key)")
                            .font(.subheadline.weight(.semibold))
                        Text("ID: \(String(tp.device_id.prefix(12)))… • \(tp.last_ip)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Untrust") {
                        vm.runAction("untrust_or_block_peer", params: ["deviceId": tp.device_id, "block": false])
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Button("Block") {
                        vm.runAction("untrust_or_block_peer", params: ["deviceId": tp.device_id, "block": true])
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(10)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            }

            ForEach(s?.trust.blocked_device_ids.filter { bid in
                !(s?.discovered_peers ?? []).contains(where: { $0.device_id == bid && $0.blocked })
            } ?? [], id: \.self) { blockedId in
                HStack(spacing: 8) {
                    Text("Blocked Device: \(String(blockedId.prefix(12)))…")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Unblock") {
                        vm.runAction("untrust_or_block_peer", params: ["deviceId": blockedId, "block": false])
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(8)
                .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }

            Label("SPAKE2 + Ed25519 Mutual Auth Enforced on USB-C & LAN (v2.0 Locked)", systemImage: "checkmark.seal.fill")
                .font(.caption2)
                .foregroundStyle(.green)
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 6: Route Telemetry & Speed

    private var routeSpeedCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "speedometer",
                title: "Route Telemetry & Link Speed",
                pillText: s?.link_speed ?? "--",
                pillColor: s?.peer_connected == true ? .cyan : .secondary
            )

            HStack(spacing: 16) {
                metricBox("Route", s?.link_type ?? "--")
                metricBox("Speed", s?.link_speed ?? "--")
                metricBox("RTT", s?.rtt_ms.map { String(format: "%.2f ms", $0) } ?? "--")
            }

            if let r = vm.speedResult {
                Text(String(format: "Peak %.2f Gbps • ↑ %.2f Gbps (%.0f MB/s) • ↓ %.2f Gbps (%.0f MB/s)",
                            r.max_gbps, r.upload_gbps, r.upload_mb_s, r.download_gbps, r.download_mb_s))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.green)
            } else {
                Text("Interfaces: \((s?.local_interfaces ?? []).map { "\($0.name): \($0.ip)" }.joined(separator: ", "))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            HStack {
                Button(vm.isRunningSpeedTest ? "Benchmarking..." : "Run Live Speed Test") {
                    vm.runSpeedBenchmark()
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isRunningSpeedTest || s?.peer_connected != true || !(flags.benchmark ?? true))
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    private func metricBox(_ label: String, _ val: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(val).font(.subheadline.weight(.semibold)).lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Card 7: Auto-Mounted Shared Storage

    private var sharedStorageCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "externaldrive.connected.to.line.below",
                title: "Auto-Mounted Shared Storage",
                pillText: s?.storage_mounted == true ? "Mounted" : "Unmounted",
                pillColor: s?.storage_mounted == true ? .green : .secondary,
                toggleBinding: Binding(
                    get: { flags.storage },
                    set: { vm.toggleFeature("storage", enabled: $0) }
                )
            )

            Text(storageSummaryText)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)

            HStack(spacing: 8) {
                TextField("Preferred Share Name", text: Binding(
                    get: { vm.preferredShareInput },
                    set: {
                        vm.preferredShareInput = $0
                        vm.preferredShareDirty = true
                    }
                ))
                .textFieldStyle(.roundedBorder)
                Button("Set Share") {
                    let trimmed = vm.preferredShareInput.trimmingCharacters(in: .whitespaces)
                    vm.preferredShareDirty = false
                    vm.runAction("set_preferred_peer_share", params: ["share": trimmed.isEmpty ? NSNull() : trimmed])
                }
                .buttonStyle(.bordered)
            }

            HStack(spacing: 8) {
                Button(s?.storage_mounted == true ? "Unmount Storage" : "Mount Shared Storage") {
                    vm.runAction(s?.storage_mounted == true ? "unmount_shared_storage" : "mount_shared_storage")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!flags.storage)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    private var storageSummaryText: String {
        guard let st = s?.storage_status else { return "SMB volume ready on trusted peer" }
        if !st.mount_path.isEmpty { return st.mount_path }
        if !st.message.isEmpty { return st.message }
        return "SMB volume ready on trusted peer"
    }

    // MARK: - Card 8: True Tone & Chromatic Sync

    private var trueToneCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "sun.max",
                title: "True Tone & Chromatic Sync",
                pillText: s?.ambient_supported == true
                    ? String(format: "%.0f lux • %dK", s?.ambient_lux ?? 0, s?.ambient_cct ?? 6500)
                    : "Manual",
                pillColor: flags.truetone ? .yellow : .secondary,
                toggleBinding: Binding(
                    get: { flags.truetone },
                    set: { vm.toggleFeature("truetone", enabled: $0) }
                )
            )

            HStack {
                Text("CCT").font(.caption).foregroundStyle(.secondary).frame(width: 44, alignment: .leading)
                Slider(value: $vm.trueToneCct, in: 3500...8000, step: 100)
                Text("\(Int(vm.trueToneCct))K").font(.caption.monospacedDigit()).frame(width: 52, alignment: .trailing)
            }
            HStack {
                Text("Gamma").font(.caption).foregroundStyle(.secondary).frame(width: 44, alignment: .leading)
                Slider(value: $vm.trueToneComp, in: 0.70...1.30, step: 0.05)
                Text(String(format: "%.2fx", vm.trueToneComp)).font(.caption.monospacedDigit()).frame(width: 52, alignment: .trailing)
            }

            HStack {
                Button("Sync Calibration") {
                    vm.runAction("apply_truetone_calibration", params: [
                        "cct": Int(vm.trueToneCct),
                        "compFactor": Float(vm.trueToneComp)
                    ])
                }
                .buttonStyle(.borderedProminent)
                .disabled(!flags.truetone)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 9: Touch Bar Hardware HUD

    private var touchBarCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "menubar.rectangle",
                title: "Touch Bar Hardware HUD",
                pillText: s?.touchbar_active == true ? "Active" : (s?.has_touch_bar == true ? "Ready" : "Unavailable"),
                pillColor: s?.touchbar_active == true ? .green : .secondary,
                toggleBinding: Binding(
                    get: { flags.touchbar },
                    set: { vm.toggleFeature("touchbar", enabled: $0) }
                )
            )

            Text(s?.has_touch_bar == true
                 ? "Liquid Glass Touch Bar GPU telemetry strip & quick controls."
                 : "No Apple Touch Bar hardware detected on this workstation.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button("Toggle Touch Bar HUD") { vm.runAction("toggle_touchbar_hud") }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.touchbar || s?.has_touch_bar != true)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 10: Dynamic Audio Routing

    private var audioCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "speaker.wave.3",
                title: "Dynamic Audio Routing",
                pillText: "UDP :58284",
                pillColor: flags.audio ? .green : .secondary,
                toggleBinding: Binding(
                    get: { flags.audio },
                    set: { vm.toggleFeature("audio", enabled: $0) }
                )
            )

            Text(s?.audio_status.topology ?? "Authenticated ChaCha20-Poly1305 spatial UDP audio sink ready.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button("Play Spatial Test Chime") { vm.runAction("play_spatial_chime") }
                    .buttonStyle(.borderedProminent)
                    .disabled(!flags.audio)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 11: System & Autostart

    private var systemLifecycleCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "gearshape.2",
                title: "System & Autostart",
                pillText: s?.autostart_enabled == true ? "Launch at Login" : "Manual Launch",
                pillColor: s?.autostart_enabled == true ? .green : .secondary
            )

            Toggle("Launch Integrator Automatically at Login", isOn: Binding(
                get: { s?.autostart_enabled ?? false },
                set: { vm.runAction("set_autostart", params: ["enabled": $0]) }
            ))
            .toggleStyle(.switch)

            Text("Roadmap Modules: Touch ID Biometric Gate • Mac → PC Camera • Multi-WAN Bonding")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 12: Live Logs Console

    private var renderedLogs: [RenderedLogEntry] {
        var counts: [String: Int] = [:]
        return (s?.recent_logs ?? []).suffix(40).map { entry in
            let base = "\(entry.ts_ms)-\(entry.level)-\(entry.message)"
            let n = counts[base, default: 0]
            counts[base] = n + 1
            return RenderedLogEntry(id: "\(base)#\(n)", entry: entry)
        }
    }

    private var logsCard: some View {
        let rows = renderedLogs
        return VStack(alignment: .leading, spacing: 10) {
            CardHeader(
                icon: "terminal",
                title: "Live Telemetry & Security Logs",
                pillText: "\(s?.recent_logs.count ?? 0) lines",
                pillColor: .secondary
            )

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 3) {
                    ForEach(rows) { row in
                        let entry = row.entry
                        Text("[\(entry.level)] \(entry.message)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(entry.level == "WARN" || entry.level == "ERROR" ? .orange : .primary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(8)
            }
            .frame(height: 140)
            .background(Color(nsColor: .textBackgroundColor).opacity(0.55), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.primary.opacity(0.10), lineWidth: 1))
        }
        .modifier(LiquidGlassCardModifier())
    }
}

private struct VisualEffectBackdrop: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}

// MARK: - AppKit Shell + Menu Bar Tray + Event Callback

@MainActor
private final class MacAppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var statusItem: NSStatusItem?
    var mainWindow: NSWindow?
    var startHidden: Bool = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMainMenu()
        setupStatusBar()
        setupMainWindow()

        if startHidden {
            NSApp.setActivationPolicy(.accessory)
            mainWindow?.orderOut(nil)
            IntegratorViewModel.shared.setPollingPaused(true)
        } else {
            NSApp.setActivationPolicy(.regular)
            showDashboard()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showDashboard()
        return true
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        IntegratorViewModel.shared.setPollingPaused(true)
        return false
    }

    func windowDidMiniaturize(_ notification: Notification) {
        IntegratorViewModel.shared.setPollingPaused(true)
    }

    func windowDidDeminiaturize(_ notification: Notification) {
        IntegratorViewModel.shared.setPollingPaused(false)
    }

    private func setupMainMenu() {
        let mainMenu = NSMenu()

        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu(title: "Integrator")
        appMenu.addItem(withTitle: "Show Dashboard", action: #selector(onShowDashboard), keyEquivalent: "d").target = self
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Quit Integrator", action: #selector(onQuit), keyEquivalent: "q").target = self
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        let fileMenuItem = NSMenuItem()
        let fileMenu = NSMenu(title: "File")
        fileMenu.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        fileMenuItem.submenu = fileMenu
        mainMenu.addItem(fileMenuItem)

        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redoItem = editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        redoItem.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        NSApp.mainMenu = mainMenu
    }

    private func setupStatusBar() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let btn = item.button {
            btn.image = NSImage(systemSymbolName: "link.circle", accessibilityDescription: "Integrator")
            btn.image?.isTemplate = true
        }
        let menu = NSMenu()
        menu.addItem(withTitle: "Show Dashboard", action: #selector(onShowDashboard), keyEquivalent: "d")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Paste Remote Item", action: #selector(onPasteRemote), keyEquivalent: "v")
        menu.addItem(withTitle: "Toggle Extended Screen", action: #selector(onToggleDisplay), keyEquivalent: "e")
        menu.addItem(withTitle: "Open Clipboard Cache", action: #selector(onOpenCache), keyEquivalent: "c")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Integrator", action: #selector(onQuit), keyEquivalent: "q")
        for mi in menu.items where mi.action != nil {
            mi.target = self
        }
        item.menu = menu
        statusItem = item
    }

    private func setupMainWindow() {
        let hosting = NSHostingController(rootView: MainDashboardView(vm: IntegratorViewModel.shared))
        let win = NSWindow(contentViewController: hosting)
        win.title = "Integrator"
        win.setContentSize(NSSize(width: 1240, height: 820))
        win.minSize = NSSize(width: 960, height: 640)
        win.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.isOpaque = false
        win.backgroundColor = .clear
        win.center()
        win.delegate = self
        mainWindow = win
    }

    func showDashboard() {
        NSApp.setActivationPolicy(.regular)
        mainWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        IntegratorViewModel.shared.setPollingPaused(false)
    }

    func hideDashboard() {
        mainWindow?.orderOut(nil)
        IntegratorViewModel.shared.setPollingPaused(true)
    }

    @objc private func onShowDashboard() { showDashboard() }
    @objc private func onPasteRemote() { "paste_remote".withCString { rustCoreTrayAction($0) } }
    @objc private func onToggleDisplay() { "toggle_display".withCString { rustCoreTrayAction($0) } }
    @objc private func onOpenCache() { "open_cache".withCString { rustCoreTrayAction($0) } }
    @objc private func onQuit() {
        IntegratorViewModel.shared.stopPolling()
        rustCoreSetUiCallback(nil)
        rustCoreShutdown()
        NSApp.terminate(nil)
    }
}

private var gMacAppDelegate: MacAppDelegate? = nil

private let swiftUiEventTrampoline: RustUiCallback = { evPtr, payloadPtr in
    let eventName = evPtr.map { String(cString: $0) } ?? ""
    if eventName == "log_entry" {
        return
    }
    let payloadStr = payloadPtr.map { String(cString: $0) } ?? "{}"
    DispatchQueue.main.async {
        switch eventName {
        case "show_window":
            gMacAppDelegate?.showDashboard()
        case "hide_window":
            gMacAppDelegate?.hideDashboard()
        case "toast":
            if let data = payloadStr.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let msg = obj["message"] as? String
            {
                let kind = (obj["kind"] as? String) ?? "info"
                IntegratorViewModel.shared.showToast(kind, msg)
            }
        case "quit":
            IntegratorViewModel.shared.stopPolling()
            rustCoreSetUiCallback(nil)
            NSApp.terminate(nil)
        default:
            break
        }
    }
}

@MainActor
@_cdecl("integrator_macos_run_app")
public func integrator_macos_run_app(isHidden: Bool) {
    let app = NSApplication.shared
    let delegate = MacAppDelegate()
    delegate.startHidden = isHidden
    gMacAppDelegate = delegate
    app.delegate = delegate
    rustCoreSetUiCallback(swiftUiEventTrampoline)
    app.run()
}
