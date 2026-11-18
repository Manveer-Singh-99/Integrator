// ==============================================================================================
// Integrator macOS Native Client & Liquid Glass UI Shell (`ui-macos/IntegratorApp.swift`)
//
// 1. Module Purpose & System Scope:
//    - Serves as the primary user-facing interface for Integrator on macOS (13.0+ / Ventura through Sequoia).
//    - Hosts the native SwiftUI dashboard (`MainDashboardView`) inside an AppKit window container (`NSWindow`,
//      `NSHostingController`) managed by `MacAppDelegate`.
//    - Provides zero-latency hardware telemetry, interactive multi-display desk layout configuration,
//      peer pairing & cryptographic trust management, dynamic GPU routing preferences, live log stream
//      monitoring, and status bar menu (`NSStatusItem`) control.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Dynamic Library Linkage: Direct C-ABI dynamic invocation against `integrator_core.dylib` via
//      `@_silgen_name` bindings:
//        * `integrator_core_invoke(method, paramsJson) -> *mut c_char`: Synchronous JSON-RPC request/response.
//        * `integrator_core_free_string(ptr)`: Releases heap-allocated UTF-8 C-string buffers from Rust.
//        * `integrator_core_tray_action(action)`: Fires one-way asynchronous tray notifications into Rust.
//        * `integrator_core_shutdown()`: Performs graceful teardown of Tokio runtimes, daemon tasks, and network listeners.
//        * `integrator_core_set_ui_callback(cb)`: Registers the reverse event trampoline (`RustUiCallback`).
//    - JSON-RPC Dispatch Pipeline:
//        * High-level requests from UI interactions or the 2.0s polling timer are packaged into JSON strings.
//        * Dispatched onto background GCD queues (`DispatchQueue.global(qos: .userInitiated)`) to ensure the
//          macOS Main Thread (and AppKit UI rendering loop) is never blocked by synchronous Rust RPC calls.
//        * The raw JSON string returned by Rust is parsed into strongly-typed Codable structures (`BridgeStatusModel`,
//          `SpeedTestResultModel`, `GpuTelemetryModel`, etc.) and published to `@MainActor` state variables.
//    - Asynchronous Event Trampoline (`swiftUiEventTrampoline`):
//        * Registered with Rust core at startup (`integrator_core_set_ui_callback`).
//        * Core pushes notifications for window control (`show_window`, `hide_window`), toast banners (`toast`),
//          and lifecycle termination (`quit`).
//        * High-frequency telemetry events (`log_entry`) are dropped at the C-trampoline boundary to prevent
//          main thread saturation; log rings are polled deterministically via snapshot snapshots.
//
// 3. Card Architecture & Subsystems:
//    - Card 1: Extended Screen & GPU Acceleration (DirectX/NVENC/Moonlight vs Apple Silicon VideoToolbox).
//    - Card 2: Universal Input KVM & Desk Layout (Interactive 2D spatial monitor arrangement, edge hop delays,
//      modifier translation Cmd<->Ctrl, corner guard dead zones, macOS Accessibility hook status).
//    - Card 3: Cross-Screen Drag & Drop (Zero-RAM file streaming, ghost thumbnail badge, QoS clamping, drop directory).
//    - Card 4: Universal Clipboard (ChaCha20 encrypted sync, SHA-256 integrity, atomic staging cache).
//    - Card 5: Peer Discovery & v1.0 Trust (mDNS / UDP beacon discovery, SPAKE2 6-digit PIN pairing, manual IP routing,
//      Ed25519 identity key pinning, peer unpairing and device blocking).
//    - Card 6: Route Telemetry & Link Speed (Active interface discovery, real-time RTT latency, TCP/UDP link benchmarking).
//    - Card 7: Auto-Mounted Shared Storage (Automated SMB volume negotiation, preferred share mounts, mount state tracking).
//    - Card 8: True Tone & Chromatic Sync (Ambient light sensor / CCT synchronization, manual chromaticity calibration).
//    - Card 9: Touch Bar Hardware HUD (Touch Bar telemetry strip, quick-action controls for supported MacBooks).
//    - Card 10: Dynamic Audio Routing (ChaCha20-Poly1305 encrypted spatial UDP sink, test chime invocation).
//    - Card 10B: Mac -> PC Shared Camera (AVFoundation 720p30 capture streaming over TCP :58287 to Windows Virtual Camera).
//    - Card 11: System & Autostart (macOS SMAppService login item autostart, Liquid Glass shader intensity slider).
//    - Card 12: Live Telemetry & Security Logs (Monospaced tailing log console with ANSI/log-level visual highlighting).
//
// 4. Liquid Glass Shader & Visual Styling:
//    - Utilizes custom SwiftUI view modifiers (`LiquidGlassCardModifier`, `LiquidGlassSidebarModifier`).
//    - On macOS 26.0+ (compiler >= 6.2), binds to `.glassEffect(intensity < 0.35 ? .clear : .regular)`.
//    - Gracefully degrades on earlier macOS versions to dynamic material backdrops (`.ultraThinMaterial`,
//      `.thinMaterial`, `.regularMaterial`), layered over `NSVisualEffectView` behind-window blurs.
//    - Modulated dynamically by the user-controllable `@AppStorage("liquidGlassIntensity")` slider (10% to 100%),
//      adjusting background fill opacity, specular border highlights, and refractive blur depth.
//
// 5. Threading & Concurrency Model:
//    - UI Execution: `@MainActor` executes all SwiftUI view rendering, AppKit window updates, and `@Published` state mutations.
//    - Core RPC Invocations: Offloaded to `DispatchQueue.global(qos: .userInitiated)` with safe C-pointer conversions.
//    - Timers: Polling runs on a 2.0-second repeating `Timer` scheduled on the main runloop, automatically paused
//      when the dashboard window is minimized, hidden to the menu bar tray, or closed.
//    - Memory Safety: Strict allocation management: all C-strings allocated via `withCString` are stack-bound,
//      and all heap-allocated return strings from `integrator_core_invoke` are explicitly freed via `rustCoreFreeString`.
//
// 6. Security & Safety Invariants:
//    - Sandboxing & Access Controls: Verifies macOS Accessibility permissions for mouse/keyboard capture and injection.
//    - Memory Hygiene: C-ABI pointers are verified non-null before dereferencing; exceptions during JSON decode
//      are caught and surfaced as user-friendly toast banners rather than crashing the process.
//    - Cryptographic Trust: Displays SPAKE2 mutual authentication and Ed25519 verification states clearly in status pills.
// ==============================================================================================

import AppKit
import Foundation
import SwiftUI

// MARK: - Rust Core C-ABI Declarations

/// Synchronous JSON-RPC dispatch bridge into `integrator_core.dylib`.
///
/// - Parameters:
///   - method: Null-terminated UTF-8 C-string specifying the RPC endpoint (e.g., `"get_bridge_status"`).
///   - paramsJson: Null-terminated UTF-8 C-string containing the JSON-encoded parameter payload.
/// - Returns: A heap-allocated, null-terminated UTF-8 C-string containing the JSON response envelope
///   (`RpcEnvelope`), or `nil` on native execution failure. The caller MUST free this pointer
///   using `rustCoreFreeString`.
@_silgen_name("integrator_core_invoke")
private func rustCoreInvoke(
    _ method: UnsafePointer<CChar>,
    _ paramsJson: UnsafePointer<CChar>
) -> UnsafeMutablePointer<CChar>?

/// Deallocates a heap-allocated UTF-8 string previously returned by `integrator_core_invoke`.
///
/// - Parameter ptr: The raw mutable C-string pointer allocated by Rust's global allocator (`CString::into_raw`).
///   Safe to call with `nil` (no-op).
@_silgen_name("integrator_core_free_string")
private func rustCoreFreeString(_ ptr: UnsafeMutablePointer<CChar>?)

/// Sends a one-way notification string from the macOS status bar menu or UI shell directly
/// into the Rust core's tray dispatch subsystem.
///
/// - Parameter action: Null-terminated UTF-8 action key (e.g., `"paste_remote"`, `"toggle_display"`, `"open_cache"`).
@_silgen_name("integrator_core_tray_action")
private func rustCoreTrayAction(_ action: UnsafePointer<CChar>)

/// Initiates synchronous shutdown of the Rust backend runtime, terminating active TCP/UDP listeners,
/// canceling Tokio tasks, and unmounting remote shares.
@_silgen_name("integrator_core_shutdown")
private func rustCoreShutdown()

/// C-compatible function pointer signature for reverse notifications pushed from the Rust core
/// into the macOS UI layer.
///
/// - Parameters:
///   - eventName: Null-terminated UTF-8 event identifier (e.g., `"show_window"`, `"hide_window"`, `"toast"`).
///   - payloadJson: Null-terminated UTF-8 JSON string containing event metadata.
typealias RustUiCallback = @convention(c) (
    UnsafePointer<CChar>?,
    UnsafePointer<CChar>?
) -> Void

/// Registers or unregisters the global reverse event callback in `integrator_core.dylib`.
///
/// - Parameter cb: The C-convention callback function pointer, or `nil` during shutdown.
@_silgen_name("integrator_core_set_ui_callback")
private func rustCoreSetUiCallback(_ cb: RustUiCallback?)

// MARK: - Codable Data Models (mirror Rust Core BridgeStatus & RPC payloads)

/// Standard JSON-RPC response wrapper deserialized from `integrator_core_invoke`.
private struct RpcEnvelope<T: Decodable>: Decodable {
    /// Boolean indicating whether the native RPC method executed successfully.
    let ok: Bool
    /// Typed payload data returned on success, or `nil` on failure.
    let data: T?
    /// Error message returned when `ok` is `false`.
    let error: String?
}

/// Primary display geometry and scaling factor of the local macOS workstation.
struct PrimaryDisplayInfo: Codable, Hashable {
    /// Native horizontal resolution in pixels.
    var width: UInt32 = 0
    /// Native vertical resolution in pixels.
    var height: UInt32 = 0
    /// Refresh rate in frames per second (e.g., 60, 120).
    var fps: UInt32 = 60
    /// Retina scale factor (e.g., 2.0 for standard MacBook Pro displays).
    var scale_factor: Double = 2.0
}

/// Metadata describing an individual GPU detected on the local or peer machine.
struct GpuDeviceInfo: Codable, Identifiable, Hashable {
    /// Stable identifier constructed from the GPU index and name.
    var id: String { "\(index)-\(name)" }
    /// Zero-based adapter index assigned by Metal or DirectX.
    var index: UInt32
    /// Marketing or device name of the graphics adapter.
    var name: String
    /// Hardware vendor string (e.g., "Apple", "NVIDIA", "AMD", "Intel").
    var vendor: String
    /// True if the adapter is a dedicated discrete GPU; false for integrated graphics.
    var is_discrete: Bool
    /// Dedicated video memory in megabytes, if available from the driver.
    var vram_mb: UInt64?
}

/// Geometric attributes of a display monitor.
struct DisplayGeometryModel: Codable, Hashable {
    /// Width in physical pixels.
    var width: UInt32
    /// Height in physical pixels.
    var height: UInt32
    /// Refresh rate in hertz.
    var fps: UInt32
}

/// Network interface descriptor capturing IP address, link speed, and interface type.
struct LocalInterfaceModel: Codable, Identifiable, Hashable {
    /// Composite identifier based on interface name and IP.
    var id: String { "\(name)-\(ip)" }
    /// System interface device name (e.g., "en0", "bridge0").
    var name: String
    /// User-friendly label (e.g., "Thunderbolt Bridge", "Wi-Fi").
    var friendly_name: String?
    /// Bound IPv4 or IPv6 address string.
    var ip: String
    /// Subnet mask string.
    var netmask: String?
    /// Directed broadcast address string.
    var broadcast: String?
    /// CIDR prefix length (e.g., 24 for /24 subnets).
    var cidr_prefix: UInt8?
    /// Physical transport medium (e.g., "Thunderbolt", "Ethernet", "Wi-Fi").
    var transport: String?
    /// Negotiated link speed in megabits per second (e.g., 10000 for 10GbE).
    var link_speed_mbps: UInt32?
    /// Diagnostic description of the interface link status.
    var description: String?
}

/// Unpaired peer device discovered over the local network or direct cable.
struct PendingPeerModel: Codable, Identifiable, Hashable {
    /// Stable device identifier.
    var id: String { device_id }
    /// Cryptographic device identifier string.
    var device_id: String
    /// Network hostname of the pending peer.
    var hostname: String
    /// Reachable IP address of the peer.
    var ip: String
    /// Indicates whether connection is established over a point-to-point cable.
    var is_direct_cable: Bool
    /// Authentication trust flag.
    var trusted: Bool
    /// Administrative block flag.
    var blocked: Bool
}

/// Record of an authenticated and trusted peer workstation.
struct TrustedPeerModel: Codable, Identifiable, Hashable {
    /// Stable device identifier.
    var id: String { device_id }
    /// Cryptographic device identifier string.
    var device_id: String
    /// Hostname of the trusted peer.
    var hostname: String
    /// Last observed IP address.
    var last_ip: String
    /// Unix timestamp in seconds when pairing was established.
    var paired_at_epoch: UInt64?
    /// Whether pairing occurred over direct physical cable.
    var via_direct_cable: Bool
    /// Hex-encoded Ed25519 identity public key for mutual authentication.
    var ed25519_pubkey_hex: String?
    /// Hex-encoded identifier derived from the peer's public key.
    var key_id_hex: String?
}

/// Discovered peer device actively broadcasting mDNS/UDP beacons.
struct DiscoveredPeerModel: Codable, Identifiable, Hashable {
    /// Composite identifier combining device ID and IP address.
    var id: String { "\(device_id)-\(ip)" }
    /// Cryptographic device identifier string.
    var device_id: String
    /// Hostname announced by the peer.
    var hostname: String
    /// Operating system string (e.g., "macOS", "Windows").
    var os: String
    /// Hardware model string (e.g., "MacBookPro18,1", "Custom PC").
    var hardware_model: String
    /// Reachable IPv4 address.
    var ip: String
    /// Local interface IP address used to communicate with this peer.
    var local_ip_used: String?
    /// Human-readable transport label (e.g., "Thunderbolt 4", "10GbE").
    var transport_label: String
    /// True if direct point-to-point link.
    var is_direct_cable: Bool
    /// Link throughput in Mbps.
    var link_speed_mbps: UInt32?
    /// Descriptive string of connection topology.
    var link_description: String
    /// Measured round-trip latency in milliseconds.
    var rtt_ms: Double?
    /// Display resolution and refresh rate of the peer.
    var display: DisplayGeometryModel
    /// List of GPU names available on the peer machine.
    var gpus: [String]
    /// Discovered SMB/NFS share name published by the peer.
    var share_name: String?
    /// True if authenticated and present in the trust store.
    var trusted: Bool
    /// True if device ID is in the administrative blocklist.
    var blocked: Bool
}

/// Complete snapshot of the cryptographic pairing and trust database.
struct TrustSnapshotModel: Codable, Hashable {
    /// Current 6-digit SPAKE2 pairing PIN code generated by the local machine.
    var pairing_pin: String
    /// Policy flag: automatically trust peers on direct point-to-point cables.
    var auto_trust_direct_cable: Bool
    /// Policy flag: require manual PIN pairing for all peers discovered over LAN.
    var require_pairing_on_lan: Bool
    /// List of peers awaiting user approval or PIN confirmation.
    var pending_peers: [PendingPeerModel]
    /// List of persistently trusted peers stored in the OS keystore.
    var trusted_peers: [TrustedPeerModel]
    /// List of device identifiers blocked from communicating with this host.
    var blocked_device_ids: [String]
}

/// Current mount status of the peer's shared network storage volume.
struct StorageStatusModel: Codable, Hashable {
    /// True if the SMB volume is currently mounted in macOS `/Volumes`.
    var is_mounted: Bool
    /// Local filesystem path where the volume is mounted.
    var mount_path: String
    /// Remote host IP address hosting the SMB share.
    var remote_ip: String
    /// Share name on the remote host (e.g., "IntegratorShare").
    var remote_share: String
    /// Diagnostic message or error string from the mount subsystem.
    var message: String
}

/// Status of the low-latency authenticated UDP spatial audio stream.
struct AudioRoutingStatusModel: Codable, Hashable {
    /// Human-readable description of active audio topology (e.g., "Mac -> PC Stereo").
    var topology: String
    /// End-to-end measured audio routing latency in milliseconds.
    var latency_ms: Float
    /// Audio sample rate in Hz (e.g., 48000).
    var sample_rate: UInt32
    /// Audio bit depth (e.g., 16 or 24 bit PCM).
    var bit_depth: UInt8
    /// True if the audio capture or playback stream is actively running.
    var is_active: Bool
}

/// Telemetry and state of the Mac -> PC shared virtual camera pipeline.
struct CameraStatusModel: Codable, Hashable {
    /// True if camera capture hardware is supported and present.
    var supported: Bool
    /// True if the camera stream is actively transmitting frames over TCP :58287.
    var active: Bool
    /// Operational role: "sender" (macOS) or "receiver" (Windows Virtual Camera).
    var role: String
    /// Current state description (e.g., "Streaming", "Standby", "Disabled").
    var state: String
    /// Whether AVFoundation camera permissions have been granted by macOS.
    var permission_granted: Bool
    /// Frame width in pixels (typically 1280 for 720p).
    var width: UInt32
    /// Frame height in pixels (typically 720 for 720p).
    var height: UInt32
    /// Frame rate in FPS (typically 30).
    var fps: UInt32
    /// Total cumulative frames transferred across the network session.
    var frames_transferred: UInt64
    /// Last error encountered during capture, encoding, or transmission.
    var last_error: String?
}

/// Boolean feature flags controlling active subsystem daemons in Rust core.
struct FeatureFlagsModel: Codable, Hashable {
    /// Extended display streaming subsystem flag.
    var display: Bool
    /// Universal input KVM capture and injection flag.
    var input_kvm: Bool
    /// Encrypted clipboard synchronization flag.
    var clipboard: Bool
    /// Cross-screen drag and drop file transfer flag.
    var dragdrop: Bool
    /// True Tone and ambient chromaticity synchronization flag.
    var truetone: Bool
    /// Apple Touch Bar telemetry HUD flag.
    var touchbar: Bool
    /// Automated SMB shared storage mounting flag.
    var storage: Bool
    /// Authenticated UDP spatial audio routing flag.
    var audio: Bool
    /// Live link speed throughput benchmark flag.
    var benchmark: Bool? = true
    /// Mac -> PC shared virtual camera streaming flag.
    var camera: Bool? = false
}

/// User-configured desk layout configuration for multi-monitor cursor transitions.
struct KvmLayoutConfigModel: Codable, Hashable {
    /// Screen edge where peer monitor is placed: "left", "right", "top", or "bottom".
    var peer_edge: String
    /// Fractional alignment offset along the shared boundary (-0.5 to +0.5).
    var alignment_offset: Float
    /// Delay in milliseconds required at the edge before hopping to the peer screen.
    var hop_delay_ms: UInt32
    /// Prevents accidental hops when slamming cursor into screen corners.
    var dead_corners: Bool
    /// Translates macOS Command keys to Windows Control keys and vice versa.
    var modifier_translation: Bool
    /// Translates high-precision trackpad gestures across machines.
    var precision_touchpad: Bool
    /// Displays a semi-transparent floating thumbnail of dragged files.
    var ghost_thumbnail: Bool
    /// Applies bandwidth QoS clamping during large file drag operations.
    var qos_clamp: Bool
    /// Target folder name for dropped items ("downloads", "desktop", "cache").
    var drop_folder: String
    /// Timestamp in milliseconds when this layout configuration was updated.
    var updated_at_ms: UInt64
}

/// Live operational state of the universal input KVM subsystem.
struct KvmStatusSnapshotModel: Codable, Hashable {
    /// Overall KVM subsystem enable flag.
    var enabled: Bool
    /// Cross-screen drag and drop active state.
    var dragdrop_enabled: Bool
    /// macOS Accessibility API CGEventTap hook operational status.
    var hook_active: Bool?
    /// Current KVM role: "idle", "controlling" (local cursor captured), or "controlled".
    var role: String
    /// IP address of peer currently engaged in KVM control.
    var connected_peer_ip: String?
    /// Operating system of the active peer.
    var peer_os: String?
    /// Screen width of the active peer display.
    var peer_width: UInt32
    /// Screen height of the active peer display.
    var peer_height: UInt32
    /// Filename or label of the payload currently being dragged across displays.
    var active_drag_label: String?
    /// Current desk layout geometry and edge transition settings.
    var layout: KvmLayoutConfigModel
}

/// Single log entry emitted by the Rust core tracing subscriber.
struct LogEntryModel: Codable, Identifiable, Hashable {
    /// Unique identifier constructed from timestamp, log level, and message content.
    var id: String { "\(ts_ms)-\(level)-\(message)" }
    /// Milliseconds since Unix epoch when log was recorded.
    var ts_ms: UInt64
    /// Severity level string: "TRACE", "DEBUG", "INFO", "WARN", or "ERROR".
    var level: String
    /// Formatted log message text.
    var message: String
}

/// UI presentation wrapper around `LogEntryModel` ensuring unique SwiftUI list item identities.
private struct RenderedLogEntry: Identifiable {
    /// Deduplicated identifier including ordinal counter.
    let id: String
    /// Underlying structured log entry.
    let entry: LogEntryModel
}

/// Results from an active TCP/UDP link throughput benchmark.
struct SpeedTestResultModel: Codable, Hashable {
    /// Peak measured throughput in gigabits per second.
    var max_gbps: Double
    /// Upload bandwidth in gigabits per second.
    var upload_gbps: Double
    /// Upload throughput in megabytes per second.
    var upload_mb_s: Double
    /// Download bandwidth in gigabits per second.
    var download_gbps: Double
    /// Download throughput in megabytes per second.
    var download_mb_s: Double
    /// Round-trip ping latency in milliseconds during test.
    var latency_ms: Double
    /// Formatted summary string of the benchmark test run.
    var summary: String
}

/// Hardware telemetry metrics polled from a discrete or integrated GPU.
struct GpuTelemetryModel: Codable, Hashable {
    /// Name of the monitored GPU adapter.
    var gpu_name: String
    /// Die temperature in degrees Celsius.
    var temperature_c: UInt32
    /// Real-time power draw in watts.
    var power_usage_watts: Float
    /// GPU core operating frequency in MHz.
    var core_clock_mhz: UInt32
    /// Video memory currently allocated in megabytes.
    var memory_used_mb: UInt64
    /// Total available video memory in megabytes.
    var memory_total_mb: UInt64
    /// Video memory controller utilization percentage (0-100%).
    var memory_utilization_percent: UInt32
    /// GPU graphics core load percentage (0-100%).
    var gpu_utilization_percent: UInt32
}

/// Aggregate system state model returned by `get_bridge_status` RPC.
struct BridgeStatusModel: Codable {
    /// Cryptographic identifier of the local workstation.
    var device_id: String
    /// Network hostname of the local workstation.
    var hostname: String
    /// Operating system name.
    var os: String
    /// Local operating system identifier.
    var local_os: String
    /// Hardware product model name.
    var hardware_model: String
    /// Processor architecture and brand string.
    var cpu_brand: String
    /// Primary local display configuration.
    var primary_display: PrimaryDisplayInfo
    /// List of graphics adapters present in the local machine.
    var local_gpus: [GpuDeviceInfo]
    /// Published SMB/NFS share folders on this host.
    var local_share_names: [String]
    /// True if the local machine features an Apple Touch Bar.
    var has_touch_bar: Bool

    /// True if a remote peer is actively connected via TCP control channel.
    var peer_connected: Bool
    /// True if the connected peer has completed SPAKE2 mutual pairing.
    var peer_trusted: Bool
    /// Device ID of the connected peer.
    var peer_device_id: String?
    /// IPv4/IPv6 address of the connected peer.
    var peer_ip: String?
    /// Operating system of the connected peer.
    var peer_os: String?
    /// Hostname of the connected peer.
    var peer_name: String?
    /// Hardware model of the connected peer.
    var peer_hardware_model: String?
    /// Display geometry of the peer's primary monitor.
    var peer_display: DisplayGeometryModel?
    /// List of GPUs present on the peer machine.
    var peer_gpus: [String]
    /// Storage share announced by the peer.
    var peer_share_name: String?
    /// Local IP interface address chosen for routing traffic to the peer.
    var peer_local_ip_used: String?
    /// Description of the physical connection (e.g., "Thunderbolt 4 Direct Cable").
    var transport_label: String
    /// True if connection is via point-to-point physical cable.
    var is_direct_cable: Bool
    /// Negotiated physical link speed in Mbps.
    var link_speed_mbps: UInt32?
    /// Detailed description of link topology.
    var link_description: String
    /// Round-trip ping time in milliseconds.
    var rtt_ms: Double?
    /// Formatted link speed string (e.g., "40 Gbps").
    var link_speed: String
    /// Link medium category (e.g., "Thunderbolt", "Ethernet").
    var link_type: String

    /// True if extended screen streaming is currently active.
    var display_active: Bool
    /// Active display streaming mode (e.g., "Mac -> PC" or "PC -> Mac").
    var active_mode: String?
    /// True if Windows is the primary master controlling display streaming.
    var is_windows_master: Bool
    /// Preferred hardware GPU identifier for video encoding.
    var encode_gpu: String
    /// Preferred hardware GPU identifier for video decoding.
    var decode_gpu: String
    /// True if the current platform supports explicit GPU adapter selection.
    var gpu_controls_supported: Bool
    /// True if the Touch Bar telemetry strip is actively visible.
    var touchbar_active: Bool

    /// True if ambient light sensor hardware is supported.
    var ambient_supported: Bool
    /// Measured ambient illuminance in lux.
    var ambient_lux: Float?
    /// Correlated Color Temperature in Kelvin.
    var ambient_cct: UInt32?

    /// True if remote storage volume is mounted.
    var storage_mounted: Bool
    /// Detailed shared storage mount telemetry.
    var storage_status: StorageStatusModel
    /// User's preferred SMB share name override.
    var preferred_peer_share: String?

    /// Spatial audio routing status.
    var audio_status: AudioRoutingStatusModel
    /// Shared virtual camera streaming status.
    var camera_status: CameraStatusModel?
    /// Current feature flag toggles.
    var feature_flags: FeatureFlagsModel
    /// KVM input and desk layout snapshot.
    var kvm: KvmStatusSnapshotModel

    /// List of network interfaces detected on the local workstation.
    var local_interfaces: [LocalInterfaceModel]
    /// User-specified manual peer IP targets.
    var manual_peer_ips: [String]
    /// List of peers discovered via mDNS and UDP broadcasts.
    var discovered_peers: [DiscoveredPeerModel]
    /// Trust store snapshot including pairing PIN and trusted peer list.
    var trust: TrustSnapshotModel

    /// True if Integrator is configured to launch at user login.
    var autostart_enabled: Bool
    /// Rolling ring buffer of recent log entries from the Rust core.
    var recent_logs: [LogEntryModel]
}

// MARK: - ViewModel

/// High-level navigation categories for filtering cards on the dashboard.
enum NavSection: String, CaseIterable, Identifiable {
    /// Displays all thirteen subsystem cards in a scrollable responsive grid.
    case all = "All Modules"
    /// Filters to Extended Display, GPU Acceleration, True Tone, and Touch Bar controls.
    case display = "Display & GPU"
    /// Filters to Universal Input KVM, Cross-Screen Drag & Drop, and Universal Clipboard.
    case input = "Input & Clipboard"
    /// Filters to Peer Discovery, SPAKE2 Pairing Trust, Route Telemetry, and Shared Storage.
    case network = "Network & Trust"
    /// Filters to Spatial Audio, Shared Camera, System Autostart, and Live Logs.
    case system = "System & Audio"

    /// Unique string identifier matching the raw string value.
    var id: String { rawValue }

    /// SF Symbol icon name representing the navigation category.
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

/// Ephemeral toast notification banner presented at the bottom of the dashboard.
struct ToastBanner: Identifiable {
    /// Unique identifier for SwiftUI transition tracking.
    let id = UUID()
    /// Notification style kind: "success", "error", or "info".
    let kind: String
    /// Text message displayed within the notification pill.
    let message: String
}

/// Central application ViewModel orchestrating JSON-RPC communication with `integrator_core.dylib`,
/// maintaining reactive UI state on `@MainActor`, and driving periodic status polling.
@MainActor
final class IntegratorViewModel: ObservableObject {
    /// Shared singleton instance bound to the application lifetime.
    static let shared = IntegratorViewModel()

    /// Currently active navigation section for card category filtering.
    @Published var section: NavSection = .all
    /// Latest bridge status snapshot returned by the Rust core backend.
    @Published var status: BridgeStatusModel? = nil
    /// Most recent live throughput speed test results.
    @Published var speedResult: SpeedTestResultModel? = nil
    /// Real-time discrete GPU metrics polled from the peer machine.
    @Published var gpuTelemetry: GpuTelemetryModel? = nil
    /// Active toast banner notification, or nil if no message is displayed.
    @Published var toast: ToastBanner? = nil
    /// True while an asynchronous speed benchmark run is executing.
    @Published var isRunningSpeedTest = false
    /// General busy state indicator for long-running operations.
    @Published var isBusy = false

    // MARK: - Local Interactive Form States

    /// Selected GPU identifier for hardware video encoding ("auto", "nvidia", "amd", "intel", "apple").
    @Published var selectedEncodeGpu: String = "auto"
    /// Selected GPU identifier for hardware video decoding.
    @Published var selectedDecodeGpu: String = "auto"
    /// True if the user has changed the encode GPU dropdown without saving.
    @Published var encodeGpuDirty: Bool = false
    /// True if the user has changed the decode GPU dropdown without saving.
    @Published var decodeGpuDirty: Bool = false
    /// User input text field for manually adding an unadvertised peer IP.
    @Published var manualIpInput: String = ""
    /// Ephemeral 6-digit PIN inputs keyed by peer IP address.
    @Published var pairPinInputs: [String: String] = [:]
    /// User input text for specifying a preferred remote SMB share name.
    @Published var preferredShareInput: String = ""
    /// True if preferred share input has uncommitted edits.
    @Published var preferredShareDirty: Bool = false
    /// True Tone Correlated Color Temperature calibration slider value (Kelvin).
    @Published var trueToneCct: Double = 6500
    /// True Tone chromatic compensation factor slider value.
    @Published var trueToneComp: Double = 1.0

    // MARK: - Editable KVM Layout Draft

    /// Tracks unsaved local modifications to the KVM monitor layout.
    private var kvmLayoutDirty = false
    /// Guard flag preventing local dirty flags from setting during remote updates.
    private var isApplyingRemoteLayout = false
    /// Timestamp of the last synchronized server layout.
    private var lastServerLayoutUpdatedMs: UInt64 = 0

    /// Live editable KVM layout configuration draft.
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
            // Flag layout as dirty when modified by user interactions in the UI
            if !isApplyingRemoteLayout {
                kvmLayoutDirty = true
            }
        }
    }

    /// Repeating 2.0-second timer polling the Rust core bridge status.
    private var pollTimer: Timer? = nil
    /// Flag indicating whether background polling is paused (e.g., window hidden or minimized).
    private var isPollingPaused: Bool = false
    /// Reentrancy guard preventing overlapping asynchronous RPC refresh calls.
    private var isRefreshInFlight: Bool = false

    /// Starts the periodic status polling loop and triggers an immediate refresh.
    func startPolling() {
        isPollingPaused = false
        refresh()
        schedulePollTimer()
    }

    /// Suspends or resumes the periodic status polling loop based on window visibility.
    ///
    /// - Parameter paused: True to pause timer and conserve system resources; false to resume.
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

    /// Permanently halts background polling during application shutdown.
    func stopPolling() {
        isPollingPaused = true
        pollTimer?.invalidate()
        pollTimer = nil
    }

    /// Internal scheduler configuring a repeating 2.0-second main-thread timer.
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

    /// Displays an ephemeral toast banner for 4.0 seconds.
    ///
    /// - Parameters:
    ///   - kind: Style type ("success", "error", or "info").
    ///   - msg: Message text to display.
    func showToast(_ kind: String, _ msg: String) {
        toast = ToastBanner(kind: kind, message: msg)
        let capturedId = toast?.id
        // Auto-dismiss the toast banner after exactly 4.0 seconds
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) { [weak self] in
            if self?.toast?.id == capturedId {
                self?.toast = nil
            }
        }
    }

    /// Determines the vendor tag ("nvidia", "amd", "intel", "apple", "discrete") for a GPU descriptor.
    ///
    /// - Parameter gpu: GPU metadata model.
    /// - Returns: Canonical lowercase vendor tag.
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

    /// Builds unique picker options for GPU selection dropdowns.
    ///
    /// - Parameter gpus: List of available GPU adapters.
    /// - Returns: Array of tag and display label pairs.
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

    /// Resolves a raw GPU preference string to a valid picker tag.
    ///
    /// - Parameters:
    ///   - raw: Raw preference string from config.
    ///   - gpus: Available GPU adapters.
    /// - Returns: Resolved option tag.
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

    /// Fetches the latest system snapshot from `integrator_core.dylib` via JSON-RPC.
    func refresh() {
        guard !isRefreshInFlight else { return }
        isRefreshInFlight = true
        invoke("get_bridge_status", params: "{}", as: BridgeStatusModel.self) { [weak self] res in
            guard let self = self else { return }
            self.isRefreshInFlight = false
            switch res {
            case .success(let model):
                self.status = model
                // Preserve local draft of KVM layout if user is currently editing sliders
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
                // Clear paired PIN inputs for successfully authenticated peers
                for peer in model.discovered_peers where peer.trusted {
                    self.pairPinInputs.removeValue(forKey: peer.ip)
                }
            case .failure(let err):
                self.showToast("error", err.message)
            }
        }
    }

    /// Executes a parameterless or parameterized RPC action on the Rust core.
    ///
    /// - Parameters:
    ///   - method: Native RPC method name.
    ///   - params: Parameter dictionary serialized to JSON.
    ///   - refreshAfter: If true, automatically re-queries system status upon completion.
    ///   - suppressDataToast: If true, suppresses automatic success toasts.
    ///   - successToast: Custom toast message to show on success.
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

    /// Toggles a subsystem feature flag in the Rust core feature manager.
    ///
    /// - Parameters:
    ///   - feature: Subsystem key (e.g., "display", "input_kvm", "clipboard").
    ///   - enabled: Boolean enable state.
    func toggleFeature(_ feature: String, enabled: Bool) {
        runAction("set_feature_flag", params: ["feature": feature, "enabled": enabled])
    }

    /// Synchronizes the locally drafted KVM desk layout configuration with the Rust core.
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

    /// Updates the active peer edge transition direction while preserving unsaved draft sliders.
    ///
    /// - Parameter edge: New monitor edge ("top", "bottom", "left", "right").
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

    /// Triggers an active live throughput benchmark against the connected peer.
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

    /// Queries real-time discrete GPU metrics from the peer machine.
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

    /// Helper deserializing a JSON string result from raw response bytes.
    private static func decodeStringResult(_ data: Data?) -> String? {
        guard let data = data,
              let s = try? JSONDecoder().decode(String.self, from: data)
        else { return nil }
        return s
    }

    /// Dispatches a strongly-typed JSON-RPC request to `integrator_core.dylib` on a background queue.
    ///
    /// - Parameters:
    ///   - method: Native RPC method name.
    ///   - params: JSON parameter string.
    ///   - type: Expected decodable result type.
    ///   - completion: Completion handler invoked on `@MainActor`.
    private func invoke<T: Decodable>(
        _ method: String,
        params: String,
        as type: T.Type,
        completion: @escaping @MainActor (Result<T, RpcErrorMessage>) -> Void
    ) {
        // Offload synchronous C FFI invocation to a background thread to prevent UI freezing
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
            // Ensure native C-string allocated by Rust allocator is immediately released
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

    /// Dispatches an RPC request where the data payload may be optional or null.
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

    /// Dispatches an RPC request and returns raw JSON bytes without strict decoding.
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

/// Strongly typed error wrapper for native RPC failure messages.
struct RpcErrorMessage: Error, LocalizedError {
    /// Human-readable error description returned by the Rust core.
    let message: String
    /// Initializes with an error string.
    init(_ message: String) { self.message = message }
    /// Conformance to `LocalizedError`.
    var errorDescription: String? { message }
}

// MARK: - Liquid Glass Styling Modifiers

/// Custom ViewModifier implementing the translucent liquid glass aesthetic on macOS.
///
/// On modern macOS systems (macOS 26.0+ with Swift 6.2+), applies `.glassEffect`.
/// On prior versions, utilizes dynamic materials (`.ultraThinMaterial`, `.thinMaterial`, `.regularMaterial`)
/// with alpha blending and continuous-curve border strokes, modulated by the `liquidGlassIntensity` setting.
private struct LiquidGlassCardModifier: ViewModifier {
    /// Corner radius for the card border and clipping boundary.
    var cornerRadius: CGFloat = 16
    /// User-configured shader intensity slider (0.10 to 1.00).
    @AppStorage("liquidGlassIntensity") private var intensity: Double = 0.85

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            content
                .padding(16)
                .glassEffect(intensity < 0.35 ? .clear : .regular, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .background(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(Color.primary.opacity(0.03 * intensity))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .stroke(Color.primary.opacity(0.06 + 0.12 * intensity), lineWidth: 1)
                )
        } else {
            legacyGlassBody(content: content)
        }
        #else
        legacyGlassBody(content: content)
        #endif
    }

    /// Fallback styling for macOS 13 through 15 utilizing AppKit NSVisualEffect materials.
    @ViewBuilder
    private func legacyGlassBody(content: Content) -> some View {
        let material: Material = intensity < 0.35 ? .ultraThinMaterial : (intensity < 0.70 ? .thinMaterial : .regularMaterial)
        content
            .padding(16)
            .background(material, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.primary.opacity(0.04 * intensity))
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(Color.primary.opacity(0.06 + 0.12 * intensity), lineWidth: 1)
            )
    }
}

/// Custom ViewModifier applying liquid glass material styling to the dashboard navigation sidebar.
private struct LiquidGlassSidebarModifier: ViewModifier {
    /// User-configured shader intensity slider.
    @AppStorage("liquidGlassIntensity") private var intensity: Double = 0.85

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            content
                .glassEffect(intensity < 0.35 ? .clear : .regular, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                .background(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .fill(Color.primary.opacity(0.03 * intensity))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(Color.primary.opacity(0.06 + 0.10 * intensity), lineWidth: 1)
                )
        } else {
            legacySidebar(content: content)
        }
        #else
        legacySidebar(content: content)
        #endif
    }

    /// Legacy material backdrop for the sidebar.
    @ViewBuilder
    private func legacySidebar(content: Content) -> some View {
        let material: Material = intensity < 0.40 ? .thinMaterial : .regularMaterial
        content
            .background(material, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color.primary.opacity(0.03 * intensity))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Color.primary.opacity(0.06 + 0.10 * intensity), lineWidth: 1)
            )
    }
}

/// Compact status pill badge featuring a colored circular dot and status text.
private struct StatusPill: View {
    /// Status description label.
    let text: String
    /// Accent color for indicator dot and semi-transparent badge background.
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

/// Uniform card header presenting an SF symbol icon, title, status pill, and optional feature toggle switch.
private struct CardHeader: View {
    /// SF Symbol icon name.
    let icon: String
    /// Card title text.
    let title: String
    /// Text displayed inside the status pill.
    let pillText: String
    /// Color for the status pill.
    let pillColor: Color
    /// Optional toggle binding for subsystem enable/disable switch.
    var toggleBinding: Binding<Bool>? = nil
    /// True if the toggle switch should be disabled.
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

/// Root SwiftUI dashboard view hosting the two-column responsive grid of thirteen subsystem cards,
/// navigation sidebar, top status bar, ephemeral toast notifications, and liquid glass backdrop.
struct MainDashboardView: View {
    /// Reactive view model driving state updates and core RPC dispatches.
    @ObservedObject var vm: IntegratorViewModel
    /// User-configurable liquid glass shader opacity and refractive intensity setting.
    @AppStorage("liquidGlassIntensity") private var glassIntensity: Double = 0.85

    /// Convenience accessor for latest bridge status snapshot.
    private var s: BridgeStatusModel? { vm.status }
    /// Convenience accessor for active subsystem feature flags with fallback defaults.
    private var flags: FeatureFlagsModel {
        s?.feature_flags ?? FeatureFlagsModel(
            display: true, input_kvm: true, clipboard: true, dragdrop: true,
            truetone: true, touchbar: true, storage: true, audio: true
        )
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            // Full-window behind-window blur backdrop
            VisualEffectBackdrop(material: .underWindowBackground, blendingMode: .behindWindow)
                .ignoresSafeArea()

            HStack(spacing: 14) {
                // Persistent left navigation and peer status sidebar
                sidebar
                    .frame(width: 228)

                // Scrollable main dashboard content container
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
                            // Conditional rendering based on active NavSection filter
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
                                cameraCard
                                systemLifecycleCard
                                logsCard
                            }
                        }
                        .padding(.bottom, 16)
                    }
                }
            }
            .padding(14)

            // Ephemeral floating toast notification banner
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
        .onAppear {
            // Begin periodic polling when view hierarchy attaches
            vm.startPolling()
        }
    }

    /// Evaluates whether a card belonging to `target` category should be rendered.
    private func show(_ target: NavSection) -> Bool {
        vm.section == .all || vm.section == target
    }

    // MARK: - Sidebar

    /// Navigation sidebar presenting branding, section filters, and live peer link telemetry.
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "link.circle.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Integrator")
                        .font(.title3.bold())
                    Text("v1.0 SECURITY")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, 4)

            Divider().opacity(0.3)

            // Category navigation button list
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

            // Persistent bottom peer connection summary card
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
                        StatusPill(text: "Verified v1.0", color: .green)
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

    /// Top status bar displaying workstation host info, connection status pill, and quick action buttons.
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

    /// Card 1: Controls hardware-accelerated video streaming (Mac -> PC and PC -> Mac) and GPU selection.
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

            // Real-time discrete GPU metrics telemetry box
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

    /// Card 2: Interactive multi-display desk layout schematic, hop delay slider, and modifier key translations.
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

            // Warning banner if macOS Accessibility permissions are absent
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

    /// Renders an edge placement button ("Top", "Bottom", "Left", "Right").
    private func edgeButton(_ title: String, edge: String) -> some View {
        let active = vm.kvmLayout.peer_edge == edge
        return Button(title) {
            vm.updateEdgeAndSyncPreservingDirty(edge)
        }
        .buttonStyle(.bordered)
        .tint(active ? .accentColor : .secondary)
        .controlSize(.small)
    }

    /// Visual 2D monitor arrangement schematic reflecting relative workstation positions.
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

    /// Renders a single monitor rectangle in the desk layout schematic.
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

    /// Card 3: Cross-screen file drag and drop staging, ghost thumbnail preview, and QoS clamping.
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

    /// Card 4: Zero-RAM ChaCha20 encrypted universal clipboard synchronization and cache management.
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

    // MARK: - Card 5: Peer Discovery & v1.0 Trust

    /// Card 5: SPAKE2 cryptographic PIN pairing, manual IP target entry, peer authorization, and device blocking.
    private var discoveryTrustCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "lock.shield",
                title: "Peer Discovery & v1.0 Trust",
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

            // Display active manual IP badges with removal buttons
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

            // Discovered peers list with dynamic pairing PIN inputs
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

                            Button("Pair v1.0") {
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

            // Stale pinned keys stored in keystore that are not currently discovered on the LAN
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

            // Blocked device entries
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

            Label("SPAKE2 + Ed25519 Mutual Auth Enforced on USB-C & LAN (v1.0 Locked)", systemImage: "checkmark.seal.fill")
                .font(.caption2)
                .foregroundStyle(.green)
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 6: Route Telemetry & Speed

    /// Card 6: Active network interface routing telemetry, round-trip latency, and live speed benchmark.
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

    /// Renders an individual telemetry metric container box.
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

    /// Card 7: Automated SMB share negotiation, volume mount state, and custom share overrides.
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

    /// Formatted status summary for the shared storage card.
    private var storageSummaryText: String {
        guard let st = s?.storage_status else { return "SMB volume ready on trusted peer" }
        if !st.mount_path.isEmpty { return st.mount_path }
        if !st.message.isEmpty { return st.message }
        return "SMB volume ready on trusted peer"
    }

    // MARK: - Card 8: True Tone & Chromatic Sync

    /// Card 8: Ambient light sensor readings (Lux / CCT) and chromatic calibration controls.
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

    /// Card 9: MacBook Touch Bar hardware HUD strip status and toggle invocation.
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

    /// Card 10: Low-latency spatial audio UDP routing and test chime playback.
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

    // MARK: - Card 10B: Mac -> PC Shared Camera

    /// Card 10B: Mac AVFoundation 720p30 camera capture and encrypted TCP transmission to Windows virtual camera.
    private var cameraCard: some View {
        let camEnabled = flags.camera ?? false
        let cam = s?.camera_status
        let camActive = cam?.active == true
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "video.fill",
                title: "Mac → PC Shared Camera",
                pillText: cam?.state ?? (camEnabled ? "Standby" : "Disabled"),
                pillColor: camActive ? .green : (camEnabled ? .cyan : .secondary),
                toggleBinding: Binding(
                    get: { flags.camera ?? false },
                    set: { vm.toggleFeature("camera", enabled: $0) }
                )
            )

            if let err = cam?.last_error, !err.isEmpty {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.orange)
            } else if camActive {
                Text("\(cam?.width ?? 1280)×\(cam?.height ?? 720) @ \(cam?.fps ?? 30)fps • \(cam?.frames_transferred ?? 0) frames sent over TCP :58287")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            } else {
                Text("Streams your MacBook camera (720p30) into Windows 'Integrator MacBook Camera' (TCP :58287).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Button(camActive ? "Stop Camera Stream" : "Start Camera Stream") {
                    vm.runAction("toggle_camera")
                }
                .buttonStyle(.borderedProminent)
                Spacer()
            }
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 11: System & Autostart

    /// Card 11: System login autostart registration and Liquid Glass shader intensity slider.
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

            Divider()

            // Dynamic Liquid Glass shader opacity and material depth slider
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Label("Liquid Glass Intensity", systemImage: "sparkles")
                        .font(.subheadline.weight(.medium))
                    Spacer()
                    Text("\(Int(round(glassIntensity * 100)))%")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                Slider(value: $glassIntensity, in: 0.1...1.0, step: 0.05)
            }

            Text("Roadmap Modules: Touch ID Biometric Gate • Multi-WAN Bonding")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .modifier(LiquidGlassCardModifier())
    }

    // MARK: - Card 12: Live Logs Console

    /// Formats and deduplicates recent log records for SwiftUI list presentation.
    private var renderedLogs: [RenderedLogEntry] {
        var counts: [String: Int] = [:]
        return (s?.recent_logs ?? []).suffix(40).map { entry in
            let base = "\(entry.ts_ms)-\(entry.level)-\(entry.message)"
            let n = counts[base, default: 0]
            counts[base] = n + 1
            return RenderedLogEntry(id: "\(base)#\(n)", entry: entry)
        }
    }

    /// Card 12: Monospaced live security and telemetry log viewer.
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

/// SwiftUI wrapper around AppKit's `NSVisualEffectView` providing native window translucency.
private struct VisualEffectBackdrop: NSViewRepresentable {
    /// AppKit visual effect material.
    let material: NSVisualEffectView.Material
    /// Blending mode: behind window or within window.
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

/// Native AppKit application and window delegate coordinating menu bar status item,
/// dashboard window presentation, and graceful lifecycle termination.
@MainActor
private final class MacAppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    /// macOS status bar item in the menu bar.
    var statusItem: NSStatusItem?
    /// Main dashboard window instance.
    var mainWindow: NSWindow?
    /// Flag indicating whether the app was launched in hidden tray-only mode.
    var startHidden: Bool = false

    /// Invoked when macOS completes initial application launch sequence.
    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMainMenu()
        setupStatusBar()
        setupMainWindow()

        if startHidden {
            // Accessory policy hides the Dock icon when running purely in the status bar
            NSApp.setActivationPolicy(.accessory)
            mainWindow?.orderOut(nil)
            IntegratorViewModel.shared.setPollingPaused(true)
        } else {
            NSApp.setActivationPolicy(.regular)
            showDashboard()
        }
    }

    /// Re-activates dashboard window when user clicks the macOS Dock icon.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showDashboard()
        return true
    }

    /// Intercepts window close button to hide dashboard to menu bar tray instead of quitting.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        IntegratorViewModel.shared.setPollingPaused(true)
        return false
    }

    /// Pauses background telemetry polling when dashboard window is minimized to the Dock.
    func windowDidMiniaturize(_ notification: Notification) {
        IntegratorViewModel.shared.setPollingPaused(true)
    }

    /// Resumes background telemetry polling when dashboard window is restored from the Dock.
    func windowDidDeminiaturize(_ notification: Notification) {
        IntegratorViewModel.shared.setPollingPaused(false)
    }

    /// Configures standard macOS application menu bar (Integrator, File, Edit shortcuts).
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

    /// Configures the macOS status bar menu item (`NSStatusItem`) with quick action items.
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

    /// Creates and styles the main dashboard window with full-size content view and transparent titlebar.
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

    /// Brings dashboard window to front, ensures Regular activation policy, and resumes polling.
    func showDashboard() {
        NSApp.setActivationPolicy(.regular)
        mainWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        IntegratorViewModel.shared.setPollingPaused(false)
    }

    /// Orders out dashboard window and pauses polling to conserve CPU/power.
    func hideDashboard() {
        mainWindow?.orderOut(nil)
        IntegratorViewModel.shared.setPollingPaused(true)
    }

    @objc private func onShowDashboard() { showDashboard() }
    @objc private func onPasteRemote() { "paste_remote".withCString { rustCoreTrayAction($0) } }
    @objc private func onToggleDisplay() { "toggle_display".withCString { rustCoreTrayAction($0) } }
    @objc private func onOpenCache() { "open_cache".withCString { rustCoreTrayAction($0) } }

    /// Graceful application termination sequence.
    @objc private func onQuit() {
        IntegratorViewModel.shared.stopPolling()
        rustCoreSetUiCallback(nil)
        rustCoreShutdown()
        NSApp.terminate(nil)
    }
}

/// Global reference to delegate instance.
private var gMacAppDelegate: MacAppDelegate? = nil

/// C-convention reverse event callback registered with `integrator_core.dylib`.
///
/// Dispatches asynchronous UI notifications (show/hide window, toasts, quit commands)
/// from the background Tokio runtime onto macOS `DispatchQueue.main`.
private let swiftUiEventTrampoline: RustUiCallback = { evPtr, payloadPtr in
    let eventName = evPtr.map { String(cString: $0) } ?? ""
    // Drop high-frequency log push notifications; logs are polled on schedule
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

/// Dynamic entry point invoked by the Rust executable launcher (`core.rs` / `main.rs`).
///
/// - Parameter isHidden: True if the application was started in headless/daemon mode (`--minimized` or `--daemon`).
@MainActor
@_cdecl("integrator_macos_run_app")
public func integrator_macos_run_app(isHidden: Bool) {
    let app = NSApplication.shared
    let delegate = MacAppDelegate()
    delegate.startHidden = isHidden
    gMacAppDelegate = delegate
    app.delegate = delegate
    // Register the reverse event trampoline with Rust core
    rustCoreSetUiCallback(swiftUiEventTrampoline)
    // Enter the AppKit run loop (never returns until `NSApp.terminate`)
    app.run()
}
