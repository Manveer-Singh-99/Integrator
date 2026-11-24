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
//    - Upstream Callers:
//        * Invoked at process launch by the Rust executable entry point (`app/src/main.rs` / `app/src/core.rs`)
//          via the exported `@_cdecl("integrator_macos_run_app")` C-ABI symbol.
//        * Receives asynchronous reverse notifications from Rust core subsystems via `swiftUiEventTrampoline`.
//    - Downstream Callees & Dynamic Library Linkage:
//        * Direct C-ABI dynamic invocation against `integrator_core.dylib` via `@_silgen_name` bindings:
//            - `integrator_core_invoke(method, paramsJson) -> *mut c_char`: Synchronous JSON-RPC request/response.
//            - `integrator_core_free_string(ptr)`: Releases heap-allocated UTF-8 C-string buffers from Rust.
//            - `integrator_core_tray_action(action)`: Fires one-way asynchronous tray notifications into Rust.
//            - `integrator_core_shutdown()`: Performs graceful teardown of Tokio runtimes, daemon tasks, and network listeners.
//            - `integrator_core_set_ui_callback(cb)`: Registers the reverse event trampoline (`RustUiCallback`).
//        * Native macOS Frameworks: AppKit (`NSApplication`, `NSWindow`, `NSStatusItem`, `NSAlert`, `NSOpenPanel`),
//          SwiftUI (`View`, `ObservableObject`, `@MainActor`), CoreText (`CTLine` optical glyph centering),
//          and QuartzCore (`CAKeyframeAnimation`, `CATransform3D`).
//    - Cross-Platform / Cross-Device Flow (Mac <-> Windows 11):
//        * Synchronizes feature flags (enforcing mutual exclusion between Extended Screen and Universal Input KVM),
//          2D desk monitor layout topology, SPAKE2 pairing PINs, True Tone ambient lux/CCT calibration, Touch Bar HUD
//          telemetry, spatial UDP audio routing, and Mac -> PC shared camera & microphone capture settings over
//          authenticated TransportV2 TCP/UDP channels to the Windows 11 peer workstation.
//    - JSON-RPC Dispatch Pipeline:
//        * High-level requests from UI interactions or the 2.0s polling timer are packaged into JSON strings.
//        * Dispatched onto background GCD queues (`DispatchQueue.global(qos: .userInitiated)`) to ensure the
//          macOS Main Thread (and AppKit UI rendering loop) is never blocked by synchronous Rust RPC calls.
//        * The raw JSON string returned by Rust is parsed into strongly-typed Codable structures (`BridgeStatusModel`,
//          `SpeedTestResultModel`, `GpuTelemetryModel`, `MicDeviceModel`, etc.) and published to `@MainActor` state variables.
//    - Asynchronous Event Trampoline (`swiftUiEventTrampoline`):
//        * Registered with Rust core at startup (`integrator_core_set_ui_callback`).
//        * Core pushes notifications for window control (`show_window`, `hide_window`), toast banners (`toast`),
//          and lifecycle termination (`quit`).
//        * High-frequency telemetry events (`log_entry`) are dropped at the C-trampoline boundary to prevent
//          main thread saturation; log rings are polled deterministically via periodic status snapshots.
//
// 3. Card Architecture & Subsystems:
//    - Card 1: Extended Screen & GPU Acceleration (DirectX/NVENC/Moonlight vs Apple Silicon VideoToolbox,
//      guarded by mutual-exclusion confirmation against Universal Input KVM).
//    - Card 2: Universal Input KVM & Desk Layout (Interactive 2D spatial monitor arrangement, edge hop delays,
//      modifier translation Cmd<->Ctrl, corner guard dead zones, macOS Accessibility hook status,
//      guarded by mutual-exclusion confirmation against Extended Screen).
//    - Card 3: Cross-Screen Drag & Drop (Zero-RAM file streaming, ghost thumbnail badge, QoS clamping, drop directory).
//    - Card 4: Universal Clipboard (ChaCha20 encrypted sync, SHA-256 integrity, atomic staging cache).
//    - Card 5: Peer Discovery & v1.0 Trust (mDNS / UDP beacon discovery, SPAKE2 6-digit PIN pairing, manual IP routing,
//      Ed25519 identity key pinning, peer unpairing and device blocking).
//    - Card 6: Route Telemetry & Link Speed (Active interface discovery, real-time RTT latency, TCP/UDP link benchmarking).
//    - Card 7: Auto-Mounted Shared Storage (Automated SMB volume negotiation, preferred share mounts, mount state tracking).
//    - Card 8: True Tone & Chromatic Sync (Ambient light sensor / CCT synchronization, manual chromaticity calibration).
//    - Card 9: Touch Bar Hardware HUD (Touch Bar telemetry strip, quick-action controls for supported MacBooks).
//    - Card 10: Dynamic Audio Routing (ChaCha20-Poly1305 encrypted spatial UDP sink, test chime invocation).
//    - Card 10B: Mac -> PC Shared Camera & Mic (AVFoundation 720p30 video capture, hardware privacy shutter killswitch,
//      and shared microphone source selection, mute control, and input gain streaming over TCP :58287 to Windows).
//    - Card 11: System & Autostart (macOS SMAppService login item autostart, Liquid Glass shader intensity slider,
//      and Touch ID remote biometric gate).
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
import CoreText
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
struct PrimaryDisplayInfo: Codable, Hashable, Sendable {
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
struct GpuDeviceInfo: Codable, Identifiable, Hashable, Sendable {
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
struct DisplayGeometryModel: Codable, Hashable, Sendable {
    /// Width in physical pixels.
    var width: UInt32
    /// Height in physical pixels.
    var height: UInt32
    /// Refresh rate in hertz.
    var fps: UInt32
}

/// Network interface descriptor capturing IP address, link speed, and interface type.
struct LocalInterfaceModel: Codable, Identifiable, Hashable, Sendable {
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
struct PendingPeerModel: Codable, Identifiable, Hashable, Sendable {
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
struct TrustedPeerModel: Codable, Identifiable, Hashable, Sendable {
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
struct DiscoveredPeerModel: Codable, Identifiable, Hashable, Sendable {
    /// Composite identifier combining device ID and IP address.
    var id: String { "\(device_id)-\(ip)" }
    /// Cryptographic device identifier string.
    var device_id: String
    /// Hostname announced by the peer.
    var hostname: String
    /// Operating system string (e.g., "macOS", "Windows").
    var os: String
    /// Hardware model string (e.g., "MacBookPro18,1", "Mac14,12", "Custom PC").
    var hardware_model: String
    /// Hardware chassis form factor ("laptop", "desktop", or "unknown").
    var form_factor: String?
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
    /// Discovery transport provenance (e.g., "udp", "bonjour", "ble", "udp+bonjour+ble").
    var discovery_source: String?
}

/// Complete snapshot of the cryptographic pairing and trust database.
struct TrustSnapshotModel: Codable, Hashable, Sendable {
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
struct StorageStatusModel: Codable, Hashable, Sendable {
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

// MARK: - UI Default Constants

/// Centralized fallback constants and UI timing/sizing parameters for the macOS dashboard.
private enum UiDefaults {
    /// Fallback UDP transport port displayed for spatial audio when omitted by core status.
    static let defaultAudioPort: UInt16 = 58284
    /// Fallback TCP transport port displayed for shared camera streaming when omitted by core status.
    static let defaultCameraPort: UInt16 = 58287
    /// Fallback shared camera frame width in pixels.
    static let defaultCameraWidth: UInt32 = 1280
    /// Fallback shared camera frame height in pixels.
    static let defaultCameraHeight: UInt32 = 720
    /// Fallback shared camera frame rate in FPS.
    static let defaultCameraFps: UInt32 = 30
    /// Fallback Windows virtual camera friendly name when omitted by core status.
    static let defaultCameraDeviceName: String = "Integrator Mac Camera"
    /// Placeholder system GPU name filtered from explicit discrete/integrated GPU pickers.
    static let defaultSystemGpuName: String = "Default System GPU"
    /// Fallback remote peer hostname displayed in the desk layout schematic.
    static let defaultPeerHostname: String = "Peer PC"
    /// Fallback local workstation hostname displayed in the desk layout schematic.
    static let defaultLocalHostname: String = "This Mac"
    /// Interval in seconds between periodic `get_bridge_status` polls while dashboard is visible.
    static let statusPollIntervalSec: TimeInterval = 2.0
    /// Auto-dismiss duration in seconds for ephemeral toast notification banners.
    static let toastDismissDelaySec: TimeInterval = 4.0
    /// Exact character length required for SPAKE2 pairing PIN codes.
    static let pairingPinLength: Int = 6
    /// Visible prefix length for truncated peer device identifiers in trust cards.
    static let deviceIdPreviewLength: Int = 12
    /// Default CIE D65 neutral Correlated Color Temperature in Kelvin.
    static let defaultTrueToneCct: Double = 6500
    /// Initial dashboard window width in points.
    static let defaultWindowWidth: CGFloat = 1240
    /// Initial dashboard window height in points.
    static let defaultWindowHeight: CGFloat = 820
    /// Minimum resizable dashboard window width in points.
    static let minWindowWidth: CGFloat = 960
    /// Minimum resizable dashboard window height in points.
    static let minWindowHeight: CGFloat = 640

    /// Dynamically resolves the macOS user shared Public directory display label via `FileManager`.
    static var defaultSharedPublicFolderLabel: String {
        if let url = FileManager.default.urls(for: .sharedPublicDirectory, in: .userDomainMask).first {
            let abbreviated = (url.path as NSString).abbreviatingWithTildeInPath
            return "Default (\(abbreviated))"
        }
        return "Default (Public)"
    }
}

/// Status of the low-latency authenticated UDP spatial audio stream.
struct AudioRoutingStatusModel: Codable, Hashable, Sendable {
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
    /// Active UDP transport port bound for spatial audio streaming.
    var port: UInt16?
    /// Cross-platform audio mixer balance (-1.0 Mac boost to +1.0 Windows boost).
    var mixer_balance: Float?
    /// True if the remote Windows soundbar sink is muted.
    var sink_muted: Bool?
}

/// Telemetry and state of the Mac -> PC shared virtual camera and microphone pipeline.
struct CameraStatusModel: Codable, Hashable, Sendable {
    /// True if camera capture platform subsystem is supported.
    var supported: Bool
    /// True if a video capture device (built-in, external USB, or Continuity Camera) is currently detected.
    var camera_available: Bool?
    /// True if the camera stream is actively transmitting frames.
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
    /// Active encrypted TCP transport port bound for virtual camera streaming.
    var port: UInt16?
    /// Friendly device name exposed by the Windows virtual camera.
    var device_name: String?
    /// True if the hardware camera privacy shutter killswitch is currently engaged.
    var privacy_muted: Bool?
    /// True if Mac -> PC shared microphone forwarding is enabled.
    var mic_enabled: Bool?
    /// True if the shared microphone audio feed is currently muted.
    var mic_muted: Bool?
    /// Friendly name of the currently selected macOS microphone capture device.
    var mic_device_name: String?
    /// True if macOS TCC microphone capture permission (`AVMediaType.audio`) is granted.
    var mic_permission_granted: Bool?
    /// Linear microphone input gain multiplier (0.0 to 2.0, where 1.0 represents 100% unity gain).
    var mic_gain: Float?
}

/// Descriptor for a physical or virtual microphone audio input device discovered via AVFoundation.
struct MicDeviceModel: Codable, Hashable, Identifiable, Sendable {
    /// Stable CoreAudio / AVFoundation unique device identifier (`AVCaptureDevice.uniqueID`).
    var id: String
    /// Human-readable microphone name (e.g., "MacBook Pro Microphone", "USB Condenser Mic").
    var name: String
    /// True if this device is currently the operating system's default audio input source.
    var is_default: Bool?
}

/// Boolean feature flags controlling active subsystem daemons in Rust core.
struct FeatureFlagsModel: Codable, Hashable, Sendable {
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
    /// Windows 11 remote Touch ID biometrics and Passkey authentication flag.
    var touchid: Bool? = true
}

/// User-configured desk layout configuration for multi-monitor cursor transitions.
struct KvmLayoutConfigModel: Codable, Hashable, Sendable {
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
struct KvmStatusSnapshotModel: Codable, Hashable, Sendable {
    /// Overall KVM subsystem enable flag.
    var enabled: Bool
    /// Cross-screen drag and drop active state.
    var dragdrop_enabled: Bool
    /// macOS Accessibility API CGEventTap hook operational status.
    var hook_active: Bool?
    /// Current KVM role: "idle", "controlling" (local cursor captured), or "controlled".
    var role: String
    /// True if KVM Gaming Boundary Lock is freezing edge-hopping.
    var boundary_locked: Bool?
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
struct LogEntryModel: Codable, Identifiable, Hashable, Sendable {
    /// Unique identifier constructed from timestamp, log level, and message content.
    var id: String { "\(ts_ms)-\(level)-\(message)" }
    /// Milliseconds since Unix epoch when log was recorded.
    var ts_ms: UInt64
    /// Severity level string: "TRACE", "DEBUG", "INFO", "WARN", or "ERROR".
    var level: String
    /// Formatted log message text.
    var message: String
}

/// Operating system permission audit status item returned inside `SetupHealthSnapshotModel`.
struct PermissionStatusModel: Codable, Identifiable, Hashable, Sendable {
    /// Canonical permission identifier (e.g., "accessibility", "input_monitoring", "screen_recording").
    var id: String
    /// Human-readable permission title.
    var title: String
    /// Concise explanation of why Integrator needs this permission.
    var description: String
    /// True if permission is currently granted.
    var granted: Bool
    /// True if permission is required for core workstation functionality.
    var required: Bool
    /// True if Integrator can trigger a native OS prompt or automated fix directly.
    var can_request_directly: Bool
    /// Optional System Settings deep-link URI.
    var settings_url: String?
    /// Diagnostic status detail message.
    var detail: String
}

/// Companion streaming tool or driver dependency status item returned inside `SetupHealthSnapshotModel`.
struct DependencyStatusModel: Codable, Identifiable, Hashable, Sendable {
    /// Canonical dependency identifier ("sunshine", "moonlight", "usb_ncm", "vdd", "vcam").
    var id: String
    /// Human-readable dependency name.
    var name: String
    /// Explanation of which subsystem uses this tool or driver.
    var description: String
    /// True if detected as installed on the local machine.
    var installed: Bool
    /// Optional runtime flag indicating whether the service or daemon is currently running.
    var running: Bool?
    /// True if required for core streaming functionality.
    var required: Bool
    /// Detected binary or plist path on disk, if found.
    var detected_path: String?
    /// Primary installation method label (e.g., "Homebrew", "GitHub Release", "Guided Terminal Script").
    var install_method: String
    /// Copyable CLI installation command.
    var install_command: String
    /// Fallback official download or guide URL.
    var download_url: String
    /// True if 1-click guided installation is supported.
    var can_auto_install: Bool
}

/// Complete cross-platform OS permissions and companion dependencies health snapshot.
struct SetupHealthSnapshotModel: Codable, Hashable, Sendable {
    /// Operating system identifier ("macos", "windows").
    var os: String
    /// True if process is running with elevated privileges.
    var is_elevated: Bool
    /// True if at least one required permission or required dependency is missing.
    var needs_attention: Bool
    /// Number of missing required OS permissions.
    var missing_required_permissions: Int
    /// Number of missing required companion dependencies.
    var missing_required_dependencies: Int
    /// User-persisted flag suppressing automatic Setup sheet presentation on launch.
    var suppress_launch_prompt: Bool
    /// Audited OS permissions list.
    var permissions: [PermissionStatusModel]
    /// Audited companion dependencies list.
    var dependencies: [DependencyStatusModel]
}

/// UI presentation wrapper around `LogEntryModel` ensuring unique SwiftUI list item identities.
private struct RenderedLogEntry: Identifiable {
    /// Deduplicated identifier including ordinal counter.
    let id: String
    /// Underlying structured log entry.
    let entry: LogEntryModel
}

/// Results from an active TCP/UDP link throughput benchmark.
struct SpeedTestResultModel: Codable, Hashable, Sendable {
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
struct GpuTelemetryModel: Codable, Hashable, Sendable {
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
    /// All physical GPUs detected on the machine.
    var all_gpus: [String]?
}

/// Aggregate system state model returned by `get_bridge_status` RPC.
struct BridgeStatusModel: Codable, Sendable {
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
    /// Local hardware chassis form factor ("laptop", "desktop", or "unknown").
    var form_factor: String?
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
    /// Hardware chassis form factor of the connected peer ("laptop", "desktop", or "unknown").
    var peer_form_factor: String?
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
    /// User's configured local shared directory path.
    var local_shared_folder: String?
    /// True if SMB share is configured to mount automatically on peer detection.
    var auto_mount_storage: Bool?

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
    /// List of peers discovered via mDNS, BLE magic packets, and UDP broadcasts.
    var discovered_peers: [DiscoveredPeerModel]
    /// Active discovery mode ("all", "udp", "bonjour", "ble").
    var discovery_mode: String?
    /// True if Bonjour / mDNS (`_integrator._tcp.local.`) discovery is active.
    var bonjour_active: Bool?
    /// True if Bluetooth LE magic-packet proximity discovery is active.
    var ble_active: Bool?
    /// Trust store snapshot including pairing PIN and trusted peer list.
    var trust: TrustSnapshotModel

    /// True if Integrator is configured to launch at user login.
    var autostart_enabled: Bool
    /// Cross-platform OS permissions and companion driver/tool setup health snapshot.
    var setup_status: SetupHealthSnapshotModel?
    /// Rolling ring buffer of recent log entries from the Rust core.
    var recent_logs: [LogEntryModel]
}

// MARK: - ViewModel

/// High-level navigation categories for filtering cards on the dashboard.
enum NavSection: String, CaseIterable, Identifiable, Sendable {
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
struct ToastBanner: Identifiable, Sendable {
    /// Unique identifier for SwiftUI transition tracking.
    let id = UUID()
    /// Notification style kind: "success", "error", or "info".
    let kind: String
    /// Text message displayed within the notification pill.
    let message: String
}

/// Brings Integrator to the foreground across macOS 12–15 without triggering macOS 14+ deprecation warnings.
@MainActor
private func activateIntegratorApp() {
    if #available(macOS 14.0, *) {
        NSApp.activate()
    } else {
        NSApp.activate(ignoringOtherApps: true)
    }
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
    /// True while an extended display start or stop transition is in progress.
    @Published var isDisplayToggling = false
    /// Controls presentation of the Setup, Drivers & Permissions Assistant sheet.
    @Published var showSetupSheet: Bool = false
    /// Guard flag ensuring the automatic launch setup prompt is evaluated at most once per app launch.
    private var didEvaluateLaunchSetupPrompt: Bool = false
    /// Reentrancy guard preventing overlapping KVM <-> Extended Screen mutual-exclusion NSAlert popups.
    private var isMutualExclusionAlertOpen: Bool = false

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
    /// User configured local shared folder path.
    @Published var localSharedFolder: String = ""
    /// True Tone Correlated Color Temperature calibration slider value (Kelvin).
    @Published var trueToneCct: Double = UiDefaults.defaultTrueToneCct
    /// True Tone chromatic compensation factor slider value.
    @Published var trueToneComp: Double = 1.0
    /// Discovered macOS microphone input sources available for Mac -> PC shared microphone streaming.
    @Published var availableMics: [MicDeviceModel] = []
    /// Identifier of the currently selected macOS microphone source.
    @Published var selectedMicId: String = ""
    /// Shared microphone input gain multiplier (0.0 to 2.0, corresponding to 0% to 200%).
    @Published var micGain: Double = 1.0
    /// Dirty flag preventing background status polls from overwriting the mic gain slider while uncommitted.
    var micGainDirty: Bool = false
    /// True while the user is actively dragging the mic gain slider thumb.
    private var isEditingMicGain: Bool = false
    /// Debounce timer work item for applying mic gain changes after track clicks or keyboard steps.
    private var micGainDebounceWorkItem: DispatchWorkItem? = nil
    /// Monotonic generation counter ensuring stale in-flight gain RPC completions do not clear newer dirty edits.
    private var micGainRequestGeneration: UInt64 = 0
    /// Guard flag ensuring `refreshMics()` is triggered automatically once on initial bridge status load.
    private var didInitialMicRefresh: Bool = false

    // MARK: - Editable KVM Layout Draft

    /// Tracks unsaved local modifications to the KVM monitor layout.
    private var kvmLayoutDirty = false
    /// Guard flag preventing local dirty flags from setting during remote updates.
    private var isApplyingRemoteLayout = false

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

    /// Repeating status polling timer querying the Rust core bridge status.
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

    /// Internal scheduler configuring a repeating main-thread status timer.
    private func schedulePollTimer() {
        pollTimer?.invalidate()
        guard !isPollingPaused else { return }
        pollTimer = Timer.scheduledTimer(withTimeInterval: UiDefaults.statusPollIntervalSec, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isPollingPaused else { return }
                self.refresh()
            }
        }
    }

    /// Displays an ephemeral toast banner for the configured toast duration.
    ///
    /// - Parameters:
    ///   - kind: Style type ("success", "error", or "info").
    ///   - msg: Message text to display.
    func showToast(_ kind: String, _ msg: String) {
        toast = ToastBanner(kind: kind, message: msg)
        let capturedId = toast?.id
        // Auto-dismiss the toast banner after the configured toast delay on @MainActor
        DispatchQueue.main.asyncAfter(deadline: .now() + UiDefaults.toastDismissDelaySec) { [weak self] in
            Task { @MainActor in
                if self?.toast?.id == capturedId {
                    self?.toast = nil
                }
            }
        }
    }

    /// Determines the vendor tag ("nvidia", "amd", "intel", "apple", "qualcomm", "discrete") for a GPU descriptor.
    ///
    /// - Parameter gpu: GPU metadata model.
    /// - Returns: Canonical lowercase vendor tag.
    static func gpuVendorTag(for gpu: GpuDeviceInfo) -> String {
        let combined = "\(gpu.vendor) \(gpu.name)".lowercased()
        if combined.contains("nvidia") || combined.contains("geforce") || combined.contains("rtx") || combined.contains("gtx") || combined.contains("quadro") {
            return "nvidia"
        }
        if combined.contains("amd") || combined.contains("radeon") || combined.contains("firepro") {
            return "amd"
        }
        if combined.contains("intel") || combined.contains("arc") || combined.contains("iris") || combined.contains("uhd") {
            return "intel"
        }
        if combined.contains("apple") {
            return "apple"
        }
        if combined.contains("qualcomm") || combined.contains("adreno") || combined.contains("snapdragon") {
            return "qualcomm"
        }
        return gpu.is_discrete ? "discrete" : "integrated"
    }

    /// Resolves the appropriate SF Symbol icon name for a Mac or Windows machine based on its
    /// operating system, hardware product model, and form factor (Desktop vs Laptop).
    static func deviceSymbol(os: String?, hardwareModel: String?, formFactor: String?) -> String {
        let model = (hardwareModel ?? "").lowercased()
        let ff = (formFactor ?? "").lowercased()
        let osLower = (os ?? "").lowercased()
        let isMac = osLower.contains("mac") || osLower == "darwin" || model.hasPrefix("mac") || model.hasPrefix("imac")
        if isMac {
            if model.contains("macstudio") || model.contains("mac studio") {
                return "macstudio"
            }
            if model.contains("macmini") || model.contains("mac mini") {
                return "macmini"
            }
            if model.contains("macpro") || model.contains("mac pro") {
                return "macpro.gen3"
            }
            if model.contains("imac") || ff == "desktop" {
                return "desktopcomputer"
            }
            if model.contains("macbook") || ff == "laptop" {
                return "laptopcomputer"
            }
            return "desktopcomputer"
        } else {
            if ff == "laptop" || model.contains("laptop") || model.contains("notebook") || model.contains("thinkpad") || model.contains("surface") || model.contains("zephyrus") || model.contains("zenbook") {
                return "laptopcomputer"
            }
            return "pc"
        }
    }

    /// Builds unique picker options for GPU selection dropdowns.
    ///
    /// - Parameter gpus: List of available GPU adapters.
    /// - Returns: Array of tag and display label pairs.
    static func gpuPickerOptions(from gpus: [GpuDeviceInfo]) -> [(tag: String, label: String)] {
        var options: [(tag: String, label: String)] = [("auto", "Auto (Recommended)")]
        var usedTags: Set<String> = ["auto"]
        for g in gpus {
            if g.vendor == "System" && g.name == UiDefaults.defaultSystemGpuName {
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
                if !self.didEvaluateLaunchSetupPrompt {
                    self.didEvaluateLaunchSetupPrompt = true
                    if let setup = model.setup_status,
                       setup.needs_attention && !setup.suppress_launch_prompt
                    {
                        self.showSetupSheet = true
                    }
                }
                // Preserve local draft of KVM layout if user is currently editing sliders or if an older in-flight poll arrives
                if !self.kvmLayoutDirty && model.kvm.layout.updated_at_ms >= self.kvmLayout.updated_at_ms {
                    self.isApplyingRemoteLayout = true
                    self.kvmLayout = model.kvm.layout
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
                self.localSharedFolder = model.local_shared_folder ?? ""
                // Synchronize shared microphone gain and selected device when not actively dragging gain slider
                if !self.micGainDirty && !self.isEditingMicGain, let remoteGain = model.camera_status?.mic_gain {
                    self.micGain = min(max(Double(remoteGain), 0.0), 2.0)
                }
                if !self.didInitialMicRefresh {
                    self.didInitialMicRefresh = true
                    self.refreshMics(showErrorToast: false)
                } else if let remoteMicName = model.camera_status?.mic_device_name,
                          !remoteMicName.isEmpty,
                          let matchedMic = self.availableMics.first(where: { $0.id == remoteMicName || $0.name == remoteMicName })
                {
                    self.selectedMicId = matchedMic.id
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
    ///   - onCompleted: Optional callback invoked with success flag upon completion.
    func runAction(
        _ method: String,
        params: [String: Any] = [:],
        refreshAfter: Bool = true,
        suppressDataToast: Bool = false,
        successToast: String? = nil,
        onCompleted: (@MainActor @Sendable (Bool) -> Void)? = nil
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
            onCompleted?(ok)
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

    /// Requests a feature flag toggle while enforcing mutual exclusion between Extended Screen (`"display"`)
    /// and Universal Input KVM (`"input_kvm"`).
    ///
    /// Why mutual exclusion is required:
    /// Extended Screen streams the desktop over Moonlight/Sunshine, which captures mouse and keyboard
    /// input directly inside the stream window. Running Universal Input KVM's low-level `CGEventTap` input
    /// hooks and screen-edge cursor hopping simultaneously causes cursor capture conflicts, stuck modifier
    /// keys, and phantom screen hops.
    ///
    /// - Parameters:
    ///   - requested: The feature flag identifier (`"display"` or `"input_kvm"`).
    ///   - enabled: Desired boolean activation state.
    func requestFeatureToggleWithMutualExclusion(_ requested: String, enabled: Bool) {
        // Turning a feature OFF never conflicts with another active feature
        guard enabled else {
            toggleFeature(requested, enabled: false)
            return
        }

        let displayCurrentlyOn = (status?.feature_flags.display == true) || (status?.display_active == true)
        let kvmCurrentlyOn = (status?.feature_flags.input_kvm == true)

        if requested == "display" && kvmCurrentlyOn {
            // Force SwiftUI NSSwitch binding to revert to current state until user confirms
            objectWillChange.send()
            let confirmed = presentKvmDisplayConflictAlert(switchingToDisplay: true)
            if confirmed {
                toggleFeature("display", enabled: true)
            } else {
                DispatchQueue.main.async { [weak self] in
                    self?.objectWillChange.send()
                }
            }
            return
        }

        if requested == "input_kvm" && displayCurrentlyOn {
            // Force SwiftUI NSSwitch binding to revert to current state until user confirms
            objectWillChange.send()
            let confirmed = presentKvmDisplayConflictAlert(switchingToDisplay: false)
            if confirmed {
                toggleFeature("input_kvm", enabled: true)
            } else {
                DispatchQueue.main.async { [weak self] in
                    self?.objectWillChange.send()
                }
            }
            return
        }

        toggleFeature(requested, enabled: true)
    }

    /// Initiates or stops a Mac -> PC or PC -> Mac Extended Screen session, intercepting with a
    /// mutual-exclusion confirmation alert if Universal Input KVM (`input_kvm`) is currently enabled.
    ///
    /// - Parameters:
    ///   - rpcMethod: Core RPC endpoint (`"toggle_mac_to_pc"` or `"toggle_pc_to_mac"`).
    ///   - isCurrentlyActive: True if the user is stopping an already-active display stream.
    func requestDisplayStreamToggle(_ rpcMethod: String, isCurrentlyActive: Bool) {
        // Stopping an active stream never conflicts with KVM
        if !isCurrentlyActive && (status?.feature_flags.input_kvm == true) {
            let confirmed = presentKvmDisplayConflictAlert(switchingToDisplay: true)
            guard confirmed else { return }
            // Enable `"display"` first so Rust core atomically disables `"input_kvm"` and releases hooks,
            // then immediately trigger the requested display stream direction.
            isDisplayToggling = true
            runAction("set_feature_flag", params: ["feature": "display", "enabled": true], refreshAfter: false) { [weak self] ok in
                guard let self = self else { return }
                guard ok else {
                    self.isDisplayToggling = false
                    self.refresh()
                    return
                }
                self.runAction(rpcMethod) { [weak self] _ in
                    self?.isDisplayToggling = false
                }
            }
            return
        }

        isDisplayToggling = true
        runAction(rpcMethod) { [weak self] _ in
            self?.isDisplayToggling = false
        }
    }

    /// Presents a native modal `NSAlert` (`alertStyle = .warning`) explaining why Extended Screen
    /// and Universal Input KVM cannot run at the same time and offering a clean atomic switch.
    ///
    /// - Parameter switchingToDisplay: True when user requested Extended Screen while KVM is active;
    ///   false when user requested Universal Input KVM while Extended Screen is active.
    /// - Returns: True if the user clicked the primary `"Switch to ..."` button; false on `"Cancel"`.
    func presentKvmDisplayConflictAlert(switchingToDisplay: Bool) -> Bool {
        guard !isMutualExclusionAlertOpen else { return false }
        isMutualExclusionAlertOpen = true
        defer { isMutualExclusionAlertOpen = false }

        activateIntegratorApp()

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Extended Screen & Universal Input KVM Cannot Run Together"
        let actionPrompt = switchingToDisplay
            ? "Would you like to disable Universal Input KVM and switch to Extended Screen?"
            : "Would you like to stop Extended Screen and switch to Universal Input KVM?"
        alert.informativeText =
            "Extended Screen streams your desktop over Moonlight/Sunshine, which captures mouse and keyboard input directly. " +
            "Running Universal Input KVM's low-level input hooks and screen-edge hopping at the same time causes cursor capture conflicts, " +
            "stuck modifier keys, or phantom screen hops.\n\n" +
            actionPrompt

        let primaryTitle = switchingToDisplay
            ? "Switch to Extended Screen"
            : "Switch to Universal Input KVM"
        alert.addButton(withTitle: primaryTitle)
        let cancelBtn = alert.addButton(withTitle: "Cancel")
        cancelBtn.keyEquivalent = "\u{1b}"

        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: - Shared Camera & Microphone Controls

    /// Queries the Rust core (`"list_mics"`) for all available macOS microphone input devices
    /// and reconciles the active `selectedMicId` selection.
    ///
    /// - Parameter showErrorToast: When true, displays an error toast banner if enumeration fails.
    func refreshMics(showErrorToast: Bool = true) {
        invoke("list_mics", params: "{}", as: [MicDeviceModel].self) { [weak self] res in
            guard let self = self else { return }
            switch res {
            case .success(let mics):
                self.availableMics = mics
                if let currentName = self.status?.camera_status?.mic_device_name,
                   !currentName.isEmpty,
                   let match = mics.first(where: { $0.id == currentName || $0.name == currentName })
                {
                    self.selectedMicId = match.id
                } else if self.selectedMicId.isEmpty || !mics.contains(where: { $0.id == self.selectedMicId }) {
                    if let defaultMic = mics.first(where: { $0.is_default == true }) ?? mics.first {
                        self.selectedMicId = defaultMic.id
                    } else {
                        self.selectedMicId = ""
                    }
                }
            case .failure(let err):
                if showErrorToast {
                    self.showToast("error", err.message)
                }
            }
        }
    }

    /// Requests macOS TCC microphone capture permission (`AVCaptureDevice.requestAccess(for: .audio)`)
    /// via `"request_mic_permission"` and refreshes both bridge status and enumerated microphones.
    func requestMicPermission() {
        invoke("request_mic_permission", params: "{}", as: Bool.self) { [weak self] res in
            guard let self = self else { return }
            switch res {
            case .success(let granted):
                if granted {
                    self.showToast("success", "Microphone permission granted")
                } else {
                    self.showToast("error", "Microphone access denied — enable Integrator in System Settings > Privacy & Security > Microphone")
                }
            case .failure(let err):
                self.showToast("error", err.message)
            }
            self.refresh()
            self.refreshMics(showErrorToast: false)
        }
    }

    /// Selects a specific macOS microphone source by device identifier via the `"select_mic"` RPC.
    ///
    /// - Parameter id: CoreAudio / AVFoundation unique identifier of the target microphone.
    func selectMic(_ id: String) {
        let trimmed = id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        selectedMicId = trimmed
        runAction("select_mic", params: ["deviceId": trimmed])
    }

    /// Updates Mac -> PC shared microphone streaming state, mute state, and linear gain multiplier
    /// via the `"set_mic_settings"` RPC endpoint.
    ///
    /// - Parameters:
    ///   - enabled: True to enable shared microphone streaming alongside the virtual camera.
    ///   - muted: True to silence outgoing microphone audio packets.
    ///   - gain: Linear input gain multiplier in the range `0.0...2.0` (`0%` to `200%`).
    func updateMicSettings(enabled: Bool, muted: Bool, gain: Double) {
        let clampedGain = min(max(gain, 0.0), 2.0)
        micGain = clampedGain
        micGainRequestGeneration &+= 1
        let capturedGen = micGainRequestGeneration
        runAction(
            "set_mic_settings",
            params: [
                "enabled": enabled,
                "muted": muted,
                "gain": Float(clampedGain)
            ],
            suppressDataToast: true
        ) { [weak self] ok in
            guard let self = self else { return }
            if ok && !self.isEditingMicGain && self.micGainRequestGeneration == capturedGen {
                self.micGainDirty = false
            }
        }
    }

    /// Schedules a debounced `"set_mic_settings"` synchronization when the user adjusts the mic gain
    /// slider via track clicks, scroll wheel, or keyboard steps.
    ///
    /// - Parameters:
    ///   - newGain: New linear input gain multiplier (`0.0...2.0`).
    ///   - enabled: Current microphone share enabled state.
    ///   - muted: Current microphone mute state.
    func handleMicGainChanged(_ newGain: Double, enabled: Bool, muted: Bool) {
        let clamped = min(max(newGain, 0.0), 2.0)
        micGainDirty = true
        micGain = clamped
        micGainDebounceWorkItem?.cancel()
        // If user is not actively dragging, dispatch after a short debounce so track clicks apply reliably
        guard !isEditingMicGain else { return }
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                guard let self = self, !self.isEditingMicGain else { return }
                let latestEnabled = self.status?.camera_status?.mic_enabled ?? enabled
                let latestMuted = self.status?.camera_status?.mic_muted ?? muted
                self.updateMicSettings(enabled: latestEnabled, muted: latestMuted, gain: self.micGain)
            }
        }
        micGainDebounceWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.18, execute: work)
    }

    /// Tracks active slider drag state and commits the final mic gain value immediately on release.
    ///
    /// - Parameters:
    ///   - editing: True when drag starts; false when drag ends.
    ///   - enabled: Current microphone share enabled state.
    ///   - muted: Current microphone mute state.
    func handleMicGainEditingChanged(_ editing: Bool, enabled: Bool, muted: Bool) {
        isEditingMicGain = editing
        if editing {
            micGainDirty = true
            micGainDebounceWorkItem?.cancel()
        } else {
            micGainDebounceWorkItem?.cancel()
            updateMicSettings(enabled: enabled, muted: muted, gain: micGain)
        }
    }

    /// Toggles the hardware camera privacy shutter killswitch in the Rust core.
    ///
    /// Invokes `"toggle_camera_privacy"` (with automatic fallback to `"toggle_camera_privacy_mute"`
    /// if the alternate RPC alias is registered), applies immediate UI state feedback, and refreshes status.
    func toggleCameraPrivacyMute() {
        invokeRaw("toggle_camera_privacy", params: "{}") { [weak self] ok, dataJson, errMsg in
            guard let self = self else { return }
            if ok {
                if let bytes = dataJson,
                   let obj = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                   let muted = obj["privacy_muted"] as? Bool
                {
                    self.status?.camera_status?.privacy_muted = muted
                    self.showToast(
                        "info",
                        muted
                            ? "Camera privacy shutter closed — transmitting black privacy frame"
                            : "Camera privacy shutter opened — live video resumed"
                    )
                }
                self.refresh()
            } else if let err = errMsg, err.localizedCaseInsensitiveContains("Unknown") {
                self.runAction("toggle_camera_privacy_mute", suppressDataToast: true)
            } else {
                self.showToast("error", errMsg ?? "Failed to toggle camera privacy shutter")
                self.refresh()
            }
        }
    }

    /// Synchronizes the locally drafted KVM desk layout configuration with the Rust core.
    func syncKvmLayout() {
        isApplyingRemoteLayout = true
        kvmLayout.updated_at_ms = UInt64(Date().timeIntervalSince1970 * 1000)
        isApplyingRemoteLayout = false
        guard let encoded = try? JSONEncoder().encode(kvmLayout),
              let dict = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        else { return }
        runAction("set_kvm_layout", params: ["layout": dict]) { [weak self] ok in
            if ok {
                self?.kvmLayoutDirty = false
            }
        }
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

    /// Forces an uncached OS permissions and companion dependencies probe from the Rust core.
    func refreshSetupStatus() {
        invoke("get_setup_status", params: "{}", as: SetupHealthSnapshotModel.self) { [weak self] res in
            guard let self = self else { return }
            switch res {
            case .success(let snap):
                self.status?.setup_status = snap
                self.refresh()
            case .failure(let e):
                self.showToast("error", e.message)
            }
        }
    }

    /// Persists the user's preference to suppress or enable automatic Setup sheet prompting on app launch.
    func setSuppressLaunchSetupPrompt(_ suppress: Bool) {
        status?.setup_status?.suppress_launch_prompt = suppress
        runAction(
            "set_suppress_launch_setup_prompt",
            params: ["suppress": suppress],
            suppressDataToast: true,
            successToast: suppress
                ? "Automatic launch setup prompt disabled"
                : "Automatic launch setup prompt enabled"
        )
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
    private func invoke<T: Decodable & Sendable>(
        _ method: String,
        params: String,
        as type: T.Type,
        completion: @escaping @MainActor @Sendable (Result<T, RpcErrorMessage>) -> Void
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
                    let errMsg = env.error ?? "Command failed"
                    Task { @MainActor in completion(.failure(RpcErrorMessage(errMsg))) }
                }
            } catch {
                let errDesc = error.localizedDescription
                Task { @MainActor in completion(.failure(RpcErrorMessage("Decode error: \(errDesc)"))) }
            }
        }
    }

    /// Dispatches an RPC request where the data payload may be optional or null.
    private func invokeOptional<T: Decodable & Sendable>(
        _ method: String,
        params: String,
        as type: T.Type,
        completion: @escaping @MainActor @Sendable (Result<T?, RpcErrorMessage>) -> Void
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
                    let d = env.data
                    Task { @MainActor in completion(.success(d)) }
                } else {
                    let errMsg = env.error ?? "Command failed"
                    Task { @MainActor in completion(.failure(RpcErrorMessage(errMsg))) }
                }
            } catch {
                let errDesc = error.localizedDescription
                Task { @MainActor in completion(.failure(RpcErrorMessage("Decode error: \(errDesc)"))) }
            }
        }
    }

    /// Dispatches an RPC request and returns raw JSON bytes without strict decoding.
    private func invokeRaw(
        _ method: String,
        params: String,
        completion: @escaping @MainActor @Sendable (Bool, Data?, String?) -> Void
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
            let finalBytes = dataBytes
            Task { @MainActor in completion(ok, finalBytes, err) }
        }
    }
}

/// Strongly typed error wrapper for native RPC failure messages.
struct RpcErrorMessage: Error, LocalizedError, Sendable {
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

    /// Applies the liquid glass material, specular border, and corner clipping to the target card content.
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

    /// Applies the liquid glass material, specular border, and corner clipping to the target card content.
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

    /// Renders the capsule-shaped status pill with its leading indicator dot and status text.
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

    /// Renders the horizontal card header bar containing the icon badge, title, status pill, and toggle switch.
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
    /// When true, skips the quit confirmation dialog when quitting Integrator.
    @AppStorage("com.manveersingh.integrator.skipQuitConfirmation") private var skipQuitConfirmation: Bool = false

    /// Convenience accessor for latest bridge status snapshot.
    private var s: BridgeStatusModel? { vm.status }
    /// Convenience accessor for active subsystem feature flags with fallback defaults.
    private var flags: FeatureFlagsModel {
        s?.feature_flags ?? FeatureFlagsModel(
            display: false, input_kvm: true, clipboard: true, dragdrop: false,
            truetone: true, touchbar: true, storage: true, audio: true
        )
    }

    /// Renders the primary two-column dashboard layout, navigation sidebar, top toolbar, and toast overlay.
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
                                clipboardCard
                                dragDropCard
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
        .sheet(isPresented: $vm.showSetupSheet) {
            SetupAssistantSheetView(vm: vm)
        }
        .onAppear {
            // Begin periodic polling when view hierarchy attaches unless launched hidden in the menu bar tray
            if gMacAppDelegate?.startHidden != true || gMacAppDelegate?.mainWindow?.isVisible == true {
                vm.startPolling()
            }
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

            // Quick-access Setup, Drivers & Permissions button in sidebar
            Button {
                vm.refreshSetupStatus()
                vm.showSetupSheet = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(s?.setup_status?.needs_attention == true ? .orange : .green)
                    Text("Setup & Permissions")
                        .font(.caption.weight(.semibold))
                    Spacer()
                    if s?.setup_status?.needs_attention == true {
                        Circle()
                            .fill(Color.orange)
                            .frame(width: 8, height: 8)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(
                    (s?.setup_status?.needs_attention == true ? Color.orange : Color.accentColor).opacity(0.14),
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                )
            }
            .buttonStyle(.plain)

            // Persistent bottom peer connection summary card
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 7) {
                    Circle()
                        .fill(s?.peer_connected == true ? .green : .orange)
                        .frame(width: 8, height: 8)
                    if s?.peer_connected == true {
                        Image(systemName: IntegratorViewModel.deviceSymbol(
                            os: s?.peer_os,
                            hardwareModel: s?.peer_hardware_model,
                            formFactor: s?.peer_form_factor
                        ))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    Text(s?.peer_name ?? "Discovering Peer...")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                }
                Text(s?.link_description ?? "Awaiting USB-C / TB / Ethernet / Wi-Fi / Hotspot beacon")
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
            Image(systemName: IntegratorViewModel.deviceSymbol(
                os: s?.os ?? "macos",
                hardwareModel: s?.hardware_model,
                formFactor: s?.form_factor
            ))
            .font(.system(size: 20, weight: .medium))
            .foregroundStyle(.tint)

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

            Button {
                vm.refreshSetupStatus()
                vm.showSetupSheet = true
            } label: {
                HStack(spacing: 6) {
                    Circle()
                        .fill(s?.setup_status?.needs_attention == true ? Color.orange : Color.green)
                        .frame(width: 7, height: 7)
                    Label("Setup & Permissions", systemImage: "checkmark.shield")
                }
            }

            Button { vm.refresh() } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }

            Button { vm.runAction("open_cache_folder", refreshAfter: false) } label: {
                Label("Open Cache", systemImage: "folder")
            }

            Button { vm.runAction("hide_window", refreshAfter: false) } label: {
                Label("Hide", systemImage: "minus.rectangle")
            }

            Button {
                gMacAppDelegate?.requestQuit()
            } label: {
                Label("Quit", systemImage: "power")
                    .foregroundStyle(.red)
            }
            .help("Quit Integrator and shut down all background processes (⌘Q)")
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
                    set: { vm.requestFeatureToggleWithMutualExclusion("display", enabled: $0) }
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
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 12) {
                        Label("\(t.gpu_name)", systemImage: "cpu")
                        Label("\(t.temperature_c)°C", systemImage: "thermometer")
                        Label("\(t.gpu_utilization_percent)%", systemImage: "gauge")
                        Label("\(t.memory_used_mb)/\(t.memory_total_mb) MB", systemImage: "memorychip")
                    }
                    if let all = t.all_gpus, !all.isEmpty {
                        Text("Detected GPUs: \(all.joined(separator: " • "))")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
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

            let mode = s?.active_mode ?? ""
            let isMacToPcActive = s?.display_active == true && mode.localizedCaseInsensitiveContains("Mac -> PC")
            let isPcToMacActive = s?.display_active == true && mode.localizedCaseInsensitiveContains("PC -> Mac")

            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    if isMacToPcActive {
                        Button {
                            vm.requestDisplayStreamToggle("toggle_mac_to_pc", isCurrentlyActive: true)
                        } label: {
                            Text("Stop Extending").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!flags.display || vm.isDisplayToggling)
                    } else {
                        Button {
                            vm.requestDisplayStreamToggle("toggle_mac_to_pc", isCurrentlyActive: false)
                        } label: {
                            Text("Extend Mac -> PC").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled((!flags.display && !flags.input_kvm) || vm.isDisplayToggling)
                    }

                    if isPcToMacActive {
                        Button {
                            vm.requestDisplayStreamToggle("toggle_pc_to_mac", isCurrentlyActive: true)
                        } label: {
                            Text("Stop Extending").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!flags.display || vm.isDisplayToggling)
                    } else {
                        Button {
                            vm.requestDisplayStreamToggle("toggle_pc_to_mac", isCurrentlyActive: false)
                        } label: {
                            Text("Extend PC -> Mac").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled((!flags.display && !flags.input_kvm) || vm.isDisplayToggling)
                    }
                }
                HStack(spacing: 8) {
                    Button("Apply GPU") {
                        let enc = vm.selectedEncodeGpu
                        let dec = vm.selectedDecodeGpu
                        vm.runAction("set_gpu_preferences", params: [
                            "encodeGpu": enc,
                            "decodeGpu": dec
                        ]) { ok in
                            if ok {
                                vm.encodeGpuDirty = false
                                vm.decodeGpuDirty = false
                            }
                        }
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
                    set: { vm.requestFeatureToggleWithMutualExclusion("input_kvm", enabled: $0) }
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
        let peerName = s?.peer_name ?? UiDefaults.defaultPeerHostname
        let localName = s?.hostname ?? UiDefaults.defaultLocalHostname
        let localIcon = IntegratorViewModel.deviceSymbol(
            os: s?.os ?? "macos",
            hardwareModel: s?.hardware_model,
            formFactor: s?.form_factor
        )
        let peerIcon = IntegratorViewModel.deviceSymbol(
            os: s?.peer_os ?? "windows",
            hardwareModel: s?.peer_hardware_model,
            formFactor: s?.peer_form_factor
        )
        let localBox = monitorTile(localName, icon: localIcon, accent: true)
        let peerBox = monitorTile(peerName, icon: peerIcon, accent: false)

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
    private func monitorTile(_ label: String, icon: String, accent: Bool) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
                .font(.caption2)
                .foregroundStyle(accent ? Color.accentColor : .secondary)
            Text(label)
                .font(.caption.weight(.semibold))
                .lineLimit(1)
        }
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
                TextField("Manual Peer IPv4 (e.g. 192.168.1.50 or 172.20.10.2)", text: $vm.manualIpInput)
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
                        Image(systemName: IntegratorViewModel.deviceSymbol(
                            os: peer.os,
                            hardwareModel: peer.hardware_model,
                            formFactor: peer.form_factor
                        ))
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                            .disabled(pinDraft.count != UiDefaults.pairingPinLength)

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
                        Text("ID: \(String(tp.device_id.prefix(UiDefaults.deviceIdPreviewLength)))… • \(tp.last_ip)")
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
                    Text("Blocked Device: \(String(blockedId.prefix(UiDefaults.deviceIdPreviewLength)))…")
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

            Label("SPAKE2 + Ed25519 Mutual Auth Enforced Across All Links (v1.0 Locked)", systemImage: "checkmark.seal.fill")
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

            VStack(alignment: .leading, spacing: 4) {
                Text("Local Shared Folder")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    Text(vm.localSharedFolder.isEmpty ? (s?.local_shared_folder ?? UiDefaults.defaultSharedPublicFolderLabel) : vm.localSharedFolder)
                        .font(.caption)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                        .background(Color.secondary.opacity(0.1))
                        .cornerRadius(6)
                    Button("Choose Folder…") {
                        let panel = NSOpenPanel()
                        panel.canChooseFiles = false
                        panel.canChooseDirectories = true
                        panel.allowsMultipleSelection = false
                        panel.prompt = "Select Shared Folder"
                        if panel.runModal() == .OK, let url = panel.url {
                            let path = url.path
                            vm.localSharedFolder = path
                            vm.runAction("set_local_shared_folder", params: ["folder": path])
                        }
                    }
                    .buttonStyle(.bordered)
                    if !vm.localSharedFolder.isEmpty || s?.local_shared_folder != nil {
                        Button("Reset") {
                            vm.localSharedFolder = ""
                            vm.runAction("set_local_shared_folder", params: ["folder": NSNull()])
                        }
                        .buttonStyle(.bordered)
                    }
                }
            }

            HStack(spacing: 8) {
                TextField("Preferred Peer Share Name", text: Binding(
                    get: { vm.preferredShareInput },
                    set: {
                        vm.preferredShareInput = $0
                        vm.preferredShareDirty = true
                    }
                ))
                .textFieldStyle(.roundedBorder)
                Button("Set Share") {
                    let trimmed = vm.preferredShareInput.trimmingCharacters(in: .whitespaces)
                    vm.runAction("set_preferred_peer_share", params: ["share": trimmed.isEmpty ? NSNull() : trimmed]) { ok in
                        if ok {
                            vm.preferredShareDirty = false
                        }
                    }
                }
                .buttonStyle(.bordered)
            }

            Toggle("Auto-Mount on Peer Detect", isOn: Binding(
                get: { s?.auto_mount_storage ?? false },
                set: { vm.runAction("set_auto_mount_storage", params: ["enabled": $0]) }
            ))
            .font(.caption)

            HStack(spacing: 8) {
                Button(s?.storage_mounted == true ? "Unmount Storage" : "Mount Shared Storage") {
                    vm.runAction(s?.storage_mounted == true ? "unmount_shared_storage" : "mount_shared_storage")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!flags.storage)

                if s?.storage_mounted == true {
                    Button("Open in Finder") {
                        vm.runAction("open_shared_storage")
                    }
                    .buttonStyle(.bordered)
                }
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
        // When True Tone is disabled, display "Paused". When enabled, display "Auto • <lux> lux • <CCT>K"
        // if ambient sensor hardware is supported, or "Active • <CCT>K" otherwise (never "Manual" while active).
        let trueTonePillText: String = {
            guard flags.truetone else { return "Paused" }
            if s?.ambient_supported == true {
                return String(
                    format: "Auto • %.0f lux • %dK",
                    s?.ambient_lux ?? 0,
                    s?.ambient_cct ?? UInt32(UiDefaults.defaultTrueToneCct)
                )
            }
            return "Active • \(Int(vm.trueToneCct))K"
        }()

        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "sun.max",
                title: "True Tone & Chromatic Sync",
                pillText: trueTonePillText,
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
                 ? "Liquid Glass Touch Bar GPU telemetry & expanded Windows media controls. Tap ∫ in the Control Strip anytime to restore after closing."
                 : "No Apple Touch Bar hardware detected on this workstation.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button(s?.touchbar_active == true ? "Hide Touch Bar HUD" : "Show Touch Bar HUD") {
                    vm.runAction("toggle_touchbar_hud")
                }
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
        let audioPort: UInt16 = {
            if let p = s?.audio_status.port, p > 0 { return p }
            return UiDefaults.defaultAudioPort
        }()
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "speaker.wave.3",
                title: "Dynamic Audio Routing",
                pillText: "UDP :\(audioPort)",
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

    // MARK: - Card 10B: Mac -> PC Shared Camera & Mic

    /// Card 10B: Mac AVFoundation camera & microphone capture, hardware privacy shutter killswitch,
    /// microphone device selection, input gain control, and encrypted TCP transmission to Windows.
    private var cameraCard: some View {
        let camEnabled = flags.camera ?? false
        let cam = s?.camera_status
        let camActive = cam?.active == true
        let privacyMuted = cam?.privacy_muted == true
        let micEnabled = cam?.mic_enabled ?? false
        let micMuted = cam?.mic_muted ?? false
        let camWidth = (cam?.width ?? 0) > 0 ? (cam?.width ?? UiDefaults.defaultCameraWidth) : UiDefaults.defaultCameraWidth
        let camHeight = (cam?.height ?? 0) > 0 ? (cam?.height ?? UiDefaults.defaultCameraHeight) : UiDefaults.defaultCameraHeight
        let camFps = (cam?.fps ?? 0) > 0 ? (cam?.fps ?? UiDefaults.defaultCameraFps) : UiDefaults.defaultCameraFps
        let camPort: UInt16 = {
            if let p = cam?.port, p > 0 { return p }
            return UiDefaults.defaultCameraPort
        }()
        let camDeviceName: String = {
            if let name = cam?.device_name?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty {
                return name
            }
            return UiDefaults.defaultCameraDeviceName
        }()
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(
                icon: "video.fill",
                title: "Mac → PC Shared Camera & Mic",
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
            } else if cam?.camera_available == false && !camActive {
                Text("No camera hardware detected on this Mac. Connect a USB webcam or Continuity Camera.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if camActive {
                Text("\(camWidth)×\(camHeight) @ \(camFps)fps • \(cam?.frames_transferred ?? 0) frames sent over TCP :\(camPort)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            } else {
                Text("Streams your Mac camera (\(camHeight)p\(camFps)) & microphone into Windows '\(camDeviceName)' (TCP :\(camPort)).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 8) {
                Button(camActive ? "Stop Camera Stream" : "Start Camera Stream") {
                    vm.runAction("toggle_camera")
                }
                .buttonStyle(.borderedProminent)

                Button {
                    vm.toggleCameraPrivacyMute()
                } label: {
                    Label(
                        privacyMuted ? "Shutter Closed" : "Privacy Shutter",
                        systemImage: privacyMuted ? "video.slash.fill" : "video.fill"
                    )
                    .foregroundStyle(privacyMuted ? .red : .primary)
                }
                .buttonStyle(.bordered)
                .tint(privacyMuted ? .red : .secondary)
                .help(privacyMuted
                    ? "Disengage hardware camera privacy shutter to resume live video frames"
                    : "Engage hardware camera privacy shutter (transmits studio-black privacy frame)")

                Spacer()
            }

            Divider().opacity(0.35)

            // Shared Microphone Subsection
            VStack(alignment: .leading, spacing: 8) {
                if cam?.mic_permission_granted == false {
                    HStack(spacing: 8) {
                        Label("macOS Microphone permission is required to stream Mac audio input to Windows.", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                        Spacer()
                        Button("Grant Mic Access") {
                            vm.requestMicPermission()
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                    .padding(8)
                    .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                }

                HStack(spacing: 10) {
                    Toggle("Share Mac Microphone", isOn: Binding(
                        get: { micEnabled },
                        set: { newEnabled in
                            vm.updateMicSettings(enabled: newEnabled, muted: micMuted, gain: vm.micGain)
                        }
                    ))
                    .toggleStyle(.switch)
                    .font(.subheadline.weight(.medium))

                    Spacer()

                    Button {
                        vm.updateMicSettings(enabled: micEnabled, muted: !micMuted, gain: vm.micGain)
                    } label: {
                        Label(
                            micMuted ? "Mic Muted" : "Mic Live",
                            systemImage: micMuted ? "mic.slash.fill" : "mic.fill"
                        )
                        .foregroundStyle(micMuted ? .red : .green)
                    }
                    .buttonStyle(.bordered)
                    .tint(micMuted ? .red : .green)
                    .controlSize(.small)
                    .disabled(!micEnabled)
                }

                HStack(spacing: 8) {
                    Text("Mic Source")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 68, alignment: .leading)

                    Picker("", selection: Binding(
                        get: {
                            if !vm.selectedMicId.isEmpty && vm.availableMics.contains(where: { $0.id == vm.selectedMicId }) {
                                return vm.selectedMicId
                            }
                            return vm.availableMics.first?.id ?? ""
                        },
                        set: { newId in
                            if !newId.isEmpty && newId != vm.selectedMicId {
                                vm.selectMic(newId)
                            }
                        }
                    )) {
                        if vm.availableMics.isEmpty {
                            Text((cam?.mic_device_name?.isEmpty == false) ? (cam?.mic_device_name ?? "System Default Microphone") : "System Default Microphone")
                                .tag("")
                        } else {
                            ForEach(vm.availableMics) { mic in
                                Text(mic.is_default == true ? "\(mic.name) (Default)" : mic.name)
                                    .tag(mic.id)
                            }
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: .infinity)

                    Button {
                        vm.refreshMics(showErrorToast: true)
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .help("Refresh available macOS microphone input devices")
                }

                HStack(spacing: 8) {
                    Text("Mic Gain")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 68, alignment: .leading)

                    Slider(
                        value: Binding(
                            get: { vm.micGain },
                            set: { newGain in
                                vm.handleMicGainChanged(newGain, enabled: micEnabled, muted: micMuted)
                            }
                        ),
                        in: 0.0...2.0,
                        step: 0.05,
                        onEditingChanged: { isEditing in
                            vm.handleMicGainEditingChanged(isEditing, enabled: micEnabled, muted: micMuted)
                        }
                    )

                    Text("\(Int(round(vm.micGain * 100)))%")
                        .font(.caption.monospacedDigit())
                        .frame(width: 44, alignment: .trailing)
                }
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

            Toggle("Ask for Confirmation Before Quitting", isOn: Binding(
                get: { !skipQuitConfirmation },
                set: { skipQuitConfirmation = !$0 }
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

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Label("Touch ID Biometric Gate (Mac → Windows 11)", systemImage: "touchid")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { flags.touchid ?? true },
                        set: { vm.toggleFeature("touchid", enabled: $0) }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                }
                Text("Authenticates local or remote Windows 11 Touch ID challenges via Apple Secure Enclave over encrypted TransportV2.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Test Touch ID Prompt") {
                    vm.showToast("info", "Place your finger on the Touch ID sensor…")
                    vm.runAction("verify_touchid")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!(flags.touchid ?? true))
            }
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

// MARK: - Setup, Drivers & Permissions Assistant Sheet

/// Modal macOS Setup, Drivers & Permissions Assistant sheet presented automatically on launch when
/// required permissions or streaming tools are missing (unless suppressed) or opened on-demand from the toolbar/sidebar.
private struct SetupAssistantSheetView: View {
    /// Shared ViewModel coordinating RPC dispatches and live status refreshes.
    @ObservedObject var vm: IntegratorViewModel

    /// Latest setup health snapshot from the bridge status.
    private var setup: SetupHealthSnapshotModel? {
        vm.status?.setup_status
    }

    /// Renders the modal setup assistant sheet with OS permission audit rows and companion tool installers.
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Sheet Header
            HStack(spacing: 12) {
                Image(systemName: setup?.needs_attention == true ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                    .font(.system(size: 26))
                    .foregroundStyle(setup?.needs_attention == true ? .orange : .green)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Setup, Drivers & Permissions Assistant")
                        .font(.title3.bold())
                    Text(headerSubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                StatusPill(
                    text: setup?.needs_attention == true ? "Action Needed" : "All Required Ready",
                    color: setup?.needs_attention == true ? .orange : .green
                )

                Button {
                    vm.refreshSetupStatus()
                } label: {
                    Label("Refresh Status", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Friendly Architecture & Explanations Card
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "sparkles")
                                .font(.system(size: 20))
                                .foregroundStyle(Color.accentColor)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Core Features Require Zero Additional Downloads")
                                    .font(.subheadline.weight(.semibold))
                                Text("KVM mouse & keyboard sharing, clipboard synchronization, folder drag-and-drop, and True Tone sync are 100% self-contained and ready to use immediately once Accessibility permission is granted.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        Divider()

                        Text("Optional Feature Companions (Only install if you use these features):")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.primary)

                        HStack(alignment: .top, spacing: 14) {
                            VStack(alignment: .leading, spacing: 2) {
                                Label("Virtual Displays", systemImage: "display.2")
                                    .font(.caption.weight(.semibold))
                                Text("Sunshine (Host) & Moonlight (Client) enable low-latency 4K 120Hz/240Hz screen extension. Available via Homebrew or direct DMG download.")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)

                            VStack(alignment: .leading, spacing: 2) {
                                Label("Native Sound Sink", systemImage: "speaker.wave.3")
                                    .font(.caption.weight(.semibold))
                                Text("Creates 'Windows PC (Integrator)' in Control Center to stream Mac system audio to PC speakers with sub-5ms latency. 1-click install.")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)

                            VStack(alignment: .leading, spacing: 2) {
                                Label("Direct Cable Link", systemImage: "cable.connector")
                                    .font(.caption.weight(.semibold))
                                Text("Auto-configures 40Gbps networking when connecting Mac and PC with a direct USB-C/Thunderbolt cable without Wi-Fi. 1-click install.")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(12)
                    .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))

                    // Section 1: Operating System Permissions
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Label("macOS Privacy & Security Permissions", systemImage: "lock.shield")
                                .font(.headline)
                            Spacer()
                            Button("Request All Missing Permissions") {
                                vm.runAction("request_all_missing_permissions") { _ in
                                    vm.refreshSetupStatus()
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                            .disabled((setup?.missing_required_permissions ?? 0) == 0)
                        }

                        ForEach(setup?.permissions ?? []) { perm in
                            permissionRow(perm)
                        }
                    }

                    Divider()

                    // Section 2: Drivers & Companion Streaming Tools
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Companion Tools & Drivers (Optional)", systemImage: "shippingbox.fill")
                            .font(.headline)

                        ForEach(setup?.dependencies ?? []) { dep in
                            dependencyRow(dep)
                        }
                    }
                }
                .padding(.vertical, 4)
            }

            Divider()

            // Footer Bar: Suppress Launch Prompt Toggle + Close Button
            HStack {
                Toggle(
                    "Don't prompt automatically on launch",
                    isOn: Binding(
                        get: { setup?.suppress_launch_prompt ?? false },
                        set: { vm.setSuppressLaunchSetupPrompt($0) }
                    )
                )
                .toggleStyle(.checkbox)
                .font(.caption)

                Spacer()

                Button("Done") {
                    vm.showSetupSheet = false
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(18)
        .frame(minWidth: 740, idealWidth: 780, minHeight: 560, idealHeight: 620)
    }

    /// Summary subtitle in the Setup sheet header.
    private var headerSubtitle: String {
        guard let snap = setup else {
            return "Auditing macOS TCC permissions and companion streaming tools…"
        }
        if !snap.needs_attention {
            return "All required macOS permissions are configured. Core features are 100% ready."
        }
        var parts: [String] = []
        if snap.missing_required_permissions > 0 {
            parts.append("\(snap.missing_required_permissions) required permission(s)")
        }
        if snap.missing_required_dependencies > 0 {
            parts.append("\(snap.missing_required_dependencies) required tool(s)")
        }
        return "\(parts.joined(separator: " and ")) need attention."
    }

    /// Renders an individual OS permission audit row with status badge, detail text, and 1-click Request / Settings actions.
    private func permissionRow(_ perm: PermissionStatusModel) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: perm.granted ? "checkmark.circle.fill" : (perm.required ? "exclamationmark.triangle.fill" : "info.circle.fill"))
                .font(.system(size: 16))
                .foregroundStyle(perm.granted ? .green : (perm.required ? .orange : .secondary))
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(perm.title)
                        .font(.subheadline.weight(.semibold))
                    StatusPill(
                        text: perm.granted ? "Granted" : (perm.required ? "Required • Missing" : "Optional"),
                        color: perm.granted ? .green : (perm.required ? .orange : .secondary)
                    )
                }
                Text(perm.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(perm.detail)
                    .font(.caption2)
                    .foregroundStyle(perm.granted ? Color.secondary : Color.orange)
            }

            Spacer(minLength: 8)

            HStack(spacing: 6) {
                if perm.can_request_directly && !perm.granted {
                    Button("Request") {
                        vm.runAction("request_permission", params: ["id": perm.id]) { _ in
                            vm.refreshSetupStatus()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }

                if perm.settings_url != nil {
                    Button("Settings") {
                        vm.runAction("open_permission_settings", params: ["id": perm.id]) { _ in
                            vm.refreshSetupStatus()
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(10)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }

    /// Renders an individual companion tool/driver row with Installed/Missing badge, 1-click Install/Download, and copyable CLI command.
    private func dependencyRow(_ dep: DependencyStatusModel) -> some View {
        let installTitle: String = {
            if dep.installed { return "Reinstall / Guide" }
            if dep.install_method.contains("DMG") { return "Download DMG" }
            if dep.install_method.contains("1-Click") { return "1-Click Install" }
            if dep.install_method.contains("Homebrew") { return "Install (Brew)" }
            return "Install / Download"
        }()

        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: dep.installed ? "checkmark.seal.fill" : (dep.required ? "exclamationmark.circle.fill" : "wrench.and.screwdriver.fill"))
                    .font(.system(size: 16))
                    .foregroundStyle(dep.installed ? .green : (dep.required ? .orange : .secondary))
                    .padding(.top, 2)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(dep.name)
                            .font(.subheadline.weight(.semibold))
                        StatusPill(
                            text: dep.installed ? "Installed" : (dep.required ? "Required • Missing" : "Optional Companion"),
                            color: dep.installed ? .green : (dep.required ? .orange : .secondary)
                        )
                        if let running = dep.running {
                            StatusPill(
                                text: running ? "Running" : "Stopped",
                                color: running ? .cyan : .secondary
                            )
                        }
                    }
                    Text(dep.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let path = dep.detected_path, !path.isEmpty {
                        Text("Detected: \(path)")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer(minLength: 8)

                Button(installTitle) {
                    vm.runAction("install_dependency", params: ["id": dep.id]) { _ in
                        vm.refreshSetupStatus()
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }

            if !dep.install_command.isEmpty {
                HStack(spacing: 8) {
                    Text("\(dep.install_method):")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(dep.install_command)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color(nsColor: .textBackgroundColor).opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
                    Spacer()
                    if dep.install_method.contains("DMG") {
                        if let url = URL(string: dep.download_url) {
                            Link(destination: url) {
                                Label("Open DMG Page", systemImage: "arrow.up.right.square")
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                        }
                    } else {
                        Button("Copy Command") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(dep.install_command, forType: .string)
                            vm.showToast("success", "Copied install command to clipboard")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                    }
                }
            }
        }
        .padding(10)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// SwiftUI wrapper around AppKit's `NSVisualEffectView` providing native window translucency.
private struct VisualEffectBackdrop: NSViewRepresentable {
    /// AppKit visual effect material.
    let material: NSVisualEffectView.Material
    /// Blending mode: behind window or within window.
    let blendingMode: NSVisualEffectView.BlendingMode

    /// Instantiates and configures the underlying AppKit `NSVisualEffectView`.
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }

    /// Synchronizes updated material and blending parameters with the existing `NSVisualEffectView`.
    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}

// MARK: - Graceful Shutdown Progress View (macOS)

/// Lifecycle state of an individual subsystem teardown step during graceful application exit.
private enum ShutdownStepState: Equatable {
    /// Step is queued and awaiting teardown of prior subsystems.
    case pending
    /// Subsystem is actively executing its synchronous FFI/runtime shutdown routine.
    case stopping
    /// Subsystem has completed teardown and released all OS resources.
    case stopped
}

/// Model representing a single subsystem row inside the floating graceful shutdown window.
private struct ShutdownStepItem: Identifiable {
    /// Canonical subsystem identifier passed to `"shutdown_subsystem"` (`"audio"`, `"camera"`, `"display"`, `"storage"`, `"kvm"`).
    let id: String
    /// Human-readable subsystem title displayed in the shutdown checklist.
    let title: String
    /// Detailed status description shown while the subsystem is actively stopping.
    let detail: String
    /// Current lifecycle state of this teardown step.
    var state: ShutdownStepState = .pending
}

/// Reactive view model driving the live subsystem teardown checklist during graceful application termination.
@MainActor
private final class ShutdownProgressViewModel: ObservableObject {
    /// Primary headline text displayed at the top of the shutdown window.
    @Published var headerTitle: String = "Shutting Down Integrator…"
    /// Subtitle text explaining the current shutdown phase.
    @Published var headerSubtitle: String = "Stopping all background processes and services"
    /// True once every subsystem and the Rust Tokio runtime have cleanly stopped.
    @Published var allComplete: Bool = false
    /// Ordered list of subsystem teardown steps executed sequentially on exit.
    @Published var steps: [ShutdownStepItem] = [
        ShutdownStepItem(id: "audio", title: "Dynamic Audio Routing", detail: "Stopping CoreAudio & UDP sink"),
        ShutdownStepItem(id: "camera", title: "Shared Camera & Mic", detail: "Stopping AVFoundation capture & streams"),
        ShutdownStepItem(id: "display", title: "Extended Display & GPU", detail: "Stopping Moonlight, virtual display & gamma"),
        ShutdownStepItem(id: "storage", title: "Clipboard & Shared Storage", detail: "Clearing cache & unmounting remote shares"),
        ShutdownStepItem(id: "kvm", title: "KVM Hooks & Core Services", detail: "Releasing input taps & closing network sockets"),
    ]

    /// Transitions the specified subsystem row into the `.stopping` spinner state.
    ///
    /// - Parameter id: Canonical subsystem identifier.
    func markStopping(_ id: String) {
        if let idx = steps.firstIndex(where: { $0.id == id }) {
            steps[idx].state = .stopping
        }
    }

    /// Transitions the specified subsystem row into the `.stopped` completed checkmark state.
    ///
    /// - Parameter id: Canonical subsystem identifier.
    func markStopped(_ id: String) {
        if let idx = steps.firstIndex(where: { $0.id == id }) {
            steps[idx].state = .stopped
        }
    }

    /// Marks all subsystem steps complete and updates the header before final `NSApp.terminate`.
    func markAllDone() {
        for idx in steps.indices {
            steps[idx].state = .stopped
        }
        allComplete = true
        headerTitle = "All Integrator Processes Stopped"
        headerSubtitle = "Quitting cleanly…"
    }
}

/// SwiftUI view rendered inside the floating HUD window during graceful application teardown.
private struct ShutdownProgressView: View {
    /// Observed view model tracking step-by-step teardown progress.
    @ObservedObject var model: ShutdownProgressViewModel

    /// Renders the HUD backdrop, progress header, and per-subsystem checklist rows.
    var body: some View {
        ZStack {
            VisualEffectBackdrop(material: .hudWindow, blendingMode: .behindWindow)
                .ignoresSafeArea()

            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(model.allComplete ? Color.green.opacity(0.18) : Color.red.opacity(0.16))
                            .frame(width: 38, height: 38)
                        if model.allComplete {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 19, weight: .semibold))
                                .foregroundStyle(.green)
                        } else {
                            ProgressView()
                                .controlSize(.small)
                        }
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(model.headerTitle)
                            .font(.headline)
                        Text(model.headerSubtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                Divider()

                VStack(alignment: .leading, spacing: 9) {
                    ForEach(model.steps) { step in
                        HStack(spacing: 10) {
                            Group {
                                switch step.state {
                                case .pending:
                                    Image(systemName: "circle")
                                        .font(.system(size: 13))
                                        .foregroundStyle(.tertiary)
                                case .stopping:
                                    ProgressView()
                                        .controlSize(.mini)
                                        .scaleEffect(0.85)
                                case .stopped:
                                    Image(systemName: "checkmark.circle.fill")
                                        .font(.system(size: 14))
                                        .foregroundStyle(.green)
                                }
                            }
                            .frame(width: 18, height: 18)

                            VStack(alignment: .leading, spacing: 1) {
                                Text(step.title)
                                    .font(.subheadline.weight(step.state == .stopping ? .semibold : .medium))
                                    .foregroundStyle(step.state == .pending ? .secondary : .primary)
                                Text(step.state == .stopped ? "Stopped" : (step.state == .stopping ? step.detail : "Waiting…"))
                                    .font(.caption2)
                                    .foregroundStyle(step.state == .stopped ? .green : .secondary)
                            }
                            Spacer()
                        }
                    }
                }
            }
            .padding(20)
        }
        .frame(width: 420, height: 310)
    }
}

// MARK: - AppKit Shell + Menu Bar Tray + Event Callback

/// Layer-backed rotating icon view for the macOS menu bar status item.
///
/// Provides a smooth hardware-accelerated 60/120fps rotation animation pivoting
/// strictly around the exact optical center of the integral glyph (`∫`) between
/// vertical (0°) when inactive and horizontal (-90°) when the menu opens.
private final class RotatingIntegralIconView: NSView {
    /// Backing image view rendering the template integral glyph (`∫`).
    private let imageView: NSImageView
    /// True when the icon is currently rotated to the horizontal (-90°) open-menu orientation.
    private(set) var isHorizontal: Bool = false
    /// Current target rotation angle in radians (`0.0` vertical, `-pi/2` horizontal).
    private var currentAngle: CGFloat = 0.0

    /// Initializes the rotating icon view with the given status bar button frame.
    override init(frame frameRect: NSRect) {
        self.imageView = NSImageView(frame: NSRect(origin: .zero, size: frameRect.size))
        super.init(frame: frameRect)
        setup()
    }

    /// Initializes the rotating icon view from an AppKit storyboard or nib coder.
    required init?(coder: NSCoder) {
        self.imageView = NSImageView(frame: .zero)
        super.init(coder: coder)
        setup()
    }

    /// Returns `nil` so mouse events pass directly through to the parent `NSStatusBarButton`.
    override func hitTest(_ point: NSPoint) -> NSView? {
        // Transparent to mouse clicks so the parent NSStatusBarButton receives clicks directly
        return nil
    }

    /// Configures CoreAnimation layer-backing and embeds the centered integral glyph subview.
    private func setup() {
        wantsLayer = true
        layer?.masksToBounds = false
        autoresizingMask = [.width, .height]

        imageView.image = makeIntegralGlyph()
        imageView.imageAlignment = .alignCenter
        imageView.imageScaling = .scaleNone
        imageView.wantsLayer = true
        imageView.layer?.masksToBounds = false
        imageView.frame = bounds
        imageView.autoresizingMask = [.width, .height]
        addSubview(imageView)
    }

    /// Synchronizes subview geometry on layout passes and reapplies the center-pivoted transform.
    override func layout() {
        super.layout()
        // Keep imageView aligned to full bounds and re-center the rotation transform
        // around the live (bounds.midX, bounds.midY) without fighting AppKit's anchorPoint.
        imageView.frame = bounds
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        imageView.layer?.transform = centeredRotation(currentAngle)
        CATransaction.commit()
    }

    /// Computes a pure 2D Z-axis rotation matrix pivoting strictly around `(bounds.midX, bounds.midY)`
    /// while leaving AppKit's native `(0, 0)` backing-layer anchorPoint untouched.
    private func centeredRotation(_ angle: CGFloat) -> CATransform3D {
        let cx = bounds.midX
        let cy = bounds.midY
        var t = CATransform3DIdentity
        t = CATransform3DTranslate(t, cx, cy, 0)
        t = CATransform3DRotate(t, angle, 0, 0, 1)
        t = CATransform3DTranslate(t, -cx, -cy, 0)
        return t
    }

    /// Evaluates a smooth cubic ease-in-out curve for normalized progress `t` in `0.0...1.0`.
    private static func easeInOutCubic(_ t: CGFloat) -> CGFloat {
        return t < 0.5 ? 4 * t * t * t : 1 - pow(-2 * t + 2, 3) / 2
    }

    /// Rotates the integral glyph between vertical (`0°`) and horizontal (`-90°`) using a 32-step
    /// center-pinned `CAKeyframeAnimation` that eliminates translational drift during rotation.
    ///
    /// - Parameters:
    ///   - horizontal: True to rotate to `-90°` (menu open); false to restore `0°` (menu closed).
    ///   - animated: True to animate smoothly over 220ms; false to snap immediately.
    func setRotated(_ horizontal: Bool, animated: Bool = true) {
        guard isHorizontal != horizontal else { return }
        isHorizontal = horizontal

        guard let layer = imageView.layer else { return }
        let targetAngle: CGFloat = horizontal ? -CGFloat.pi / 2 : 0.0

        if !animated {
            currentAngle = targetAngle
            layer.removeAllAnimations()
            CATransaction.begin()
            CATransaction.setDisableActions(true)
            layer.transform = centeredRotation(targetAngle)
            CATransaction.commit()
            return
        }

        // Sample live in-flight rotation angle from the presentation layer so rapid open/close reverses smoothly
        let startAngle: CGFloat
        if let pres = layer.presentation() {
            let m = pres.transform
            startAngle = atan2(m.m12, m.m11)
        } else {
            startAngle = currentAngle
        }
        currentAngle = targetAngle

        // Sample 32 ease-in-out keyframes of `T(cx,cy) * R_z(theta) * T(-cx,-cy)` so every GPU frame
        // keeps the exact geometric center of `∫` pinned with zero translational drift.
        let steps = 32
        var values: [NSValue] = []
        var keyTimes: [NSNumber] = []
        values.reserveCapacity(steps + 1)
        keyTimes.reserveCapacity(steps + 1)
        for i in 0...steps {
            let frac = CGFloat(i) / CGFloat(steps)
            let eased = Self.easeInOutCubic(frac)
            let theta = startAngle + (targetAngle - startAngle) * eased
            values.append(NSValue(caTransform3D: centeredRotation(theta)))
            keyTimes.append(NSNumber(value: Double(frac)))
        }

        let anim = CAKeyframeAnimation(keyPath: "transform")
        anim.values = values
        anim.keyTimes = keyTimes
        anim.calculationMode = .linear
        anim.duration = 0.22
        anim.isRemovedOnCompletion = true

        CATransaction.begin()
        CATransaction.setDisableActions(true)
        layer.transform = centeredRotation(targetAngle)
        CATransaction.commit()
        layer.add(anim, forKey: "smoothCenterRotation")
    }

    /// Draws the mathematical integral glyph (`∫`) optically centered inside an 18×18 template image
    /// using CoreText glyph path bounds so its inked center sits at exactly `(9.0, 9.0)`.
    private func makeIntegralGlyph() -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let img = NSImage(size: size, flipped: false) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let font = NSFont.systemFont(ofSize: 15, weight: .semibold)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: NSColor.black
            ]
            let attrStr = NSAttributedString(string: "∫", attributes: attrs)
            let line = CTLineCreateWithAttributedString(attrStr)
            let optical = CTLineGetBoundsWithOptions(line, .useGlyphPathBounds)
            let drawX = (size.width - optical.width) / 2.0 - optical.origin.x
            let drawY = (size.height - optical.height) / 2.0 - optical.origin.y
            ctx.saveGState()
            ctx.textMatrix = .identity
            ctx.textPosition = CGPoint(x: drawX, y: drawY)
            CTLineDraw(line, ctx)
            ctx.restoreGState()
            return true
        }
        img.isTemplate = true
        return img
    }
}

/// Native AppKit application and window delegate coordinating menu bar status item,
/// dashboard window presentation, and graceful lifecycle termination.
@MainActor
private final class MacAppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate {
    /// `UserDefaults` key storing the user's preference to skip the quit confirmation dialog.
    private static let skipQuitConfirmationKey = "com.manveersingh.integrator.skipQuitConfirmation"

    /// macOS status bar item in the menu bar.
    var statusItem: NSStatusItem?
    /// Custom rotating integral icon view providing smooth 60fps rotation animation.
    private var statusIconView: RotatingIntegralIconView?
    /// Main dashboard window instance.
    var mainWindow: NSWindow?
    /// Floating shutdown progress window displayed during graceful exit.
    var shutdownWindow: NSWindow?
    /// Flag indicating whether the app was launched in hidden tray-only mode.
    var startHidden: Bool = false
    /// Reentrancy guard while the quit confirmation alert is presented.
    private var isQuitPromptOpen: Bool = false
    /// Reentrancy guard while graceful shutdown is in progress.
    private var isShuttingDown: Bool = false
    /// Set to true only after all shutdown steps finish so `applicationShouldTerminate` permits exit.
    private var isTerminationApproved: Bool = false

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
        if !isShuttingDown {
            showDashboard()
        }
        return true
    }

    /// Intercepts all NSApplication termination attempts (Dock Quit, Cmd+Q, AppleEvent) so the
    /// confirmation prompt and live process shutdown sequence always run cleanly.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if isTerminationApproved {
            return .terminateNow
        }
        if isShuttingDown {
            return .terminateLater
        }
        DispatchQueue.main.async { [weak self] in
            self?.requestQuit()
        }
        return .terminateCancel
    }

    /// Intercepts window close button to hide dashboard to menu bar tray instead of quitting.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if isShuttingDown {
            return false
        }
        hideDashboard()
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
            let blank = NSImage(size: NSSize(width: 18, height: 18))
            blank.isTemplate = true
            btn.image = blank
            let iconView = RotatingIntegralIconView(frame: btn.bounds)
            btn.addSubview(iconView)
            statusIconView = iconView
        }
        let menu = NSMenu()
        menu.delegate = self
        menu.addItem(withTitle: "Show Dashboard", action: #selector(onShowDashboard), keyEquivalent: "d")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Paste Remote Item", action: #selector(onPasteRemote), keyEquivalent: "v")
        menu.addItem(withTitle: "Toggle Extended Screen", action: #selector(onToggleDisplay), keyEquivalent: "e")
        menu.addItem(withTitle: "Toggle Touch Bar HUD", action: #selector(onToggleTouchBar), keyEquivalent: "t")
        menu.addItem(withTitle: "Open Clipboard Cache", action: #selector(onOpenCache), keyEquivalent: "c")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Integrator", action: #selector(onQuit), keyEquivalent: "q")
        for mi in menu.items where mi.action != nil {
            mi.target = self
        }
        item.menu = menu
        statusItem = item
    }

    // MARK: - NSMenuDelegate (Menu Bar Icon Animation)

    /// Rotates the menu bar integral glyph (`∫`) to horizontal (`-90°`) when the status menu opens.
    func menuWillOpen(_ menu: NSMenu) {
        statusIconView?.setRotated(true, animated: true)
    }

    /// Restores the menu bar integral glyph (`∫`) to vertical (`0°`) when the status menu closes.
    func menuDidClose(_ menu: NSMenu) {
        statusIconView?.setRotated(false, animated: true)
    }

    /// Creates and styles the main dashboard window with full-size content view and transparent titlebar.
    private func setupMainWindow() {
        let hosting = NSHostingController(rootView: MainDashboardView(vm: IntegratorViewModel.shared))
        let win = NSWindow(contentViewController: hosting)
        win.title = "Integrator"
        win.setContentSize(NSSize(width: UiDefaults.defaultWindowWidth, height: UiDefaults.defaultWindowHeight))
        win.minSize = NSSize(width: UiDefaults.minWindowWidth, height: UiDefaults.minWindowHeight)
        win.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.isOpaque = false
        win.backgroundColor = .clear
        // Exclude dashboard window from screen recording / screen sharing to protect SPAKE2 PINs and Ed25519 keys
        win.sharingType = .none
        win.center()
        win.delegate = self
        mainWindow = win
    }

    /// Brings dashboard window to front, ensures Regular activation policy, and resumes polling.
    func showDashboard() {
        NSApp.setActivationPolicy(.regular)
        mainWindow?.makeKeyAndOrderFront(nil)
        activateIntegratorApp()
        IntegratorViewModel.shared.setPollingPaused(false)
    }

    /// Orders out dashboard window, switches to Accessory policy to avoid an orphaned Dock icon,
    /// and pauses background polling to conserve CPU/power.
    func hideDashboard() {
        mainWindow?.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
        IntegratorViewModel.shared.setPollingPaused(true)
    }

    /// Menu bar action: reveals and focuses the main dashboard window.
    @objc private func onShowDashboard() { showDashboard() }
    /// Menu bar action: triggers remote clipboard item paste via the Rust core tray handler.
    @objc private func onPasteRemote() { "paste_remote".withCString { rustCoreTrayAction($0) } }
    /// Menu bar action: toggles Extended Screen streaming, enforcing KVM mutual-exclusion confirmation if KVM is active.
    @objc private func onToggleDisplay() {
        let vm = IntegratorViewModel.shared
        let displayActive = vm.status?.display_active == true
        if !displayActive && (vm.status?.feature_flags.input_kvm == true) {
            guard vm.presentKvmDisplayConflictAlert(switchingToDisplay: true) else { return }
            vm.runAction("set_feature_flag", params: ["feature": "display", "enabled": true], refreshAfter: false) { ok in
                if ok {
                    "toggle_display".withCString { rustCoreTrayAction($0) }
                }
            }
            return
        }
        "toggle_display".withCString { rustCoreTrayAction($0) }
    }
    /// Menu bar action: shows or hides the MacBook Touch Bar hardware HUD strip.
    @objc private func onToggleTouchBar() { "toggle_touchbar".withCString { rustCoreTrayAction($0) } }
    /// Menu bar action: opens the local encrypted clipboard staging cache folder in Finder.
    @objc private func onOpenCache() { "open_cache".withCString { rustCoreTrayAction($0) } }

    /// Menu bar, App menu, and Cmd+Q entry point.
    @objc private func onQuit() {
        requestQuit()
    }

    /// Prompts the user to confirm quitting (unless "Don't ask again" was previously checked),
    /// warning that all Integrator features and background processes will stop working.
    func requestQuit() {
        if isShuttingDown || isQuitPromptOpen { return }

        if UserDefaults.standard.bool(forKey: Self.skipQuitConfirmationKey) {
            beginGracefulShutdown()
            return
        }

        isQuitPromptOpen = true
        defer { isQuitPromptOpen = false }

        activateIntegratorApp()

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Quit Integrator?"
        alert.informativeText =
            "Are you sure you want to quit Integrator?\n\n" +
            "All of Integrator's features and background processes will stop working — including KVM mouse & keyboard sharing, Universal Clipboard & Drag-and-Drop, Extended Screen, Shared Camera, Dynamic Audio Routing, Shared Storage, and Touch ID / Passkey bridging."
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = "Don't ask again"

        let quitBtn = alert.addButton(withTitle: "Quit Integrator")
        if #available(macOS 11.0, *) {
            quitBtn.hasDestructiveAction = true
        }
        let cancelBtn = alert.addButton(withTitle: "Cancel")
        cancelBtn.keyEquivalent = "\u{1b}"

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            if alert.suppressionButton?.state == .on {
                UserDefaults.standard.set(true, forKey: Self.skipQuitConfirmationKey)
            }
            beginGracefulShutdown()
        }
    }

    /// Displays a live floating shutdown progress window while tearing down every Integrator
    /// subsystem and process sequentially, then terminates the application cleanly.
    func beginGracefulShutdown() {
        if isShuttingDown { return }
        isShuttingDown = true

        IntegratorViewModel.shared.stopPolling()
        mainWindow?.orderOut(nil)

        let model = ShutdownProgressViewModel()
        let hosting = NSHostingController(rootView: ShutdownProgressView(model: model))
        let win = NSWindow(contentViewController: hosting)
        win.title = "Shutting Down Integrator"
        win.setContentSize(NSSize(width: 420, height: 310))
        win.styleMask = [.titled, .fullSizeContentView]
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.isOpaque = false
        win.backgroundColor = .clear
        win.level = .floating
        win.isReleasedWhenClosed = false
        win.center()
        shutdownWindow = win

        activateIntegratorApp()
        win.makeKeyAndOrderFront(nil)

        let orderedSteps = ["audio", "camera", "display", "storage", "kvm"]
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            for step in orderedSteps {
                // Use non-blocking main-actor dispatch to avoid deadlocking if the main thread is awaiting FFI
                DispatchQueue.main.async {
                    model.markStopping(step)
                }
                let payload = "{\"step\":\"\(step)\"}"
                "shutdown_subsystem".withCString { mPtr in
                    payload.withCString { pPtr in
                        if let raw = rustCoreInvoke(mPtr, pPtr) {
                            rustCoreFreeString(raw)
                        }
                    }
                }
                // Brief visual beat so each process teardown transition is legible
                Thread.sleep(forTimeInterval: 0.14)
                DispatchQueue.main.async {
                    model.markStopped(step)
                }
            }

            rustCoreSetUiCallback(nil)
            rustCoreShutdown()

            DispatchQueue.main.async { [weak self] in
                if let item = self?.statusItem {
                    NSStatusBar.system.removeStatusItem(item)
                    self?.statusItem = nil
                }
                model.markAllDone()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) { [weak self] in
                    self?.shutdownWindow?.orderOut(nil)
                    self?.shutdownWindow = nil
                    self?.isTerminationApproved = true
                    NSApp.terminate(nil)
                }
            }
        }
    }
}

/// Global `@MainActor`-isolated reference to the application delegate instance.
@MainActor
private var gMacAppDelegate: MacAppDelegate? = nil

/// C-convention reverse event callback registered with `integrator_core.dylib`.
///
/// Dispatches asynchronous UI notifications (show/hide window, toasts, quit commands)
/// from the background Tokio runtime onto macOS `@MainActor`.
private let swiftUiEventTrampoline: RustUiCallback = { evPtr, payloadPtr in
    let eventName = evPtr.map { String(cString: $0) } ?? ""
    // Drop high-frequency log push notifications; logs are polled on schedule
    if eventName == "log_entry" {
        return
    }
    let payloadStr = payloadPtr.map { String(cString: $0) } ?? "{}"
    Task { @MainActor in
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
            gMacAppDelegate?.beginGracefulShutdown()
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
