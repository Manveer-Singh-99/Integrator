//! # Central Application Engine & Subsystem Orchestrator (`core.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `core.rs` defines `IntegratorCore`, the central orchestrator and state machine supervisor for the
//! entire Integrator workstation continuity platform.
//!
//! It brings together all operational subsystems into a cohesive engine:
//! - **Asynchronous Runtime**: Owns and manages the dedicated Tokio multi-threaded runtime.
//! - **Peer Discovery & Route Selection**: Runs the `DiscoveryManager` to maintain low-latency peer routes.
//! - **Virtual Display Engine**: Coordinates `DisplayController` and `DisplayServer` for screen extension and mirroring.
//! - **Cross-Platform KVM & Gestures**: Integrates `KvmService` for seamless pointer, keyboard, and drag-and-drop routing.
//! - **Unified Clipboard**: Manages `ClipboardService` for bidirectional synchronization of text, images, and files.
//! - **Shared Virtual Camera**: Operates `CameraService` forwarding video frames between macOS and Windows 11.
//! - **Audio Bridging & Spatial Sound**: Controls WASAPI and CoreAudio streaming pipelines.
//! - **Hardware Telemetry & TrueTone**: Gathers GPU metrics and synchronizes display white points across machines.
//! - **Cryptographic Trust Store**: Manages SPAKE2+ PIN pairing, Ed25519 authorization, and peer blacklisting.
//! - **Native UI Gateway & In-Memory Logging**: Dispatches JSON-RPC calls from native frontends (`dispatch_json`),
//!   streams UI push events (`emit_ui_event`), and retains an in-memory ring buffer of diagnostic logs (`LOG_RING`).
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `main.rs`: Bootstraps the application via `IntegratorCore::init_global()`, checks for single-instance
//!   activation via `try_focus_existing_instance()`, and handles CLI subcommands via `run_cli_if_requested()`.
//! - `ffi.rs`: Delegates external C ABI requests (`integrator_core_invoke`, `integrator_core_tray_action`,
//!   `integrator_core_shutdown`) to the global core singleton (`GLOBAL_CORE`).
//!
//! ### Downstream Callees:
//! - Subsystems: `audio`, `autostart`, `benchmark`, `camera`, `clipboard`, `discovery`, `display`,
//!   `features`, `kvm`, `storage`, `system_info`, `telemetry`, `truetone`, `trust`.
//! - Logging Framework: Configures `tracing-subscriber` with stdout, rotating private log files (`~/.integrator.log`),
//!   and an in-memory UI ring layer (`UiRingLogLayer`).
//! - OS Firewall: Automates Windows Defender Firewall rules (`ensure_windows_firewall_rules`) on Windows hosts.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! High-level control actions (e.g., toggling screen extension, initiating pairing, syncing TrueTone calibration,
//! mounting remote file shares) flow through `dispatch_json`. When interacting with a remote peer, `core.rs`
//! serializes requests into `DisplayRpcRequest` packets and dispatches them across the authenticated control
//! channel to the peer's `DisplayServer`. Status reports are aggregated into a unified `BridgeStatus` snapshot.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Multi-Threaded Executor**: `IntegratorCore::rt` powers all asynchronous I/O and tasks.
//! - **Synchronous FFI Dispatch**: Native UI threads invoke `dispatch_json`, which blocks synchronously on the
//!   internal Tokio runtime (`rt.block_on`) to return immediate responses.
//! - **UI Callback Lifecycle Protection**: Native function pointers registered via `register_ui_callback`
//!   are protected by an atomic in-flight counter (`IN_FLIGHT_UI_CALLBACKS`). When deregistering a callback,
//!   the thread yields for up to 250ms until all in-flight callback executions complete, eliminating
//!   native code execution after unmap.
//! - **Offloading OS Blocking Calls**: Synchronous file system, process execution, and registry lookups
//!   are dispatched via `tokio::task::spawn_blocking`.
//!
//! ## 4. Security & Safety Invariants
//! - **Private Log File Permissions**: Log files on Unix systems are opened strictly with mode `0o600`.
//!   Symlinks are detected and rejected to prevent symlink-poisoning attacks.
//! - **Log Rotation**: Active log files exceeding 5 MiB (`MAX_LOG_FILE_BYTES`) are automatically rotated
//!   to `.log.1` to prevent disk filling.
//! - **Inbound Firewall Scoping**: Windows firewall rules are dynamically scoped to `LocalSubnet`,
//!   RFC 3927 link-local (`169.254.0.0/16`), active local IPv4 adapter network CIDRs, and validated
//!   user-authorized `firewall_extra_subnets`.
//! - **Mandatory Cryptographic Pairing**: Operations requiring mutual trust strictly enforce SPAKE2+
//!   PIN verification before granting access.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::audio::{self, AudioRoutingStatus};
use crate::autostart;
use crate::benchmark;
use crate::camera::{CameraService, CameraStatus};
use crate::clipboard::ClipboardService;
use crate::config;
use crate::discovery::DiscoveryManager;
use crate::display::{DisplayController, DisplayRpcRequest, DisplayServer};
use crate::features::{FeatureFlags, FeatureManager};
use crate::kvm::{KvmLayoutConfig, KvmService, KvmStatusSnapshot};
use crate::storage::{self, StorageStatus};
use crate::system_info;
use crate::telemetry;
use crate::truetone;
use crate::trust;

/// Function pointer type definition for native UI push event notifications.
///
/// Passes NUL-terminated UTF-8 C string pointers for `event_name` and `payload_json`.
pub type UiEventCallback = extern "C" fn(event_name: *const c_char, payload_json: *const c_char);

/// Maximum number of log entries retained in the in-memory UI diagnostic ring buffer.
const LOG_RING_CAPACITY: usize = 200;

/// Maximum duration to wait for in-flight native UI callbacks to drain during deregistration.
const UI_CALLBACK_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Sleep interval while polling in-flight native UI callbacks during deregistration.
const UI_CALLBACK_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// TCP connect timeout when probing loopback to detect an existing Integrator instance.
const SINGLE_INSTANCE_PROBE_TIMEOUT: Duration = Duration::from_millis(150);

/// Canonical IPv4 loopback address string for local CLI-to-daemon RPC invocations.
const LOOPBACK_IPV4: &str = "127.0.0.1";

/// macOS System Settings deep link opening the Privacy & Security Accessibility pane.
#[cfg(target_os = "macos")]
const MACOS_ACCESSIBILITY_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

/// Windows process creation flag suppressing visible console window creation.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Windows Defender Firewall rule name for core Integrator TCP services.
#[cfg(target_os = "windows")]
const WIN_FW_RULE_CORE_TCP: &str = "Integrator Core (TCP)";

/// Windows Defender Firewall rule name for core Integrator UDP services.
#[cfg(target_os = "windows")]
const WIN_FW_RULE_CORE_UDP: &str = "Integrator Core (UDP)";

/// Windows Defender Firewall rule name for inbound SMB file sharing.
#[cfg(target_os = "windows")]
const WIN_FW_RULE_SMB_TCP: &str = "Integrator SMB File Sharing (TCP)";

/// Windows Defender Firewall symbolic scope keyword permitting local on-link subnet peers.
#[cfg(any(target_os = "windows", test))]
const FIREWALL_SCOPE_LOCAL_SUBNET: &str = "LocalSubnet";

/// Global singleton container holding the active `IntegratorCore` engine instance.
pub static GLOBAL_CORE: OnceLock<Arc<IntegratorCore>> = OnceLock::new();

/// Global function pointer slot for native UI callback bridge.
static UI_EVENT_CALLBACK: Mutex<Option<UiEventCallback>> = Mutex::new(None);

/// Atomic counter tracking the number of active callback invocations currently executing inside native UI code.
static IN_FLIGHT_UI_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

/// In-memory ring buffer storing the most recent [`LOG_RING_CAPACITY`] formatted log entries for UI diagnostics views.
static LOG_RING: Mutex<Option<VecDeque<LogEntry>>> = Mutex::new(None);

#[cfg(target_os = "macos")]
extern "C" {
    /// Configures the TCP control RPC port used by the macOS Touch Bar HUD prior to initialization.
    fn set_touchbar_rpc_port_in_app(port: u16);
    /// Native macOS Objective-C/Swift Touch Bar initialization entry point.
    fn init_touchbar_in_app(peer_ip: *const c_char);
    /// Native macOS Touch Bar dismissal entry point.
    fn dismiss_touchbar_in_app();
    /// Checks whether the macOS Touch Bar HUD is currently visible.
    fn is_touchbar_active_in_app() -> bool;
    /// Installs or removes the persistent `∫` Control Strip system tray button on Touch Bar Macs.
    fn set_touchbar_tray_enabled_in_app(enabled: bool);
    /// CLI loop driving the Touch Bar interface standalone.
    fn run_touchbar_cli_loop(peer_ip: *const c_char);
    /// Illuminates or dismisses the far-right animated Touch ID sensor prompt on the Touch Bar.
    fn notify_touchbar_touchid_prompt_in_app(label: *const c_char, active: bool);
    /// Updates the illuminated green/red Camera Privacy Killswitch pill on the Touch Bar.
    fn notify_touchbar_camera_state_in_app(active: bool, muted: bool);
    /// Updates the KVM Gaming Boundary Lock toggle pill on the Touch Bar.
    fn notify_touchbar_kvm_lock_state_in_app(locked: bool);
    /// Updates the Display Mode Quick-Slider pill state on the Touch Bar.
    fn notify_touchbar_display_mode_in_app(width: u32, height: u32, fps: u32, hdr: bool);
}

/// Illuminates or dismisses the visual Touch ID passkey/UAC prompt strip on the macOS Touch Bar.
pub fn notify_touchbar_touchid_prompt(label: &str, active: bool) {
    #[cfg(target_os = "macos")]
    {
        if let Ok(c_lbl) = CString::new(label) {
            unsafe { notify_touchbar_touchid_prompt_in_app(c_lbl.as_ptr(), active) };
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (label, active);
    }
}

/// Synchronizes the macOS Touch Bar Hardware Camera Privacy Killswitch pill with live camera state.
pub fn notify_touchbar_camera_state(active: bool, muted: bool) {
    #[cfg(target_os = "macos")]
    {
        unsafe { notify_touchbar_camera_state_in_app(active, muted) };
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (active, muted);
    }
}

/// Synchronizes the macOS Touch Bar KVM Gaming Boundary Lock toggle with live KVM state.
pub fn notify_touchbar_kvm_lock_state(locked: bool) {
    #[cfg(target_os = "macos")]
    {
        unsafe { notify_touchbar_kvm_lock_state_in_app(locked) };
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = locked;
    }
}

/// Synchronizes the macOS Touch Bar Display Mode Quick-Slider state with live display settings.
pub fn notify_touchbar_display_mode(width: u32, height: u32, fps: u32, hdr: bool) {
    #[cfg(target_os = "macos")]
    {
        unsafe { notify_touchbar_display_mode_in_app(width, height, fps, hdr) };
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (width, height, fps, hdr);
    }
}

/// C-ABI entry point invoked by `touchbar_hud.swift` when the user scrubs refresh rate or toggles resolution/HDR.
#[no_mangle]
pub extern "C" fn set_rust_display_mode(width: u32, height: u32, fps: u32, hdr: bool) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(core) = GLOBAL_CORE.get() else {
            return false;
        };
        let core_ref = Arc::clone(core);
        core.rt.spawn(async move {
            match core_ref.display_ctrl.set_display_mode(width, height, fps, hdr).await {
                Ok(msg) => emit_ui_toast("info", &msg),
                Err(e) => emit_ui_toast("error", &format!("Display mode error: {}", e)),
            }
        });
        true
    }))
    .unwrap_or(false)
}

/// C-ABI entry point invoked by `touchbar_hud.swift` when tapping the Hardware Camera Privacy Killswitch pill.
#[no_mangle]
pub extern "C" fn toggle_rust_camera_privacy_mute() -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Some(core) = GLOBAL_CORE.get() {
            let muted = core.camera.toggle_privacy_muted();
            emit_ui_toast(
                if muted { "warning" } else { "success" },
                if muted {
                    "Camera privacy shutter engaged (feeding black NV12 frames to PC)"
                } else {
                    "Camera privacy shutter released (live FaceTime HD restored)"
                },
            );
            muted
        } else {
            crate::camera::set_camera_privacy_muted(!crate::camera::is_camera_privacy_muted())
        }
    }))
    .unwrap_or(false)
}

/// C-ABI entry point invoked by `touchbar_hud.swift` when scrubbing the Cross-Platform Audio Mixer slider or tapping mute.
#[no_mangle]
pub extern "C" fn set_rust_audio_mixer(balance: f32, muted: bool) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = audio::AudioManager::set_mixer(balance, muted);
    }));
}

/// C-ABI entry point invoked by `touchbar_hud.swift` when tapping the KVM Gaming Boundary Lock toggle.
#[no_mangle]
pub extern "C" fn toggle_rust_kvm_boundary_lock() -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(core) = GLOBAL_CORE.get() else {
            return false;
        };
        let locked = core.kvm.toggle_boundary_locked();
        let core_ref = Arc::clone(core);
        core.rt.spawn(async move {
            if let Some(peer_ip) = core_ref.discovery.get_peer_ip().await {
                let _ = DisplayController::send_remote_rpc(
                    &peer_ip,
                    &DisplayRpcRequest::SetKvmBoundaryLock { locked },
                )
                .await;
            }
        });
        emit_ui_toast(
            "info",
            if locked {
                "KVM Cursor Boundary LOCKED (gaming mode)"
            } else {
                "KVM Cursor Boundary UNLOCKED"
            },
        );
        locked
    }))
    .unwrap_or(false)
}

/// C-ABI entry point invoked by `touchbar_hud.swift` to control Windows Spotify/YouTube/VLC media playback.
///
/// `cmd_code`: `0 = PlayPause`, `1 = Next`, `2 = Previous`, `3 = Seek(seek_secs)`.
#[no_mangle]
pub extern "C" fn send_rust_windows_media_cmd(cmd_code: i32, seek_secs: f64) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(core) = GLOBAL_CORE.get() else {
            return false;
        };
        let action = match cmd_code {
            0 => crate::media::MediaControlAction::PlayPause,
            1 => crate::media::MediaControlAction::Next,
            2 => crate::media::MediaControlAction::Previous,
            3 => crate::media::MediaControlAction::Seek {
                position_secs: if seek_secs.is_finite() { seek_secs.max(0.0) } else { 0.0 },
            },
            _ => return false,
        };
        let core_ref = Arc::clone(core);
        core.rt.spawn(async move {
            if let Some(peer_ip) = core_ref.discovery.get_peer_ip().await {
                let _ = DisplayController::send_remote_rpc(
                    &peer_ip,
                    &DisplayRpcRequest::SendMediaCommand { action },
                )
                .await;
            }
        });
        true
    }))
    .unwrap_or(false)
}

/// Aggregated live snapshot polled by `touchbar_hud.swift` over a single C-ABI round-trip.
#[derive(Serialize)]
struct TouchBarLiveSnapshot {
    gpu_telemetry: Option<telemetry::GpuTelemetry>,
    media_state: Option<crate::media::MediaPlaybackState>,
    camera_active: bool,
    camera_muted: bool,
    kvm_locked: bool,
    audio_balance: f32,
    audio_muted: bool,
    display_active: bool,
    display_width: u32,
    display_height: u32,
    display_fps: u32,
    display_hdr: bool,
}

/// C-ABI entry point polled by `touchbar_hud.swift` to fetch synchronized GPU telemetry,
/// Windows GSMTC media state, camera privacy state, KVM boundary lock, audio mixer, and display mode.
#[no_mangle]
pub extern "C" fn fetch_rust_touchbar_snapshot_json(
    peer_ip_ptr: *const c_char,
    out_buf: *mut u8,
    cap: usize,
) -> usize {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out_buf.is_null() || cap < 2 {
            return 0;
        }
        let hinted_ip = if !peer_ip_ptr.is_null() {
            let s = unsafe { CStr::from_ptr(peer_ip_ptr) }
                .to_string_lossy()
                .trim()
                .to_string();
            if !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok() {
                Some(s)
            } else {
                None
            }
        } else {
            None
        };

        let fetch_future = async move {
            let core_opt = GLOBAL_CORE.get().cloned();
            let peer_ip = if let Some(ip) = hinted_ip {
                Some(ip)
            } else if let Some(ref c) = core_opt {
                c.discovery.get_peer_ip().await
            } else {
                None
            };

            let (gpu_telemetry, media_state) = if let Some(ref ip) = peer_ip {
                let (gpu_res, media_res) = tokio::join!(
                    DisplayController::send_remote_rpc(ip, &DisplayRpcRequest::GetGpuTelemetry),
                    DisplayController::send_remote_rpc(ip, &DisplayRpcRequest::GetMediaState),
                );
                (
                    gpu_res.ok().and_then(|r| r.gpu_telemetry),
                    media_res.ok().and_then(|r| r.media_state),
                )
            } else {
                (None, None)
            };

            let (camera_active, kvm_locked, display_active, disp_ov) = if let Some(ref c) = core_opt {
                (
                    c.camera.status().active,
                    c.kvm.is_boundary_locked(),
                    c.display_ctrl.is_active().await,
                    c.display_ctrl.get_preferred_mode().await,
                )
            } else {
                (false, false, false, None)
            };

            TouchBarLiveSnapshot {
                gpu_telemetry,
                media_state,
                camera_active,
                camera_muted: crate::camera::is_camera_privacy_muted(),
                kvm_locked,
                audio_balance: audio::AudioManager::mixer_balance(),
                audio_muted: audio::AudioManager::is_sink_muted(),
                display_active,
                display_width: disp_ov.map(|m| m.width).unwrap_or(0),
                display_height: disp_ov.map(|m| m.height).unwrap_or(0),
                display_fps: disp_ov.map(|m| m.fps).unwrap_or(120),
                display_hdr: disp_ov.map(|m| m.hdr).unwrap_or(false),
            }
        };

        let snap = if let Some(core) = GLOBAL_CORE.get() {
            if tokio::runtime::Handle::try_current().is_ok() {
                let h = core.rt.handle().clone();
                let Ok(s) = std::thread::spawn(move || h.block_on(fetch_future)).join() else {
                    return 0;
                };
                s
            } else {
                core.rt.block_on(fetch_future)
            }
        } else if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            rt.block_on(fetch_future)
        } else {
            return 0;
        };

        let Ok(bytes) = serde_json::to_vec(&snap) else {
            return 0;
        };
        if bytes.is_empty() || bytes.len() >= cap {
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
            *out_buf.add(bytes.len()) = 0;
        }
        bytes.len()
    }))
    .unwrap_or(0)
}

/// Structured record representing an individual log event stored in the UI ring buffer.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// POSIX timestamp in milliseconds when the event was recorded.
    pub ts_ms: u64,
    /// Tracing severity level string (`"INFO"`, `"WARN"`, `"ERROR"`, `"DEBUG"`).
    pub level: String,
    /// Formatted log message text, including appended tracing fields.
    pub message: String,
}

/// Physical pixel dimensions and refresh rate characterizing a display output.
#[derive(Debug, Clone, Serialize)]
pub struct DisplayGeometry {
    /// Horizontal resolution in physical pixels.
    pub width: u32,
    /// Vertical resolution in physical pixels.
    pub height: u32,
    /// Frame refresh rate in Hertz (FPS).
    pub fps: u32,
}

/// Detailed metadata snapshot for a remote peer discovered on the local network.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPeerInfo {
    /// Unique 32-character hexadecimal identifier derived from the peer's Ed25519 public key.
    pub device_id: String,
    /// Machine hostname.
    pub hostname: String,
    /// Operating system platform name (`"macos"`, `"windows"`).
    pub os: String,
    /// Hardware product model name.
    pub hardware_model: String,
    /// Detected chassis form factor (`"laptop"`, `"desktop"`, or `"unknown"`).
    #[serde(default)]
    pub form_factor: String,
    /// Resolved IP address string.
    pub ip: String,
    /// Local network interface IP used to reach this peer.
    pub local_ip_used: Option<String>,
    /// Human-readable transport medium label (`"Thunderbolt"`, `"Direct USB-C"`, `"Ethernet"`, `"Wi-Fi"`).
    pub transport_label: String,
    /// Indicates whether the physical connection is a direct point-to-point bridge cable.
    pub is_direct_cable: bool,
    /// Estimated link physical throughput in Megabits per second.
    pub link_speed_mbps: Option<u32>,
    /// Human-readable network route description.
    pub link_description: String,
    /// Measured TCP round-trip latency in milliseconds.
    pub rtt_ms: Option<f64>,
    /// Primary display resolution and refresh rate of remote machine.
    pub display: DisplayGeometry,
    /// List of GPU adapter model names installed on remote machine.
    pub gpus: Vec<String>,
    /// Optional SMB share name advertised by remote peer.
    pub share_name: Option<String>,
    /// Cryptographic pairing status: `true` if peer's public key is in local trust store.
    pub trusted: bool,
    /// Blacklist status: `true` if peer has been explicitly blocked.
    pub blocked: bool,
    /// Discovery transport(s) that reported this peer (`"udp"`, `"bonjour"`, `"ble"`, or combined).
    #[serde(default)]
    pub discovery_source: String,
}

/// Complete snapshot of cryptographic pairing state and authorization policies.
#[derive(Debug, Clone, Serialize)]
pub struct TrustSnapshotInfo {
    /// Currently active 6-digit numeric pairing PIN.
    pub pairing_pin: String,
    /// Policy flag: whether direct bridge cables are automatically trusted without PIN entry.
    pub auto_trust_direct_cable: bool,
    /// Policy flag: whether LAN peers strictly require PIN pairing.
    pub require_pairing_on_lan: bool,
    /// List of unconfirmed peer pairing connection requests awaiting user approval.
    pub pending_peers: Vec<trust::PendingPeerInfo>,
    /// List of authorized paired peers stored in the keystore.
    pub trusted_peers: Vec<trust::TrustedPeerRecord>,
    /// List of explicitly blocked remote device ID hex strings.
    pub blocked_device_ids: Vec<String>,
}

/// Top-level comprehensive health and connectivity state structure sent to native UI views.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeStatus {
    // Local Machine Identity & Hardware
    /// Unique device ID hex string of the local machine.
    pub device_id: String,
    /// Local machine hostname.
    pub hostname: String,
    /// Local operating system platform string (`"macos"`, `"windows"`).
    pub os: String,
    /// Local operating system identifier.
    pub local_os: String,
    /// Local hardware model name (e.g. `"MacBookPro18,1"`, `"Mac14,12"`, or motherboard model).
    pub hardware_model: String,
    /// Local hardware chassis form factor (`"laptop"`, `"desktop"`, or `"unknown"`).
    #[serde(default)]
    pub form_factor: String,
    /// Local CPU processor brand string.
    pub cpu_brand: String,
    /// Local primary display geometry and color depth.
    pub primary_display: system_info::PrimaryDisplayInfo,
    /// Local GPU adapters detected.
    pub local_gpus: Vec<system_info::GpuDeviceInfo>,
    /// Published SMB share names on local machine.
    pub local_share_names: Vec<String>,
    /// Indicates whether physical Touch Bar hardware is present on this machine.
    pub has_touch_bar: bool,

    // Active Remote Peer & Link Route
    /// `true` if an active peer candidate is currently elected.
    pub peer_connected: bool,
    /// `true` if the active peer is cryptographically verified and trusted.
    pub peer_trusted: bool,
    /// Unique device ID of active peer.
    pub peer_device_id: Option<String>,
    /// Target IP address string of active peer.
    pub peer_ip: Option<String>,
    /// Operating system of active peer.
    pub peer_os: Option<String>,
    /// Computer hostname of active peer.
    pub peer_name: Option<String>,
    /// Hardware product model of active peer.
    pub peer_hardware_model: Option<String>,
    /// Hardware chassis form factor of active peer (`"laptop"`, `"desktop"`, or `"unknown"`).
    #[serde(default)]
    pub peer_form_factor: Option<String>,
    /// Display geometry of active peer.
    pub peer_display: Option<DisplayGeometry>,
    /// GPU adapters of active peer.
    pub peer_gpus: Vec<String>,
    /// Published SMB share name of active peer.
    pub peer_share_name: Option<String>,
    /// Local interface IP communicating with active peer.
    pub peer_local_ip_used: Option<String>,
    /// Label of active transport route (`"Thunderbolt"`, `"Ethernet"`, `"Wi-Fi"`).
    pub transport_label: String,
    /// `true` if active link is a point-to-point direct cable.
    pub is_direct_cable: bool,
    /// Link throughput speed in Mbps.
    pub link_speed_mbps: Option<u32>,
    /// Route adapter description.
    pub link_description: String,
    /// Measured round-trip connection latency in ms.
    pub rtt_ms: Option<f64>,
    /// Formatted link speed string (e.g. `"20 Gbps"` or `"1000 Mbps"`).
    pub link_speed: String,
    /// Transport medium type string.
    pub link_type: String,

    // Display Acceleration & Encoding
    /// `true` if virtual display extension or mirroring is actively streaming.
    pub display_active: bool,
    /// Active display streaming mode (`"mac_to_pc"`, `"pc_to_mac"`, or `None`).
    pub active_mode: Option<String>,
    /// Platform indicator: `true` if local host is running Windows.
    pub is_windows_master: bool,
    /// Selected hardware GPU encoder adapter on Windows (`"auto"`, `"nvidia"`, `"amd"`, `"intel"`).
    pub encode_gpu: String,
    /// Selected hardware GPU decoder adapter on Windows.
    pub decode_gpu: String,
    /// Indicates whether hardware GPU selection controls are supported.
    pub gpu_controls_supported: bool,
    /// Indicates whether Touch Bar remote HUD is actively presented.
    pub touchbar_active: bool,

    // Ambient Lighting & TrueTone
    /// `true` if ambient light sensor hardware is supported.
    pub ambient_supported: bool,
    /// Measured ambient illuminance in Lux.
    pub ambient_lux: Option<f32>,
    /// Correlated Color Temperature in Kelvin.
    pub ambient_cct: Option<u32>,

    // Shared Storage Status
    /// `true` if remote SMB file share is mounted locally.
    pub storage_mounted: bool,
    /// Storage mount path and connection status details.
    pub storage_status: StorageStatus,
    /// User-preferred peer SMB share name.
    pub preferred_peer_share: Option<String>,
    /// User-configured local folder path being shared to peer.
    pub local_shared_folder: Option<String>,
    /// `true` if SMB share is configured to mount automatically on peer detection.
    #[serde(default)]
    pub auto_mount_storage: bool,

    // Audio Routing Status
    /// Active audio sink/source capture and playback routing states.
    pub audio_status: AudioRoutingStatus,

    // Virtual Camera Status
    /// Virtual webcam capture and forwarding status.
    pub camera_status: CameraStatus,

    // Capability Master Switches & KVM
    /// Current feature toggle flags.
    pub feature_flags: FeatureFlags,
    /// Low-latency keyboard, mouse, and gesture router status snapshot.
    pub kvm: KvmStatusSnapshot,

    // Network Interfaces & Cryptographic Trust
    /// All active physical and virtual local network interface endpoints.
    pub local_interfaces: Vec<system_info::LocalInterfaceInfo>,
    /// User-configured manual peer unicast target IPs.
    pub manual_peer_ips: Vec<String>,
    /// All discovered peers on the network.
    pub discovered_peers: Vec<DiscoveredPeerInfo>,
    /// Active discovery mode (`"all"`, `"udp_only"`, `"bonjour_only"`, `"ble_only"`).
    #[serde(default)]
    pub discovery_mode: String,
    /// `true` when standard Bonjour / mDNS (`_integrator._tcp.local.`) is actively running.
    #[serde(default)]
    pub bonjour_active: bool,
    /// `true` when Bluetooth LE magic-packet proximity discovery is actively running.
    #[serde(default)]
    pub ble_active: bool,
    /// Keystore pairing PIN and trusted peer list.
    pub trust: TrustSnapshotInfo,

    // Autostart, Setup Health & Diagnostic Logs
    /// `true` if OS login autostart is registered.
    pub autostart_enabled: bool,
    /// Cross-platform OS permissions and companion dependencies setup health snapshot.
    #[serde(default)]
    pub setup_status: crate::setup::SetupHealthSnapshot,
    /// Recent diagnostic log lines from the in-memory ring buffer.
    pub recent_logs: Vec<LogEntry>,
}

/// Central application orchestrator managing lifecycle, state machines, and native UI dispatch.
pub struct IntegratorCore {
    /// Dedicated multi-threaded Tokio runtime driving all asynchronous tasks.
    pub rt: tokio::runtime::Runtime,
    /// Zero-configuration peer beacon broadcaster and listener manager.
    pub discovery: DiscoveryManager,
    /// Screen capture, stream encoding, and display RPC client controller.
    pub display_ctrl: DisplayController,
    /// Bidirectional synchronized clipboard engine.
    pub clipboard: ClipboardService,
    /// Master feature switches and capability persistence manager.
    pub features: Arc<FeatureManager>,
    /// Low-latency universal input routing service.
    pub kvm: Arc<KvmService>,
    /// Virtual webcam capture and frame forwarding service.
    pub camera: Arc<CameraService>,
}

/// Helper visitor extracting message strings and key-value fields from `tracing::Event`.
#[derive(Default)]
struct LogVisitor {
    msg: String,
    fields: Vec<String>,
}

impl LogVisitor {
    /// Formats extracted fields into a single human-readable log string.
    fn into_message(self) -> String {
        if self.fields.is_empty() {
            self.msg
        } else if self.msg.is_empty() {
            self.fields.join(", ")
        } else {
            format!("{} [{}]", self.msg, self.fields.join(", "))
        }
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let mut rendered = format!("{:?}", value);
        if rendered.starts_with('"') && rendered.ends_with('"') && rendered.len() >= 2 {
            rendered = rendered[1..rendered.len() - 1].to_string();
        }
        if field.name() == "message" {
            self.msg = rendered;
        } else {
            self.fields.push(format!("{}={}", field.name(), rendered));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.msg = value.to_string();
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }
}

/// Tracing subscriber layer storing formatted events into `LOG_RING` and emitting UI events.
struct UiRingLogLayer;

impl<S: tracing::Subscriber> Layer<S> for UiRingLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut vis = LogVisitor::default();
        event.record(&mut vis);
        let formatted_msg = vis.into_message();
        if formatted_msg.is_empty() {
            return;
        }
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let entry = LogEntry {
            ts_ms,
            level: event.metadata().level().to_string(),
            message: formatted_msg,
        };

        // Append to in-memory bounded ring buffer
        if let Ok(mut guard) = LOG_RING.lock() {
            let deque = guard.get_or_insert_with(|| VecDeque::with_capacity(LOG_RING_CAPACITY));
            if deque.len() >= LOG_RING_CAPACITY {
                deque.pop_front();
            }
            deque.push_back(entry.clone());
        }

        // Push real-time event to native UI callback
        if let Ok(json) = serde_json::to_string(&entry) {
            emit_ui_event("log_entry", &json);
        }
    }
}

/// RAII guard decrementing `IN_FLIGHT_UI_CALLBACKS` upon completion of a native UI callback execution.
struct InFlightCallbackGuard;

impl Drop for InFlightCallbackGuard {
    fn drop(&mut self) {
        IN_FLIGHT_UI_CALLBACKS.fetch_sub(1, Ordering::Release);
    }
}

/// Registers or deregisters the native UI event callback function pointer.
///
/// When passing `None` to deregister, blocks for up to 250ms until all currently executing
/// in-flight native callback frames finish, preventing use-after-free in unloaded UI modules.
pub fn register_ui_callback(cb: Option<UiEventCallback>) {
    if let Ok(mut guard) = UI_EVENT_CALLBACK.lock() {
        *guard = cb;
    }
    if cb.is_none() {
        let deadline = std::time::Instant::now() + UI_CALLBACK_DRAIN_TIMEOUT;
        while IN_FLIGHT_UI_CALLBACKS.load(Ordering::Acquire) > 0
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
            std::thread::sleep(UI_CALLBACK_DRAIN_POLL_INTERVAL);
        }
    }
}

/// Pushes an asynchronous event notification across the FFI boundary to the native UI frontend.
///
/// Converts Rust string slices to C-style NUL-terminated strings and increments the in-flight guard.
pub fn emit_ui_event(event_name: &str, payload_json: &str) {
    let Ok(ev) = CString::new(event_name) else { return };
    let Ok(pl) = CString::new(payload_json) else { return };
    let (cb, _guard) = {
        let Ok(guard) = UI_EVENT_CALLBACK.lock() else {
            return;
        };
        let Some(cb) = *guard else {
            return;
        };
        IN_FLIGHT_UI_CALLBACKS.fetch_add(1, Ordering::AcqRel);
        (cb, InFlightCallbackGuard)
    };
    cb(ev.as_ptr(), pl.as_ptr());
}

/// Helper emitting an in-app banner toast notification to the native UI.
///
/// # Arguments
/// * `kind` - Notification style (`"info"`, `"success"`, `"error"`, `"warning"`).
/// * `message` - Banner text to display.
pub fn emit_ui_toast(kind: &str, message: &str) {
    let payload = serde_json::json!({ "kind": kind, "message": message }).to_string();
    emit_ui_event("toast", &payload);
}

/// Signals the native UI layer to bring the main application window to the foreground.
pub fn request_show_window() {
    emit_ui_event("show_window", "{}");
}

/// Returns a cloned snapshot of all log entries currently stored in `LOG_RING`.
pub fn get_recent_logs() -> Vec<LogEntry> {
    if let Ok(guard) = LOG_RING.lock() {
        if let Some(deque) = guard.as_ref() {
            return deque.iter().cloned().collect();
        }
    }
    Vec::new()
}

/// Spawns an external operating system process and detaches a background thread to reap its exit status.
///
/// Prevents zombie process accumulation.
fn spawn_and_reap(mut cmd: std::process::Command) {
    if let Ok(mut child) = cmd.spawn() {
        let _ = std::thread::Builder::new()
            .name("process-reaper".to_string())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

/// Opens the user's persistent application data folder in the native file manager (Finder or Explorer).
pub fn open_app_data_folder() {
    let cache_dir = system_info::app_data_dir();
    let _ = std::fs::create_dir_all(&cache_dir);

    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new(config::MACOS_OPEN_BIN);
        cmd.arg(&cache_dir);
        spawn_and_reap(cmd);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let explorer = system_info::windows_root_dir().join("explorer.exe");
        let mut cmd = std::process::Command::new(explorer);
        cmd.arg(&cache_dir).creation_flags(CREATE_NO_WINDOW);
        spawn_and_reap(cmd);
    }
}

/// Formats a measured benchmark bandwidth into human-readable Gbps or Mbps text.
fn format_measured_speed(max_gbps: f64) -> String {
    if max_gbps >= 1.0 {
        format!("{:.2} Gbps", max_gbps)
    } else {
        format!("{:.0} Mbps", (max_gbps * 1000.0).round())
    }
}

/// Formats physical interface link speed in Mbps into formatted Gbps/Mbps string.
fn format_link_speed(speed_mbps: Option<u32>, connected: bool) -> String {
    match speed_mbps {
        Some(mbps) if mbps >= 1000 => {
            if mbps % 1000 == 0 {
                format!("{} Gbps", mbps / 1000)
            } else {
                format!("{:.1} Gbps", mbps as f64 / 1000.0)
            }
        }
        Some(mbps) => format!("{} Mbps", mbps),
        None if connected => "Link Active".to_string(),
        None => "--".to_string(),
    }
}

/// Detects whether an active Integrator instance is already running locally.
///
/// Probes `127.0.0.1:CONTROL_PORT`. If connection succeeds, sends `ShowWindow` RPC to bring the
/// active window forward and returns `true`.
pub fn try_focus_existing_instance() -> bool {
    if let Ok(stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, config::CONTROL_PORT)),
        SINGLE_INSTANCE_PROBE_TIMEOUT,
    ) {
        drop(stream);
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let _ = rt.block_on(DisplayController::send_remote_rpc(
                LOOPBACK_IPV4,
                &DisplayRpcRequest::ShowWindow,
            ));
        }
        return true;
    }
    false
}

/// Parses and executes CLI subcommands passed into the process without launching the full GUI.
///
/// Supported subcommands: `paste-remote`, `benchmark <ip>`, `telemetry <ip>`, `touchbar <ip>`,
/// `display [toggle|stop|status]`, `pin`, `pair <ip> <pin>`, `status`, `camera [toggle|start|stop|status]`.
pub fn run_cli_if_requested(args: &[String]) -> Option<Result<()>> {
    if args.len() <= 1 {
        return None;
    }
    match args[1].as_str() {
        "paste-remote" | "--paste-remote" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match DisplayController::send_remote_rpc(
                    LOOPBACK_IPV4,
                    &DisplayRpcRequest::PasteRemote,
                )
                .await
                {
                    Ok(resp) => {
                        println!("{}", resp.message);
                        if !resp.success {
                            anyhow::bail!("Remote paste failed: {}", resp.message);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "Failed to connect to Integrator daemon: {}. Is Integrator running?",
                            e
                        );
                    }
                }
            })
        })()),
        "benchmark" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let Some(target_ip) = args
                    .get(2)
                    .map(|s| s.as_str())
                    .filter(|s| !s.trim().is_empty())
                else {
                    anyhow::bail!("Missing target peer IP. Usage: integrator benchmark <peer_ip>");
                };
                let features = FeatureManager::new();
                let res = benchmark::BenchmarkClient::run_test(target_ip, &features).await?;
                println!(
                    "Max Bandwidth: {:.2} Gbps | Upload: {:.2} Gbps | Download: {:.2} Gbps | RTT: {:.2} ms",
                    res.max_gbps, res.upload_gbps, res.download_gbps, res.latency_ms
                );
                println!("{}", res.summary);
                Ok(())
            })
        })()),
        "telemetry" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let Some(target_ip) = args
                    .get(2)
                    .map(|s| s.as_str())
                    .filter(|s| !s.trim().is_empty())
                else {
                    anyhow::bail!("Missing target peer IP. Usage: integrator telemetry <peer_ip>");
                };
                let resp = DisplayController::send_remote_rpc(
                    target_ip,
                    &DisplayRpcRequest::GetGpuTelemetry,
                )
                .await?;
                if let Some(t) = resp.gpu_telemetry {
                    println!(
                        "{} | Temp: {}°C | Power: {:.1}W | Clock: {}MHz | VRAM: {}/{} MB ({}%) | Util: {}%",
                        t.gpu_name,
                        t.temperature_c,
                        t.power_usage_watts,
                        t.core_clock_mhz,
                        t.memory_used_mb,
                        t.memory_total_mb,
                        t.memory_utilization_percent,
                        t.gpu_utilization_percent
                    );
                } else {
                    println!("{}", resp.message);
                }
                Ok(())
            })
        })()),
        "touchbar" => Some((|| {
            #[cfg(target_os = "macos")]
            {
                if !system_info::has_touch_bar_hardware() {
                    anyhow::bail!("No Touch Bar hardware detected on this Mac.");
                }
                let Some(peer_ip) = args
                    .get(2)
                    .map(|s| s.as_str())
                    .filter(|s| !s.trim().is_empty())
                else {
                    anyhow::bail!("Usage: integrator touchbar <peer_ip>");
                };
                let c_ip = CString::new(peer_ip)?;
                unsafe {
                    set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                    run_touchbar_cli_loop(c_ip.as_ptr());
                }
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("Touch Bar is only available on macOS");
                Ok(())
            }
        })()),
        "display" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("toggle");
                let req = match subcmd {
                    "toggle" | "toggle-mac-to-pc" => DisplayRpcRequest::ToggleMacToPc,
                    "toggle-pc-to-mac" => DisplayRpcRequest::TogglePcToMac,
                    "stop" | "stop-all" => DisplayRpcRequest::StopAll,
                    "status" => DisplayRpcRequest::GetStatus,
                    _ => anyhow::bail!("Unknown display subcommand: {}", subcmd),
                };
                let resp = DisplayController::send_remote_rpc(LOOPBACK_IPV4, &req).await?;
                println!("{}", resp.message);
                if !resp.success {
                    anyhow::bail!("Display command failed: {}", resp.message);
                }
                Ok(())
            })
        })()),
        "pin" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let resp = DisplayController::send_remote_rpc(
                    LOOPBACK_IPV4,
                    &DisplayRpcRequest::GetPairingPin,
                )
                .await?;
                println!("{}", resp.pairing_token.unwrap_or(resp.message));
                Ok(())
            })
        })()),
        "pair" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let Some(ip) = args
                    .get(2)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                else {
                    anyhow::bail!("Usage: integrator pair <peer_ip> <6_digit_pin>");
                };
                let Some(pin) = args
                    .get(3)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                else {
                    anyhow::bail!("Usage: integrator pair <peer_ip> <6_digit_pin>");
                };
                let resp = DisplayController::send_remote_rpc(
                    LOOPBACK_IPV4,
                    &DisplayRpcRequest::PairWithPeer { ip, pin },
                )
                .await?;
                println!("{}", resp.message);
                if !resp.success {
                    anyhow::bail!("Failed to pair: {}", resp.message);
                }
                Ok(())
            })
        })()),
        "status" | "bridge-status" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let resp = DisplayController::send_remote_rpc(
                    LOOPBACK_IPV4,
                    &DisplayRpcRequest::GetBridgeStatus,
                )
                .await?;
                if let Some(s) = resp.bridge_status {
                    println!("{}", serde_json::to_string_pretty(&s)?);
                } else {
                    println!("{}", resp.message);
                }
                Ok(())
            })
        })()),
        "camera" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("status");
                let req = match subcmd {
                    "toggle" => DisplayRpcRequest::ToggleCamera,
                    "start" => DisplayRpcRequest::StartCamera,
                    "stop" => DisplayRpcRequest::StopCamera,
                    "status" => DisplayRpcRequest::GetCameraStatus,
                    _ => anyhow::bail!("Unknown camera subcommand: {}. Use toggle, start, stop, or status.", subcmd),
                };
                let resp = DisplayController::send_remote_rpc(LOOPBACK_IPV4, &req).await?;
                println!("{}", resp.message);
                if let Some(cs) = resp.camera_status {
                    println!("{}", serde_json::to_string_pretty(&cs)?);
                }
                if !resp.success {
                    anyhow::bail!("Camera command failed: {}", resp.message);
                }
                Ok(())
            })
        })()),
        "setup" => Some((|| {
            let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match subcmd {
                "status" | "table" => {
                    crate::setup::invalidate_setup_cache();
                    let snap = crate::setup::collect_setup_health_snapshot(false, false);
                    print!("{}", crate::setup::format_setup_cli_table(&snap));
                    Ok(())
                }
                "json" | "--json" => {
                    crate::setup::invalidate_setup_cache();
                    let snap = crate::setup::collect_setup_health_snapshot(false, false);
                    println!("{}", serde_json::to_string_pretty(&snap)?);
                    Ok(())
                }
                _ => anyhow::bail!(
                    "Unknown setup subcommand: {}. Use `integrator setup` or `integrator setup status`.",
                    subcmd
                ),
            }
        })()),
        "discovery" => Some((|| {
            let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match subcmd {
                "status" => {
                    let mode = crate::discovery::DiscoveryMode::from_env();
                    let status = serde_json::json!({
                        "discovery_mode": mode.as_str(),
                        "bonjour_service_type": config::BONJOUR_SERVICE_TYPE,
                        "ble_service_uuid": config::BLE_SERVICE_UUID,
                        "ble_manufacturer_company_id": format!("0x{:04X}", config::BLE_MANUFACTURER_COMPANY_ID),
                        "local_device_id": trust::local_device_id_hex(),
                        "macos_bluetooth_auth_status": crate::ble_discovery::macos_bluetooth_auth_status(),
                    });
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    Ok(())
                }
                "auth-via-ble" => {
                    let timeout_secs: u64 = args
                        .get(3)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(20)
                        .clamp(3, 120);
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                        let proof = crate::discovery::authenticate_peer_via_ble(
                            Duration::from_secs(timeout_secs),
                        )
                        .await?;
                        println!("{}", serde_json::to_string_pretty(&proof)?);
                        Ok(())
                    })
                }
                "auth-via-bonjour" => {
                    let timeout_secs: u64 = args
                        .get(3)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(15)
                        .clamp(3, 120);
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                        let proof = crate::discovery::authenticate_peer_via_bonjour(
                            Duration::from_secs(timeout_secs),
                        )
                        .await?;
                        println!("{}", serde_json::to_string_pretty(&proof)?);
                        Ok(())
                    })
                }
                _ => anyhow::bail!(
                    "Unknown discovery subcommand: {}. Use `status`, `auth-via-ble [secs]`, or `auth-via-bonjour [secs]`.",
                    subcmd
                ),
            }
        })()),
        "touchid" => Some((|| {
            let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("verify");
            match subcmd {
                "status" => {
                    let status = serde_json::json!({
                        "local_os": std::env::consts::OS,
                        "local_touchid_available": trust::is_local_touchid_available(),
                        "local_device_id": trust::local_device_id_hex(),
                    });
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    Ok(())
                }
                "verify" => {
                    let target_ip_opt = args
                        .get(3)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    let challenge_nonce_hex = trust::generate_random_token_hex(32);
                    let my_device_id = trust::local_device_id_hex();
                    let my_hostname = system_info::get_hostname();
                    let started = std::time::Instant::now();

                    if cfg!(target_os = "macos") && target_ip_opt.is_none() {
                        let assertion = trust::evaluate_local_touchid_and_sign(
                            &challenge_nonce_hex,
                            &my_device_id,
                            &my_hostname,
                        )
                        .map_err(|e| anyhow::anyhow!(e))?;
                        trust::verify_touchid_assertion(
                            &assertion,
                            &challenge_nonce_hex,
                            &my_device_id,
                            &my_device_id,
                        )
                        .map_err(|e| anyhow::anyhow!(e))?;
                        let out = serde_json::json!({
                            "verified": true,
                            "mode": "local_macos_secure_enclave",
                            "elapsed_ms": (started.elapsed().as_secs_f64() * 1000.0).round(),
                            "assertion": assertion,
                        });
                        println!("{}", serde_json::to_string_pretty(&out)?);
                        Ok(())
                    } else {
                        let rt = tokio::runtime::Runtime::new()?;
                        rt.block_on(async {
                            let peer_ip = match target_ip_opt {
                                Some(ip) => ip,
                                None => {
                                    let (cfg, _) = trust::get_trust_snapshot();
                                    cfg.trusted_peers
                                        .first()
                                        .map(|p| p.last_ip.clone())
                                        .filter(|ip| !ip.is_empty())
                                        .ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "Usage: integrator touchid verify <mac_peer_ip>"
                                            )
                                        })?
                                }
                            };
                            let rpc = DisplayRpcRequest::VerifyTouchId {
                                challenge_nonce_hex: challenge_nonce_hex.clone(),
                                requester_hostname: my_hostname,
                            };
                            let resp = DisplayController::send_remote_rpc(&peer_ip, &rpc).await?;
                            if !resp.success {
                                anyhow::bail!("Remote Touch ID verification failed: {}", resp.message);
                            }
                            let assertion = resp.touchid_assertion.ok_or_else(|| {
                                anyhow::anyhow!("Remote Mac returned success without Touch ID assertion")
                            })?;
                            trust::verify_touchid_assertion(
                                &assertion,
                                &challenge_nonce_hex,
                                &my_device_id,
                                &assertion.signer_device_id,
                            )
                            .map_err(|e| anyhow::anyhow!(e))?;
                            let out = serde_json::json!({
                                "verified": true,
                                "mode": "remote_transport_v2_secure_enclave",
                                "peer_ip": peer_ip,
                                "elapsed_ms": (started.elapsed().as_secs_f64() * 1000.0).round(),
                                "assertion": assertion,
                            });
                            println!("{}", serde_json::to_string_pretty(&out)?);
                            Ok(())
                        })
                    }
                }
                _ => anyhow::bail!(
                    "Unknown touchid subcommand: {}. Use `status` or `verify [mac_ip]`.",
                    subcmd
                ),
            }
        })()),
        "passkey" => Some((|| {
            let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match subcmd {
                "status" | "info" => {
                    let info_cbor = crate::security::passkey::get_info_cbor_bytes();
                    let info_hex = crate::security::hex_encode(&info_cbor);
                    let creds = crate::security::passkey::list_resident_passkeys()
                        .unwrap_or_default();
                    let out = serde_json::json!({
                        "plugin_authenticator": "Integrator Touch ID",
                        "aaguid": crate::security::hex_encode(&crate::security::passkey::INTEGRATOR_AAGUID),
                        "get_info_cbor_hex": info_hex,
                        "stored_passkeys_count": creds.len(),
                        "stored_passkeys": creds,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                    Ok(())
                }
                "list" => {
                    let creds = crate::security::passkey::list_resident_passkeys()
                        .map_err(|e| anyhow::anyhow!(e))?;
                    if creds.is_empty() {
                        println!("No resident passkeys stored.");
                    } else {
                        println!("{:<32} {:<24} {:<24} {:<8}", "CREDENTIAL ID", "RP ID", "USER", "SIG COUNT");
                        println!("{}", "-".repeat(90));
                        for c in &creds {
                            let cred_short = if c.credential_id_hex.len() > 30 {
                                format!("{}…", &c.credential_id_hex[..29])
                            } else {
                                c.credential_id_hex.clone()
                            };
                            println!("{:<32} {:<24} {:<24} {:<8}", cred_short, c.rp_id, c.user_name, c.sign_count);
                        }
                    }
                    Ok(())
                }
                "test" => {
                    // Usage: integrator passkey test [mac_ip] [rp_id]
                    let target_ip_opt = args.get(3).cloned();
                    let rp_id = args.get(4).cloned().unwrap_or_else(|| "webauthn.io".to_string());
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                        let peer_ip = match target_ip_opt {
                            Some(ip) => ip,
                            None => {
                                let (cfg, _) = trust::get_trust_snapshot();
                                cfg.trusted_peers
                                    .first()
                                    .map(|p| p.last_ip.clone())
                                    .filter(|ip| !ip.is_empty())
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "Usage: integrator passkey test <mac_peer_ip> [rp_id]"
                                        )
                                    })?
                            }
                        };
                        println!("==> Initiating Passkey MakeCredential test for RP '{}' against {}...", rp_id, peer_ip);
                        let client_data_hash = crate::security::hex_encode(&crate::security::csprng_array::<32>());
                        let user_id = crate::security::hex_encode(&crate::security::csprng_array::<16>());
                        let make_req = crate::security::passkey::PasskeyMakeCredentialRequest {
                            rp_id: rp_id.clone(),
                            user_id_hex: user_id,
                            user_name: "manveer".to_string(),
                            user_display_name: "Manveer Singh".to_string(),
                            client_data_hash_hex: client_data_hash.clone(),
                            requester_hostname: system_info::get_hostname(),
                        };
                        let resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::PasskeyMakeCredential(make_req),
                        ).await?;
                        if !resp.success {
                            anyhow::bail!("Passkey creation failed: {}", resp.message);
                        }
                        let cred = resp.passkey_credential.ok_or_else(|| {
                            anyhow::anyhow!("Mac peer returned success without passkey credential")
                        })?;
                        println!("==> Success! Passkey created with ID: {}", cred.credential_id_hex);

                        println!("==> Now testing Passkey GetAssertion for RP '{}'...", rp_id);
                        let assert_req = crate::security::passkey::PasskeyGetAssertionRequest {
                            rp_id: rp_id.clone(),
                            client_data_hash_hex: client_data_hash,
                            allow_credential_ids_hex: vec![cred.credential_id_hex.clone()],
                            requester_hostname: system_info::get_hostname(),
                        };
                        let assert_resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::PasskeyGetAssertion(assert_req),
                        ).await?;
                        if !assert_resp.success {
                            anyhow::bail!("Passkey assertion failed: {}", assert_resp.message);
                        }
                        let assertion = assert_resp.passkey_assertion.ok_or_else(|| {
                            anyhow::anyhow!("Mac peer returned success without assertion signature")
                        })?;
                        println!("==> Success! Passkey assertion signed via Touch ID: {}…", &assertion.signature_der_hex[..20]);
                        Ok(())
                    })
                }
                "make-hex" => {
                    // Stateless bridge invoked by IntegratorPasskeyHost.exe (Medium-IL packaged COM server).
                    // Arg 3: hex-encoded UTF-8 JSON of PasskeyMakeCredentialRequest.
                    let payload_hex = args.get(3).ok_or_else(|| anyhow::anyhow!("Missing hex payload"))?;
                    let payload_bytes = crate::security::hex_decode(payload_hex)
                        .ok_or_else(|| anyhow::anyhow!("Invalid hex payload"))?;
                    let make_req: crate::security::passkey::PasskeyMakeCredentialRequest =
                        serde_json::from_slice(&payload_bytes)?;
                    let rt = tokio::runtime::Runtime::new()?;
                    let out = rt.block_on(async {
                        let (cfg, _) = trust::get_trust_snapshot();
                        let peer_ip = cfg
                            .trusted_peers
                            .iter()
                            .find(|p| !p.last_ip.is_empty())
                            .map(|p| p.last_ip.clone())
                            .ok_or_else(|| "No paired Mac peer found in KeystoreV2".to_string())?;
                        let resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::PasskeyMakeCredential(make_req),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        if !resp.success {
                            return Err(resp.message);
                        }
                        let cred = resp
                            .passkey_credential
                            .ok_or_else(|| "Mac peer returned success without passkey credential".to_string())?;
                        Ok::<_, String>(cred)
                    });
                    match out {
                        Ok(cred) => {
                            println!("{}", serde_json::json!({ "ok": true, "data": cred }));
                            Ok(())
                        }
                        Err(err) => {
                            println!("{}", serde_json::json!({ "ok": false, "error": err }));
                            Ok(())
                        }
                    }
                }
                "assert-hex" => {
                    // Stateless bridge invoked by IntegratorPasskeyHost.exe (Medium-IL packaged COM server).
                    // Arg 3: hex-encoded UTF-8 JSON of PasskeyGetAssertionRequest.
                    let payload_hex = args.get(3).ok_or_else(|| anyhow::anyhow!("Missing hex payload"))?;
                    let payload_bytes = crate::security::hex_decode(payload_hex)
                        .ok_or_else(|| anyhow::anyhow!("Invalid hex payload"))?;
                    let assert_req: crate::security::passkey::PasskeyGetAssertionRequest =
                        serde_json::from_slice(&payload_bytes)?;
                    let rt = tokio::runtime::Runtime::new()?;
                    let out = rt.block_on(async {
                        let (cfg, _) = trust::get_trust_snapshot();
                        let peer_ip = cfg
                            .trusted_peers
                            .iter()
                            .find(|p| !p.last_ip.is_empty())
                            .map(|p| p.last_ip.clone())
                            .ok_or_else(|| "No paired Mac peer found in KeystoreV2".to_string())?;
                        let resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::PasskeyGetAssertion(assert_req),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        if !resp.success {
                            return Err(resp.message);
                        }
                        let assertion = resp
                            .passkey_assertion
                            .ok_or_else(|| "Mac peer returned success without assertion".to_string())?;
                        Ok::<_, String>(assertion)
                    });
                    match out {
                        Ok(assertion) => {
                            println!("{}", serde_json::json!({ "ok": true, "data": assertion }));
                            Ok(())
                        }
                        Err(err) => {
                            let not_found = err.contains("NO_PASSKEY_FOUND") || err.contains("No passkey found");
                            println!("{}", serde_json::json!({ "ok": false, "error": err, "not_found": not_found }));
                            Ok(())
                        }
                    }
                }
                _ => anyhow::bail!("Unknown passkey subcommand: {}. Use status, list, test, make-hex, or assert-hex.", subcmd),
            }
        })()),
        _ => None,
    }
}

/// Maximum size allowed for `.integrator.log` before rotation (5 MiB).
const MAX_LOG_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Opens the application log file with private permissions (`0o600`), symlink rejection, and rotation.
fn open_private_rotating_log(path: &Path) -> Option<std::fs::File> {
    // Symlink inspection: reject symlinks to prevent arbitrary file truncation
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            eprintln!(
                "Refusing to open symlinked log file at {}",
                path.display()
            );
            return None;
        }

        // Rotate file if size exceeds 5 MiB
        if meta.len() > MAX_LOG_FILE_BYTES {
            let backup = path.with_extension("log.1");
            let backup_is_symlink = std::fs::symlink_metadata(&backup)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if !backup_is_symlink {
                let _ = std::fs::remove_file(&backup);
                let _ = std::fs::rename(path, &backup);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).ok()
}

/// Formats a slice of numeric TCP/UDP ports into a comma-separated `netsh` `localport=` value.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn format_firewall_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Computes the canonical IPv4 network CIDR (e.g. `192.168.1.0/24`, `172.20.10.0/28`) for an active local interface.
#[cfg(any(target_os = "windows", test))]
fn interface_to_cidr(iface: &system_info::LocalInterfaceInfo) -> Option<String> {
    let ip = iface.ip.trim().parse::<Ipv4Addr>().ok()?;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
        return None;
    }

    let mask = if let Ok(parsed_mask) = iface.netmask.trim().parse::<Ipv4Addr>() {
        if system_info::is_valid_contiguous_netmask(parsed_mask) {
            parsed_mask
        } else {
            system_info::prefix_to_mask(iface.cidr_prefix)?
        }
    } else {
        system_info::prefix_to_mask(iface.cidr_prefix)?
    };

    system_info::compute_network_cidr(ip, mask)
}

/// Validates and normalizes an extra Windows firewall remote scope entry (IPv4 CIDR or host IP).
///
/// Rejects wildcard `/0` ranges, control characters, and non-IPv4 tokens to prevent `netsh` injection
/// or overly permissive rules.
#[cfg(any(target_os = "windows", test))]
fn validate_firewall_scope_entry(raw: &str) -> Option<String> {
    if raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        let ip = ip_part.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix_part.parse::<u8>().ok()?;
        if !(1..=32).contains(&prefix) {
            return None;
        }
        let mask = if prefix == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        let network = Ipv4Addr::from(u32::from(ip) & mask);
        if network.is_unspecified() {
            return None;
        }
        return Some(format!("{}/{}", network, prefix));
    }
    let ip = trimmed.parse::<Ipv4Addr>().ok()?;
    if ip.is_unspecified() || ip.is_broadcast() {
        return None;
    }
    Some(ip.to_string())
}

/// Pure helper building the deduplicated comma-separated Windows Defender Firewall `remoteip=`
/// string from `LocalSubnet`, [`config::IPV4_LINK_LOCAL_CIDR`], active physical/hotspot adapter
/// network CIDRs (excluding VPN/WSL/Docker/VM virtual switches), and validated user-configured extra subnets.
#[cfg(any(target_os = "windows", test))]
fn build_windows_firewall_remote_scopes_from(
    interfaces: &[system_info::LocalInterfaceInfo],
    extra_subnets: &[String],
) -> String {
    let mut scopes: Vec<String> = Vec::new();
    let mut push_unique = |entry: String| {
        if !scopes.iter().any(|existing| existing.eq_ignore_ascii_case(&entry)) {
            scopes.push(entry);
        }
    };

    push_unique(FIREWALL_SCOPE_LOCAL_SUBNET.to_string());
    push_unique(config::IPV4_LINK_LOCAL_CIDR.to_string());

    for iface in interfaces {
        if iface.transport == system_info::LinkTransport::Unknown
            || system_info::is_excluded_virtual_interface(&iface.name, &iface.friendly_name)
        {
            continue;
        }
        if let Some(cidr) = interface_to_cidr(iface) {
            push_unique(cidr);
        }
    }

    for extra in extra_subnets {
        if let Some(validated) = validate_firewall_scope_entry(extra) {
            push_unique(validated);
        }
    }

    scopes.join(",")
}

/// Builds the dynamic Windows Defender Firewall `remoteip=` scope list by combining `LocalSubnet`,
/// [`config::IPV4_LINK_LOCAL_CIDR`], currently active local IPv4 adapter subnets, and validated
/// `AppPathPreferences.firewall_extra_subnets`.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn build_windows_firewall_remote_scopes() -> String {
    let interfaces = system_info::list_local_ipv4_interfaces();
    let prefs = system_info::load_path_preferences();
    build_windows_firewall_remote_scopes_from(&interfaces, &prefs.firewall_extra_subnets)
}

/// Background macOS watcher that monitors paired Windows media playback and auto-presents
/// the Integrator Touch Bar HUD when Windows begins playing Spotify/YouTube/VLC media.
#[cfg(target_os = "macos")]
async fn run_macos_touchbar_media_watcher(
    discovery: DiscoveryManager,
    features: Arc<FeatureManager>,
) {
    if !system_info::has_touch_bar_hardware() {
        return;
    }
    let mut was_playing = false;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !features.is_enabled("touchbar") {
            was_playing = false;
            continue;
        }
        // If Touch Bar HUD is already active, its own 1s snapshot poller handles media updates directly
        if unsafe { is_touchbar_active_in_app() } {
            was_playing = true;
            continue;
        }
        let Some(peer_ip) = discovery.get_peer_ip().await else {
            was_playing = false;
            continue;
        };
        let playing_now = DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetMediaState)
            .await
            .ok()
            .and_then(|r| r.media_state)
            .map(|m| m.has_session && m.is_playing)
            .unwrap_or(false);

        if playing_now && !was_playing {
            if let Ok(c_ip) = CString::new(peer_ip) {
                unsafe {
                    set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                    init_touchbar_in_app(c_ip.as_ptr());
                }
            }
        }
        was_playing = playing_now;
    }
}

/// Continuously watches for active Windows UAC (`consent.exe`) or Windows Hello
/// (`CredentialUIBroker.exe`) prompts on the Windows workstation and sends
/// `DisplayRpcRequest::NotifyTouchIdPrompt` to the paired Mac so its Touch Bar illuminates
/// the animated pointer pointing directly at the physical Touch ID sensor.
#[cfg(target_os = "windows")]
async fn run_windows_touchid_prompt_watcher(
    discovery: DiscoveryManager,
    features: Arc<FeatureManager>,
) {
    let mut last_prompt: Option<&'static str> = None;
    let mut active_peer_notified: Option<String> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(450)).await;
        if !features.is_enabled("touchid") {
            if last_prompt.is_some() {
                if let Some(ip) = active_peer_notified.take() {
                    let _ = DisplayController::send_remote_rpc(
                        &ip,
                        &DisplayRpcRequest::NotifyTouchIdPrompt {
                            label: String::new(),
                            active: false,
                        },
                    )
                    .await;
                }
                last_prompt = None;
            }
            continue;
        }

        let current = tokio::task::spawn_blocking(IntegratorCore::detect_active_windows_security_prompt)
            .await
            .ok()
            .flatten();
        if current != last_prompt {
            match current {
                Some(label) => {
                    if let Some(peer_ip) = discovery.get_peer_ip().await {
                        let _ = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::NotifyTouchIdPrompt {
                                label: label.to_string(),
                                active: true,
                            },
                        )
                        .await;
                        active_peer_notified = Some(peer_ip);
                    }
                }
                None => {
                    let target = active_peer_notified
                        .take()
                        .or(discovery.get_peer_ip().await);
                    if let Some(peer_ip) = target {
                        let _ = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::NotifyTouchIdPrompt {
                                label: String::new(),
                                active: false,
                            },
                        )
                        .await;
                    }
                }
            }
            last_prompt = current;
        }
    }
}

/// Automatically configures Windows Defender Firewall rules for Integrator on Windows hosts.
///
/// Ensures direct Thunderbolt/USB4, USB-C NCM, Ethernet, and Mobile Hotspot interfaces
/// permit inbound traffic on Integrator TCP/UDP/SMB ports even if assigned to Public network profiles.
#[cfg(target_os = "windows")]
pub(crate) fn ensure_windows_firewall_rules() {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    let Ok(exe_path) = std::env::current_exe() else {
        return;
    };
    let exe_str = exe_path.to_string_lossy().trim().to_string();
    if exe_str.is_empty()
        || exe_str.contains('"')
        || exe_str.chars().any(|c| c.is_control())
    {
        return;
    }

    let remote_scopes = build_windows_firewall_remote_scopes();
    let tcp_ports_str = format_firewall_ports(&config::TCP_SERVICE_PORTS);
    let udp_ports_str = format_firewall_ports(&config::UDP_SERVICE_PORTS);
    let smb_ports_str = format_firewall_ports(&config::SMB_SERVICE_PORTS);

    let netsh = system_info::system32_exe("netsh.exe");
    let rules: [(&str, &str, &[u16], &str); 2] = [
        (
            WIN_FW_RULE_CORE_TCP,
            "TCP",
            &config::TCP_SERVICE_PORTS,
            &tcp_ports_str,
        ),
        (
            WIN_FW_RULE_CORE_UDP,
            "UDP",
            &config::UDP_SERVICE_PORTS,
            &udp_ports_str,
        ),
    ];

    let scopes_match = |txt: &str| {
        remote_scopes.split(',').all(|scope| {
            let lower_scope = scope.to_ascii_lowercase();
            let ip_token = lower_scope.split('/').next().unwrap_or(&lower_scope);
            txt.contains(&lower_scope) || txt.contains(ip_token)
        })
    };

    for (rule_name, proto, port_list, ports_arg) in rules {
        let already_matches = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", rule_name),
                "verbose",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                let txt = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
                let has_all_ports = port_list.iter().all(|p| txt.contains(&p.to_string()));
                txt.contains(&exe_str.to_ascii_lowercase()) && scopes_match(&txt) && has_all_ports
            })
            .unwrap_or(false);

        if already_matches {
            continue;
        }

        // Delete obsolete rule
        let _ = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Add dynamically scoped rule
        let _ = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=allow",
                &format!("program={}", exe_str),
                &format!("protocol={}", proto),
                &format!("localport={}", ports_arg),
                &format!("remoteip={}", remote_scopes),
                "profile=private,domain",
                "enable=yes",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Ensure inbound SMB file sharing is permitted across all dynamically resolved local subnets
    let smb_matches = Command::new(&netsh)
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={}", WIN_FW_RULE_SMB_TCP),
            "verbose",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let txt = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            let has_all_smb_ports = config::SMB_SERVICE_PORTS
                .iter()
                .all(|p| txt.contains(&p.to_string()));
            scopes_match(&txt) && has_all_smb_ports
        })
        .unwrap_or(false);

    if !smb_matches {
        let _ = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", WIN_FW_RULE_SMB_TCP),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let _ = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", WIN_FW_RULE_SMB_TCP),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", smb_ports_str),
                &format!("remoteip={}", remote_scopes),
                "profile=private,domain",
                "enable=yes",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl IntegratorCore {
    /// Initializes the global `IntegratorCore` singleton runtime.
    ///
    /// # Startup Pipeline:
    /// 1. Initializes private rotating logger and tracing subscriber.
    /// 2. Spawns Tokio multi-threaded runtime.
    /// 3. Initializes `FeatureManager` and loads `features.json`.
    /// 4. Bootstraps `DiscoveryManager`, `ClipboardService`, `DisplayController`, `DisplayServer`,
    ///    `BenchmarkServer`, `AudioManager`, `KvmService`, and `CameraService`.
    /// 5. Configures native keyboard shortcut hooks on macOS.
    /// 6. Spawns background Windows firewall rule verifier on Windows.
    /// 7. Stores instance into `GLOBAL_CORE`.
    pub fn init_global() -> Result<Arc<Self>> {
        if let Some(existing) = GLOBAL_CORE.get() {
            return Ok(Arc::clone(existing));
        }

        // 1. Logging setup (private file permissions, symlink guard, 5 MiB rotation cap)
        let log_path = system_info::user_home_dir().join(config::LOG_FILE_NAME);
        let file_opt = open_private_rotating_log(&log_path);

        let env_filter =
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
        let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

        if let Some(f) = file_opt {
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(Mutex::new(f))
                .with_ansi(false);
            let _ = tracing_subscriber::registry()
                .with(env_filter)
                .with(stdout_layer)
                .with(file_layer)
                .with(UiRingLogLayer)
                .try_init();
        } else {
            let _ = tracing_subscriber::registry()
                .with(env_filter)
                .with(stdout_layer)
                .with(UiRingLogLayer)
                .try_init();
        }

        let device_name = system_info::get_hostname();
        tracing::info!(
            "🚀 Integrator v1.0 Native Core initializing on {} [{}]...",
            std::env::consts::OS,
            device_name
        );

        // 2. Spawn Tokio Multi-Thread Runtime
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let _ = crate::clipboard::TOKIO_HANDLE.set(rt.handle().clone());

        let feature_manager = Arc::new(FeatureManager::new());

        // 3. Initialize background services within runtime context
        let (discovery, display_ctrl, clipboard, kvm, camera) = rt.block_on(async {
            let discovery = DiscoveryManager::new(&device_name);
            discovery
                .start()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start discovery: {e}"))?;

            let clipboard = ClipboardService::new(discovery.clone())
                .map_err(|e| anyhow::anyhow!("Failed to initialize clipboard: {e}"))?;
            clipboard.set_feature_manager(Arc::clone(&feature_manager));
            clipboard
                .start()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start clipboard: {e}"))?;

            let display_ctrl = DisplayController::new(discovery.clone(), Arc::clone(&feature_manager));
            let display_server = DisplayServer::new(display_ctrl.clone(), Arc::clone(&feature_manager));
            display_server
                .start()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start display RPC server: {e}"))?;

            benchmark::BenchmarkServer::start(Arc::clone(&feature_manager))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start benchmark server: {e}"))?;

            if let Err(e) = audio::AudioManager::start_sink_server().await {
                tracing::warn!("Failed to start dynamic audio sink server: {}", e);
            }

            let kvm = KvmService::new(
                discovery.clone(),
                clipboard.clone(),
                Arc::clone(&feature_manager),
            );
            kvm.start()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start KVM engine: {e}"))?;

            let camera = CameraService::new(discovery.clone(), Arc::clone(&feature_manager));
            if let Err(e) = camera.start_server().await {
                tracing::warn!("Failed to start shared camera listener: {}", e);
            }

            // Spawn continuous True Tone ambient sync daemon
            let disc_tt = discovery.clone();
            let feat_tt = Arc::clone(&feature_manager);
            tokio::spawn(async move {
                truetone::run_continuous_truetone_sync(disc_tt, feat_tt).await;
            });

            // On macOS with Touch Bar hardware, watch for Windows media playback starting and
            // auto-present the Touch Bar HUD seamlessly so Spotify/YouTube controls appear immediately.
            #[cfg(target_os = "macos")]
            {
                let disc_tb = discovery.clone();
                let feat_tb = Arc::clone(&feature_manager);
                tokio::spawn(async move {
                    run_macos_touchbar_media_watcher(disc_tb, feat_tb).await;
                });
            }

            // On Windows, watch for UAC elevation (`consent.exe`) and Windows Hello (`CredentialUIBroker.exe`)
            // prompts and illuminate the paired Mac Touch Bar Touch ID sensor pointer in real time.
            #[cfg(target_os = "windows")]
            {
                let disc_tid = discovery.clone();
                let feat_tid = Arc::clone(&feature_manager);
                tokio::spawn(async move {
                    run_windows_touchid_prompt_watcher(disc_tid, feat_tid).await;
                });
            }

            Ok::<_, anyhow::Error>((discovery, display_ctrl, clipboard, kvm, camera))
        })?;

        #[cfg(target_os = "macos")]
        unsafe {
            crate::clipboard::service::init_shortcut_interceptor();
            if system_info::has_touch_bar_hardware() && feature_manager.is_enabled("touchbar") {
                set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                set_touchbar_tray_enabled_in_app(true);
            }
        }

        let core = Arc::new(Self {
            rt,
            discovery,
            display_ctrl,
            clipboard,
            features: feature_manager,
            kvm,
            camera,
        });
        let _ = GLOBAL_CORE.set(Arc::clone(&core));

        #[cfg(target_os = "windows")]
        {
            let _ = std::thread::Builder::new()
                .name("win-fw-init".into())
                .spawn(ensure_windows_firewall_rules);
            let _ = crate::autostart::migrate_task_to_least_privilege_windows();
        }

        Ok(core)
    }

    /// Background Windows watcher that detects active UAC (`consent.exe`) or Windows Hello
    /// (`CredentialUIBroker.exe`) prompts via unprivileged Win32 Toolhelp snapshots and
    /// illuminates the paired Mac Touch Bar's animated Touch ID pointer in real time.
    #[cfg(target_os = "windows")]
    fn detect_active_windows_security_prompt() -> Option<&'static str> {
        #[repr(C)]
        struct ProcessEntry32W {
            dw_size: u32,
            cnt_usage: u32,
            th32_process_id: u32,
            th32_default_heap_id: usize,
            th32_module_id: u32,
            cnt_threads: u32,
            th32_parent_process_id: u32,
            pc_pri_class_base: i32,
            dw_flags: u32,
            sz_exe_file: [u16; 260],
        }
        const TH32CS_SNAPPROCESS: u32 = 0x00000002;
        const INVALID_HANDLE_VALUE: isize = -1;
        extern "system" {
            fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> isize;
            fn Process32FirstW(h_snapshot: isize, lppe: *mut ProcessEntry32W) -> i32;
            fn Process32NextW(h_snapshot: isize, lppe: *mut ProcessEntry32W) -> i32;
            fn CloseHandle(h_object: isize) -> i32;
        }

        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == 0 || snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry = ProcessEntry32W {
            dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; 260],
        };
        let mut found: Option<&'static str> = None;
        if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
            loop {
                let nul_pos = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..nul_pos]).to_ascii_lowercase();
                if name == "consent.exe" {
                    found = Some("Approve Windows UAC Prompt");
                    break;
                } else if name == "credentialuibroker.exe" {
                    found = Some("Approve Windows Hello Login");
                }
                if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe {
            CloseHandle(snap);
        }
        found
    }

    /// Assembles a complete, unified `BridgeStatus` diagnostic structure.
    ///
    /// Aggregates hardware profiles, active peer candidates, link latency, audio/camera routing,
    /// display streaming states, TrueTone ambient sensor readings, and trust snapshot.
    pub async fn build_bridge_status(&self) -> BridgeStatus {
        let local_prof = tokio::task::spawn_blocking(system_info::collect_local_profile)
            .await
            .unwrap_or_default();
        let local_interfaces = tokio::task::spawn_blocking(system_info::list_local_ipv4_interfaces)
            .await
            .unwrap_or_default();

        let all_peers = self.discovery.get_all_peers().await;
        let manual_peer_ips = self.discovery.get_manual_peer_ips().await;
        let best = self.discovery.get_best_peer().await;

        let display_active = self.display_ctrl.is_active().await;
        let active_mode = self.display_ctrl.get_active_mode().await;

        let best_ip = best.as_ref().map(|p| p.addr.ip().to_string());
        let best_share = best.as_ref().and_then(|p| p.share_name.clone());

        let feature_flags = self.features.get_flags();
        let truetone_enabled = feature_flags.truetone;
        let camera_enabled = feature_flags.camera;
        let has_peer_discovered = best.is_some() || !all_peers.is_empty();
        let (
            storage_status,
            preferred_peer_share,
            local_shared_folder,
            auto_mount_storage,
            autostart_enabled,
            (enc_gpu, dec_gpu),
            als,
            (trust_cfg, pending_peers),
            setup_status,
        ) = tokio::task::spawn_blocking({
            let bip = best_ip.clone();
            let bsh = best_share.clone();
            let storage_on = feature_flags.storage;
            move || {
                let mut st =
                    storage::StorageManager::status_with_share(bip.as_deref(), bsh.as_deref());
                let auto_mount = storage::StorageManager::is_auto_mount_on_peer_detect();
                if storage_on && auto_mount && !st.is_mounted {
                    if let Some(ref peer_ip) = bip {
                        if let Ok(mounted_st) =
                            storage::StorageManager::mount_with_share(peer_ip, bsh.as_deref())
                        {
                            st = mounted_st;
                        }
                    }
                }
                let pref = storage::StorageManager::get_preferred_peer_share();
                let local_folder = storage::StorageManager::get_local_shared_folder();
                let auto = autostart::AutostartManager::is_enabled();
                #[cfg(target_os = "windows")]
                let gpus = crate::display::win_display::WinDisplayManager::get_gpu_preferences();
                #[cfg(not(target_os = "windows"))]
                let gpus = ("auto".to_string(), "auto".to_string());
                let als = if truetone_enabled {
                    truetone::read_ambient_light()
                } else {
                    truetone::AmbientLightData {
                        lux: 0.0,
                        cct_kelvin: config::D65_CCT_KELVIN,
                        supported: false,
                        updated_at_secs: 0,
                    }
                };
                let trust_snap = trust::get_trust_snapshot();
                let setup_snap = crate::setup::collect_setup_health_snapshot(
                    camera_enabled,
                    has_peer_discovered,
                );
                (st, pref, local_folder, auto_mount, auto, gpus, als, trust_snap, setup_snap)
            }
        })
        .await
        .unwrap_or_else(|_| {
            let auto_mount = storage::StorageManager::is_auto_mount_on_peer_detect();
            (
                StorageStatus {
                    is_mounted: false,
                    mount_path: String::new(),
                    remote_ip: String::new(),
                    remote_share: String::new(),
                    message: String::new(),
                },
                None,
                None,
                auto_mount,
                false,
                ("auto".to_string(), "auto".to_string()),
                truetone::AmbientLightData {
                    lux: 0.0,
                    cct_kelvin: config::D65_CCT_KELVIN,
                    supported: false,
                    updated_at_secs: 0,
                },
                (
                    trust::TrustConfigFile {
                        auto_trust_direct_cable: false,
                        require_pairing_on_lan: true,
                        pairing_pin: String::new(),
                        pin_created_at_epoch: 0,
                        trusted_peers: Vec::new(),
                        blocked_device_ids: Vec::new(),
                        blocked_ips: Vec::new(),
                    },
                    Vec::new(),
                ),
                crate::setup::SetupHealthSnapshot::default(),
            )
        });

        let blocked_set: HashMap<String, bool> = trust_cfg
            .blocked_device_ids
            .iter()
            .map(|id| (id.clone(), true))
            .collect();
        let trusted_set: HashMap<String, bool> = trust_cfg
            .trusted_peers
            .iter()
            .map(|p| (p.device_id.clone(), true))
            .collect();

        let discovered_peers = all_peers
            .into_iter()
            .map(|p| DiscoveredPeerInfo {
                trusted: p.trusted || *trusted_set.get(&p.device_id).unwrap_or(&false),
                blocked: *blocked_set.get(&p.device_id).unwrap_or(&false),
                device_id: p.device_id,
                hostname: p.device_name,
                os: p.os,
                hardware_model: p.hardware_model,
                form_factor: p.form_factor,
                ip: p.addr.ip().to_string(),
                local_ip_used: p.local_ip_used,
                transport_label: p.transport.label().to_string(),
                is_direct_cable: p.transport.is_direct_cable(),
                link_speed_mbps: p.link_speed_mbps,
                link_description: p.link_description,
                rtt_ms: p.rtt_ms,
                display: DisplayGeometry {
                    width: p.display_width,
                    height: p.display_height,
                    fps: p.display_fps,
                },
                gpus: p.gpus,
                share_name: p.share_name,
                discovery_source: p.discovery_source,
            })
            .collect();

        #[cfg(target_os = "macos")]
        let touchbar_active = unsafe { is_touchbar_active_in_app() };
        #[cfg(not(target_os = "macos"))]
        let touchbar_active = false;

        let measured_bench = best_ip
            .as_deref()
            .and_then(benchmark::latest_measurement_for_peer);
        let effective_speed_mbps = measured_bench
            .as_ref()
            .map(|m| (m.max_gbps * 1000.0).round().clamp(1.0, u32::MAX as f64) as u32)
            .or_else(|| best.as_ref().and_then(|p| p.link_speed_mbps));
        let link_speed = if let Some(ref m) = measured_bench {
            format_measured_speed(m.max_gbps)
        } else {
            best.as_ref()
                .map(|p| format_link_speed(p.link_speed_mbps, true))
                .unwrap_or_else(|| "--".to_string())
        };
        let link_type = best
            .as_ref()
            .map(|p| p.transport.label().to_string())
            .unwrap_or_else(|| "Discovering...".to_string());

        BridgeStatus {
            device_id: local_prof.device_id,
            hostname: local_prof.hostname,
            os: local_prof.os.clone(),
            local_os: std::env::consts::OS.to_string(),
            hardware_model: local_prof.hardware_model,
            form_factor: local_prof.form_factor.as_str().to_string(),
            cpu_brand: local_prof.cpu_brand,
            primary_display: local_prof.primary_display,
            local_gpus: local_prof.gpus,
            local_share_names: local_prof.default_share_names,
            has_touch_bar: local_prof.has_touch_bar,

            peer_connected: best.is_some(),
            peer_trusted: best
                .as_ref()
                .map(|p| p.trusted || *trusted_set.get(&p.device_id).unwrap_or(&false))
                .unwrap_or(false),
            peer_device_id: best.as_ref().map(|p| p.device_id.clone()),
            peer_ip: best_ip,
            peer_os: best.as_ref().map(|p| p.os.clone()),
            peer_name: best.as_ref().map(|p| p.device_name.clone()),
            peer_hardware_model: best.as_ref().map(|p| p.hardware_model.clone()),
            peer_form_factor: best.as_ref().map(|p| p.form_factor.clone()),
            peer_display: best.as_ref().map(|p| DisplayGeometry {
                width: p.display_width,
                height: p.display_height,
                fps: p.display_fps,
            }),
            peer_gpus: best.as_ref().map(|p| p.gpus.clone()).unwrap_or_default(),
            peer_share_name: best_share,
            peer_local_ip_used: best.as_ref().and_then(|p| p.local_ip_used.clone()),
            transport_label: link_type.clone(),
            is_direct_cable: best
                .as_ref()
                .map(|p| p.transport.is_direct_cable())
                .unwrap_or(false),
            link_speed_mbps: effective_speed_mbps,
            link_description: best
                .as_ref()
                .map(|p| p.link_description.clone())
                .unwrap_or_else(|| "Awaiting peer beacon".to_string()),
            rtt_ms: best.as_ref().and_then(|p| p.rtt_ms),
            link_speed,
            link_type,

            display_active,
            active_mode,
            is_windows_master: cfg!(target_os = "windows"),
            encode_gpu: enc_gpu,
            decode_gpu: dec_gpu,
            gpu_controls_supported: cfg!(target_os = "windows"),
            touchbar_active,

            ambient_supported: als.supported,
            ambient_lux: if als.supported { Some(als.lux) } else { None },
            ambient_cct: if als.supported {
                Some(als.cct_kelvin)
            } else {
                None
            },

            storage_mounted: storage_status.is_mounted,
            storage_status,
            preferred_peer_share,
            local_shared_folder,
            auto_mount_storage,

            audio_status: audio::AudioManager::status(),
            camera_status: self.camera.status(),
            feature_flags,
            kvm: self.kvm.get_status_snapshot(),

            local_interfaces,
            manual_peer_ips,
            discovered_peers,
            discovery_mode: crate::discovery::DiscoveryMode::from_env()
                .as_str()
                .to_string(),
            bonjour_active: crate::bonjour_discovery::is_bonjour_active(),
            ble_active: crate::ble_discovery::is_ble_active(),
            trust: TrustSnapshotInfo {
                pairing_pin: trust_cfg.pairing_pin,
                auto_trust_direct_cable: trust_cfg.auto_trust_direct_cable,
                require_pairing_on_lan: trust_cfg.require_pairing_on_lan,
                pending_peers,
                trusted_peers: trust_cfg.trusted_peers,
                blocked_device_ids: trust_cfg.blocked_device_ids,
            },

            autostart_enabled,
            setup_status,
            recent_logs: get_recent_logs(),
        }
    }

    /// Primary JSON-RPC dispatcher processing incoming method calls from native GUI frontends.
    ///
    /// # Arguments
    /// * `method` - Method name string (e.g. `"get_bridge_status"`, `"pair_with_peer"`).
    /// * `params_json` - JSON string containing parameter dictionary.
    ///
    /// # Return Value
    /// Returns a serialized JSON string containing either `{"ok": true, "data": ...}` or `{"ok": false, "error": "..."}`.
    pub fn dispatch_json(&self, method: &str, params_json: &str) -> String {
        let params_val: serde_json::Value = if params_json.trim().is_empty() {
            serde_json::json!({})
        } else {
            match serde_json::from_str(params_json) {
                Ok(v) => v,
                Err(e) => return wrap_err(format!("Invalid parameters JSON: {}", e)),
            }
        };

        let res: Result<serde_json::Value, String> = self.rt.block_on(async {
            match method {
                "get_status" => Ok(serde_json::json!("Integrator v1.0 Native Active")),
                "get_bridge_status" => {
                    let s = self.build_bridge_status().await;
                    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
                }
                "get_logs" => Ok(serde_json::to_value(get_recent_logs()).map_err(|e| e.to_string())?),
                "toggle_display" => {
                    if !self.features.is_enabled("display") {
                        return Err("Extended Screen & GPU Acceleration is disabled".into());
                    }
                    if !self.display_ctrl.is_active().await && self.display_ctrl.get_active_mode().await.is_none() {
                        if self.features.is_enabled("input_kvm") || self.features.is_enabled("input") {
                            self.features.set_flag("input_kvm", false);
                            self.features.set_flag("input", false);
                            self.kvm.force_release_all(true);
                            tracing::info!("🖥️ Screen extension starting: automatically disabled KVM to prevent cursor capture conflicts.");
                        }
                    }
                    let msg = if cfg!(target_os = "macos") {
                        self.display_ctrl.toggle_mac_to_pc().await
                    } else {
                        self.display_ctrl.toggle_pc_to_mac().await
                    }
                    .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "toggle_mac_to_pc" => {
                    if !self.features.is_enabled("display") {
                        return Err("Extended Screen & GPU Acceleration is disabled".into());
                    }
                    if !self.display_ctrl.is_active().await && self.display_ctrl.get_active_mode().await.is_none() {
                        if self.features.is_enabled("input_kvm") || self.features.is_enabled("input") {
                            self.features.set_flag("input_kvm", false);
                            self.features.set_flag("input", false);
                            self.kvm.force_release_all(true);
                            tracing::info!("🖥️ Screen extension (Mac -> PC) starting: automatically disabled KVM to prevent cursor capture conflicts.");
                        }
                    }
                    let msg = self
                        .display_ctrl
                        .toggle_mac_to_pc()
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "toggle_pc_to_mac" => {
                    if !self.features.is_enabled("display") {
                        return Err("Extended Screen & GPU Acceleration is disabled".into());
                    }
                    if !self.display_ctrl.is_active().await && self.display_ctrl.get_active_mode().await.is_none() {
                        if self.features.is_enabled("input_kvm") || self.features.is_enabled("input") {
                            self.features.set_flag("input_kvm", false);
                            self.features.set_flag("input", false);
                            self.kvm.force_release_all(true);
                            tracing::info!("🖥️ Screen extension (PC -> Mac) starting: automatically disabled KVM to prevent cursor capture conflicts.");
                        }
                    }
                    let msg = self
                        .display_ctrl
                        .toggle_pc_to_mac()
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "open_cache_folder" => {
                    open_app_data_folder();
                    Ok(serde_json::json!(true))
                }
                "hide_window" => {
                    emit_ui_event("hide_window", "{}");
                    Ok(serde_json::json!(true))
                }
                "set_window_visible" => {
                    emit_ui_event("show_window", "{}");
                    Ok(serde_json::json!(true))
                }
                "quit_app" => {
                    self.kvm.force_release_all(true);
                    std::process::exit(0);
                }
                "set_gpu_preferences" => {
                    #[allow(dead_code)]
                    #[derive(Deserialize)]
                    struct GpuArgs {
                        #[serde(alias = "encodeGpu")]
                        encode_gpu: String,
                        #[serde(alias = "decodeGpu")]
                        decode_gpu: String,
                    }
                    let args: GpuArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    #[cfg(target_os = "windows")]
                    {
                        tokio::task::spawn_blocking(move || {
                            crate::display::win_display::WinDisplayManager::set_gpu_preferences(
                                &args.encode_gpu,
                                &args.decode_gpu,
                            )
                        })
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                        Ok(serde_json::json!("Updated GPU encode/decode preferences"))
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        let _ = args;
                        Ok(serde_json::json!("macOS uses Apple Unified Silicon VideoToolbox"))
                    }
                }
                "run_speed_test" => {
                    if !self.features.is_enabled("benchmark") {
                        return Err("Network speed benchmark is disabled by master switch".into());
                    }
                    let peer_ip = self
                        .discovery
                        .get_peer_ip()
                        .await
                        .ok_or_else(|| "No connected peer for speed benchmark".to_string())?;
                    let r = benchmark::BenchmarkClient::run_test(&peer_ip, &self.features)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(r).map_err(|e| e.to_string())?)
                }
                "get_gpu_telemetry" => {
                    let t_opt = if cfg!(target_os = "windows") {
                        tokio::task::spawn_blocking(telemetry::query_gpu_telemetry)
                            .await
                            .unwrap_or(None)
                    } else if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::GetGpuTelemetry,
                        )
                        .await
                        .ok()
                        .and_then(|r| r.gpu_telemetry)
                    } else {
                        None
                    };
                    Ok(serde_json::to_value(t_opt).map_err(|e| e.to_string())?)
                }
                "toggle_touchbar_hud" => {
                    #[cfg(target_os = "macos")]
                    {
                        if !self.features.is_enabled("touchbar") {
                            return Err("Touch Bar HUD is disabled by master switch".into());
                        }
                        if !system_info::has_touch_bar_hardware() {
                            return Err("No Touch Bar hardware detected on this Mac".into());
                        }
                        let active = unsafe { is_touchbar_active_in_app() };
                        if active {
                            unsafe { dismiss_touchbar_in_app() };
                            Ok(serde_json::json!(false))
                        } else {
                            let peer_ip = self.discovery.get_peer_ip().await;
                            unsafe {
                                set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                                set_touchbar_tray_enabled_in_app(true);
                                if let Some(ip) = peer_ip.and_then(|s| CString::new(s).ok()) {
                                    init_touchbar_in_app(ip.as_ptr());
                                } else {
                                    init_touchbar_in_app(std::ptr::null());
                                }
                            }
                            Ok(serde_json::json!(true))
                        }
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        Err("Touch Bar HUD is only supported on macOS".into())
                    }
                }
                "paste_remote" => {
                    let msg = self
                        .clipboard
                        .paste_remote(None)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "get_ambient_light" => {
                    let data = if !self.features.is_enabled("truetone") {
                        truetone::AmbientLightData {
                            lux: 0.0,
                            cct_kelvin: config::D65_CCT_KELVIN,
                            supported: false,
                            updated_at_secs: 0,
                        }
                    } else {
                        let als = tokio::task::spawn_blocking(truetone::read_ambient_light)
                            .await
                            .unwrap_or(truetone::AmbientLightData {
                                lux: 0.0,
                                cct_kelvin: config::D65_CCT_KELVIN,
                                supported: false,
                                updated_at_secs: 0,
                            });
                        if !als.supported || !als.lux.is_finite() || als.lux < 0.0 {
                            truetone::AmbientLightData {
                                lux: 0.0,
                                cct_kelvin: config::D65_CCT_KELVIN,
                                supported: false,
                                updated_at_secs: 0,
                            }
                        } else {
                            als
                        }
                    };
                    Ok(serde_json::to_value(data).map_err(|e| e.to_string())?)
                }
                "apply_truetone_calibration" => {
                    if !self.features.is_enabled("truetone") {
                        return Err("True Tone & Chromatic Sync is disabled".into());
                    }
                    #[derive(Deserialize)]
                    struct TtArgs {
                        cct: u32,
                        #[serde(alias = "compFactor")]
                        comp_factor: f32,
                    }
                    let args: TtArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    if !(config::MIN_CCT_KELVIN..=config::MAX_CCT_KELVIN).contains(&args.cct) {
                        return Err(format!(
                            "Invalid color temperature {}K (must be {}..={}K)",
                            args.cct,
                            config::MIN_CCT_KELVIN,
                            config::MAX_CCT_KELVIN
                        ));
                    }
                    if !args.comp_factor.is_finite()
                        || !(config::MIN_GAMMA_COMP_FACTOR..=config::MAX_GAMMA_COMP_FACTOR)
                            .contains(&args.comp_factor)
                    {
                        return Err(format!(
                            "Invalid gamma compensation factor {} (must be {}..={})",
                            args.comp_factor,
                            config::MIN_GAMMA_COMP_FACTOR,
                            config::MAX_GAMMA_COMP_FACTOR
                        ));
                    }
                    if cfg!(target_os = "windows") {
                        let cct = args.cct;
                        let comp = args.comp_factor;
                        tokio::task::spawn_blocking(move || {
                            truetone::apply_hardware_gamma_ramp(cct, comp)
                        })
                        .await
                        .map_err(|e| format!("TrueTone task panicked: {}", e))?
                        .map_err(|e| e.to_string())?;
                        Ok(serde_json::json!(format!(
                            "Injected Bradford CAT Gamma LUT on Windows: {}K ({:.2}x)",
                            args.cct, args.comp_factor
                        )))
                    } else {
                        let peer_ip = self
                            .discovery
                            .get_peer_ip()
                            .await
                            .ok_or_else(|| "No peer connected to sync True Tone calibration".to_string())?;
                        let als = tokio::task::spawn_blocking(truetone::read_ambient_light)
                            .await
                            .unwrap_or(truetone::AmbientLightData {
                                lux: 0.0,
                                cct_kelvin: config::D65_CCT_KELVIN,
                                supported: false,
                                updated_at_secs: 0,
                            });
                        let lux = if als.supported && als.lux.is_finite() && als.lux >= 0.0 {
                            als.lux
                        } else {
                            0.0
                        };
                        let rpc = DisplayRpcRequest::SyncTrueTone {
                            lux,
                            cct: args.cct,
                            gamma_comp: args.comp_factor,
                        };
                        let resp = DisplayController::send_remote_rpc(&peer_ip, &rpc)
                            .await
                            .map_err(|e| e.to_string())?;
                        if resp.success {
                            Ok(serde_json::json!(resp.message))
                        } else {
                            Err(resp.message)
                        }
                    }
                }
                "mount_shared_storage" => {
                    if !self.features.is_enabled("storage") {
                        return Err("Auto-Mounted Shared Storage is disabled".into());
                    }
                    let peer = self
                        .discovery
                        .get_best_peer()
                        .await
                        .ok_or_else(|| "No peer connected to mount shared storage".to_string())?;
                    let peer_ip = peer.addr.ip().to_string();
                    let peer_share = peer.share_name;
                    let mount_ip = peer_ip.clone();
                    let status = tokio::task::spawn_blocking(move || {
                        storage::StorageManager::mount_with_share(&mount_ip, peer_share.as_deref())
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                    tokio::spawn(async move {
                        let _ = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::MountStorage,
                        )
                        .await;
                    });
                    Ok(serde_json::to_value(status).map_err(|e| e.to_string())?)
                }
                "unmount_shared_storage" => {
                    let status = tokio::task::spawn_blocking(storage::StorageManager::unmount)
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                    if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        tokio::spawn(async move {
                            let _ = DisplayController::send_remote_rpc(
                                &peer_ip,
                                &DisplayRpcRequest::UnmountStorage,
                            )
                            .await;
                        });
                    }
                    Ok(serde_json::to_value(status).map_err(|e| e.to_string())?)
                }
                "get_storage_status" => {
                    let best = self.discovery.get_best_peer().await;
                    let pip = best.as_ref().map(|p| p.addr.ip().to_string());
                    let psh = best.and_then(|p| p.share_name);
                    let st = tokio::task::spawn_blocking(move || {
                        storage::StorageManager::status_with_share(pip.as_deref(), psh.as_deref())
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(st).map_err(|e| e.to_string())?)
                }
                "play_spatial_chime" => {
                    if !self.features.is_enabled("audio") {
                        return Err("Dynamic Audio Routing is disabled".into());
                    }
                    let msg = tokio::task::spawn_blocking(audio::AudioManager::play_spatial_test_chime)
                        .await
                        .map_err(|e| format!("Audio chime task panicked: {}", e))?
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "get_feature_flags" => {
                    Ok(serde_json::to_value(self.features.get_flags()).map_err(|e| e.to_string())?)
                }
                "set_feature_flag" => {
                    #[derive(Deserialize)]
                    struct FlagArgs {
                        feature: String,
                        enabled: bool,
                    }
                    let args: FlagArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let feat = args.feature.trim();
                    let flags = self.features.set_flag_checked(feat, args.enabled)?;
                    if feat == "camera" {
                        self.camera.sync_with_feature_flag(args.enabled).await;
                    } else if args.enabled {
                        if matches!(feat, "input_kvm" | "input") {
                            if self.display_ctrl.is_active().await
                                || self.display_ctrl.get_active_mode().await.is_some()
                            {
                                let _ = self.display_ctrl.stop_mac_to_pc().await;
                                let _ = self.display_ctrl.stop_pc_to_mac().await;
                                tracing::info!("⌨️🖱️ KVM enabled: automatically stopped active screen extension.");
                            }
                        } else if feat == "touchbar" {
                            #[cfg(target_os = "macos")]
                            if system_info::has_touch_bar_hardware() {
                                unsafe {
                                    set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                                    set_touchbar_tray_enabled_in_app(true);
                                }
                            }
                        }
                    } else {
                        match feat {
                            "display" => {
                                if self.display_ctrl.is_active().await
                                    || self.display_ctrl.get_active_mode().await.is_some()
                                {
                                    let _ = self.display_ctrl.stop_mac_to_pc().await;
                                    let _ = self.display_ctrl.stop_pc_to_mac().await;
                                }
                            }
                            "storage" => {
                                let _ = tokio::task::spawn_blocking(storage::StorageManager::unmount).await;
                            }
                            "truetone" => {
                                let _ = tokio::task::spawn_blocking(truetone::reset_hardware_gamma_ramp).await;
                            }
                            "touchbar" => {
                                #[cfg(target_os = "macos")]
                                if system_info::has_touch_bar_hardware() {
                                    unsafe {
                                        dismiss_touchbar_in_app();
                                        set_touchbar_tray_enabled_in_app(false);
                                    }
                                }
                            }
                            "input_kvm" | "input" | "dragdrop" | "clipboard" => {
                                if matches!(feat, "input_kvm" | "input") {
                                    self.kvm.force_release_all(true);
                                }
                                if !self.features.is_enabled("clipboard")
                                    && !self.features.is_enabled("dragdrop")
                                {
                                    self.clipboard.clear_pending_state().await;
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(serde_json::to_value(flags).map_err(|e| e.to_string())?)
                }
                "toggle_camera" => {
                    let msg = self.camera.toggle().await?;
                    Ok(serde_json::json!(msg))
                }
                "start_camera" => {
                    let msg = self.camera.start().await?;
                    Ok(serde_json::json!(msg))
                }
                "stop_camera" => {
                    self.camera.stop().await;
                    Ok(serde_json::json!("Shared Camera stopped"))
                }
                "get_kvm_status" => {
                    Ok(serde_json::to_value(self.kvm.get_status_snapshot()).map_err(|e| e.to_string())?)
                }
                "set_kvm_layout" => {
                    #[derive(Deserialize)]
                    struct LayoutArgs {
                        layout: KvmLayoutConfig,
                    }
                    let cfg: KvmLayoutConfig = if params_val.get("layout").is_some() {
                        serde_json::from_value::<LayoutArgs>(params_val)
                            .map_err(|e| e.to_string())?
                            .layout
                    } else {
                        serde_json::from_value::<KvmLayoutConfig>(params_val)
                            .map_err(|e| e.to_string())?
                    };
                    let saved = self.kvm.update_layout(cfg).map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(saved).map_err(|e| e.to_string())?)
                }
                "release_kvm_control" => {
                    self.kvm.force_release_all(true);
                    Ok(serde_json::json!("Released remote KVM control"))
                }
                "request_kvm_accessibility" => {
                    #[cfg(target_os = "macos")]
                    {
                        let trusted = tokio::task::spawn_blocking(
                            crate::kvm::macos_backend::request_accessibility,
                        )
                        .await
                        .unwrap_or(false);
                        if !trusted {
                            let mut cmd = std::process::Command::new(config::MACOS_OPEN_BIN);
                            cmd.arg(MACOS_ACCESSIBILITY_SETTINGS_URL);
                            spawn_and_reap(cmd);
                        }
                        Ok(serde_json::json!(if trusted {
                            "Accessibility permission verified and KVM hook active"
                        } else {
                            "Opened macOS Accessibility settings — toggle Integrator ON"
                        }))
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        Ok(serde_json::json!("KVM input hooks ready"))
                    }
                }
                "get_autostart" => {
                    let b = tokio::task::spawn_blocking(autostart::AutostartManager::is_enabled)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(b))
                }
                "set_autostart" => {
                    #[derive(Deserialize)]
                    struct AutoArgs {
                        enabled: bool,
                    }
                    let args: AutoArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let b = tokio::task::spawn_blocking(move || {
                        autostart::AutostartManager::set_enabled(args.enabled)
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(b))
                }
                "add_manual_peer_ip" => {
                    #[derive(Deserialize)]
                    struct IpArgs {
                        ip: String,
                    }
                    let args: IpArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    self.discovery
                        .add_manual_peer_ip(&args.ip)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(self.discovery.get_manual_peer_ips().await)
                        .map_err(|e| e.to_string())?)
                }
                "remove_manual_peer_ip" => {
                    #[derive(Deserialize)]
                    struct IpArgs {
                        ip: String,
                    }
                    let args: IpArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    self.discovery.remove_manual_peer_ip(&args.ip).await;
                    Ok(serde_json::to_value(self.discovery.get_manual_peer_ips().await)
                        .map_err(|e| e.to_string())?)
                }
                "set_auto_mount_storage" => {
                    #[derive(Deserialize)]
                    struct AutoMountArgs {
                        enabled: bool,
                    }
                    let args: AutoMountArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let res = tokio::task::spawn_blocking(move || {
                        storage::StorageManager::set_auto_mount_on_peer_detect(args.enabled)
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(res))
                }
                "set_preferred_peer_share" => {
                    #[derive(Deserialize)]
                    struct ShareArgs {
                        share: Option<String>,
                    }
                    let args: ShareArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let res = tokio::task::spawn_blocking(move || {
                        storage::StorageManager::set_preferred_peer_share(args.share.as_deref())
                            .map_err(|e| e.to_string())?;
                        Ok::<_, String>(storage::StorageManager::get_preferred_peer_share())
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::to_value(res).map_err(|e| e.to_string())?)
                }
                "set_local_shared_folder" => {
                    #[derive(Deserialize)]
                    struct FolderArgs {
                        folder: Option<String>,
                    }
                    let args: FolderArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let res = tokio::task::spawn_blocking(move || {
                        storage::StorageManager::set_local_shared_folder(args.folder.as_deref())
                            .map_err(|e| e.to_string())?;
                        Ok::<_, String>(storage::StorageManager::get_local_shared_folder())
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::to_value(res).map_err(|e| e.to_string())?)
                }
                "get_local_shared_folder" => {
                    let res = tokio::task::spawn_blocking(storage::StorageManager::get_local_shared_folder)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(res).map_err(|e| e.to_string())?)
                }
                "open_shared_storage" => {
                    tokio::task::spawn_blocking(storage::StorageManager::open_mounted_storage)
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!("Opened mounted shared storage folder"))
                }
                "trust_peer_device" => {
                    #[derive(Deserialize)]
                    struct TrustArgs {
                        #[serde(alias = "deviceId")]
                        device_id: String,
                        hostname: String,
                        ip: String,
                    }
                    let args: TrustArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let cid = args.device_id.trim();
                    if cid.is_empty() {
                        return Err("Device ID cannot be empty".into());
                    }
                    let cip = args.ip.trim();
                    if !cip.is_empty() && !system_info::is_valid_ipv4(cip) {
                        return Err(format!("Invalid peer IPv4 address: {}", args.ip));
                    }
                    if !trust::is_device_trusted(cid) {
                        return Err("Integrator v1.0 requires cryptographic PIN pairing (SPAKE2 + Ed25519) before trusting a peer.".into());
                    }
                    Ok(serde_json::json!(format!("Verified paired peer {} ({})", args.hostname.trim(), cip)))
                }
                "untrust_or_block_peer" => {
                    #[derive(Deserialize)]
                    struct BlockArgs {
                        #[serde(alias = "deviceId")]
                        device_id: String,
                        block: bool,
                    }
                    let args: BlockArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let cid = args.device_id.trim();
                    if cid.is_empty() {
                        return Err("Device ID cannot be empty".into());
                    }
                    trust::untrust_or_block_device(cid, args.block)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(if args.block {
                        format!("Blocked device {}", cid)
                    } else {
                        format!("Removed trust for device {}", cid)
                    }))
                }
                "unpair_peer" => {
                    #[derive(Deserialize)]
                    struct UnpairArgs {
                        #[serde(alias = "deviceId")]
                        device_id: String,
                    }
                    let args: UnpairArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let cid = args.device_id.trim();
                    if cid.is_empty() {
                        return Err("Device ID cannot be empty".into());
                    }
                    let removed = trust::unpair_device(cid)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(if removed {
                        format!("Unpaired device {}", cid)
                    } else {
                        format!("Device {} was not paired", cid)
                    }))
                }
                "regenerate_pairing_pin" => Ok(serde_json::json!(trust::regenerate_pin())),
                "set_trust_policy" => {
                    #[derive(Deserialize)]
                    struct PolicyArgs {
                        #[serde(alias = "autoTrustCable", default)]
                        auto_trust_cable: bool,
                        #[serde(alias = "requireLanPairing", default = "default_true")]
                        require_lan_pairing: bool,
                    }
                    fn default_true() -> bool {
                        true
                    }
                    let args: PolicyArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    trust::set_trust_policy(args.auto_trust_cable, args.require_lan_pairing);
                    Ok(serde_json::json!("Integrator v1.0 enforces mandatory cryptographic pairing on all interfaces"))
                }
                "pair_with_peer" => {
                    #[derive(Deserialize)]
                    struct PairArgs {
                        ip: String,
                        pin: String,
                    }
                    let args: PairArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let tip = args.ip.trim().to_string();
                    if !system_info::is_valid_ipv4(&tip) {
                        return Err(format!("Invalid peer IPv4 address: {}", args.ip));
                    }
                    let tpin = args.pin.trim().to_string();
                    if tpin.len() != config::PAIRING_PIN_LENGTH
                        || !tpin.chars().all(|c| c.is_ascii_digit())
                    {
                        return Err(format!(
                            "Pairing PIN must be {} digits",
                            config::PAIRING_PIN_LENGTH
                        ));
                    }
                    let (creds, sas_6) =
                        trust::pair_with_remote_peer_v2(&tip, config::CONTROL_PORT, &tpin).await?;
                    Ok(serde_json::json!(format!(
                        "Paired with {} ({}) [SAS: {}]",
                        creds.hostname, tip, sas_6
                    )))
                }
                "get_setup_status" => {
                    let cam_enabled = self.features.is_enabled("camera");
                    let has_peers = !self.discovery.get_all_peers().await.is_empty();
                    let snap = tokio::task::spawn_blocking(move || {
                        crate::setup::invalidate_setup_cache();
                        crate::setup::collect_setup_health_snapshot(cam_enabled, has_peers)
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                    Ok(serde_json::to_value(snap).map_err(|e| e.to_string())?)
                }
                "request_permission" => {
                    #[derive(Deserialize)]
                    struct PermArgs {
                        id: String,
                    }
                    let args: PermArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let msg = tokio::task::spawn_blocking(move || {
                        crate::setup::request_permission(&args.id)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::json!(msg))
                }
                "request_all_missing_permissions" => {
                    let cam_enabled = self.features.is_enabled("camera");
                    let has_peers = !self.discovery.get_all_peers().await.is_empty();
                    let msg = tokio::task::spawn_blocking(move || {
                        crate::setup::request_all_missing_permissions(cam_enabled, has_peers)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::json!(msg))
                }
                "open_permission_settings" => {
                    #[derive(Deserialize)]
                    struct OpenPermArgs {
                        id: String,
                    }
                    let args: OpenPermArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let msg = tokio::task::spawn_blocking(move || {
                        crate::setup::open_permission_settings(&args.id)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::json!(msg))
                }
                "install_dependency" => {
                    #[derive(Deserialize)]
                    struct DepArgs {
                        id: String,
                    }
                    let args: DepArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let msg = tokio::task::spawn_blocking(move || {
                        crate::setup::install_dependency(&args.id)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::json!(msg))
                }
                "set_suppress_launch_setup_prompt" => {
                    #[derive(Deserialize)]
                    struct SuppressArgs {
                        suppress: bool,
                    }
                    let args: SuppressArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let saved = tokio::task::spawn_blocking(move || {
                        crate::setup::set_suppress_launch_setup_prompt(args.suppress)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    Ok(serde_json::json!(saved))
                }
                "verify_touchid" => {
                    let _ = self.features.set_flag_checked("touchid", true);
                    let challenge_nonce_hex = trust::generate_random_token_hex(32);
                    let my_device_id = trust::local_device_id_hex();
                    let my_hostname = system_info::get_hostname();
                    let started = std::time::Instant::now();

                    if cfg!(target_os = "macos") {
                        let nonce_clone = challenge_nonce_hex.clone();
                        let dev_clone = my_device_id.clone();
                        let host_clone = my_hostname.clone();
                        let assertion = tokio::task::spawn_blocking(move || {
                            trust::evaluate_local_touchid_and_sign(&nonce_clone, &dev_clone, &host_clone)
                        })
                        .await
                        .map_err(|e| format!("Touch ID task panicked: {}", e))??;
                        trust::verify_touchid_assertion(
                            &assertion,
                            &challenge_nonce_hex,
                            &my_device_id,
                            &my_device_id,
                        )?;
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                        Ok(serde_json::json!(format!(
                            "Touch ID Secure Enclave verified on '{}' in {:.0} ms [Ed25519 sig: {}…]",
                            assertion.signer_hostname,
                            elapsed_ms,
                            assertion.signature_hex.chars().take(16).collect::<String>()
                        )))
                    } else {
                        let peer = self
                            .discovery
                            .get_best_peer()
                            .await
                            .ok_or_else(|| "No paired Mac discovered to request Touch ID verification".to_string())?;
                        let peer_ip = peer.addr.ip().to_string();
                        let peer_dev_id = peer.device_id.clone();
                        let rpc = DisplayRpcRequest::VerifyTouchId {
                            challenge_nonce_hex: challenge_nonce_hex.clone(),
                            requester_hostname: my_hostname,
                        };
                        let resp = DisplayController::send_remote_rpc(&peer_ip, &rpc)
                            .await
                            .map_err(|e| e.to_string())?;
                        if !resp.success {
                            return Err(resp.message);
                        }
                        let assertion = resp
                            .touchid_assertion
                            .ok_or_else(|| "Mac peer returned success without a signed Touch ID assertion".to_string())?;
                        trust::verify_touchid_assertion(
                            &assertion,
                            &challenge_nonce_hex,
                            &my_device_id,
                            &peer_dev_id,
                        )?;
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                        Ok(serde_json::json!(format!(
                            "Touch ID verified on '{}' ({}) in {:.0} ms [Ed25519 sig: {}…]",
                            assertion.signer_hostname,
                            peer_ip,
                            elapsed_ms,
                            assertion.signature_hex.chars().take(16).collect::<String>()
                        )))
                    }
                }
                "passkey_list" => {
                    let creds = tokio::task::spawn_blocking(crate::security::passkey::list_resident_passkeys)
                        .await
                        .map_err(|e| e.to_string())??;
                    Ok(serde_json::to_value(creds).map_err(|e| e.to_string())?)
                }
                "passkey_get_info" => {
                    let bytes = crate::security::passkey::get_info_cbor_bytes();
                    let hex = crate::security::hex_encode(&bytes);
                    Ok(serde_json::json!({
                        "cbor_hex": hex,
                        "aaguid": crate::security::hex_encode(&crate::security::passkey::INTEGRATOR_AAGUID),
                    }))
                }
                "passkey_make_credential_remote" => {
                    #[derive(Deserialize)]
                    struct MakeRemoteArgs {
                        peer_ip: Option<String>,
                        request: crate::security::passkey::PasskeyMakeCredentialRequest,
                    }
                    let args: MakeRemoteArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let target_ip = match args.peer_ip {
                        Some(ip) => ip,
                        None => {
                            let peer = self
                                .discovery
                                .get_best_peer()
                                .await
                                .ok_or_else(|| "No paired Mac discovered for passkey registration".to_string())?;
                            peer.addr.ip().to_string()
                        }
                    };
                    let rpc = DisplayRpcRequest::PasskeyMakeCredential(args.request);
                    let resp = DisplayController::send_remote_rpc(&target_ip, &rpc)
                        .await
                        .map_err(|e| e.to_string())?;
                    if !resp.success {
                        return Err(resp.message);
                    }
                    let cred = resp.passkey_credential
                        .ok_or_else(|| "Remote Mac returned success without passkey credential".to_string())?;
                    Ok(serde_json::to_value(cred).map_err(|e| e.to_string())?)
                }
                "passkey_get_assertion_remote" => {
                    #[derive(Deserialize)]
                    struct AssertRemoteArgs {
                        peer_ip: Option<String>,
                        request: crate::security::passkey::PasskeyGetAssertionRequest,
                    }
                    let args: AssertRemoteArgs =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let target_ip = match args.peer_ip {
                        Some(ip) => ip,
                        None => {
                            let peer = self
                                .discovery
                                .get_best_peer()
                                .await
                                .ok_or_else(|| "No paired Mac discovered for passkey sign-in".to_string())?;
                            peer.addr.ip().to_string()
                        }
                    };
                    let rpc = DisplayRpcRequest::PasskeyGetAssertion(args.request);
                    let resp = DisplayController::send_remote_rpc(&target_ip, &rpc)
                        .await
                        .map_err(|e| e.to_string())?;
                    if !resp.success {
                        return Err(resp.message);
                    }
                    let assertion = resp.passkey_assertion
                        .ok_or_else(|| "Remote Mac returned success without passkey assertion".to_string())?;
                    Ok(serde_json::to_value(assertion).map_err(|e| e.to_string())?)
                }
                "set_display_mode" => {
                    #[derive(Deserialize)]
                    struct ModeArgs {
                        #[serde(default)]
                        width: u32,
                        #[serde(default)]
                        height: u32,
                        #[serde(default = "default_mode_fps")]
                        fps: u32,
                        #[serde(default)]
                        hdr: bool,
                    }
                    fn default_mode_fps() -> u32 { 120 }
                    let args: ModeArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let msg = self
                        .display_ctrl
                        .set_display_mode(args.width, args.height, args.fps, args.hdr)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(serde_json::json!(msg))
                }
                "toggle_camera_privacy" => {
                    let muted = self.camera.toggle_privacy_muted();
                    Ok(serde_json::json!({ "privacy_muted": muted }))
                }
                "set_camera_privacy" => {
                    #[derive(Deserialize)]
                    struct PrivacyArgs {
                        muted: bool,
                    }
                    let args: PrivacyArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let muted = self.camera.set_privacy_muted(args.muted);
                    Ok(serde_json::json!({ "privacy_muted": muted }))
                }
                "set_audio_mixer" => {
                    #[derive(Deserialize)]
                    struct MixerArgs {
                        #[serde(default)]
                        balance: f32,
                        #[serde(default)]
                        muted: bool,
                    }
                    let args: MixerArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let (bal, muted) = audio::AudioManager::set_mixer(args.balance, args.muted);
                    Ok(serde_json::json!({ "mixer_balance": bal, "sink_muted": muted }))
                }
                "toggle_kvm_boundary_lock" => {
                    let locked = self.kvm.toggle_boundary_locked();
                    if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        let _ = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::SetKvmBoundaryLock { locked },
                        )
                        .await;
                    }
                    Ok(serde_json::json!({ "boundary_locked": locked }))
                }
                "set_kvm_boundary_lock" => {
                    #[derive(Deserialize)]
                    struct LockArgs {
                        locked: bool,
                    }
                    let args: LockArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let locked = self.kvm.set_boundary_locked(args.locked, true);
                    if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        let _ = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::SetKvmBoundaryLock { locked },
                        )
                        .await;
                    }
                    Ok(serde_json::json!({ "boundary_locked": locked }))
                }
                "get_windows_media_state" => {
                    let state = if cfg!(target_os = "windows") {
                        tokio::task::spawn_blocking(crate::media::query_media_state)
                            .await
                            .unwrap_or_default()
                    } else if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetMediaState)
                            .await
                            .ok()
                            .and_then(|r| r.media_state)
                            .unwrap_or_default()
                    } else {
                        crate::media::MediaPlaybackState::default()
                    };
                    Ok(serde_json::to_value(state).map_err(|e| e.to_string())?)
                }
                "send_windows_media_cmd" => {
                    let action: crate::media::MediaControlAction =
                        serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    if cfg!(target_os = "windows") {
                        let msg = tokio::task::spawn_blocking(move || {
                            crate::media::execute_media_command(&action)
                        })
                        .await
                        .map_err(|e| e.to_string())??;
                        Ok(serde_json::json!(msg))
                    } else {
                        let peer_ip = self
                            .discovery
                            .get_peer_ip()
                            .await
                            .ok_or_else(|| "No connected Windows peer for media control".to_string())?;
                        let resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::SendMediaCommand { action },
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        if resp.success {
                            Ok(serde_json::json!(resp.message))
                        } else {
                            Err(resp.message)
                        }
                    }
                }
                "notify_touchid_prompt" => {
                    #[derive(Deserialize)]
                    struct PromptArgs {
                        #[serde(default)]
                        label: String,
                        active: bool,
                    }
                    let args: PromptArgs = serde_json::from_value(params_val).map_err(|e| e.to_string())?;
                    let lbl = if args.label.trim().is_empty() {
                        "Approve Windows Hello Login".to_string()
                    } else {
                        args.label
                    };
                    if cfg!(target_os = "macos") {
                        notify_touchbar_touchid_prompt(&lbl, args.active);
                        Ok(serde_json::json!("Updated Touch Bar Touch ID prompt"))
                    } else if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                        let resp = DisplayController::send_remote_rpc(
                            &peer_ip,
                            &DisplayRpcRequest::NotifyTouchIdPrompt {
                                label: lbl,
                                active: args.active,
                            },
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        if resp.success {
                            Ok(serde_json::json!(resp.message))
                        } else {
                            Err(resp.message)
                        }
                    } else {
                        Err("No paired Mac discovered for Touch ID Touch Bar prompt".into())
                    }
                }
                _ => Err(format!("Unknown native command: {}", method)),
            }
        });

        match res {
            Ok(data) => serde_json::json!({ "ok": true, "data": data }).to_string(),
            Err(err) => wrap_err(err),
        }
    }

    /// Immediately and completely tears down all active subsystem sessions (KVM input streams,
    /// camera capture, display streams, clipboard staging, and UDP audio sessions) associated
    /// with the specified peer device ID hex, awaiting completion of all asynchronous teardown paths.
    ///
    /// Note: Phase A transport sessions were already invalidated and terminated during keystore
    /// trust invalidation at the synchronized trust generation. Phase B (this function) runs
    /// outside the keystore lock and must NOT double-increment or desynchronize trust generations.
    pub async fn terminate_peer_connections_async(&self, device_id_hex: &str, target_generation: u64) -> Result<(), String> {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        tracing::info!("🛑 Terminating all active subsystem sessions for peer {} at gen {} (async/awaited)", clean_id, target_generation);

        // 1. Tear down active KVM session if connected to this peer
        self.kvm.teardown_peer_if_connected(&clean_id);

        // 2. Stop camera capture and reset consent specifically for this peer - AWAITED!
        if let Err(e) = self.camera.teardown_peer_stream_async(&clean_id).await {
            tracing::warn!("Error tearing down camera stream for peer {}: {}", clean_id, e);
            return Err(format!("Camera teardown failed for peer {}: {}", clean_id, e));
        }

        // 3. Immediately evict all active UDP audio sessions for this peer
        crate::audio::AudioManager::revoke_peer_audio_sessions(&clean_id);

        // 4. Teardown active Display streams owned by this peer (Moonlight client or Sunshine host) - AWAITED!
        if let Err(e) = self.display_ctrl.teardown_peer_display(&clean_id).await {
            tracing::warn!("Error tearing down display session for revoked peer {}: {}", clean_id, e);
            return Err(format!("Display teardown failed for peer {}: {}", clean_id, e));
        }

        // 5. Purge clipboard pending remote data and active drag sessions scoped to this peer and generation - AWAITED!
        self.clipboard.clear_peer_remote_state_bounded_async(&clean_id, target_generation).await;

        Ok(())
    }

    /// Immediately tears down all active subsystem sessions (KVM input streams, camera capture,
    /// display streams, clipboard staging, and UDP audio) associated with the specified peer device ID hex.
    ///
    /// Synchronous convenience wrapper for non-async execution contexts.
    pub fn terminate_peer_connections(&self, device_id_hex: &str, target_generation: u64) {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        tracing::info!("🛑 Terminating all active subsystem sessions for peer {} at gen {}", clean_id, target_generation);

        // 1. Tear down active KVM session if connected to this peer
        self.kvm.teardown_peer_if_connected(&clean_id);

        // 2. Stop camera capture and reset consent specifically for this peer
        self.camera.teardown_peer_stream(&clean_id);

        // 3. Immediately evict all active UDP audio sessions for this peer
        crate::audio::AudioManager::revoke_peer_audio_sessions(&clean_id);

        // 4. Purge clipboard pending remote data and active drag sessions scoped to this peer and generation
        self.clipboard.clear_peer_remote_state_bounded(&clean_id, target_generation);

        // 5. Teardown active Display streams owned by this peer (Moonlight client or Sunshine host)
        let display = self.display_ctrl.clone();
        let cid = clean_id.clone();
        self.rt.spawn(async move {
            if let Err(e) = display.teardown_peer_display(&cid).await {
                tracing::warn!("Error tearing down display session for revoked peer {}: {}", cid, e);
            }
        });
    }

    /// Shuts down all active services, releasing system hooks and closing sockets.
    pub fn shutdown(&self) {
        #[cfg(target_os = "macos")]
        if system_info::has_touch_bar_hardware() {
            unsafe {
                dismiss_touchbar_in_app();
                set_touchbar_tray_enabled_in_app(false);
            }
        }
        self.camera.shutdown_sync();
        self.kvm.shutdown();
        register_ui_callback(None);
    }

    /// Triggers a system menu bar / tray action.
    ///
    /// # Supported Actions:
    /// - `"paste_remote"`: Initiates remote clipboard paste operation.
    /// - `"toggle_display"`: Starts or stops screen extension streaming.
    /// - `"toggle_touchbar"`: Shows or hides the macOS Touch Bar HUD strip.
    /// - `"open_cache"`: Reveals application data folder in file manager.
    /// - `"quit"`: Releases input locks and emits application exit event.
    pub fn trigger_tray_action(&self, action: &str) {
        match action {
            "paste_remote" => {
                let cb = self.clipboard.clone();
                self.rt.spawn(async move {
                    match cb.paste_remote(None).await {
                        Ok(msg) => emit_ui_toast("success", &msg),
                        Err(e) => emit_ui_toast("error", &format!("Remote paste failed: {}", e)),
                    }
                });
            }
            "toggle_display" => {
                if !self.features.is_enabled("display") {
                    emit_ui_toast("error", "Display Extension & Mirroring is disabled");
                    return;
                }
                let ctrl = self.display_ctrl.clone();
                self.rt.spawn(async move {
                    let res = if cfg!(target_os = "macos") {
                        ctrl.toggle_mac_to_pc().await
                    } else {
                        ctrl.toggle_pc_to_mac().await
                    };
                    match res {
                        Ok(msg) => emit_ui_toast("success", &msg),
                        Err(e) => emit_ui_toast("error", &e.to_string()),
                    }
                });
            }
            "toggle_touchbar" => {
                #[cfg(target_os = "macos")]
                {
                    if !self.features.is_enabled("touchbar") {
                        emit_ui_toast("error", "Touch Bar HUD is disabled by master switch");
                        return;
                    }
                    if !system_info::has_touch_bar_hardware() {
                        emit_ui_toast("info", "No Apple Touch Bar detected on this Mac");
                        return;
                    }
                    let disc = self.discovery.clone();
                    self.rt.spawn(async move {
                        let active = unsafe { is_touchbar_active_in_app() };
                        if active {
                            unsafe { dismiss_touchbar_in_app() };
                        } else {
                            let peer_ip = disc.get_peer_ip().await;
                            unsafe {
                                set_touchbar_rpc_port_in_app(config::CONTROL_PORT);
                                set_touchbar_tray_enabled_in_app(true);
                                if let Some(ip) = peer_ip.and_then(|s| CString::new(s).ok()) {
                                    init_touchbar_in_app(ip.as_ptr());
                                } else {
                                    init_touchbar_in_app(std::ptr::null());
                                }
                            }
                        }
                    });
                }
            }
            "open_cache" => open_app_data_folder(),
            "quit" => {
                self.kvm.force_release_all(true);
                emit_ui_event("quit", "{}");
            }
            _ => {}
        }
    }
}

/// Formats an error string into a standard JSON error envelope `{"ok": false, "error": ...}`.
fn wrap_err(msg: String) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Converts a raw C-string pointer (`*const c_char`) into an owned Rust `String`.
///
/// Returns an empty string if `ptr` is null, or lossy UTF-8 if invalid sequences are encountered.
pub fn c_str_to_rust(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Pointer is non-null and assumed to point to a NUL-terminated C string.
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_ports_format_from_canonical_config() {
        assert_eq!(
            format_firewall_ports(&config::TCP_SERVICE_PORTS),
            format!(
                "{},{},{},{},{}",
                config::CONTROL_PORT,
                config::CLIPBOARD_PORT,
                config::TELEMETRY_PORT,
                config::INPUT_PORT,
                config::CAMERA_PORT
            )
        );
        assert_eq!(
            format_firewall_ports(&config::UDP_SERVICE_PORTS),
            format!("{},{}", config::DISCOVERY_PORT, config::AUDIO_PORT)
        );
        assert_eq!(
            format_firewall_ports(&config::SMB_SERVICE_PORTS),
            format!("{},{}", config::SMB_TCP_PORT, config::NETBIOS_SSN_PORT)
        );
    }

    #[test]
    fn dynamic_windows_firewall_scopes_combine_adapters_and_validated_extras() {
        let ifaces = vec![
            system_info::LocalInterfaceInfo {
                name: "Ethernet 2".into(),
                friendly_name: "USB-C Direct".into(),
                ip: "10.99.99.2".into(),
                netmask: "255.255.255.0".into(),
                broadcast: "10.99.99.255".into(),
                cidr_prefix: 24,
                transport: system_info::LinkTransport::DirectUsb,
                link_speed_mbps: None,
                description: "USB-C Direct".into(),
            },
            system_info::LocalInterfaceInfo {
                name: "Wi-Fi".into(),
                friendly_name: "Wi-Fi".into(),
                ip: "192.168.50.42".into(),
                netmask: "255.255.252.0".into(),
                broadcast: "192.168.51.255".into(),
                cidr_prefix: 22,
                transport: system_info::LinkTransport::Wifi,
                link_speed_mbps: None,
                description: "Wi-Fi".into(),
            },
            system_info::LocalInterfaceInfo {
                name: "Wi-Fi 2".into(),
                friendly_name: "iPhone Personal Hotspot".into(),
                ip: "172.20.10.7".into(),
                netmask: "255.255.255.240".into(),
                broadcast: "172.20.10.15".into(),
                cidr_prefix: 28,
                transport: system_info::LinkTransport::Hotspot,
                link_speed_mbps: Some(866),
                description: "Mobile Hotspot".into(),
            },
            system_info::LocalInterfaceInfo {
                name: "Local Area Connection* 10".into(),
                friendly_name: "Microsoft Wi-Fi Direct Virtual Adapter".into(),
                ip: "192.168.137.1".into(),
                netmask: "255.255.255.0".into(),
                broadcast: "192.168.137.255".into(),
                cidr_prefix: 24,
                transport: system_info::LinkTransport::Hotspot,
                link_speed_mbps: Some(866),
                description: "Mobile Hotspot".into(),
            },
            system_info::LocalInterfaceInfo {
                name: "Thunderbolt".into(),
                friendly_name: "Thunderbolt Bridge".into(),
                ip: "169.254.10.2".into(),
                netmask: "255.255.0.0".into(),
                broadcast: "169.254.255.255".into(),
                cidr_prefix: 16,
                transport: system_info::LinkTransport::Thunderbolt,
                link_speed_mbps: None,
                description: "Thunderbolt".into(),
            },
            // Virtual / VPN interfaces that MUST be excluded from firewall scope generation
            system_info::LocalInterfaceInfo {
                name: "vEthernet (WSL)".into(),
                friendly_name: "Hyper-V Virtual Ethernet Adapter".into(),
                ip: "172.28.16.1".into(),
                netmask: "255.255.240.0".into(),
                broadcast: "172.28.31.255".into(),
                cidr_prefix: 20,
                transport: system_info::LinkTransport::Ethernet,
                link_speed_mbps: Some(10000),
                description: "WSL".into(),
            },
            system_info::LocalInterfaceInfo {
                name: "Tailscale".into(),
                friendly_name: "Tailscale Tunnel".into(),
                ip: "100.101.102.103".into(),
                netmask: "255.192.0.0".into(),
                broadcast: "100.127.255.255".into(),
                cidr_prefix: 10,
                transport: system_info::LinkTransport::Unknown,
                link_speed_mbps: None,
                description: "Tailscale".into(),
            },
        ];

        let extras = vec![
            "172.20.10.5/24".to_string(),
            "10.10.10.7".to_string(),
            "0.0.0.0/0".to_string(),
            "any".to_string(),
            "192.168.1.0/24; calc.exe".to_string(),
            "10.99.99.0/24".to_string(), // duplicate of active adapter CIDR
        ];

        let scopes = build_windows_firewall_remote_scopes_from(&ifaces, &extras);
        assert_eq!(
            scopes,
            format!(
                "LocalSubnet,{},10.99.99.0/24,192.168.48.0/22,172.20.10.0/28,192.168.137.0/24,172.20.10.0/24,10.10.10.7",
                config::IPV4_LINK_LOCAL_CIDR
            )
        );
        assert!(!scopes.contains("172.28.16.0/20"), "WSL vEthernet subnet must be excluded");
        assert!(!scopes.contains("100.64.0.0/10"), "Tailscale VPN subnet must be excluded");

        let live_scopes = build_windows_firewall_remote_scopes();
        assert!(live_scopes.starts_with(&format!("LocalSubnet,{}", config::IPV4_LINK_LOCAL_CIDR)));
    }
}
