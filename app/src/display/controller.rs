//! # Display Controller & Session Orchestrator
//!
//! ## 1. Module Purpose & Scope
//! This module implements [`DisplayController`], the central stateful orchestrator for the
//! **Integrator Extended Display Subsystem** (`display` feature) and local/remote RPC request routing.
//!
//! It manages the lifecycle of extended desktop streaming between macOS and Windows 11,
//! coordinating native virtual display creation, Sunshine streaming server configuration,
//! non-destructive Moonlight client resolution, and dynamic bitrate/resolution adaptation.
//! It also serves as the command dispatcher for all incoming [`DisplayRpcRequest`] messages,
//! including Shared Camera & Microphone management, True Tone gamma synchronization, remote
//! clipboard pasting, storage filesystem mounting, and low-latency UDP audio negotiation.
//!
//! ## 2. Architectural Linkages & Cross-Platform Pipelines
//! - **Upstream Callers**:
//!   - [`crate::core::IntegratorCore`]: Owns the [`DisplayController`] singleton and calls toggle/mode/RPC
//!     client helpers.
//!   - [`super::server::DisplayServer`]: Feeds incoming authenticated [`DisplayRpcRequest`] messages into
//!     [`DisplayController::handle_rpc`].
//!   - [`fetch_rust_gpu_telemetry_json`]: C-ABI bridge polled by the macOS Touch Bar GPU HUD
//!     (`touchbar_hud.swift`).
//! - **Downstream Callees**:
//!   - [`super::mac_display::MacDisplayManager`] and [`super::win_display::WinDisplayManager`]: Native
//!     virtual display, Sunshine, and Moonlight execution layers.
//!   - [`crate::camera::CameraService`], [`crate::audio::AudioManager`], [`crate::truetone`],
//!     [`crate::storage::StorageManager`], [`crate::trust`], [`crate::security::passkey`],
//!     [`crate::media`], [`crate::telemetry`], [`crate::clipboard::ClipboardService`].
//!
//! ### Mac-to-PC Extended Display Pipeline (`start_mac_to_pc_locked`)
//! 1. **Peer Discovery & Resolution**: Resolves target peer display dimensions (`width`, `height`),
//!    refresh rate (`fps`), and route IP via [`DisplayController::resolve_peer_display_and_host`].
//! 2. **In-Process Virtual Display (macOS)**: Invokes `MacDisplayManager::start_virtual_display`
//!    which calls `virtual_display.m` to instantiate a private `CGVirtualDisplay` with Integrator
//!    Vendor ID (`0x494E`) and Product ID (`0x0165`).
//! 3. **Sunshine Capture Configuration**: Dynamically writes `output_name = <display_id>` into
//!    `sunshine.conf` (`MacDisplayManager::configure_sunshine_output`) and starts Sunshine.
//! 4. **Hardware Encoding & Port Readiness**: Sunshine captures the virtual display via ScreenCaptureKit /
//!    Desktop Duplication and initializes Apple Silicon VideoToolbox hardware encoders.
//!    Controller waits until Sunshine binds local port 47989.
//! 5. **Remote Moonlight Invocation**: Sends an authenticated [`DisplayRpcRequest::StartMoonlight`]
//!    RPC to the Windows peer over `TransportSessionV2` on port 58281. The Windows PC launches
//!    fullscreen Moonlight with D3D11 / NVDEC / AMF / Intel QSV hardware decoding.
//!
//! ### PC-to-Mac Extended Display Pipeline (`start_pc_to_mac_locked`)
//! 1. **Virtual Display Driver (Windows 11)**: Invokes `WinDisplayManager::enable_vdd_device`
//!    to activate the IddSampleDriver / Apollo Indirect Display Driver via PnP and attach slot 1
//!    via `VddCtl.exe join 1`.
//! 2. **Sunshine Host Supervision**: Verifies that `SunshineService` or `SunshineSecondary` task
//!    is listening on port 47989 or secondary port 48989.
//! 3. **Hardware Encoding (Windows)**: Sunshine captures the virtual display via DXGI Desktop Duplication
//!    and encodes video using discrete GPU hardware (NVIDIA NVENC, AMD AMF, or Intel QuickSync).
//! 4. **Remote Moonlight Invocation**: Sends [`DisplayRpcRequest::StartMoonlight`] to the Mac peer.
//!    The Mac launches fullscreen Moonlight decoding with VideoToolbox hardware acceleration.
//!
//! ### Shared Camera & Microphone Interaction
//! While display streaming operates over Sunshine/Moonlight (ports 47989/48989), the Shared Camera
//! operates concurrently over `TransportSessionV2` on port 58287. Camera and microphone commands
//! ([`DisplayRpcRequest::StartCamera`], [`DisplayRpcRequest::ToggleCamera`], [`DisplayRpcRequest::StopCamera`],
//! [`DisplayRpcRequest::GetCameraStatus`], [`DisplayRpcRequest::ListCameras`], [`DisplayRpcRequest::SelectCamera`],
//! [`DisplayRpcRequest::ListMics`], [`DisplayRpcRequest::SelectMic`], [`DisplayRpcRequest::SetMicSettings`])
//! delegate to [`crate::camera::CameraService`], activating AVFoundation capture/audio selection on Mac
//! and the driverless Windows 11 Media Foundation FrameServer virtual webcam (`integrator_vcam.dll`)
//! without mutual interference or encoder resource contention.
//!
//! ### Cross-Screen True Tone Sync
//! Inbound [`DisplayRpcRequest::SyncTrueTone`] RPCs validate finite illuminance, color temperature, and
//! gamma bounds, program the Windows GPU LUT (`apply_hardware_gamma_ramp`), and record the synced Mac
//! ambient reading (`crate::truetone::record_synced_ambient`) so Windows surfaces live lux/CCT status.
//!
//! ## 3. Threading & Concurrency Model
//! - **Transition Serialization**: An internal async `Mutex<()>` (`transition_lock`) serializes
//!   all state changes (`start_mac_to_pc`, `stop_mac_to_pc`, `start_pc_to_mac`, `stop_pc_to_mac`,
//!   `StopAll`). This guarantees that concurrent UI toggles or remote RPCs cannot induce race
//!   conditions during virtual display creation or Sunshine port binding.
//! - **Lock-Free Read Access**: Shared state (`host_active`, `client_active`, `active_mode`,
//!   `active_peer_ip`) is stored in `tokio::sync::RwLock` containers, permitting high-frequency
//!   status queries without lock contention.
//! - **Blocking Offload**: System commands, registry operations, and process launches are
//!   offloaded to `tokio::task::spawn_blocking` to prevent starving the Tokio async thread pool.
//!
//! ## 4. Security & Safety Invariants
//! - **Loopback Call Guarding**: Sensitive RPC requests (`PasteRemote`, `ShowWindow`, `GetPairingPin`,
//!   `PairWithPeer`) are strictly restricted to local loopback CLI callers (`127.0.0.1` / `::1`)
//!   unless explicitly authorized for cross-machine desktop toggling.
//! - **Redirect Attack Mitigation**: In `StartMoonlight`, incoming `host_ip` parameters from remote
//!   callers are validated against the authenticated peer's socket address, preventing malicious
//!   redirection of Moonlight clients to arbitrary third-party IP addresses.
//! - **Dynamic Bitrate Clamping**: Stream bitrates are strictly clamped between 5,000 and 500,000 kbps,
//!   and display geometries are clamped to even integer dimensions within 800x600 to 7680x4320.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::config::{self, CONTROL_PORT};
use crate::discovery::{DiscoveryManager, PeerCandidate};
use crate::features::FeatureManager;
use crate::system_info;
use crate::trust;
use super::mac_display::MacDisplayManager;
use super::protocol::{required_feature_for_rpc, DisplayRpcRequest, DisplayRpcResponse};
use super::win_display::WinDisplayManager;

/// Single-attempt TCP connect timeout when probing Sunshine or peer port readiness.
const TCP_PORT_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Polling interval between TCP port readiness probe attempts.
const TCP_PORT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Settling delay after instantiating a macOS virtual display before configuring Sunshine output.
const VIRTUAL_DISPLAY_SETTLE_DELAY: Duration = Duration::from_millis(400);

/// Maximum wait duration for macOS Sunshine to bind its configured listen port.
const MAC_SUNSHINE_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum polling iterations (at [`TCP_PORT_POLL_INTERVAL`]) waiting for Windows Sunshine readiness (~8s).
const WIN_SUNSHINE_READY_MAX_ATTEMPTS: usize = 40;

/// Initial polling attempts reserved for a secondary Sunshine instance to come online before accepting primary.
const WIN_SUNSHINE_PRIMARY_GRACE_ATTEMPTS: usize = 3;

/// Per-port wait timeout when probing remote Sunshine fallback ports during `StartMoonlight`.
const REMOTE_PORT_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Transport handshake connect timeout for outbound Display RPC requests.
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Socket write timeout for outbound Display RPC requests.
const RPC_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket read timeout awaiting remote Display RPC responses.
const RPC_RECV_TIMEOUT: Duration = Duration::from_secs(15);

/// Extended socket read timeout awaiting interactive human Touch ID fingerprint authentication on the remote Mac.
const TOUCHID_RPC_RECV_TIMEOUT: Duration = Duration::from_secs(50);

/// Maximum permitted size in bytes for an inbound Display RPC response payload (1 MiB).
const MAX_RPC_RESPONSE_BYTES: usize = 1_048_576;

/// Lowest unprivileged TCP/UDP port accepted for remote Sunshine streaming targets.
const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Fallback display host label used on macOS when hostname resolution fails.
const FALLBACK_MAC_HOST_NAME: &str = "Mac";

/// Fallback display host label used on Windows when hostname resolution fails.
const FALLBACK_WINDOWS_HOST_NAME: &str = "Windows";

/// Maximum permitted ambient illuminance in Lux for `SyncTrueTone` wire validation.
const TRUETONE_MAX_LUX: f32 = 200_000.0;

/// Minimum permitted color temperature in Kelvin for `SyncTrueTone` wire validation.
const TRUETONE_MIN_WIRE_CCT: u32 = 1000;

/// Maximum permitted color temperature in Kelvin for `SyncTrueTone` wire validation.
const TRUETONE_MAX_WIRE_CCT: u32 = 15_000;

/// Minimum permitted gamma compensation factor for `SyncTrueTone` wire validation.
const TRUETONE_MIN_WIRE_GAMMA: f32 = 0.2;

/// Maximum permitted gamma compensation factor for `SyncTrueTone` wire validation.
const TRUETONE_MAX_WIRE_GAMMA: f32 = 3.0;

/// Resolves the secondary Sunshine port from preferences, falling back to [`config::SUNSHINE_SECONDARY_PORT`].
fn resolve_secondary_sunshine_port(prefs: &system_info::AppPathPreferences) -> u16 {
    prefs
        .sunshine_secondary_port
        .filter(|&p| p >= MIN_UNPRIVILEGED_PORT)
        .unwrap_or(config::SUNSHINE_SECONDARY_PORT)
}

/// Resolves the secondary Sunshine configuration filename from preferences, rejecting path traversal.
fn resolve_secondary_sunshine_conf_name(prefs: &system_info::AppPathPreferences) -> String {
    if let Some(ref custom) = prefs.sunshine_secondary_conf_name {
        if !custom.chars().any(|c| c.is_control()) {
            let trimmed = custom.trim();
            if !trimmed.is_empty()
                && !trimmed.contains('/')
                && !trimmed.contains('\\')
                && !trimmed.contains("..")
            {
                return trimmed.to_string();
            }
        }
    }
    config::SUNSHINE_SECONDARY_CONF_NAME.to_string()
}

/// Resolves PC-to-Mac stream dimensions from the peer's reported resolution `(w, h)` against
/// configured VDD maximum bounds (`vdd_max_width` / `vdd_max_height`).
///
/// Preserves the peer's actual resolution (whether a 1080p desktop monitor, 1440p QHD display,
/// 2560×1600 MacBook Retina display, or 4K Studio Display) on both primary and secondary Sunshine
/// instances instead of forcing 2560×1600 on the secondary port. When `(w, h)` exceeds `(max_w, max_h)`,
/// scales down proportionally to fit within `(max_w, max_h)` while preserving the peer's aspect ratio
/// and even-pixel alignment required by H.264/HEVC hardware encoders.
fn resolve_vdd_stream_dimensions(
    w: u32,
    h: u32,
    _active_port: u16,
    _secondary_port: u16,
    prefs: &system_info::AppPathPreferences,
) -> (u32, u32) {
    let max_w = prefs
        .vdd_max_width
        .unwrap_or(config::VDD_DEFAULT_MAX_WIDTH)
        .clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH)
        & !1;
    let max_h = prefs
        .vdd_max_height
        .unwrap_or(config::VDD_DEFAULT_MAX_HEIGHT)
        .clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT)
        & !1;
    if w == 0 || h == 0 {
        return (max_w, max_h);
    }
    if w <= max_w && h <= max_h {
        let even_w = w.clamp(config::MIN_DISPLAY_WIDTH, max_w) & !1;
        let even_h = h.clamp(config::MIN_DISPLAY_HEIGHT, max_h) & !1;
        (even_w, even_h)
    } else {
        let scale = (max_w as f64 / w as f64).min(max_h as f64 / h as f64);
        let scaled_w = ((w as f64 * scale).round() as u32)
            .clamp(config::MIN_DISPLAY_WIDTH, max_w)
            & !1;
        let scaled_h = ((h as f64 * scale).round() as u32)
            .clamp(config::MIN_DISPLAY_HEIGHT, max_h)
            & !1;
        (scaled_w, scaled_h)
    }
}

/// User-selected display resolution, refresh rate (Hz), and HDR override applied via Touch Bar or UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayModeOverride {
    /// Target horizontal resolution in pixels (`0` uses native peer display width).
    pub width: u32,
    /// Target vertical resolution in pixels (`0` uses native peer display height).
    pub height: u32,
    /// Target refresh rate in Hertz (`60`, `120`, `165`, etc.).
    pub fps: u32,
    /// Whether HDR video streaming should be enabled.
    pub hdr: bool,
}

/// RAII guard that yields Integrator's custom system-modal Touch Bar while macOS `LAContext`
/// presents Apple's native Touch ID Touch Bar UI, restoring the HUD on return, error, or panic.
struct TouchBarTouchIdGuard;

impl TouchBarTouchIdGuard {
    /// Temporarily yields Integrator's modal Touch Bar so Apple's native Touch ID prompt renders
    /// unobstructed, returning an RAII guard that restores the HUD when dropped.
    fn activate(label: &str) -> Self {
        crate::core::notify_touchbar_touchid_prompt(label, true);
        Self
    }
}

impl Drop for TouchBarTouchIdGuard {
    fn drop(&mut self) {
        crate::core::notify_touchbar_touchid_prompt("", false);
    }
}

/// Stateful controller managing extended display sessions, bitrate calculations, and RPC routing.
#[derive(Clone)]
pub struct DisplayController {
    /// Peer discovery manager for resolving counterpart device IP addresses and link characteristics.
    discovery: DiscoveryManager,
    /// Feature flag manager governing feature enablement.
    features: Arc<FeatureManager>,
    /// Serializes display session transitions (start, stop, toggle) to prevent re-entrant races.
    transition_lock: Arc<Mutex<()>>,
    /// Whether this machine is currently acting as the Sunshine display host.
    host_active: Arc<RwLock<bool>>,
    /// Whether this machine is currently acting as the Moonlight display client.
    client_active: Arc<RwLock<bool>>,
    /// Human-readable description of the current display mode (e.g. `"Mac -> PC (2560x1440 @ 120Hz)"`).
    active_mode: Arc<RwLock<Option<String>>>,
    /// IP address of the peer currently engaged in an active display session.
    active_peer_ip: Arc<RwLock<Option<String>>>,
    /// Device ID hex of the peer for whom this machine is acting as Sunshine host.
    host_peer_id: Arc<RwLock<Option<String>>>,
    /// Device ID hex of the peer whose screen this machine is viewing via Moonlight client.
    client_peer_id: Arc<RwLock<Option<String>>>,
    /// Optional user-selected display resolution / refresh rate / HDR override.
    preferred_mode: Arc<RwLock<Option<DisplayModeOverride>>>,
}

impl DisplayController {
    /// Instantiates a new [`DisplayController`] tied to discovery and feature managers.
    pub fn new(discovery: DiscoveryManager, features: Arc<FeatureManager>) -> Self {
        #[cfg(target_os = "windows")]
        {
            let _ = WinDisplayManager::disable_vdd_device();
        }
        Self {
            discovery,
            features,
            transition_lock: Arc::new(Mutex::new(())),
            host_active: Arc::new(RwLock::new(false)),
            client_active: Arc::new(RwLock::new(false)),
            active_mode: Arc::new(RwLock::new(None)),
            active_peer_ip: Arc::new(RwLock::new(None)),
            host_peer_id: Arc::new(RwLock::new(None)),
            client_peer_id: Arc::new(RwLock::new(None)),
            preferred_mode: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns the currently configured display mode override `(width, height, fps, hdr)` if any.
    pub async fn get_preferred_mode(&self) -> Option<DisplayModeOverride> {
        *self.preferred_mode.read().await
    }

    /// Applies a new display resolution, refresh rate (Hz), and HDR preference, immediately
    /// reconfiguring any active extended display session without opening system settings.
    pub async fn set_display_mode(&self, width: u32, height: u32, fps: u32, hdr: bool) -> Result<String> {
        let clamped_fps = if fps > 0 {
            fps.clamp(config::MIN_DISPLAY_FPS, config::MAX_DISPLAY_FPS)
        } else {
            config::DEFAULT_DISPLAY_FPS
        };
        let clamped_w = if width > 0 {
            width.clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH) & !1
        } else {
            0
        };
        let clamped_h = if height > 0 {
            height.clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT) & !1
        } else {
            0
        };

        let next_mode = DisplayModeOverride {
            width: clamped_w,
            height: clamped_h,
            fps: clamped_fps,
            hdr,
        };
        *self.preferred_mode.write().await = Some(next_mode);
        crate::core::notify_touchbar_display_mode(clamped_w, clamped_h, clamped_fps, hdr);

        let is_host = *self.host_active.read().await;
        let is_client = *self.client_active.read().await;

        // If we are currently hosting an extended display, hot-reconfigure the active stream
        // (re-check `host_active` after acquiring `transition_lock` to close TOCTOU stop race).
        if is_host {
            let _tx = self.transition_lock.lock().await;
            if *self.host_active.read().await {
                #[cfg(target_os = "macos")]
                {
                    let _ = self.stop_mac_to_pc_locked().await;
                    self.start_mac_to_pc_locked().await?;
                }
                #[cfg(target_os = "windows")]
                {
                    let _ = self.stop_pc_to_mac_locked().await;
                    self.start_pc_to_mac_locked().await?;
                }
            }
        } else if is_client {
            // Forward the mode update to the peer currently hosting our extended display
            let target_ip = match self.active_peer_ip.read().await.clone() {
                Some(ip) => Some(ip),
                None => self.discovery.get_peer_ip().await,
            };
            if let Some(peer_ip) = target_ip {
                let rpc = DisplayRpcRequest::SetDisplayMode {
                    width: clamped_w,
                    height: clamped_h,
                    fps: clamped_fps,
                    hdr,
                };
                let resp = Self::send_remote_rpc(&peer_ip, &rpc).await?;
                if !resp.success {
                    anyhow::bail!("{}", resp.message);
                }
            }
        }

        let res_label = if clamped_w > 0 && clamped_h > 0 {
            format!("{}x{}", clamped_w, clamped_h)
        } else {
            "Native".to_string()
        };
        let hdr_label = if hdr { " HDR" } else { "" };
        Ok(format!("Display mode set to {} @ {}Hz{}", res_label, clamped_fps, hdr_label))
    }

    /// Constructs a baseline [`DisplayRpcResponse`] populated with current active state.
    async fn base_response(&self, success: bool, message: impl Into<String>) -> DisplayRpcResponse {
        DisplayRpcResponse {
            success,
            message: message.into(),
            is_active: self.is_active().await,
            active_mode: self.active_mode.read().await.clone(),
            ..Default::default()
        }
    }

    /// Formats an IP address and port into a valid IPv4/IPv6 socket target string.
    fn format_socket_target(ip: &str, port: u16) -> String {
        if let Ok(parsed) = ip.trim().parse::<IpAddr>() {
            SocketAddr::new(parsed, port).to_string()
        } else {
            format!("{}:{}", ip.trim(), port)
        }
    }

    /// Checks whether a TCP port is currently open and accepting connections within [`TCP_PORT_PROBE_TIMEOUT`].
    async fn is_tcp_port_open(ip: &str, port: u16) -> bool {
        let addr = Self::format_socket_target(ip, port);
        matches!(
            tokio::time::timeout(TCP_PORT_PROBE_TIMEOUT, TcpStream::connect(&addr)).await,
            Ok(Ok(_))
        )
    }

    /// Polls a TCP port periodically until it becomes open or `timeout` expires.
    async fn wait_for_tcp_port(ip: &str, port: u16, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if Self::is_tcp_port_open(ip, port).await {
                return true;
            }
            tokio::time::sleep(TCP_PORT_POLL_INTERVAL).await;
        }
        false
    }

    /// Calculates the adaptive streaming bitrate in kilobits per second from link transport,
    /// reported link speed, and refresh rate using canonical [`config`] ladder bounds.
    ///
    /// # Topology Adaptation
    /// 1. **Direct Cable (`DirectUsb` / `Thunderbolt`)**: Full 100 Mbps (60Hz) / 150 Mbps (120Hz+) point-to-point tier.
    /// 2. **Mobile Hotspot (`Hotspot`)**: Derates nominal 802.11 PHY link speeds (`866 Mbps`, `1200 Mbps`) by
    ///    [`config::BITRATE_HOTSPOT_PHY_MBPS_MULTIPLIER`] and caps at [`config::BITRATE_HOTSPOT_STANDARD_KBPS`] (20 Mbps)
    ///    or [`config::BITRATE_HOTSPOT_HIGH_FPS_KBPS`] (25 Mbps) to prevent bufferbloat and packet drops over
    ///    PC Mobile Hotspots (`Wi-Fi Direct` / ICS) and iPhone / Android Personal Hotspots.
    /// 3. **Wi-Fi LAN (`Wifi`)**: Derates half-duplex 802.11 PHY rates by [`config::BITRATE_WIFI_PHY_MBPS_MULTIPLIER`]
    ///    and caps at [`config::BITRATE_WIFI_MAX_STANDARD_KBPS`] (45 Mbps) or [`config::BITRATE_WIFI_MAX_HIGH_FPS_KBPS`]
    ///    (55 Mbps) so high nominal PHY link speeds (`866 Mbps` / `1200 Mbps`) never jump into wired 1GbE/2.5GbE tiers.
    /// 4. **Wired Ethernet (`Ethernet`)**: Uses full-duplex 2.5GbE (`100–150 Mbps`), 1GbE (`65–85 Mbps`), or sub-gigabit ladders.
    fn compute_adaptive_bitrate_kbps(
        transport: system_info::LinkTransport,
        link_speed_mbps: Option<u32>,
        fps: u32,
        override_kbps: Option<u32>,
    ) -> u32 {
        if let Some(custom_kbps) = override_kbps.filter(|&b| b > 0) {
            return custom_kbps.clamp(config::MIN_BITRATE_KBPS, config::MAX_BITRATE_KBPS);
        }
        let high_fps = fps >= config::HIGH_FPS_THRESHOLD;
        if transport.is_direct_cable() {
            return if high_fps {
                config::BITRATE_DIRECT_CABLE_HIGH_FPS_KBPS
            } else {
                config::BITRATE_DIRECT_CABLE_STANDARD_KBPS
            };
        }

        match transport {
            system_info::LinkTransport::Hotspot => {
                let cap = if high_fps {
                    config::BITRATE_HOTSPOT_HIGH_FPS_KBPS
                } else {
                    config::BITRATE_HOTSPOT_STANDARD_KBPS
                };
                match link_speed_mbps {
                    Some(mbps) if mbps > 0 => mbps
                        .saturating_mul(config::BITRATE_HOTSPOT_PHY_MBPS_MULTIPLIER)
                        .clamp(config::BITRATE_HOTSPOT_MIN_KBPS, cap),
                    _ => cap,
                }
            }
            system_info::LinkTransport::Wifi => {
                let cap = if high_fps {
                    config::BITRATE_WIFI_MAX_HIGH_FPS_KBPS
                } else {
                    config::BITRATE_WIFI_MAX_STANDARD_KBPS
                };
                match link_speed_mbps {
                    Some(mbps) if mbps > 0 => mbps
                        .saturating_mul(config::BITRATE_WIFI_PHY_MBPS_MULTIPLIER)
                        .clamp(config::BITRATE_SUB_GIG_MIN_KBPS, cap),
                    _ => config::BITRATE_WIFI_FALLBACK_KBPS,
                }
            }
            _ => match link_speed_mbps {
                Some(mbps) if mbps >= config::LINK_SPEED_2500M_THRESHOLD_MBPS => {
                    if high_fps {
                        config::BITRATE_2500M_HIGH_FPS_KBPS
                    } else {
                        config::BITRATE_2500M_STANDARD_KBPS
                    }
                }
                Some(mbps) if mbps >= config::LINK_SPEED_1000M_THRESHOLD_MBPS => {
                    if high_fps {
                        config::BITRATE_1000M_HIGH_FPS_KBPS
                    } else {
                        config::BITRATE_1000M_STANDARD_KBPS
                    }
                }
                Some(mbps) if mbps > 0 => mbps
                    .saturating_mul(config::BITRATE_SUB_GIG_MBPS_MULTIPLIER)
                    .clamp(
                        config::BITRATE_SUB_GIG_MIN_KBPS,
                        config::BITRATE_SUB_GIG_MAX_KBPS,
                    ),
                _ => match transport {
                    system_info::LinkTransport::Ethernet => {
                        if high_fps {
                            config::BITRATE_ETH_FALLBACK_HIGH_FPS_KBPS
                        } else {
                            config::BITRATE_ETH_FALLBACK_STANDARD_KBPS
                        }
                    }
                    _ => config::BITRATE_UNKNOWN_FALLBACK_KBPS,
                },
            },
        }
    }

    /// Calculates the optimal streaming bitrate in kilobits per second based on user override,
    /// link transport, link speed, and refresh rate.
    fn compute_optimal_bitrate_kbps(peer: &PeerCandidate, fps: u32) -> u32 {
        let prefs = system_info::load_path_preferences();
        Self::compute_adaptive_bitrate_kbps(
            peer.transport,
            peer.link_speed_mbps,
            fps,
            prefs.display_bitrate_override_kbps,
        )
    }

    /// Resolves the target peer's real display `(width, height, fps)` and hostname,
    /// querying `GetHardwareProfile` over RPC if beacon fields are incomplete,
    /// clamping refresh rate to [`config::MIN_DISPLAY_FPS`]..=[`config::MAX_DISPLAY_FPS`],
    /// and falling back to the local primary display.
    async fn resolve_peer_display_and_host(&self, peer: &PeerCandidate) -> (u32, u32, u32, String) {
        let peer_ip = peer.addr.ip().to_string();
        let mut width = peer.display_width;
        let mut height = peer.display_height;
        let mut fps = peer.display_fps;
        let mut hostname = peer.device_name.trim().to_string();

        if width == 0 || height == 0 || fps == 0 || hostname.is_empty() {
            if let Ok(resp) = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetHardwareProfile).await {
                if let Some(profile) = resp.hardware_profile {
                    if width == 0 || height == 0 {
                        width = profile.primary_display.width;
                        height = profile.primary_display.height;
                    }
                    if fps == 0 {
                        fps = profile.primary_display.fps;
                    }
                    if hostname.is_empty() && !profile.hostname.trim().is_empty() {
                        hostname = profile.hostname.trim().to_string();
                    }
                }
            }
        }

        let local_disp = tokio::task::spawn_blocking(system_info::get_primary_display_info)
            .await
            .unwrap_or(system_info::PrimaryDisplayInfo {
                width: config::DEFAULT_DISPLAY_WIDTH,
                height: config::DEFAULT_DISPLAY_HEIGHT,
                fps: config::DEFAULT_DISPLAY_FPS,
                scale_factor: 1.0,
            });
        // Ensure even dimensions required by video encoders (width & !1, height & !1)
        let final_w = (if width > 0 { width } else { local_disp.width })
            .clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH)
            & !1;
        let final_h = (if height > 0 { height } else { local_disp.height })
            .clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT)
            & !1;
        let raw_fps = if fps > 0 { fps } else { local_disp.fps };
        let final_fps = (if raw_fps > 0 {
            raw_fps
        } else {
            config::DEFAULT_DISPLAY_FPS
        })
        .clamp(config::MIN_DISPLAY_FPS, config::MAX_DISPLAY_FPS);
        let final_hostname = if hostname.is_empty() { peer_ip } else { hostname };

        (final_w, final_h, final_fps, final_hostname)
    }

    /// Reads optional custom sunshine server name from the configured secondary Sunshine config file.
    fn read_secondary_sunshine_name() -> Option<String> {
        let prefs = system_info::load_path_preferences();
        let secondary_conf_name = resolve_secondary_sunshine_conf_name(&prefs);
        let conf_path = system_info::find_sunshine_conf()?
            .parent()?
            .join(secondary_conf_name);
        let content = std::fs::read_to_string(conf_path).ok()?;
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with('#') || !t.contains('=') {
                continue;
            }
            let (k, v) = t.split_once('=')?;
            if k.trim().eq_ignore_ascii_case("sunshine_name") {
                let name = v.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Toggles Mac-as-Host extended desktop to the discovered peer.
    ///
    /// When invoked on Windows, forwards the toggle request over authenticated TransportV2 to the Mac peer.
    pub async fn toggle_mac_to_pc(&self) -> Result<String> {
        #[cfg(not(target_os = "macos"))]
        {
            let peer = self
                .discovery
                .get_best_peer()
                .await
                .context("No active Mac peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
            let peer_ip = peer.addr.ip().to_string();
            let resp = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::ToggleMacToPc).await?;
            if !resp.success {
                anyhow::bail!("{}", resp.message);
            }
            return Ok(resp.message);
        }

        #[cfg(target_os = "macos")]
        {
            let Ok(_tx) = self.transition_lock.try_lock() else {
                return Ok("Display transition already in progress...".into());
            };
            let is_running =
                *self.host_active.read().await || MacDisplayManager::is_virtual_display_active();
            if is_running {
                self.stop_mac_to_pc_locked().await?;
                Ok("Stopped Mac-to-PC extended display".into())
            } else {
                self.start_mac_to_pc_locked().await?;
                let mode = self
                    .active_mode
                    .read()
                    .await
                    .clone()
                    .unwrap_or_else(|| "Extended display".to_string());
                Ok(format!("Started {}", mode))
            }
        }
    }

    /// Starts Mac-as-Host extended desktop to the discovered peer.
    pub async fn start_mac_to_pc(&self) -> Result<()> {
        let _tx = self.transition_lock.lock().await;
        self.start_mac_to_pc_locked().await
    }

    /// Clears internal host session flags and resets active mode.
    async fn clear_host_state(&self) {
        *self.host_active.write().await = false;
        *self.host_peer_id.write().await = None;
        let client_on = *self.client_active.read().await;
        if !client_on {
            *self.active_peer_ip.write().await = None;
            *self.active_mode.write().await = None;
        } else {
            *self.active_mode.write().await = Some("Client".into());
        }
    }

    /// Clears internal client session flags and resets active mode.
    async fn clear_client_state(&self) {
        *self.client_active.write().await = false;
        *self.client_peer_id.write().await = None;
        let host_on = *self.host_active.read().await;
        if !host_on {
            *self.active_peer_ip.write().await = None;
            *self.active_mode.write().await = None;
        }
    }

    /// Tears down display streaming resources associated with a specific revoked peer.
    ///
    /// - If the peer is the Moonlight client viewing our screen: terminates the local Sunshine host
    ///   and disables virtual display / VDD.
    /// - If the peer is the Sunshine host whose screen we are viewing: terminates the local Moonlight
    ///   client process.
    /// - If the peer owns neither, active display sessions of other peers are preserved without disruption.
    pub async fn teardown_peer_display(&self, peer_device_id_hex: &str) -> Result<()> {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let _tx = self.transition_lock.lock().await;

        let is_client_peer = {
            let lock = self.client_peer_id.read().await;
            lock.as_deref() == Some(&clean_id)
        };
        let is_host_peer = {
            let lock = self.host_peer_id.read().await;
            lock.as_deref() == Some(&clean_id)
        };

        if !is_client_peer && !is_host_peer {
            tracing::debug!("Teardown display: peer {} owns neither host nor client session; preserving active sessions", clean_id);
            return Ok(());
        }

        if is_client_peer {
            tracing::info!("🛑 Revocation: stopping local Moonlight client owned by peer {}", clean_id);
            tokio::task::spawn_blocking(|| -> Result<()> {
                #[cfg(target_os = "macos")]
                crate::display::mac_display::MacDisplayManager::stop_moonlight_client()?;
                #[cfg(target_os = "windows")]
                crate::display::win_display::WinDisplayManager::stop_moonlight_client()?;
                Ok(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("Moonlight client stop task panicked: {}", e))??;
            self.clear_client_state().await;
        }

        if is_host_peer {
            tracing::info!("🛑 Revocation: stopping local Sunshine host and virtual display owned by peer {}", clean_id);
            tokio::task::spawn_blocking(|| -> Result<()> {
                #[cfg(target_os = "macos")]
                {
                    if let Err(e) = crate::display::mac_display::MacDisplayManager::stop_virtual_display() {
                        tracing::warn!("Virtual display teardown notice: {}", e);
                    }
                    if let Err(e) = crate::display::mac_display::MacDisplayManager::stop_sunshine() {
                        tracing::warn!("Sunshine host stop notice: {}", e);
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    let _ = crate::display::win_display::WinDisplayManager::disable_vdd_device();
                }
                Ok(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("Sunshine host stop task panicked: {}", e))??;
            self.clear_host_state().await;
        }

        Ok(())
    }

    /// Sets the active host peer device ID.
    pub async fn set_active_host_peer(&self, peer_device_id: Option<String>) {
        *self.host_peer_id.write().await = peer_device_id.map(|s| s.trim().to_ascii_lowercase());
    }

    /// Sets the active client peer device ID.
    pub async fn set_active_client_peer(&self, peer_device_id: Option<String>) {
        *self.client_peer_id.write().await = peer_device_id.map(|s| s.trim().to_ascii_lowercase());
    }

    /// Returns the active host peer device ID if currently hosting.
    pub async fn host_peer_id(&self) -> Option<String> {
        self.host_peer_id.read().await.clone()
    }

    /// Returns the active client peer device ID if currently acting as Moonlight client.
    pub async fn client_peer_id(&self) -> Option<String> {
        self.client_peer_id.read().await.clone()
    }

    /// Internal locked implementation of Mac-to-PC extended desktop initiation.
    async fn start_mac_to_pc_locked(&self) -> Result<()> {
        let peer = self
            .discovery
            .get_best_peer()
            .await
            .context("No active peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
        let peer_ip = peer.addr.ip().to_string();
        let peer_ip_route = peer_ip.clone();
        let my_ip = tokio::task::spawn_blocking(move || system_info::local_ip_for_peer(&peer_ip_route))
            .await
            .ok()
            .flatten()
            .with_context(|| format!("Could not determine local route IP to reach peer {}", peer_ip))?;

        let (mut w, mut h, mut fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        let mut hdr = false;
        if let Some(ov) = *self.preferred_mode.read().await {
            if ov.width > 0 && ov.height > 0 {
                w = ov.width;
                h = ov.height;
            }
            if ov.fps > 0 {
                fps = ov.fps;
            }
            hdr = ov.hdr;
        }
        info!(
            "Starting Mac-to-PC extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz{})",
            my_ip, peer_hostname, peer_ip, w, h, fps, if hdr { " HDR" } else { "" }
        );

        // 1. Spawn virtual display matching peer display dimensions and configure Sunshine output ID
        let disp_id = tokio::task::spawn_blocking(move || MacDisplayManager::start_virtual_display(w, h, fps))
            .await
            .context("Virtual display task panicked")??;
        tokio::time::sleep(VIRTUAL_DISPLAY_SETTLE_DELAY).await;
        if let Err(e) = tokio::task::spawn_blocking(move || MacDisplayManager::configure_sunshine_output(disp_id))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("{}", e)))
        {
            warn!("Failed to configure Sunshine output_name = {}: {}", disp_id, e);
        }

        // 2. Start local Sunshine and wait for its configured port
        if let Err(e) = tokio::task::spawn_blocking(MacDisplayManager::start_sunshine)
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("{}", e)))
        {
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
            self.clear_host_state().await;
            return Err(e);
        }

        let (my_sunshine_name, my_sunshine_port, _) =
            tokio::task::spawn_blocking(system_info::read_sunshine_config_info)
                .await
                .unwrap_or((None, config::SUNSHINE_DEFAULT_PORT, None));
        info!("Waiting for Sunshine server on port {}...", my_sunshine_port);
        if !MacDisplayManager::wait_for_sunshine_ready(MAC_SUNSHINE_READY_TIMEOUT).await {
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_sunshine).await;
            self.clear_host_state().await;
            anyhow::bail!(
                "Mac Sunshine server failed to listen on port {} within {}s (check Screen Recording permission for Sunshine.app and ~/Library/Logs/sunshine.log)",
                my_sunshine_port,
                MAC_SUNSHINE_READY_TIMEOUT.as_secs()
            );
        }

        let fallback_host = tokio::task::spawn_blocking(system_info::get_hostname)
            .await
            .unwrap_or_else(|_| FALLBACK_MAC_HOST_NAME.to_string());
        let host_name = my_sunshine_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback_host);
        let bitrate_kbps = Self::compute_optimal_bitrate_kbps(&peer, fps);

        // 3. Send RPC to peer to launch Moonlight in fullscreen at peer native resolution/refresh
        let rpc = DisplayRpcRequest::StartMoonlight {
            host_ip: my_ip,
            host_port: my_sunshine_port,
            host_name,
            width: w,
            height: h,
            fps,
            bitrate_kbps,
            audio_on_host: false,
            hdr,
        };

        let resp = match Self::send_remote_rpc(&peer_ip, &rpc).await {
            Ok(r) => r,
            Err(e) => {
                let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
                let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_sunshine).await;
                self.clear_host_state().await;
                return Err(e);
            }
        };
        if !resp.success {
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_sunshine).await;
            self.clear_host_state().await;
            anyhow::bail!("Peer {} failed to start Moonlight: {}", peer_hostname, resp.message);
        }

        let mode_summary = format!("{}x{} @ {}Hz", w, h, fps);
        let notify_msg = format!("{} active on {}", mode_summary, peer_hostname);
        let _ = tokio::task::spawn_blocking(move || {
            MacDisplayManager::show_notification("Second Screen Enabled", &notify_msg);
        })
        .await;

        *self.host_active.write().await = true;
        *self.host_peer_id.write().await = Some(peer.device_id.trim().to_ascii_lowercase());
        *self.active_peer_ip.write().await = Some(peer_ip);
        *self.active_mode.write().await = Some(format!("Mac -> {} ({})", peer_hostname, mode_summary));

        Ok(())
    }

    /// Stops Mac-as-Host extended desktop cleanly even if no peer is reachable.
    pub async fn stop_mac_to_pc(&self) -> Result<()> {
        let _tx = self.transition_lock.lock().await;
        self.stop_mac_to_pc_locked().await
    }

    /// Internal locked teardown routine for Mac-as-Host session.
    async fn stop_mac_to_pc_locked(&self) -> Result<()> {
        info!("Stopping Mac-to-PC extended display...");

        let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
        let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_sunshine).await;

        let target_ip = match self.active_peer_ip.read().await.clone() {
            Some(ip) => Some(ip),
            None => self.discovery.get_peer_ip().await,
        };
        if let Some(peer_ip) = target_ip {
            let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;
        } else {
            warn!("No active peer reachable during stop_mac_to_pc; cleaned up local display state");
        }

        let _ = tokio::task::spawn_blocking(|| {
            MacDisplayManager::show_notification("Second Screen Disabled", "Virtual display stopped.");
        })
        .await;

        self.clear_host_state().await;

        Ok(())
    }

    /// Toggles PC-as-Host extended desktop to the discovered Mac peer.
    ///
    /// When invoked on macOS, forwards the toggle request over authenticated TransportV2 to the Windows peer.
    pub async fn toggle_pc_to_mac(&self) -> Result<String> {
        #[cfg(not(target_os = "windows"))]
        {
            let peer = self
                .discovery
                .get_best_peer()
                .await
                .context("No active Windows peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
            let peer_ip = peer.addr.ip().to_string();
            let resp = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::TogglePcToMac).await?;
            if !resp.success {
                anyhow::bail!("{}", resp.message);
            }
            return Ok(resp.message);
        }

        #[cfg(target_os = "windows")]
        {
            let Ok(_tx) = self.transition_lock.try_lock() else {
                return Ok("Display transition already in progress...".into());
            };
            let is_running = *self.host_active.read().await;
            if is_running {
                self.stop_pc_to_mac_locked().await?;
                Ok("Stopped PC-to-Mac extended display".into())
            } else {
                self.start_pc_to_mac_locked().await?;
                let mode = self
                    .active_mode
                    .read()
                    .await
                    .clone()
                    .unwrap_or_else(|| "Extended display".to_string());
                Ok(format!("Started {}", mode))
            }
        }
    }

    /// Starts PC-as-Host extended desktop to the discovered Mac peer.
    pub async fn start_pc_to_mac(&self) -> Result<()> {
        let _tx = self.transition_lock.lock().await;
        self.start_pc_to_mac_locked().await
    }

    /// Internal locked initiation routine for PC-as-Host extended desktop mode.
    async fn start_pc_to_mac_locked(&self) -> Result<()> {
        let peer = self
            .discovery
            .get_best_peer()
            .await
            .context("No active peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
        let peer_ip = peer.addr.ip().to_string();
        let peer_ip_route = peer_ip.clone();
        let my_ip = tokio::task::spawn_blocking(move || system_info::local_ip_for_peer(&peer_ip_route))
            .await
            .ok()
            .flatten()
            .with_context(|| format!("Could not determine local route IP to reach peer {}", peer_ip))?;

        let (mut w, mut h, mut fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        let mut hdr = false;
        if let Some(ov) = *self.preferred_mode.read().await {
            if ov.width > 0 && ov.height > 0 {
                w = ov.width;
                h = ov.height;
            }
            if ov.fps > 0 {
                fps = ov.fps;
            }
            hdr = ov.hdr;
        }
        info!(
            "Starting PC-to-Mac extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz{})",
            my_ip, peer_hostname, peer_ip, w, h, fps, if hdr { " HDR" } else { "" }
        );

        // 1. Enable Windows virtual display / secondary Sunshine if present
        tokio::task::spawn_blocking(WinDisplayManager::enable_vdd_device)
            .await
            .context("VDD enable task panicked")??;

        // 2. Wait for local Sunshine on configured port (or configured secondary port if open)
        let prefs = tokio::task::spawn_blocking(system_info::load_path_preferences)
            .await
            .unwrap_or_default();
        let secondary_port = resolve_secondary_sunshine_port(&prefs);
        let loopback = Ipv4Addr::LOCALHOST.to_string();
        let (my_sunshine_name, configured_port, _) =
            tokio::task::spawn_blocking(system_info::read_sunshine_config_info)
                .await
                .unwrap_or((None, config::SUNSHINE_DEFAULT_PORT, None));
        let mut active_port = configured_port;
        let mut ready = false;
        for attempt in 0..WIN_SUNSHINE_READY_MAX_ATTEMPTS {
            if configured_port != secondary_port
                && Self::is_tcp_port_open(&loopback, secondary_port).await
            {
                active_port = secondary_port;
                ready = true;
                break;
            }
            if Self::is_tcp_port_open(&loopback, configured_port).await
                && (attempt >= WIN_SUNSHINE_PRIMARY_GRACE_ATTEMPTS
                    || configured_port == secondary_port)
            {
                active_port = configured_port;
                ready = true;
                break;
            }
            tokio::time::sleep(TCP_PORT_POLL_INTERVAL).await;
        }
        if !ready {
            let _ = tokio::task::spawn_blocking(WinDisplayManager::disable_vdd_device).await;
            self.clear_host_state().await;
            anyhow::bail!(
                "Windows Sunshine server failed to listen on port {} (or secondary {}) within {}s",
                configured_port,
                secondary_port,
                (TCP_PORT_POLL_INTERVAL * WIN_SUNSHINE_READY_MAX_ATTEMPTS as u32).as_secs()
            );
        }

        let secondary_name = if active_port == secondary_port {
            tokio::task::spawn_blocking(Self::read_secondary_sunshine_name)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let fallback_host = tokio::task::spawn_blocking(system_info::get_hostname)
            .await
            .unwrap_or_else(|_| FALLBACK_WINDOWS_HOST_NAME.to_string());
        let host_name = secondary_name
            .or(my_sunshine_name)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback_host);
        let bitrate_kbps = Self::compute_optimal_bitrate_kbps(&peer, fps);

        // Clamp display dimensions against configured VDD maximums (or secondary slot max)
        let (stream_w, stream_h) =
            resolve_vdd_stream_dimensions(w, h, active_port, secondary_port, &prefs);

        // Ensure Sunshine REST API has cleared any lingering stream before client connects
        let api_port = active_port.saturating_add(config::SUNSHINE_WEB_PORT_OFFSET);
        let _ = tokio::task::spawn_blocking(move || {
            WinDisplayManager::call_sunshine_api(api_port, config::SUNSHINE_API_CLOSE_PATH);
        })
        .await;

        // 3. Send RPC to peer to launch Moonlight client
        let rpc = DisplayRpcRequest::StartMoonlight {
            host_ip: my_ip,
            host_port: active_port,
            host_name,
            width: stream_w,
            height: stream_h,
            fps,
            bitrate_kbps,
            audio_on_host: false,
            hdr,
        };

        let resp = match Self::send_remote_rpc(&peer_ip, &rpc).await {
            Ok(r) => r,
            Err(e) => {
                let _ = tokio::task::spawn_blocking(WinDisplayManager::disable_vdd_device).await;
                self.clear_host_state().await;
                return Err(e);
            }
        };
        if !resp.success {
            let _ = tokio::task::spawn_blocking(WinDisplayManager::disable_vdd_device).await;
            self.clear_host_state().await;
            anyhow::bail!("Peer {} failed to start Moonlight: {}", peer_hostname, resp.message);
        }

        let mode_summary = format!("{}x{} @ {}Hz", stream_w, stream_h, fps);
        *self.host_active.write().await = true;
        *self.host_peer_id.write().await = Some(peer.device_id.trim().to_ascii_lowercase());
        *self.active_peer_ip.write().await = Some(peer_ip);
        *self.active_mode.write().await = Some(format!("PC -> {} ({})", peer_hostname, mode_summary));

        Ok(())
    }

    /// Stops PC-as-Host extended desktop cleanly even if no peer is reachable.
    pub async fn stop_pc_to_mac(&self) -> Result<()> {
        let _tx = self.transition_lock.lock().await;
        self.stop_pc_to_mac_locked().await
    }

    /// Internal locked teardown routine for PC-as-Host session.
    async fn stop_pc_to_mac_locked(&self) -> Result<()> {
        info!("Stopping PC-to-Mac extended display...");

        let _ = tokio::task::spawn_blocking(WinDisplayManager::disable_vdd_device).await;

        let target_ip = match self.active_peer_ip.read().await.clone() {
            Some(ip) => Some(ip),
            None => self.discovery.get_peer_ip().await,
        };
        if let Some(peer_ip) = target_ip {
            let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;
        } else {
            warn!("No active peer reachable during stop_pc_to_mac; cleaned up local VDD state");
        }

        self.clear_host_state().await;

        Ok(())
    }

    /// Handles an incoming [`DisplayRpcRequest`] on the local machine with security authorization checks.
    ///
    /// Validates loopback-only caller constraints, feature flag status, and parameter sanity before
    /// dispatching to specific subsystem handlers.
    pub async fn handle_rpc(
        &self,
        req: DisplayRpcRequest,
        peer_ip: Option<IpAddr>,
        peer_device_id: Option<&str>,
    ) -> DisplayRpcResponse {
        let is_loopback_caller = peer_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
        let is_authorized_remote_toggle = match req {
            DisplayRpcRequest::ToggleMacToPc => cfg!(target_os = "macos") && peer_ip.is_some(),
            DisplayRpcRequest::TogglePcToMac => cfg!(target_os = "windows") && peer_ip.is_some(),
            _ => false,
        };
        // Enforce loopback restriction on sensitive administrative commands
        if matches!(
            req,
            DisplayRpcRequest::ToggleMacToPc
                | DisplayRpcRequest::TogglePcToMac
                | DisplayRpcRequest::PasteRemote
                | DisplayRpcRequest::ShowWindow
                | DisplayRpcRequest::GetPairingPin
                | DisplayRpcRequest::PairWithPeer { .. }
                | DisplayRpcRequest::RouteRemoteAudio { .. }
                | DisplayRpcRequest::StopAudioRouting
                | DisplayRpcRequest::GetAudioStatus
        ) && !is_loopback_caller
            && !is_authorized_remote_toggle
        {
            warn!(
                "🚫 Rejected local-only DisplayRpcRequest {:?} from non-loopback peer {:?}",
                req, peer_ip
            );
            return self
                .base_response(false, "Rejected: request is restricted to local loopback CLI")
                .await;
        }

        // Verify that the requested subsystem feature flag is enabled
        if let Some(feature) = required_feature_for_rpc(&req) {
            if !self.features.is_enabled(feature)
                && !(is_loopback_caller && matches!(req, DisplayRpcRequest::StopAll | DisplayRpcRequest::StopMoonlight))
            {
                warn!(
                    "🚫 Rejected DisplayRpcRequest {:?} from {:?}: feature '{}' is disabled",
                    req, peer_ip, feature
                );
                return self
                    .base_response(
                        false,
                        format!("Rejected: feature '{}' is disabled on this device", feature),
                    )
                    .await;
            }
        }

        match req {
            DisplayRpcRequest::Ping => self.base_response(true, "pong").await,
            DisplayRpcRequest::GetHardwareProfile => {
                let Ok(profile) = tokio::task::spawn_blocking(system_info::collect_local_profile).await
                else {
                    return self
                        .base_response(false, "Failed to collect hardware profile")
                        .await;
                };
                let mut resp = self
                    .base_response(true, format!("Hardware profile for {}", profile.hostname))
                    .await;
                resp.hardware_profile = Some(profile);
                resp
            }
            DisplayRpcRequest::StartMoonlight {
                host_ip,
                host_port,
                host_name,
                width,
                height,
                fps,
                bitrate_kbps,
                audio_on_host,
                hdr,
            } => {
                let caller_ip_str = peer_ip.map(|ip| ip.to_string()).unwrap_or_default();
                let is_loopback_caller = peer_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
                let trimmed_host_ip = host_ip.trim();

                // Prevent malicious redirect attacks to third-party endpoints
                if !is_loopback_caller
                    && !trimmed_host_ip.is_empty()
                    && !caller_ip_str.is_empty()
                    && trimmed_host_ip != caller_ip_str
                {
                    warn!(
                        "🚫 Rejected StartMoonlight from {}: tried to redirect client to third-party host {}",
                        caller_ip_str, trimmed_host_ip
                    );
                    return self
                        .base_response(
                            false,
                            "Rejected StartMoonlight: host_ip must match the authenticated peer address",
                        )
                        .await;
                }

                let effective_host_ip = if !is_loopback_caller && !caller_ip_str.is_empty() {
                    caller_ip_str
                } else if !trimmed_host_ip.is_empty() {
                    trimmed_host_ip.to_string()
                } else {
                    caller_ip_str
                };
                if effective_host_ip.is_empty() || !system_info::is_valid_ipv4(&effective_host_ip) {
                    return self
                        .base_response(false, "Missing or invalid host_ip in StartMoonlight request")
                        .await;
                }
                if host_port > 0 && host_port < MIN_UNPRIVILEGED_PORT {
                    return self
                        .base_response(false, "Rejected StartMoonlight: invalid privileged host_port")
                        .await;
                }

                info!("Handling StartMoonlight RPC from host {}", effective_host_ip);

                let prefs = tokio::task::spawn_blocking(system_info::load_path_preferences)
                    .await
                    .unwrap_or_default();
                let secondary_port = resolve_secondary_sunshine_port(&prefs);

                let port = if host_port >= MIN_UNPRIVILEGED_PORT {
                    host_port
                } else if Self::is_tcp_port_open(&effective_host_ip, config::SUNSHINE_DEFAULT_PORT)
                    .await
                {
                    config::SUNSHINE_DEFAULT_PORT
                } else if Self::is_tcp_port_open(&effective_host_ip, secondary_port).await {
                    secondary_port
                } else if Self::wait_for_tcp_port(
                    &effective_host_ip,
                    config::SUNSHINE_DEFAULT_PORT,
                    REMOTE_PORT_WAIT_TIMEOUT,
                )
                .await
                {
                    config::SUNSHINE_DEFAULT_PORT
                } else if Self::wait_for_tcp_port(
                    &effective_host_ip,
                    secondary_port,
                    REMOTE_PORT_WAIT_TIMEOUT,
                )
                .await
                {
                    secondary_port
                } else {
                    config::SUNSHINE_DEFAULT_PORT
                };

                let effective_host_name = if !host_name.trim().is_empty() {
                    host_name
                } else {
                    self.discovery
                        .get_all_peers()
                        .await
                        .into_iter()
                        .find(|c| c.addr.ip().to_string() == effective_host_ip)
                        .and_then(|c| {
                            c.sunshine_name
                                .filter(|s| !s.trim().is_empty())
                                .or(Some(c.device_name))
                        })
                        .unwrap_or_else(|| effective_host_ip.clone())
                };

                let _tx = self.transition_lock.lock().await;
                let local_disp = tokio::task::spawn_blocking(system_info::get_primary_display_info)
                    .await
                    .unwrap_or(system_info::PrimaryDisplayInfo {
                        width: config::DEFAULT_DISPLAY_WIDTH,
                        height: config::DEFAULT_DISPLAY_HEIGHT,
                        fps: config::DEFAULT_DISPLAY_FPS,
                        scale_factor: 1.0,
                    });
                let eff_w = (if width > 0 { width } else { local_disp.width })
                    .clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH)
                    & !1;
                let eff_h = (if height > 0 { height } else { local_disp.height })
                    .clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT)
                    & !1;
                let raw_fps = if fps > 0 { fps } else { local_disp.fps };
                let eff_fps = (if raw_fps > 0 {
                    raw_fps
                } else {
                    config::DEFAULT_DISPLAY_FPS
                })
                .clamp(config::MIN_DISPLAY_FPS, config::MAX_DISPLAY_FPS);
                let eff_bitrate = if bitrate_kbps > 0 {
                    bitrate_kbps.clamp(config::MIN_BITRATE_KBPS, config::MAX_BITRATE_KBPS)
                } else {
                    config::DEFAULT_BITRATE_KBPS
                };

                let host_ip_arg = effective_host_ip.clone();
                let host_name_arg = effective_host_name.clone();
                let launch_res = tokio::task::spawn_blocking(move || {
                    if cfg!(target_os = "windows") {
                        WinDisplayManager::start_moonlight_client(
                            &host_ip_arg,
                            port,
                            &host_name_arg,
                            eff_w,
                            eff_h,
                            eff_fps,
                            eff_bitrate,
                            audio_on_host,
                            hdr,
                        )
                    } else {
                        MacDisplayManager::start_moonlight_client(
                            &host_ip_arg,
                            port,
                            &host_name_arg,
                            eff_w,
                            eff_h,
                            eff_fps,
                            eff_bitrate,
                            audio_on_host,
                            hdr,
                        )
                    }
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Moonlight launcher panicked: {}", e)));

                match launch_res {
                    Ok(_) => {
                        *self.client_active.write().await = true;
                        *self.client_peer_id.write().await = peer_device_id.map(|s| s.trim().to_ascii_lowercase());
                        *self.active_peer_ip.write().await = Some(effective_host_ip.clone());
                        let client_mode_str = if cfg!(target_os = "windows") {
                            "Mac -> PC (Client)"
                        } else {
                            "PC -> Mac (Client)"
                        };
                        *self.active_mode.write().await = Some(client_mode_str.into());
                        self.base_response(
                            true,
                            format!(
                                "Started Moonlight client for {} ({}:{}) at {}x{} @ {}Hz",
                                effective_host_name, effective_host_ip, port, eff_w, eff_h, eff_fps
                            ),
                        )
                        .await
                    }
                    Err(e) => {
                        self.clear_client_state().await;
                        self.base_response(false, format!("Failed to start Moonlight client: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::StopMoonlight => {
                info!("Handling StopMoonlight RPC");
                let _tx = self.transition_lock.lock().await;
                let _ = tokio::task::spawn_blocking(|| {
                    if cfg!(target_os = "windows") {
                        let _ = WinDisplayManager::stop_moonlight_client();
                    } else {
                        let _ = MacDisplayManager::stop_moonlight_client();
                    }
                })
                .await;
                self.clear_client_state().await;
                self.base_response(true, "Stopped Moonlight client").await
            }
            DisplayRpcRequest::ToggleMacToPc => match self.toggle_mac_to_pc().await {
                Ok(msg) => self.base_response(true, msg).await,
                Err(e) => self
                    .base_response(false, format!("Error toggling Mac-to-PC: {}", e))
                    .await,
            },
            DisplayRpcRequest::TogglePcToMac => match self.toggle_pc_to_mac().await {
                Ok(msg) => self.base_response(true, msg).await,
                Err(e) => self
                    .base_response(false, format!("Error toggling PC-to-Mac: {}", e))
                    .await,
            },
            DisplayRpcRequest::StopAll => {
                let _tx = self.transition_lock.lock().await;
                if cfg!(target_os = "macos") {
                    let _ = self.stop_mac_to_pc_locked().await;
                    let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_moonlight_client)
                        .await;
                } else if cfg!(target_os = "windows") {
                    let _ = self.stop_pc_to_mac_locked().await;
                    let _ = tokio::task::spawn_blocking(WinDisplayManager::stop_moonlight_client)
                        .await;
                }
                if is_loopback_caller {
                    if let Some(remote_ip) = self.discovery.get_peer_ip().await {
                        if let Ok(ip) = remote_ip.parse::<IpAddr>() {
                            if !ip.is_loopback() {
                                let _ =
                                    Self::send_remote_rpc(&remote_ip, &DisplayRpcRequest::StopAll)
                                        .await;
                            }
                        }
                    }
                }
                *self.host_active.write().await = false;
                *self.client_active.write().await = false;
                *self.host_peer_id.write().await = None;
                *self.client_peer_id.write().await = None;
                *self.active_peer_ip.write().await = None;
                *self.active_mode.write().await = None;
                self.base_response(true, "All display extensions stopped")
                    .await
            }
            DisplayRpcRequest::GetStatus => {
                let active = self.is_active().await;
                let mode = self.active_mode.read().await.clone();
                DisplayRpcResponse {
                    success: true,
                    message: format!("Status: active={}, mode={:?}", active, mode),
                    is_active: active,
                    active_mode: mode,
                    ..Default::default()
                }
            }
            DisplayRpcRequest::GetGpuTelemetry => {
                let telemetry = tokio::task::spawn_blocking(crate::telemetry::query_gpu_telemetry)
                    .await
                    .unwrap_or(None);
                let success = telemetry.is_some();
                let msg = if success {
                    "GPU telemetry retrieved"
                } else {
                    "GPU telemetry unavailable"
                };
                let mut resp = self.base_response(success, msg).await;
                resp.gpu_telemetry = telemetry;
                resp
            }
            DisplayRpcRequest::PasteRemote => {
                if let Some(service) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
                    match service.paste_remote(None).await {
                        Ok(msg) => self.base_response(true, msg).await,
                        Err(e) => self
                            .base_response(false, format!("Failed to paste remote item: {}", e))
                            .await,
                    }
                } else {
                    self.base_response(false, "Clipboard service not initialized")
                        .await
                }
            }
            DisplayRpcRequest::ShowWindow => {
                crate::core::request_show_window();
                self.base_response(true, "Window focused").await
            }
            DisplayRpcRequest::SyncTrueTone {
                lux,
                cct,
                gamma_comp,
                raw_als,
                als_ch0,
                als_ch1,
                als_ch2,
                cie_x,
                cie_y,
                cie_z,
            } => {
                let valid_opt = |v: Option<f32>| -> bool {
                    v.map_or(true, |x| x.is_finite() && (0.0..=1_000_000.0).contains(&x))
                };
                if !lux.is_finite()
                    || !(0.0..=TRUETONE_MAX_LUX).contains(&lux)
                    || !gamma_comp.is_finite()
                    || !(TRUETONE_MIN_WIRE_GAMMA..=TRUETONE_MAX_WIRE_GAMMA).contains(&gamma_comp)
                    || (!raw_als && !(TRUETONE_MIN_WIRE_CCT..=TRUETONE_MAX_WIRE_CCT).contains(&cct))
                    || !valid_opt(als_ch0)
                    || !valid_opt(als_ch1)
                    || !valid_opt(als_ch2)
                    || !valid_opt(cie_x)
                    || !valid_opt(cie_y)
                    || !valid_opt(cie_z)
                {
                    return self
                        .base_response(false, "Rejected SyncTrueTone: out-of-range calibration values")
                        .await;
                }
                let res: Result<(f32, u32), anyhow::Error> = tokio::task::spawn_blocking(move || {
                    if raw_als {
                        let (eff_lux, eff_cct) = crate::truetone::apply_raw_als_sync(
                            lux, als_ch0, als_ch1, als_ch2, cie_x, cie_y, cie_z, gamma_comp,
                        )?;
                        crate::truetone::record_synced_ambient(eff_lux, eff_cct);
                        Ok((eff_lux, eff_cct))
                    } else {
                        let clamped_cct = cct.clamp(config::MIN_CCT_KELVIN, config::MAX_CCT_KELVIN);
                        crate::truetone::apply_hardware_gamma_ramp(clamped_cct, gamma_comp)?;
                        crate::truetone::record_synced_ambient(lux, clamped_cct);
                        Ok((lux, clamped_cct))
                    }
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("TrueTone task panicked: {}", e)));
                let success = res.is_ok();
                let (out_lux, out_cct, message) = match res {
                    Ok((eff_lux, eff_cct)) => (
                        eff_lux,
                        eff_cct,
                        format!(
                            "Applied True Tone LUT: CCT={}K, Lux={:.1}, Gamma={:.2}x",
                            eff_cct, eff_lux, gamma_comp
                        ),
                    ),
                    Err(e) => (
                        lux,
                        cct,
                        format!("Failed to apply True Tone LUT: {}", e),
                    ),
                };
                let mut resp = self.base_response(success, message).await;
                resp.ambient_light = Some(crate::truetone::AmbientLightData {
                    lux: out_lux,
                    cct_kelvin: out_cct,
                    supported: success && out_lux >= 0.0,
                    updated_at_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                });
                resp
            }
            DisplayRpcRequest::MountStorage => {
                let (target_ip, share_hint) = if let Some(rip) = peer_ip.filter(|ip| !ip.is_loopback())
                {
                    let peers = self.discovery.get_all_peers().await;
                    let hint = peers
                        .into_iter()
                        .find(|c| c.addr.ip() == rip)
                        .and_then(|c| c.share_name);
                    (Some(rip.to_string()), hint)
                } else {
                    let best = self.discovery.get_best_peer().await;
                    (
                        best.as_ref().map(|p| p.addr.ip().to_string()),
                        best.and_then(|p| p.share_name),
                    )
                };

                let Some(target_ip) = target_ip else {
                    return self
                        .base_response(false, "No active peer discovered to mount storage from.")
                        .await;
                };

                let mount_res = tokio::task::spawn_blocking(move || {
                    crate::storage::StorageManager::mount_with_share(
                        &target_ip,
                        share_hint.as_deref(),
                    )
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Mount task panicked: {}", e)));

                match mount_res {
                    Ok(status) => {
                        let mut resp = self
                            .base_response(status.is_mounted, status.message.clone())
                            .await;
                        resp.storage_status = Some(status);
                        resp
                    }
                    Err(e) => self
                        .base_response(false, format!("Mount request failed: {}", e))
                        .await,
                }
            }
            DisplayRpcRequest::UnmountStorage => {
                let unmount_res = tokio::task::spawn_blocking(crate::storage::StorageManager::unmount)
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("Unmount task panicked: {}", e)));
                match unmount_res {
                    Ok(status) => {
                        let mut resp = self.base_response(true, status.message.clone()).await;
                        resp.storage_status = Some(status);
                        resp
                    }
                    Err(e) => self
                        .base_response(false, format!("Unmount request failed: {}", e))
                        .await,
                }
            }
            DisplayRpcRequest::NegotiateAudioSession {
                sender_nonce_hex,
                sample_rate,
                channels,
                bit_depth,
            } => {
                let Some(caller_ip) = peer_ip else {
                    return self
                        .base_response(false, "Missing peer IP for audio session negotiation")
                        .await;
                };
                // Fail-closed: require authenticated, non-revoked peer_device_id (AUD-1G7-15)
                let Some(auth_id_raw) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) else {
                    return self
                        .base_response(false, "Audio session negotiation requires authenticated peer identity")
                        .await;
                };
                if crate::security::transport::is_peer_revoked(auth_id_raw) {
                    return self
                        .base_response(false, "Audio session negotiation rejected: requesting peer is revoked")
                        .await;
                }
                let auth_id = auth_id_raw.to_string();
                let nonce_arg = sender_nonce_hex;
                let neg_res = tokio::task::spawn_blocking(move || {
                    crate::audio::AudioManager::handle_negotiate_session_for_peer(
                        Some(auth_id.as_str()),
                        caller_ip,
                        &nonce_arg,
                        sample_rate,
                        channels,
                        bit_depth,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(format!("Audio negotiation panicked: {}", e)));

                match neg_res {
                    Ok(wire) => {
                        let mut resp = self
                            .base_response(
                                true,
                                format!(
                                    "Negotiated authenticated IUA2 UDP audio session ({}Hz, {}ch, {}-bit)",
                                    sample_rate, channels, bit_depth
                                ),
                            )
                            .await;
                        resp.audio_session = Some(wire);
                        resp
                    }
                    Err(e) => {
                        self.base_response(false, format!("Audio session negotiation failed: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::StartAudioCapture {
                sample_rate,
                channels,
                bit_depth,
            } => {
                let Some(caller_ip) = peer_ip else {
                    return self
                        .base_response(false, "Missing peer IP for audio capture request")
                        .await;
                };
                // Fail-closed: require authenticated, non-revoked peer_device_id (AUD-1G7-15)
                let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) else {
                    return self
                        .base_response(false, "StartAudioCapture requires authenticated peer identity")
                        .await;
                };
                if crate::security::transport::is_peer_revoked(auth_id) {
                    return self
                        .base_response(false, "StartAudioCapture rejected: requesting peer is revoked")
                        .await;
                }
                let ip_str = caller_ip.to_string();
                let Some(peer_creds) = trust::lookup_verified_peer_by_id_at_ip(auth_id, caller_ip) else {
                    return self
                        .base_response(
                            false,
                            format!("Peer {} ({}) is not cryptographically paired or verified", auth_id, ip_str),
                        )
                        .await;
                };
                let res = crate::audio::AudioManager::start_capture_and_stream_for_peer(
                    &ip_str,
                    peer_creds,
                    sample_rate,
                    channels,
                    bit_depth,
                )
                .await;
                match res {
                    Ok(msg) => self.base_response(true, msg).await,
                    Err(e) => {
                        self.base_response(false, format!("Failed to start audio capture: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::StopAudioCapture => {
                let Some(caller_ip) = peer_ip else {
                    return self
                        .base_response(false, "Missing peer IP for stop audio capture")
                        .await;
                };
                // Fail-closed: require authenticated, non-revoked peer_device_id and enforce session ownership (AUD-1G7-15)
                let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) else {
                    return self
                        .base_response(false, "StopAudioCapture requires authenticated peer identity")
                        .await;
                };
                if crate::security::transport::is_peer_revoked(auth_id) {
                    return self
                        .base_response(false, "StopAudioCapture rejected: requesting peer is revoked")
                        .await;
                }
                let ip_str = caller_ip.to_string();
                let Some(peer_creds) = trust::lookup_verified_peer_by_id_at_ip(auth_id, caller_ip) else {
                    return self
                        .base_response(
                            false,
                            format!("Peer {} ({}) is not cryptographically paired or verified", auth_id, ip_str),
                        )
                        .await;
                };
                match crate::audio::AudioManager::stop_capture_for_peer(&peer_creds.device_id).await {
                    Ok(msg) => self.base_response(true, msg).await,
                    Err(err) => self.base_response(false, err).await,
                }
            }
            DisplayRpcRequest::RouteRemoteAudio { peer_ip: target_ip } => {
                let res = crate::audio::AudioManager::start_audio_routing(&target_ip).await;
                match res {
                    Ok(msg) => self.base_response(true, msg).await,
                    Err(e) => {
                        self.base_response(false, format!("Failed to start audio routing: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::StopAudioRouting => {
                let res = crate::audio::AudioManager::stop_audio_routing().await;
                match res {
                    Ok(msg) => self.base_response(true, msg).await,
                    Err(e) => {
                        self.base_response(false, format!("Failed to stop audio routing: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::GetAudioStatus => {
                let st = crate::audio::AudioManager::status();
                let mut resp = self.base_response(true, "Audio status retrieved").await;
                resp.audio_status = Some(st);
                resp
            }
            DisplayRpcRequest::GetPairingPin => {
                let (pin, _ttl_secs) = trust::open_or_get_pairing_pin();
                let mut resp = self
                    .base_response(true, format!("Active Pairing PIN: {}", pin))
                    .await;
                resp.pairing_token = Some(pin);
                resp
            }
            DisplayRpcRequest::PairWithPeer { ip, pin } => {
                let trimmed_ip = ip.trim();
                let trimmed_pin = pin.trim();
                if trimmed_ip.parse::<IpAddr>().is_err() {
                    return self
                        .base_response(false, "Invalid peer IP address for pairing")
                        .await;
                }
                if trimmed_pin.len() != config::PAIRING_PIN_LENGTH
                    || !trimmed_pin.bytes().all(|b| b.is_ascii_digit())
                {
                    return self
                        .base_response(
                            false,
                            format!(
                                "Pairing PIN must be a {}-digit number",
                                config::PAIRING_PIN_LENGTH
                            ),
                        )
                        .await;
                }
                match trust::pair_with_remote_peer_v2(trimmed_ip, CONTROL_PORT, trimmed_pin).await {
                    Ok((creds, sas_6)) => {
                        self.base_response(
                            true,
                            format!(
                                "Paired and mutually authenticated with {} ({}) [SAS: {}]",
                                creds.hostname,
                                trimmed_ip,
                                sas_6
                            ),
                        )
                        .await
                    }
                    Err(e) => self.base_response(false, e).await,
                }
            }
            DisplayRpcRequest::GetBridgeStatus => {
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let s = core.build_bridge_status().await;
                    let mut resp = self.base_response(true, "Bridge status retrieved").await;
                    resp.bridge_status = serde_json::to_value(s).ok();
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::StartCamera => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                let Some(auth_peer_id) = peer_device_id.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                    return self.base_response(false, "Rejected: Camera request requires authenticated peer identity").await;
                };
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    match core.camera.start_remote_request(Some(auth_peer_id)).await {
                        Ok((msg, lease_token)) => {
                            let mut resp = self.base_response(true, msg).await;
                            resp.camera_status = Some(core.camera.status());
                            resp.camera_lease_token_hex = Some(crate::security::hex_encode(&lease_token));
                            resp
                        }
                        Err(e) => self.base_response(false, format!("Failed to start camera: {}", e)).await,
                    }
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::CheckCameraConsent => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                let Some(auth_peer_id) = peer_device_id.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                    return self.base_response(false, "Rejected: Camera request requires authenticated peer identity").await;
                };
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let status = core.camera.query_consent_status(auth_peer_id);
                    let mut resp = self.base_response(true, "Camera consent status retrieved").await;
                    resp.camera_consent_status = Some(status);
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::ToggleCamera => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                let Some(auth_peer_id) = peer_device_id.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                    return self.base_response(false, "Rejected: Camera request requires authenticated peer identity").await;
                };
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    match core.camera.toggle_remote_request(Some(auth_peer_id)).await {
                        Ok(msg) => {
                            let mut resp = self.base_response(true, msg).await;
                            resp.camera_status = Some(core.camera.status());
                            resp
                        }
                        Err(e) => self.base_response(false, format!("Failed to toggle camera: {}", e)).await,
                    }
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::StopCamera => {
                let Some(auth_peer_id) = peer_device_id.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                    return self
                        .base_response(false, "Rejected: StopCamera request requires authenticated peer identity")
                        .await;
                };
                let clean_auth_id = auth_peer_id.to_ascii_lowercase();
                if crate::security::transport::is_peer_revoked(&clean_auth_id) {
                    return self
                        .base_response(false, "Rejected: requesting peer is revoked")
                        .await;
                }
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    core.camera.teardown_peer_stream(&clean_auth_id);
                    let mut resp = self.base_response(true, format!("Shared Camera stopped for peer {}", clean_auth_id)).await;
                    resp.camera_status = Some(core.camera.status());
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::GetCameraStatus => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let mut resp = self.base_response(true, "Camera status retrieved").await;
                    resp.camera_status = Some(core.camera.status());
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::ListCameras => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::security::transport::is_peer_revoked(&auth_id.to_ascii_lowercase()) {
                        return self.base_response(false, "Rejected: requesting peer is revoked").await;
                    }
                }
                let cams = tokio::task::spawn_blocking(crate::camera::list_available_cameras)
                    .await
                    .unwrap_or_default();
                let mut resp = self.base_response(true, "Camera list retrieved").await;
                resp.available_cameras = Some(cams);
                resp
            }
            DisplayRpcRequest::SelectCamera { device_id } => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::security::transport::is_peer_revoked(&auth_id.to_ascii_lowercase()) {
                        return self.base_response(false, "Rejected: requesting peer is revoked").await;
                    }
                }
                let trimmed = device_id.trim().to_string();
                let clean_label = crate::media::sanitize_media_text(&trimmed, 64);
                if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
                    return self
                        .base_response(false, format!("Rejected SelectCamera: invalid device_id '{}'", clean_label))
                        .await;
                }
                let ok = tokio::task::spawn_blocking(move || crate::camera::select_camera_device(&trimmed))
                    .await
                    .unwrap_or(false);
                let msg = if ok {
                    format!("Selected camera '{}'", clean_label)
                } else {
                    format!("Failed to select camera '{}'", clean_label)
                };
                self.base_response(ok, msg).await
            }
            DisplayRpcRequest::ListMics => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::security::transport::is_peer_revoked(&auth_id.to_ascii_lowercase()) {
                        return self.base_response(false, "Rejected: requesting peer is revoked").await;
                    }
                }
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let cam = Arc::clone(&core.camera);
                    let mics = tokio::task::spawn_blocking(move || cam.list_mics())
                        .await
                        .unwrap_or_default();
                    let mut resp = self
                        .base_response(true, format!("Retrieved {} microphone device(s)", mics.len()))
                        .await;
                    resp.available_mics = Some(mics);
                    resp.camera_status = Some(core.camera.status());
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::SelectMic { device_id } => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::security::transport::is_peer_revoked(&auth_id.to_ascii_lowercase()) {
                        return self.base_response(false, "Rejected: requesting peer is revoked").await;
                    }
                }
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let cam = Arc::clone(&core.camera);
                    let res = tokio::task::spawn_blocking(move || cam.select_mic(&device_id))
                        .await
                        .unwrap_or_else(|e| Err(format!("SelectMic task panicked: {}", e)));
                    match res {
                        Ok(mic_name) => {
                            let mut resp = self
                                .base_response(true, format!("Selected microphone '{}'", mic_name))
                                .await;
                            resp.camera_status = Some(core.camera.status());
                            resp
                        }
                        Err(e) => self.base_response(false, e).await,
                    }
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::SetMicSettings {
                enabled,
                muted,
                gain,
            } => {
                if !self.features.is_enabled("camera") {
                    return self.base_response(false, "Rejected: feature 'camera' is disabled on this device").await;
                }
                if let Some(auth_id) = peer_device_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::security::transport::is_peer_revoked(&auth_id.to_ascii_lowercase()) {
                        return self.base_response(false, "Rejected: requesting peer is revoked").await;
                    }
                }
                if !gain.is_finite() {
                    return self
                        .base_response(false, "Rejected SetMicSettings: non-finite gain value")
                        .await;
                }
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let cam = Arc::clone(&core.camera);
                    let status = tokio::task::spawn_blocking(move || {
                        cam.set_mic_settings(enabled, muted, gain)
                    })
                    .await
                    .unwrap_or_else(|_| core.camera.status());
                    let mut resp = self
                        .base_response(
                            true,
                            format!(
                                "Shared microphone {} (muted={}, gain={:.0}%)",
                                if status.mic_enabled { "enabled" } else { "disabled" },
                                status.mic_muted,
                                status.mic_gain * 100.0
                            ),
                        )
                        .await;
                    resp.camera_status = Some(status);
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::VerifyTouchId {
                challenge_nonce_hex,
                requester_hostname,
            } => {
                if !self.features.is_enabled("touchid") {
                    return self.base_response(false, "Rejected: feature 'touchid' is disabled on this device").await;
                }
                let Some(req_dev_id) = peer_device_id.map(|s| s.to_string()) else {
                    return self
                        .base_response(
                            false,
                            "Rejected Touch ID challenge: missing authenticated TransportV2 peer identity",
                        )
                        .await;
                };
                let nonce = challenge_nonce_hex.trim().to_ascii_lowercase();
                let req_host = requester_hostname.trim().to_string();
                let host_label = if req_host.is_empty() { "Windows Hello Login" } else { &req_host };
                let _tb_guard = TouchBarTouchIdGuard::activate(&format!("Approve {}", host_label));
                crate::core::emit_ui_toast(
                    "info",
                    &format!(
                        "Touch ID requested by '{}' — place your finger on Touch ID...",
                        if req_host.is_empty() { "Paired PC" } else { &req_host }
                    ),
                );
                let eval_res = tokio::task::spawn_blocking(move || {
                    trust::evaluate_local_touchid_and_sign(&nonce, &req_dev_id, &req_host)
                })
                .await
                .unwrap_or_else(|e| Err(format!("Touch ID task panicked: {}", e)));

                match eval_res {
                    Ok(assertion) => {
                        crate::core::emit_ui_toast(
                            "success",
                            &format!(
                                "Touch ID verified via Secure Enclave for {} (sig {}…)",
                                assertion.requester_device_id.chars().take(8).collect::<String>(),
                                assertion.signature_hex.chars().take(12).collect::<String>()
                            ),
                        );
                        let mut resp = self
                            .base_response(
                                true,
                                format!(
                                    "Touch ID verified on '{}' via Apple Secure Enclave",
                                    assertion.signer_hostname
                                ),
                            )
                            .await;
                        resp.touchid_assertion = Some(assertion);
                        resp
                    }
                    Err(err_msg) => {
                        crate::core::emit_ui_toast("error", &format!("Touch ID failed: {}", err_msg));
                        self.base_response(false, err_msg).await
                    }
                }
            }
            DisplayRpcRequest::PasskeyMakeCredential(make_req) => {
                if !self.features.is_enabled("touchid") {
                    return self.base_response(false, "Rejected: feature 'touchid' is disabled on this device").await;
                }
                let req_copy = make_req.clone();
                let rp_id_label = req_copy.rp_id.clone();
                let _tb_guard = TouchBarTouchIdGuard::activate(&format!("Create Passkey: {}", rp_id_label));
                crate::core::emit_ui_toast(
                    "info",
                    &format!(
                        "Passkey registration requested for '{}' ({}) — place your finger on Touch ID...",
                        &rp_id_label, &req_copy.user_name
                    ),
                );
                // Dispatch Touch ID biometric evaluation in a dedicated blocking worker thread
                let eval_res = tokio::task::spawn_blocking(move || {
                    crate::security::passkey::evaluate_mac_touchid_and_make_credential(&req_copy)
                })
                .await
                .unwrap_or_else(|e| Err(format!("Passkey registration task panicked: {}", e)));

                match eval_res {
                    Ok(cred_resp) => {
                        crate::core::emit_ui_toast(
                            "success",
                            &format!(
                                "Passkey created for '{}' via Apple Touch ID",
                                &rp_id_label
                            ),
                        );
                        let mut resp = self
                            .base_response(
                                true,
                                format!("Passkey created for '{}' via Touch ID", rp_id_label),
                            )
                            .await;
                        resp.passkey_credential = Some(cred_resp);
                        resp
                    }
                    Err(err_msg) => {
                        crate::core::emit_ui_toast("error", &format!("Passkey creation failed: {}", err_msg));
                        self.base_response(false, err_msg).await
                    }
                }
            }
            DisplayRpcRequest::PasskeyGetAssertion(assert_req) => {
                if !self.features.is_enabled("touchid") {
                    return self.base_response(false, "Rejected: feature 'touchid' is disabled on this device").await;
                }
                let req_copy = assert_req.clone();
                let rp_id_label = req_copy.rp_id.clone();
                let _tb_guard = TouchBarTouchIdGuard::activate(&format!("Sign in to {}", rp_id_label));
                crate::core::emit_ui_toast(
                    "info",
                    &format!(
                        "Passkey sign-in requested for '{}' — place your finger on Touch ID...",
                        &rp_id_label
                    ),
                );
                // Dispatch Touch ID biometric evaluation in a dedicated blocking worker thread
                let eval_res = tokio::task::spawn_blocking(move || {
                    crate::security::passkey::evaluate_mac_touchid_and_sign_assertion(&req_copy)
                })
                .await
                .unwrap_or_else(|e| Err(format!("Passkey sign-in task panicked: {}", e)));

                match eval_res {
                    Ok(assert_resp) => {
                        crate::core::emit_ui_toast(
                            "success",
                            &format!(
                                "Passkey assertion signed for '{}' via Apple Touch ID",
                                &rp_id_label
                            ),
                        );
                        let mut resp = self
                            .base_response(
                                true,
                                format!("Passkey signed for '{}' via Touch ID", rp_id_label),
                            )
                            .await;
                        resp.passkey_assertion = Some(assert_resp);
                        resp
                    }
                    Err(err_msg) => {
                        crate::core::emit_ui_toast("error", &format!("Passkey sign-in failed: {}", err_msg));
                        self.base_response(false, err_msg).await
                    }
                }
            }
            DisplayRpcRequest::NotifyTouchIdPrompt { label, active } => {
                // Passive Windows watcher notifications no longer present a custom Touch Bar
                // banner; actual Touch ID / Passkey challenges yield Integrator's HUD so Apple's
                // native LocalAuthentication Touch Bar prompt renders unobstructed.
                let _ = (label, active);
                self.base_response(
                    true,
                    "Touch ID uses native macOS LocalAuthentication Touch Bar prompt",
                )
                .await
            }
            DisplayRpcRequest::SetDisplayMode {
                width,
                height,
                fps,
                hdr,
            } => match self.set_display_mode(width, height, fps, hdr).await {
                Ok(msg) => self.base_response(true, msg).await,
                Err(e) => self.base_response(false, e.to_string()).await,
            },
            DisplayRpcRequest::SetKvmBoundaryLock { locked } => {
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    core.kvm.set_boundary_locked(locked, false);
                    self.base_response(
                        true,
                        if locked {
                            "KVM boundary locked".to_string()
                        } else {
                            "KVM boundary unlocked".to_string()
                        },
                    )
                    .await
                } else {
                    self.base_response(false, "Integrator core not initialized").await
                }
            }
            DisplayRpcRequest::GetMediaState => {
                let st = tokio::task::spawn_blocking(crate::media::query_media_state)
                    .await
                    .unwrap_or_default();
                let mut resp = self.base_response(true, "Media state queried").await;
                resp.media_state = Some(st);
                resp
            }
            DisplayRpcRequest::SendMediaCommand { action } => {
                let act = action.clone();
                let res = tokio::task::spawn_blocking(move || crate::media::execute_media_command(&act))
                    .await
                    .unwrap_or_else(|e| Err(format!("Media task panicked: {}", e)));
                match res {
                    Ok(msg) => self.base_response(true, msg).await,
                    Err(err) => self.base_response(false, err).await,
                }
            }
        }
    }

    /// Returns whether display streaming or virtual display is currently active.
    pub async fn is_active(&self) -> bool {
        let host_active = *self.host_active.read().await;
        let client_active = *self.client_active.read().await;
        if cfg!(target_os = "macos") {
            host_active || client_active || MacDisplayManager::is_virtual_display_active()
        } else if cfg!(target_os = "windows") {
            host_active || client_active || WinDisplayManager::is_vdd_active()
        } else {
            host_active || client_active
        }
    }

    /// Returns the currently active display mode label, if any.
    pub async fn get_active_mode(&self) -> Option<String> {
        self.active_mode.read().await.clone()
    }

    /// Sends an encrypted, mutually authenticated RPC request to a remote peer over `TransportSessionV2`.
    ///
    /// - Parameters:
    ///   - `peer_ip`: Target peer IP address.
    ///   - `req`: The [`DisplayRpcRequest`] to send.
    /// - Returns: Deserialized [`DisplayRpcResponse`] on success, or an error if connection or timeout occurs.
    pub async fn send_remote_rpc(
        peer_ip: &str,
        req: &DisplayRpcRequest,
    ) -> Result<DisplayRpcResponse> {
        let recv_timeout = match req {
            DisplayRpcRequest::VerifyTouchId { .. }
            | DisplayRpcRequest::PasskeyMakeCredential(_)
            | DisplayRpcRequest::PasskeyGetAssertion(_) => TOUCHID_RPC_RECV_TIMEOUT,
            _ => RPC_RECV_TIMEOUT,
        };
        let addr = Self::format_socket_target(peer_ip, CONTROL_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CONTROL_PORT,
            crate::security::transport::ServiceId::DisplayRpc,
            RPC_CONNECT_TIMEOUT,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish TransportV2 session to {}: {}", addr, e))?;

        let payload = serde_json::to_vec(req)?;
        tokio::time::timeout(RPC_SEND_TIMEOUT, session.send_message(&payload))
            .await
            .with_context(|| format!("Timed out sending RPC request to {}", addr))?
            .map_err(|e| anyhow::anyhow!("TransportV2 send error to {}: {}", addr, e))?;

        let plain_resp = tokio::time::timeout(recv_timeout, session.recv_message())
            .await
            .with_context(|| format!("Timed out waiting for RPC response from {}", addr))?
            .map_err(|e| anyhow::anyhow!("TransportV2 receive error from {}: {}", addr, e))?;

        if plain_resp.is_empty() || plain_resp.len() > MAX_RPC_RESPONSE_BYTES {
            anyhow::bail!(
                "Invalid RPC response size {} bytes from {}",
                plain_resp.len(),
                addr
            );
        }

        let resp: DisplayRpcResponse = serde_json::from_slice(&plain_resp)?;
        Ok(resp)
    }
}

/// C FFI bridge used by the macOS Touch Bar GPU HUD (`touchbar_hud.swift`) to poll
/// `GetGpuTelemetry` over an authenticated `TransportSessionV2` (`ITR2`) channel.
///
/// # Arguments
/// - `peer_ip_ptr`: Null-terminated C string with peer IPv4/IPv6 address.
/// - `out_buf`: Destination byte buffer receiving the UTF-8 JSON response.
/// - `cap`: Capacity of `out_buf` in bytes.
///
/// # Returns
/// Number of bytes written into `out_buf` (excluding null terminator), or 0 on error.
#[no_mangle]
pub extern "C" fn fetch_rust_gpu_telemetry_json(
    peer_ip_ptr: *const std::os::raw::c_char,
    out_buf: *mut u8,
    cap: usize,
) -> usize {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if peer_ip_ptr.is_null() || out_buf.is_null() || cap < 2 {
            return 0;
        }
        // SAFETY: `peer_ip_ptr` was validated non-null above and points to a NUL-terminated C string.
        let peer_ip = unsafe { std::ffi::CStr::from_ptr(peer_ip_ptr) }
            .to_string_lossy()
            .trim()
            .to_string();
        if peer_ip.is_empty() || peer_ip.parse::<IpAddr>().is_err() {
            return 0;
        }

        let fetch_future = async move {
            DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetGpuTelemetry).await
        };

        let resp_res = if let Some(handle) = crate::clipboard::TOKIO_HANDLE.get() {
            if tokio::runtime::Handle::try_current().is_ok() {
                let h = handle.clone();
                let Ok(res) = std::thread::spawn(move || h.block_on(fetch_future)).join() else {
                    return 0;
                };
                res
            } else {
                handle.block_on(fetch_future)
            }
        } else if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            rt.block_on(fetch_future)
        } else {
            return 0;
        };

        let Ok(resp) = resp_res else {
            return 0;
        };
        let Ok(json_bytes) = serde_json::to_vec(&resp) else {
            return 0;
        };
        if json_bytes.is_empty() || json_bytes.len() >= cap {
            return 0;
        }

        // SAFETY: `json_bytes.len() < cap` ensures buffer capacity for payload plus NUL terminator.
        unsafe {
            std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_buf, json_bytes.len());
            *out_buf.add(json_bytes.len()) = 0;
        }
        json_bytes.len()
    }))
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_socket_target_supports_ipv4_and_ipv6() {
        assert_eq!(
            DisplayController::format_socket_target("10.0.0.2", CONTROL_PORT),
            format!("10.0.0.2:{}", CONTROL_PORT)
        );
        assert_eq!(
            DisplayController::format_socket_target("fe80::1", CONTROL_PORT),
            format!("[fe80::1]:{}", CONTROL_PORT)
        );
    }

    #[test]
    fn resolve_vdd_stream_dimensions_respects_prefs_and_secondary_slot() {
        let defaults = system_info::AppPathPreferences::default();
        // 1080p desktop/laptop peer preserved on both primary and secondary Sunshine ports
        assert_eq!(
            resolve_vdd_stream_dimensions(
                1920,
                1080,
                config::SUNSHINE_DEFAULT_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (1920, 1080)
        );
        assert_eq!(
            resolve_vdd_stream_dimensions(
                1920,
                1080,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (1920, 1080)
        );
        // 1440p QHD desktop peer preserved on both primary and secondary ports
        assert_eq!(
            resolve_vdd_stream_dimensions(
                2560,
                1440,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (2560, 1440)
        );
        // 2560x1600 16:10 laptop peer preserved on both primary and secondary ports
        assert_eq!(
            resolve_vdd_stream_dimensions(
                2560,
                1600,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (2560, 1600)
        );
        // 4K 16:9 desktop monitor (3840x2160) with default 2560x1600 max bounds scales aspect-preservingly to 2560x1440
        assert_eq!(
            resolve_vdd_stream_dimensions(
                3840,
                2160,
                config::SUNSHINE_DEFAULT_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (2560, 1440)
        );
        // 16:10 Retina display (3840x2400) with default 2560x1600 max bounds scales aspect-preservingly to 2560x1600
        assert_eq!(
            resolve_vdd_stream_dimensions(
                3840,
                2400,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &defaults
            ),
            (2560, 1600)
        );
        // Custom 4K VDD bounds allow native 3840x2160 on both primary and secondary ports
        let custom = system_info::AppPathPreferences {
            vdd_max_width: Some(3840),
            vdd_max_height: Some(2160),
            ..Default::default()
        };
        assert_eq!(
            resolve_vdd_stream_dimensions(
                3840,
                2160,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &custom
            ),
            (3840, 2160)
        );
        assert_eq!(
            resolve_vdd_stream_dimensions(
                1920,
                1080,
                config::SUNSHINE_SECONDARY_PORT,
                config::SUNSHINE_SECONDARY_PORT,
                &custom
            ),
            (1920, 1080)
        );
    }

    #[test]
    fn adaptive_bitrate_ladder_and_override_clamping() {
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Thunderbolt,
                Some(20_000),
                120,
                None
            ),
            config::BITRATE_DIRECT_CABLE_HIGH_FPS_KBPS
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Wifi,
                None,
                60,
                None
            ),
            config::BITRATE_WIFI_FALLBACK_KBPS
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Wifi,
                None,
                60,
                Some(120_000)
            ),
            120_000
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Wifi,
                None,
                60,
                Some(999_999)
            ),
            config::MAX_BITRATE_KBPS
        );
        // Nominal 866 Mbps / 1200 Mbps 802.11 PHY rate on Wi-Fi or Hotspot is derated and capped
        // instead of jumping into wired 1GbE (65-85 Mbps) tiers
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Wifi,
                Some(866),
                60,
                None
            ),
            43_300
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Wifi,
                Some(1200),
                60,
                None
            ),
            config::BITRATE_WIFI_MAX_STANDARD_KBPS
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Hotspot,
                Some(866),
                60,
                None
            ),
            config::BITRATE_HOTSPOT_STANDARD_KBPS
        );
        assert_eq!(
            DisplayController::compute_adaptive_bitrate_kbps(
                system_info::LinkTransport::Hotspot,
                None,
                120,
                None
            ),
            config::BITRATE_HOTSPOT_HIGH_FPS_KBPS
        );
    }

    #[tokio::test]
    async fn test_display_peer_scoped_teardown_preserves_other_peer() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("display_peer_test");
        let ctrl = DisplayController::new(discovery, features);

        let peer_host = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer_client = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let peer_unrelated = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        ctrl.set_active_host_peer(Some(peer_host.to_string())).await;
        ctrl.set_active_client_peer(Some(peer_client.to_string())).await;
        *ctrl.host_active.write().await = true;
        *ctrl.client_active.write().await = true;

        // Revoking unrelated peer must do nothing and preserve both sessions
        ctrl.teardown_peer_display(peer_unrelated).await.unwrap();
        assert_eq!(ctrl.host_peer_id().await.as_deref(), Some(peer_host));
        assert_eq!(ctrl.client_peer_id().await.as_deref(), Some(peer_client));
        assert!(*ctrl.host_active.read().await);
        assert!(*ctrl.client_active.read().await);

        // Revoking host peer clears host state, preserves client peer
        ctrl.teardown_peer_display(peer_host).await.unwrap();
        assert_eq!(ctrl.host_peer_id().await, None);
        assert!(!*ctrl.host_active.read().await);
        assert_eq!(ctrl.client_peer_id().await.as_deref(), Some(peer_client));
        assert!(*ctrl.client_active.read().await);

        // Revoking client peer clears client state
        ctrl.teardown_peer_display(peer_client).await.unwrap();
        assert_eq!(ctrl.client_peer_id().await, None);
        assert!(!*ctrl.client_active.read().await);
    }

    #[tokio::test]
    async fn test_display_server_start_camera_rpc_propagates_authenticated_peer_id() {
        let features = Arc::new(FeatureManager::new());
        let _ = features.set_flag_checked("camera", true);
        let discovery = DiscoveryManager::new("disp_cam_auth_test");
        let ctrl = DisplayController::new(discovery, features);

        let caller_ip = "192.168.1.50".parse().unwrap();

        // 1. StartCamera without authenticated peer_device_id must fail closed
        let resp_no_auth = ctrl.handle_rpc(DisplayRpcRequest::StartCamera, Some(caller_ip), None).await;
        assert!(!resp_no_auth.success);
        assert!(resp_no_auth.message.contains("requires authenticated peer identity"));

        // 2. StartCamera with empty authenticated peer_device_id must also fail closed
        let resp_empty_auth = ctrl.handle_rpc(DisplayRpcRequest::StartCamera, Some(caller_ip), Some("   ")).await;
        assert!(!resp_empty_auth.success);
        assert!(resp_empty_auth.message.contains("requires authenticated peer identity"));

        // 3. ToggleCamera without authenticated peer_device_id must fail closed
        let resp_toggle_no_auth = ctrl.handle_rpc(DisplayRpcRequest::ToggleCamera, Some(caller_ip), None).await;
        assert!(!resp_toggle_no_auth.success);
        assert!(resp_toggle_no_auth.message.contains("requires authenticated peer identity"));

        // 4. StopCamera without authenticated peer_device_id must fail closed (SEC-1D-08)
        let resp_stop_no_auth = ctrl.handle_rpc(DisplayRpcRequest::StopCamera, Some(caller_ip), None).await;
        assert!(!resp_stop_no_auth.success);
        assert!(resp_stop_no_auth.message.contains("requires authenticated peer identity"));

        // 5. StopCamera with whitespace authenticated peer_device_id must fail closed
        let resp_stop_empty = ctrl.handle_rpc(DisplayRpcRequest::StopCamera, Some(caller_ip), Some("  ")).await;
        assert!(!resp_stop_empty.success);
        assert!(resp_stop_empty.message.contains("requires authenticated peer identity"));

        // 6. StopCamera with a revoked peer must fail closed
        let revoked_peer = "9999999999999999999999999999999999999999999999999999999999999999";
        crate::security::transport::invalidate_peer_trust(revoked_peer, 2);
        let resp_stop_revoked = ctrl.handle_rpc(DisplayRpcRequest::StopCamera, Some(caller_ip), Some(revoked_peer)).await;
        assert!(!resp_stop_revoked.success);
        assert!(resp_stop_revoked.message.contains("requesting peer is revoked"));
    }

    #[tokio::test]
    async fn test_audio_routing_rpc_authorization_and_loopback_restriction() {
        // Use in-memory test feature flags so cargo test NEVER mutates live features.json (AUD-1G7-18).
        let flags_enabled = crate::features::FeatureFlags {
            audio: true,
            ..Default::default()
        };
        let features = Arc::new(FeatureManager::from_flags_for_test(flags_enabled));
        let discovery = DiscoveryManager::new("disp_audio_auth_test");
        let ctrl = DisplayController::new(discovery, features.clone());

        let remote_ip = "192.168.1.50".parse().unwrap();
        let loopback_ip = "127.0.0.1".parse().unwrap();

        // 1. Remote caller requesting RouteRemoteAudio must be rejected by loopback restriction
        let resp = ctrl
            .handle_rpc(
                DisplayRpcRequest::RouteRemoteAudio {
                    peer_ip: "192.168.1.1".to_string(),
                },
                Some(remote_ip),
                None,
            )
            .await;
        assert!(!resp.success);
        assert!(resp.message.contains("restricted to local loopback CLI"));

        // 2. Remote caller requesting StopAudioRouting must be rejected by loopback restriction
        let resp = ctrl
            .handle_rpc(DisplayRpcRequest::StopAudioRouting, Some(remote_ip), None)
            .await;
        assert!(!resp.success);
        assert!(resp.message.contains("restricted to local loopback CLI"));

        // 3. Remote caller requesting GetAudioStatus must be rejected by loopback restriction
        let resp = ctrl
            .handle_rpc(DisplayRpcRequest::GetAudioStatus, Some(remote_ip), None)
            .await;
        assert!(!resp.success);
        assert!(resp.message.contains("restricted to local loopback CLI"));

        // 4. StartAudioCapture / StopAudioCapture / NegotiateAudioSession without peer_device_id must fail closed (AUD-1G7-15)
        let resp_cap_no_auth = ctrl
            .handle_rpc(
                DisplayRpcRequest::StartAudioCapture {
                    sample_rate: 48000,
                    channels: 2,
                    bit_depth: 16,
                },
                Some(remote_ip),
                None,
            )
            .await;
        assert!(!resp_cap_no_auth.success);
        assert!(resp_cap_no_auth.message.contains("requires authenticated peer identity"));

        let resp_stop_no_auth = ctrl
            .handle_rpc(DisplayRpcRequest::StopAudioCapture, Some(remote_ip), None)
            .await;
        assert!(!resp_stop_no_auth.success);
        assert!(resp_stop_no_auth.message.contains("requires authenticated peer identity"));

        let resp_neg_no_auth = ctrl
            .handle_rpc(
                DisplayRpcRequest::NegotiateAudioSession {
                    sender_nonce_hex: "11".repeat(32),
                    sample_rate: 48000,
                    channels: 2,
                    bit_depth: 16,
                },
                Some(remote_ip),
                None,
            )
            .await;
        assert!(!resp_neg_no_auth.success);
        assert!(resp_neg_no_auth.message.contains("requires authenticated peer identity"));

        // 5. Revoked peer must fail closed on StartAudioCapture / StopAudioCapture / NegotiateAudioSession
        let revoked_id = "88888888888888888888888888888888";
        crate::security::transport::invalidate_peer_trust(revoked_id, 2);
        let resp_cap_revoked = ctrl
            .handle_rpc(
                DisplayRpcRequest::StartAudioCapture {
                    sample_rate: 48000,
                    channels: 2,
                    bit_depth: 16,
                },
                Some(remote_ip),
                Some(revoked_id),
            )
            .await;
        assert!(!resp_cap_revoked.success);
        assert!(resp_cap_revoked.message.contains("requesting peer is revoked"));

        // 6. Loopback caller with audio feature disabled must be rejected on GetAudioStatus,
        //    but StopAudioRouting must remain permitted (AUD-1G7-15).
        let flags_disabled = crate::features::FeatureFlags {
            audio: false,
            ..Default::default()
        };
        let features_off = Arc::new(FeatureManager::from_flags_for_test(flags_disabled));
        let ctrl_off = DisplayController::new(DiscoveryManager::new("disp_audio_off_test"), features_off);
        let resp = ctrl_off
            .handle_rpc(DisplayRpcRequest::GetAudioStatus, Some(loopback_ip), None)
            .await;
        assert!(!resp.success);
        assert!(resp.message.contains("feature 'audio' is disabled"));

        let resp_stop_off = ctrl_off
            .handle_rpc(DisplayRpcRequest::StopAudioRouting, Some(loopback_ip), None)
            .await;
        assert!(
            resp_stop_off.success,
            "StopAudioRouting must remain permitted even when audio feature is disabled (AUD-1G7-15): {}",
            resp_stop_off.message
        );

        // 7. Loopback caller with audio feature enabled gets status
        let resp = ctrl
            .handle_rpc(DisplayRpcRequest::GetAudioStatus, Some(loopback_ip), None)
            .await;
        assert!(resp.success);
        assert!(resp.audio_status.is_some());
    }

    #[tokio::test]
    async fn test_mic_rpc_feature_gate_revocation_and_gain_validation() {
        let remote_ip: IpAddr = "192.168.1.50".parse().unwrap();

        // Disabled camera feature rejects ListMics, SelectMic, and SetMicSettings.
        let flags_off = crate::features::FeatureFlags {
            camera: false,
            ..Default::default()
        };
        let ctrl_off = DisplayController::new(
            DiscoveryManager::new("disp_mic_off_test"),
            Arc::new(FeatureManager::from_flags_for_test(flags_off)),
        );
        assert!(
            !ctrl_off
                .handle_rpc(DisplayRpcRequest::ListMics, Some(remote_ip), None)
                .await
                .success
        );
        assert!(
            !ctrl_off
                .handle_rpc(
                    DisplayRpcRequest::SelectMic {
                        device_id: "mic-1".into(),
                    },
                    Some(remote_ip),
                    None,
                )
                .await
                .success
        );
        assert!(
            !ctrl_off
                .handle_rpc(
                    DisplayRpcRequest::SetMicSettings {
                        enabled: true,
                        muted: false,
                        gain: 1.0,
                    },
                    Some(remote_ip),
                    None,
                )
                .await
                .success
        );

        // Enabled camera feature still rejects revoked peers and non-finite gain inputs.
        let flags_on = crate::features::FeatureFlags {
            camera: true,
            ..Default::default()
        };
        let ctrl_on = DisplayController::new(
            DiscoveryManager::new("disp_mic_on_test"),
            Arc::new(FeatureManager::from_flags_for_test(flags_on)),
        );
        let revoked_peer = "7777777777777777777777777777777777777777777777777777777777777777";
        crate::security::transport::invalidate_peer_trust(revoked_peer, 2);

        let revoked_resp = ctrl_on
            .handle_rpc(DisplayRpcRequest::ListMics, Some(remote_ip), Some(revoked_peer))
            .await;
        assert!(!revoked_resp.success);
        assert!(revoked_resp.message.contains("revoked"));
        crate::security::transport::clear_peer_revocation(revoked_peer);

        let nan_resp = ctrl_on
            .handle_rpc(
                DisplayRpcRequest::SetMicSettings {
                    enabled: true,
                    muted: false,
                    gain: f32::NAN,
                },
                Some(remote_ip),
                None,
            )
            .await;
        assert!(!nan_resp.success);
        assert!(nan_resp.message.contains("non-finite gain"));
    }

    #[tokio::test]
    async fn test_sync_truetone_validation_and_ambient_recording() {
        let flags = crate::features::FeatureFlags {
            truetone: true,
            ..Default::default()
        };
        let ctrl = DisplayController::new(
            DiscoveryManager::new("disp_tt_test"),
            Arc::new(FeatureManager::from_flags_for_test(flags)),
        );
        let peer_ip: IpAddr = "192.168.1.50".parse().unwrap();

        // Out-of-range CCT or non-finite lux must be rejected before applying LUT.
        let bad = ctrl
            .handle_rpc(
                DisplayRpcRequest::SyncTrueTone {
                    lux: f32::NAN,
                    cct: 6500,
                    gamma_comp: 1.0,
                    raw_als: false,
                    als_ch0: None,
                    als_ch1: None,
                    als_ch2: None,
                    cie_x: None,
                    cie_y: None,
                    cie_z: None,
                },
                Some(peer_ip),
                None,
            )
            .await;
        assert!(!bad.success);

        crate::truetone::clear_synced_ambient();
        let ok = ctrl
            .handle_rpc(
                DisplayRpcRequest::SyncTrueTone {
                    lux: 245.5,
                    cct: 5200,
                    gamma_comp: 1.0,
                    raw_als: false,
                    als_ch0: None,
                    als_ch1: None,
                    als_ch2: None,
                    cie_x: None,
                    cie_y: None,
                    cie_z: None,
                },
                Some(peer_ip),
                None,
            )
            .await;
        if ok.success {
            let synced = crate::truetone::get_last_synced_ambient()
                .expect("successful SyncTrueTone must record ambient telemetry");
            assert!((synced.0 - 245.5).abs() < 0.2);
            assert_eq!(synced.1, 5200);
        }
        crate::truetone::clear_synced_ambient();
    }
}
