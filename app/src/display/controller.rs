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
//! including Shared Camera management, True Tone gamma synchronization, remote clipboard pasting,
//! storage filesystem mounting, and low-latency UDP audio negotiation.
//!
//! ## 2. Cross-Platform Architectural Pipelines
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
//! ### Shared Camera Interaction
//! While display streaming operates over Sunshine/Moonlight (ports 47989/48989), the Shared Camera
//! operates concurrently over `TransportSessionV2` on port 58287. Camera commands ([`DisplayRpcRequest::StartCamera`],
//! [`DisplayRpcRequest::ToggleCamera`], [`DisplayRpcRequest::StopCamera`], [`DisplayRpcRequest::GetCameraStatus`])
//! are dispatched directly to [`crate::camera::CameraService`], activating FaceTime HD capture on Mac
//! and the driverless Windows 11 Media Foundation FrameServer virtual webcam (`integrator_vcam.dll`)
//! without mutual interference or encoder resource contention.
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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::config::CONTROL_PORT;
use crate::discovery::{DiscoveryManager, PeerCandidate};
use crate::features::FeatureManager;
use crate::system_info;
use crate::trust;
use super::mac_display::MacDisplayManager;
use super::protocol::{required_feature_for_rpc, DisplayRpcRequest, DisplayRpcResponse};
use super::win_display::WinDisplayManager;

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
        }
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

    /// Checks whether a TCP port is currently open and accepting connections with a 250ms timeout.
    async fn is_tcp_port_open(ip: &str, port: u16) -> bool {
        let addr = Self::format_socket_target(ip, port);
        matches!(
            tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(&addr)).await,
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
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    /// Calculates the optimal streaming bitrate in kilobits per second based on link transport and refresh rate.
    ///
    /// Bitrate Matrix:
    /// - Direct Thunderbolt / USB4 cable: 100 Mbps (standard) / 150 Mbps (120Hz+ high-framerate).
    /// - 2.5GbE+ Ethernet: 100 Mbps / 150 Mbps.
    /// - Gigabit Ethernet: 65 Mbps / 85 Mbps.
    /// - Wi-Fi: 35 Mbps adaptive to avoid airtime congestion.
    fn compute_optimal_bitrate_kbps(peer: &PeerCandidate, fps: u32) -> u32 {
        let high_fps = fps >= 120;
        if peer.transport.is_direct_cable() {
            return if high_fps { 150_000 } else { 100_000 };
        }
        match peer.link_speed_mbps {
            Some(mbps) if mbps >= 2500 => {
                if high_fps {
                    150_000
                } else {
                    100_000
                }
            }
            Some(mbps) if mbps >= 1000 => {
                if high_fps {
                    85_000
                } else {
                    65_000
                }
            }
            Some(mbps) if mbps > 0 => (mbps.saturating_mul(350)).clamp(15_000, 55_000),
            _ => match peer.transport {
                system_info::LinkTransport::Ethernet => {
                    if high_fps {
                        80_000
                    } else {
                        60_000
                    }
                }
                system_info::LinkTransport::Wifi => 35_000,
                _ => 60_000,
            },
        }
    }

    /// Resolves the target peer's real display `(width, height, fps)` and hostname,
    /// querying `GetHardwareProfile` over RPC if beacon fields are incomplete,
    /// clamping refresh rate to `30..=240`, and falling back to the local primary display.
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
                width: 1920,
                height: 1080,
                fps: 60,
                scale_factor: 1.0,
            });
        // Ensure even dimensions required by video encoders (width & !1, height & !1)
        let final_w = (if width > 0 { width } else { local_disp.width }).clamp(800, 7680) & !1;
        let final_h = (if height > 0 { height } else { local_disp.height }).clamp(600, 4320) & !1;
        let raw_fps = if fps > 0 { fps } else { local_disp.fps };
        let final_fps = (if raw_fps > 0 { raw_fps } else { 60 }).clamp(30, 240);
        let final_hostname = if hostname.is_empty() { peer_ip } else { hostname };

        (final_w, final_h, final_fps, final_hostname)
    }

    /// Reads optional custom sunshine server name from secondary `sunshine_mac2.conf`.
    fn read_secondary_sunshine_name() -> Option<String> {
        let conf_path = system_info::find_sunshine_conf()?
            .parent()?
            .join("sunshine_mac2.conf");
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
        let host_on = *self.host_active.read().await;
        if !host_on {
            *self.active_peer_ip.write().await = None;
            *self.active_mode.write().await = None;
        }
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

        let (w, h, fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        info!(
            "Starting Mac-to-PC extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz)",
            my_ip, peer_hostname, peer_ip, w, h, fps
        );

        // 1. Spawn virtual display matching peer display dimensions and configure Sunshine output ID
        let disp_id = tokio::task::spawn_blocking(move || MacDisplayManager::start_virtual_display(w, h, fps))
            .await
            .context("Virtual display task panicked")??;
        tokio::time::sleep(Duration::from_millis(400)).await;
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
                .unwrap_or((None, 47989, None));
        info!("Waiting for Sunshine server on port {}...", my_sunshine_port);
        if !MacDisplayManager::wait_for_sunshine_ready(Duration::from_secs(10)).await {
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_virtual_display).await;
            let _ = tokio::task::spawn_blocking(MacDisplayManager::stop_sunshine).await;
            self.clear_host_state().await;
            anyhow::bail!(
                "Mac Sunshine server failed to listen on port {} within 10s (check Screen Recording permission for Sunshine.app and ~/Library/Logs/sunshine.log)",
                my_sunshine_port
            );
        }

        let fallback_host = tokio::task::spawn_blocking(system_info::get_hostname)
            .await
            .unwrap_or_else(|_| "Mac".to_string());
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

        let (w, h, fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        info!(
            "Starting PC-to-Mac extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz)",
            my_ip, peer_hostname, peer_ip, w, h, fps
        );

        // 1. Enable Windows virtual display / secondary Sunshine if present
        tokio::task::spawn_blocking(WinDisplayManager::enable_vdd_device)
            .await
            .context("VDD enable task panicked")??;

        // 2. Wait for local Sunshine on configured port (or port 48989 if a secondary instance is open)
        let (my_sunshine_name, configured_port, _) =
            tokio::task::spawn_blocking(system_info::read_sunshine_config_info)
                .await
                .unwrap_or((None, 47989, None));
        let mut active_port = configured_port;
        let mut ready = false;
        for attempt in 0..40 {
            if configured_port != 48989 && Self::is_tcp_port_open("127.0.0.1", 48989).await {
                active_port = 48989;
                ready = true;
                break;
            }
            if Self::is_tcp_port_open("127.0.0.1", configured_port).await
                && (attempt >= 3 || configured_port == 48989)
            {
                active_port = configured_port;
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !ready {
            let _ = tokio::task::spawn_blocking(WinDisplayManager::disable_vdd_device).await;
            self.clear_host_state().await;
            anyhow::bail!(
                "Windows Sunshine server failed to listen on port {} (or secondary 48989) within 8s",
                configured_port
            );
        }

        let secondary_name = if active_port == 48989 {
            tokio::task::spawn_blocking(Self::read_secondary_sunshine_name)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let fallback_host = tokio::task::spawn_blocking(system_info::get_hostname)
            .await
            .unwrap_or_else(|_| "Windows".to_string());
        let host_name = secondary_name
            .or(my_sunshine_name)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback_host);
        let bitrate_kbps = Self::compute_optimal_bitrate_kbps(&peer, fps);

        // Clamp display dimensions for secondary Mac slot to match VDD slot 1 native 2560x1600
        let (stream_w, stream_h) = if active_port == 48989 || w > 2560 || h > 1600 {
            (2560, 1600)
        } else {
            (w, h)
        };

        // Ensure Sunshine REST API has cleared any lingering stream before client connects
        let api_port = active_port + 1;
        let _ = tokio::task::spawn_blocking(move || {
            WinDisplayManager::call_sunshine_api(api_port, "/api/apps/close");
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
                if host_port > 0 && host_port < 1024 {
                    return self
                        .base_response(false, "Rejected StartMoonlight: invalid privileged host_port")
                        .await;
                }

                info!("Handling StartMoonlight RPC from host {}", effective_host_ip);

                let port = if host_port >= 1024 {
                    host_port
                } else if Self::is_tcp_port_open(&effective_host_ip, 47989).await {
                    47989
                } else if Self::is_tcp_port_open(&effective_host_ip, 48989).await {
                    48989
                } else if Self::wait_for_tcp_port(
                    &effective_host_ip,
                    47989,
                    Duration::from_secs(2),
                )
                .await
                {
                    47989
                } else if Self::wait_for_tcp_port(
                    &effective_host_ip,
                    48989,
                    Duration::from_secs(2),
                )
                .await
                {
                    48989
                } else {
                    47989
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
                        width: 1920,
                        height: 1080,
                        fps: 60,
                        scale_factor: 1.0,
                    });
                let eff_w = (if width > 0 { width } else { local_disp.width }).clamp(800, 7680) & !1;
                let eff_h = (if height > 0 { height } else { local_disp.height }).clamp(600, 4320) & !1;
                let raw_fps = if fps > 0 { fps } else { local_disp.fps };
                let eff_fps = (if raw_fps > 0 { raw_fps } else { 60 }).clamp(30, 240);
                let eff_bitrate = if bitrate_kbps > 0 {
                    bitrate_kbps.clamp(5_000, 500_000)
                } else {
                    100_000
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
                        )
                    }
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Moonlight launcher panicked: {}", e)));

                match launch_res {
                    Ok(_) => {
                        *self.client_active.write().await = true;
                        *self.active_peer_ip.write().await = Some(effective_host_ip.clone());
                        *self.active_mode.write().await = Some("Client".into());
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
            } => {
                if !lux.is_finite()
                    || !(0.0..=200_000.0).contains(&lux)
                    || !(1000..=15_000).contains(&cct)
                    || !gamma_comp.is_finite()
                    || !(0.2..=3.0).contains(&gamma_comp)
                {
                    return self
                        .base_response(false, "Rejected SyncTrueTone: out-of-range calibration values")
                        .await;
                }
                let res = tokio::task::spawn_blocking(move || {
                    crate::truetone::apply_hardware_gamma_ramp(cct, gamma_comp)
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("TrueTone task panicked: {}", e)));
                let success = res.is_ok();
                let message = match res {
                    Ok(_) => format!(
                        "Applied True Tone LUT: CCT={}K, Lux={:.1}, Gamma={:.2}x",
                        cct, lux, gamma_comp
                    ),
                    Err(e) => format!("Failed to apply True Tone LUT: {}", e),
                };
                let mut resp = self.base_response(success, message).await;
                resp.ambient_light = Some(crate::truetone::AmbientLightData {
                    lux,
                    cct_kelvin: cct,
                    supported: lux >= 0.0,
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
                let auth_id = peer_device_id.map(|s| s.to_string());
                let nonce_arg = sender_nonce_hex;
                let neg_res = tokio::task::spawn_blocking(move || {
                    crate::audio::AudioManager::handle_negotiate_session_for_peer(
                        auth_id.as_deref(),
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
                if trimmed_pin.len() != 6 || !trimmed_pin.bytes().all(|b| b.is_ascii_digit()) {
                    return self
                        .base_response(false, "Pairing PIN must be a 6-digit number")
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
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    match core.camera.start().await {
                        Ok(msg) => {
                            let mut resp = self.base_response(true, msg).await;
                            resp.camera_status = Some(core.camera.status());
                            resp
                        }
                        Err(e) => self.base_response(false, format!("Failed to start camera: {}", e)).await,
                    }
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::ToggleCamera => {
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    match core.camera.toggle().await {
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
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    core.camera.stop().await;
                    let mut resp = self.base_response(true, "Shared Camera stopped").await;
                    resp.camera_status = Some(core.camera.status());
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
                }
            }
            DisplayRpcRequest::GetCameraStatus => {
                if let Some(core) = crate::core::GLOBAL_CORE.get() {
                    let mut resp = self.base_response(true, "Camera status retrieved").await;
                    resp.camera_status = Some(core.camera.status());
                    resp
                } else {
                    self.base_response(false, "Core not initialized").await
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
        let addr = Self::format_socket_target(peer_ip, CONTROL_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CONTROL_PORT,
            crate::security::transport::ServiceId::DisplayRpc,
            Duration::from_secs(4),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish TransportV2 session to {}: {}", addr, e))?;

        let payload = serde_json::to_vec(req)?;
        tokio::time::timeout(Duration::from_secs(10), session.send_message(&payload))
            .await
            .with_context(|| format!("Timed out sending RPC request to {}", addr))?
            .map_err(|e| anyhow::anyhow!("TransportV2 send error to {}: {}", addr, e))?;

        let plain_resp = tokio::time::timeout(Duration::from_secs(15), session.recv_message())
            .await
            .with_context(|| format!("Timed out waiting for RPC response from {}", addr))?
            .map_err(|e| anyhow::anyhow!("TransportV2 receive error from {}: {}", addr, e))?;

        if plain_resp.is_empty() || plain_resp.len() > 1_048_576 {
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
            DisplayController::format_socket_target("10.0.0.2", 58281),
            "10.0.0.2:58281"
        );
        assert_eq!(
            DisplayController::format_socket_target("fe80::1", 58281),
            "[fe80::1]:58281"
        );
    }
}
