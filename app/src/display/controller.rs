//! High-level display extension controller and RPC orchestrator.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::CONTROL_PORT;
use crate::discovery::{DiscoveryManager, PeerCandidate};
use crate::system_info;
use crate::trust;
use super::mac_display::MacDisplayManager;
use super::protocol::{DisplayRpcRequest, DisplayRpcResponse};
use super::win_display::WinDisplayManager;

#[derive(Clone)]
pub struct DisplayController {
    discovery: DiscoveryManager,
    is_active: Arc<RwLock<bool>>,
    active_mode: Arc<RwLock<Option<String>>>,
}

impl DisplayController {
    pub fn new(discovery: DiscoveryManager) -> Self {
        Self {
            discovery,
            is_active: Arc::new(RwLock::new(false)),
            active_mode: Arc::new(RwLock::new(None)),
        }
    }

    async fn base_response(&self, success: bool, message: impl Into<String>) -> DisplayRpcResponse {
        DisplayRpcResponse {
            success,
            message: message.into(),
            is_active: *self.is_active.read().await,
            active_mode: self.active_mode.read().await.clone(),
            ..Default::default()
        }
    }

    async fn is_tcp_port_open(ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        matches!(
            tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(&addr)).await,
            Ok(Ok(_))
        )
    }

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

        let local_disp = system_info::get_primary_display_info();
        let final_w = (if width > 0 { width } else { local_disp.width }).clamp(800, 7680);
        let final_h = (if height > 0 { height } else { local_disp.height }).clamp(600, 4320);
        let raw_fps = if fps > 0 { fps } else { local_disp.fps };
        let final_fps = (if raw_fps > 0 { raw_fps } else { 60 }).clamp(30, 240);
        let final_hostname = if hostname.is_empty() { peer_ip } else { hostname };

        (final_w, final_h, final_fps, final_hostname)
    }

    /// Toggles Mac-as-Host extended desktop to the discovered peer.
    pub async fn toggle_mac_to_pc(&self) -> Result<String> {
        let is_running = MacDisplayManager::is_virtual_display_active();
        if is_running {
            self.stop_mac_to_pc().await?;
            Ok("Stopped Mac-to-PC extended display".into())
        } else {
            self.start_mac_to_pc().await?;
            let mode = self
                .active_mode
                .read()
                .await
                .clone()
                .unwrap_or_else(|| "Extended display".to_string());
            Ok(format!("Started {}", mode))
        }
    }

    /// Starts Mac-as-Host extended desktop to the discovered peer.
    pub async fn start_mac_to_pc(&self) -> Result<()> {
        let peer = self
            .discovery
            .get_best_peer()
            .await
            .context("No active peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
        let peer_ip = peer.addr.ip().to_string();
        let my_ip = system_info::local_ip_for_peer(&peer_ip)
            .with_context(|| format!("Could not determine local route IP to reach peer {}", peer_ip))?;

        let (w, h, fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        info!(
            "Starting Mac-to-PC extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz)",
            my_ip, peer_hostname, peer_ip, w, h, fps
        );

        // 1. Spawn virtual display matching peer display dimensions and configure Sunshine output ID
        let disp_id = MacDisplayManager::start_virtual_display(w, h, fps)?;
        tokio::time::sleep(Duration::from_millis(400)).await;
        if let Err(e) = MacDisplayManager::configure_sunshine_output(disp_id) {
            warn!("Failed to configure Sunshine output_name = {}: {}", disp_id, e);
        }

        // 2. Start local Sunshine and wait for its configured port
        if let Err(e) = MacDisplayManager::start_sunshine() {
            let _ = MacDisplayManager::stop_virtual_display();
            return Err(e);
        }

        let (my_sunshine_name, my_sunshine_port, _) = system_info::read_sunshine_config_info();
        info!("Waiting for Sunshine server on port {}...", my_sunshine_port);
        if !MacDisplayManager::wait_for_sunshine_ready(Duration::from_secs(5)).await {
            warn!(
                "Sunshine port {} not responding yet; attempting client launch anyway",
                my_sunshine_port
            );
        }

        let host_name = my_sunshine_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(system_info::get_hostname);
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
                let _ = MacDisplayManager::stop_virtual_display();
                let _ = MacDisplayManager::stop_sunshine();
                return Err(e);
            }
        };
        if !resp.success {
            let _ = MacDisplayManager::stop_virtual_display();
            let _ = MacDisplayManager::stop_sunshine();
            anyhow::bail!("Peer {} failed to start Moonlight: {}", peer_hostname, resp.message);
        }

        let mode_summary = format!("{}x{} @ {}Hz", w, h, fps);
        MacDisplayManager::show_notification(
            "Second Screen Enabled",
            &format!("{} active on {}", mode_summary, peer_hostname),
        );

        *self.is_active.write().await = true;
        *self.active_mode.write().await = Some(format!("Mac -> {} ({})", peer_hostname, mode_summary));

        Ok(())
    }

    /// Stops Mac-as-Host extended desktop cleanly even if no peer is reachable.
    pub async fn stop_mac_to_pc(&self) -> Result<()> {
        info!("Stopping Mac-to-PC extended display...");

        let _ = MacDisplayManager::stop_virtual_display();
        let _ = MacDisplayManager::stop_sunshine();

        if let Some(peer_ip) = self.discovery.get_peer_ip().await {
            let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;
        } else {
            warn!("No active peer reachable during stop_mac_to_pc; cleaned up local display state");
        }

        MacDisplayManager::show_notification("Second Screen Disabled", "Virtual display stopped.");

        *self.is_active.write().await = false;
        *self.active_mode.write().await = None;

        Ok(())
    }

    /// Toggles PC-as-Host extended desktop to the discovered Mac peer.
    pub async fn toggle_pc_to_mac(&self) -> Result<String> {
        let is_running = *self.is_active.read().await || WinDisplayManager::is_vdd_active();
        if is_running {
            self.stop_pc_to_mac().await?;
            Ok("Stopped PC-to-Mac extended display".into())
        } else {
            self.start_pc_to_mac().await?;
            let mode = self
                .active_mode
                .read()
                .await
                .clone()
                .unwrap_or_else(|| "Extended display".to_string());
            Ok(format!("Started {}", mode))
        }
    }

    /// Starts PC-as-Host extended desktop to the discovered Mac peer.
    pub async fn start_pc_to_mac(&self) -> Result<()> {
        let peer = self
            .discovery
            .get_best_peer()
            .await
            .context("No active peer discovered. Connect a direct cable or add a peer IP in Settings.")?;
        let peer_ip = peer.addr.ip().to_string();
        let my_ip = system_info::local_ip_for_peer(&peer_ip)
            .with_context(|| format!("Could not determine local route IP to reach peer {}", peer_ip))?;

        let (w, h, fps, peer_hostname) = self.resolve_peer_display_and_host(&peer).await;
        info!(
            "Starting PC-to-Mac extended display (Host: {}, Client: {} [{}], Mode: {}x{} @ {}Hz)",
            my_ip, peer_hostname, peer_ip, w, h, fps
        );

        // 1. Enable Windows virtual display / secondary Sunshine if present
        WinDisplayManager::enable_vdd_device()?;

        // 2. Wait for local Sunshine on configured port (or port 48989 if a secondary instance is open)
        let (my_sunshine_name, configured_port, _) = system_info::read_sunshine_config_info();
        let mut active_port = configured_port;
        let mut ready = false;
        for attempt in 0..20 {
            if configured_port != 48989 && Self::is_tcp_port_open("127.0.0.1", 48989).await {
                active_port = 48989;
                ready = true;
                break;
            }
            if Self::is_tcp_port_open("127.0.0.1", configured_port).await
                && (attempt >= 2 || configured_port == 48989)
            {
                active_port = configured_port;
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !ready {
            warn!(
                "Sunshine port {} not yet responding; proceeding with RPC anyway",
                active_port
            );
        }

        let host_name = my_sunshine_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(system_info::get_hostname);
        let bitrate_kbps = Self::compute_optimal_bitrate_kbps(&peer, fps);

        // 3. Send RPC to peer to launch Moonlight client
        let rpc = DisplayRpcRequest::StartMoonlight {
            host_ip: my_ip,
            host_port: active_port,
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
                let _ = WinDisplayManager::disable_vdd_device();
                return Err(e);
            }
        };
        if !resp.success {
            let _ = WinDisplayManager::disable_vdd_device();
            anyhow::bail!("Peer {} failed to start Moonlight: {}", peer_hostname, resp.message);
        }

        let mode_summary = format!("{}x{} @ {}Hz", w, h, fps);
        *self.is_active.write().await = true;
        *self.active_mode.write().await = Some(format!("PC -> {} ({})", peer_hostname, mode_summary));

        Ok(())
    }

    /// Stops PC-as-Host extended desktop cleanly even if no peer is reachable.
    pub async fn stop_pc_to_mac(&self) -> Result<()> {
        info!("Stopping PC-to-Mac extended display...");

        let _ = WinDisplayManager::disable_vdd_device();

        if let Some(peer_ip) = self.discovery.get_peer_ip().await {
            let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;
        } else {
            warn!("No active peer reachable during stop_pc_to_mac; cleaned up local VDD state");
        }

        *self.is_active.write().await = false;
        *self.active_mode.write().await = None;

        Ok(())
    }

    /// Handles an incoming DisplayRpcRequest on the local machine.
    pub async fn handle_rpc(
        &self,
        req: DisplayRpcRequest,
        peer_ip: Option<IpAddr>,
    ) -> DisplayRpcResponse {
        let is_loopback_caller = peer_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
        if matches!(
            req,
            DisplayRpcRequest::ToggleMacToPc
                | DisplayRpcRequest::TogglePcToMac
                | DisplayRpcRequest::PasteRemote
                | DisplayRpcRequest::ShowWindow
                | DisplayRpcRequest::GetPairingPin
                | DisplayRpcRequest::PairWithPeer { .. }
        ) && !is_loopback_caller
        {
            warn!(
                "🚫 Rejected local-only DisplayRpcRequest {:?} from non-loopback peer {:?}",
                req, peer_ip
            );
            return self
                .base_response(false, "Rejected: request is restricted to local loopback CLI")
                .await;
        }

        match req {
            DisplayRpcRequest::Ping => self.base_response(true, "pong").await,
            DisplayRpcRequest::GetHardwareProfile => {
                let profile = system_info::collect_local_profile();
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

                let local_disp = system_info::get_primary_display_info();
                let eff_w = (if width > 0 { width } else { local_disp.width }).clamp(800, 7680);
                let eff_h = (if height > 0 { height } else { local_disp.height }).clamp(600, 4320);
                let raw_fps = if fps > 0 { fps } else { local_disp.fps };
                let eff_fps = (if raw_fps > 0 { raw_fps } else { 60 }).clamp(30, 240);
                let eff_bitrate = if bitrate_kbps > 0 {
                    bitrate_kbps.clamp(5_000, 500_000)
                } else {
                    100_000
                };

                let launch_res = if cfg!(target_os = "windows") {
                    WinDisplayManager::start_moonlight_client(
                        &effective_host_ip,
                        port,
                        &effective_host_name,
                        eff_w,
                        eff_h,
                        eff_fps,
                        eff_bitrate,
                        audio_on_host,
                    )
                } else {
                    MacDisplayManager::start_moonlight_client(
                        &effective_host_ip,
                        port,
                        &effective_host_name,
                        eff_w,
                        eff_h,
                        eff_fps,
                        eff_bitrate,
                        audio_on_host,
                    )
                };

                match launch_res {
                    Ok(_) => {
                        *self.is_active.write().await = true;
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
                        *self.is_active.write().await = false;
                        *self.active_mode.write().await = None;
                        self.base_response(false, format!("Failed to start Moonlight client: {}", e))
                            .await
                    }
                }
            }
            DisplayRpcRequest::StopMoonlight => {
                info!("Handling StopMoonlight RPC");
                if cfg!(target_os = "windows") {
                    let _ = WinDisplayManager::stop_moonlight_client();
                } else {
                    let _ = MacDisplayManager::stop_moonlight_client();
                }
                *self.is_active.write().await = false;
                *self.active_mode.write().await = None;
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
                if cfg!(target_os = "macos") {
                    let _ = self.stop_mac_to_pc().await;
                    let _ = MacDisplayManager::stop_moonlight_client();
                } else if cfg!(target_os = "windows") {
                    let _ = self.stop_pc_to_mac().await;
                    let _ = WinDisplayManager::stop_moonlight_client();
                }
                *self.is_active.write().await = false;
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
                let telemetry = crate::telemetry::query_gpu_telemetry();
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
                if let Some(app) = crate::GLOBAL_APP_HANDLE.get() {
                    use tauri::Manager;
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.show();
                        let _ = win.unminimize();
                        let _ = win.set_focus();
                    }
                }
                self.base_response(true, "Window focused").await
            }
            DisplayRpcRequest::SyncTrueTone {
                lux,
                cct,
                gamma_comp,
            } => {
                let res = crate::truetone::apply_hardware_gamma_ramp(cct, gamma_comp);
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

                match crate::storage::StorageManager::mount_with_share(
                    &target_ip,
                    share_hint.as_deref(),
                ) {
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
            DisplayRpcRequest::UnmountStorage => match crate::storage::StorageManager::unmount() {
                Ok(status) => {
                    let mut resp = self.base_response(true, status.message.clone()).await;
                    resp.storage_status = Some(status);
                    resp
                }
                Err(e) => self
                    .base_response(false, format!("Unmount request failed: {}", e))
                    .await,
            },
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
                match crate::audio::AudioManager::handle_negotiate_session(
                    caller_ip,
                    &sender_nonce_hex,
                    sample_rate,
                    channels,
                    bit_depth,
                ) {
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
                let (cfg, _) = trust::get_trust_snapshot();
                let mut resp = self
                    .base_response(true, format!("Active Pairing PIN: {}", cfg.pairing_pin))
                    .await;
                resp.pairing_token = Some(cfg.pairing_pin);
                resp
            }
            DisplayRpcRequest::PairWithPeer { ip, pin } => {
                match trust::pair_with_remote_peer_v2(ip.trim(), CONTROL_PORT, pin.trim()).await {
                    Ok((creds, sas_6)) => {
                        self.base_response(
                            true,
                            format!(
                                "Paired and mutually authenticated with {} ({}) [SAS: {}]",
                                creds.hostname,
                                ip.trim(),
                                sas_6
                            ),
                        )
                        .await
                    }
                    Err(e) => self.base_response(false, e).await,
                }
            }
        }
    }

    /// Returns whether display streaming is currently active.
    pub async fn is_active(&self) -> bool {
        let lock_active = *self.is_active.read().await;
        if cfg!(target_os = "macos") {
            lock_active || MacDisplayManager::is_virtual_display_active()
        } else {
            lock_active
        }
    }

    /// Returns the currently active display mode, if any.
    pub async fn get_active_mode(&self) -> Option<String> {
        self.active_mode.read().await.clone()
    }

    /// Sends an encrypted, mutually authenticated RPC request to a remote peer or localhost over TransportSessionV2.
    pub async fn send_remote_rpc(
        peer_ip: &str,
        req: &DisplayRpcRequest,
    ) -> Result<DisplayRpcResponse> {
        let addr = format!("{}:{}", peer_ip, CONTROL_PORT);
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
#[no_mangle]
pub extern "C" fn fetch_rust_gpu_telemetry_json(
    peer_ip_ptr: *const std::os::raw::c_char,
    out_buf: *mut u8,
    cap: usize,
) -> usize {
    if peer_ip_ptr.is_null() || out_buf.is_null() || cap < 2 {
        return 0;
    }
    let peer_ip = unsafe { std::ffi::CStr::from_ptr(peer_ip_ptr) }
        .to_string_lossy()
        .trim()
        .to_string();
    if peer_ip.is_empty() {
        return 0;
    }

    let fetch_future = async {
        DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetGpuTelemetry).await
    };

    let resp_res = if let Some(handle) = crate::clipboard::TOKIO_HANDLE.get() {
        handle.block_on(fetch_future)
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
}

