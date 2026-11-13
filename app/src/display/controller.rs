//! High-level display extension controller and orchestrator.

use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::CONTROL_PORT;
use crate::discovery::DiscoveryManager;
use super::protocol::{DisplayRpcRequest, DisplayRpcResponse};
use super::mac_display::MacDisplayManager;
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

    /// Toggles Mac-as-Host extended desktop to PC (1920x1200 @ 165Hz).
    pub async fn toggle_mac_to_pc(&self) -> Result<String> {
        let is_running = MacDisplayManager::is_virtual_display_active();
        if is_running {
            self.stop_mac_to_pc().await?;
            Ok("Stopped Mac-to-PC second screen display".into())
        } else {
            self.start_mac_to_pc().await?;
            Ok("Started Mac-to-PC 1920x1200 @ 165Hz second screen display".into())
        }
    }

    /// Starts Mac-as-Host extended desktop to PC.
    pub async fn start_mac_to_pc(&self) -> Result<()> {
        let peer_ip = self.discovery.get_peer_ip().await
            .unwrap_or_else(|| "10.99.99.1".to_string());

        // 1. Determine Mac local IP for peer to connect to
        let my_ip = if peer_ip.starts_with("10.99.99.") {
            "10.99.99.2"
        } else if peer_ip.starts_with("192.168.2.") {
            "192.168.2.1"
        } else if peer_ip.starts_with("192.168.137.") {
            "192.168.137.2"
        } else {
            "10.99.99.2"
        };

        info!("Starting Mac-to-PC second screen (Host: {}, Client: {})", my_ip, peer_ip);

        // 2. Spawn virtual display vd165 (1920x1200 @ 165Hz)
        MacDisplayManager::start_virtual_display(1920, 1200, 165)?;
        tokio::time::sleep(Duration::from_millis(400)).await;

        // 3. Set Sunshine display output ID
        if let Some(disp_id) = MacDisplayManager::get_active_virtual_display() {
            let _ = MacDisplayManager::configure_sunshine_output(disp_id);
        } else {
            warn!("Virtual display ID not yet found; using existing Sunshine config");
        }

        // 4. Start Sunshine
        MacDisplayManager::start_sunshine()?;
        info!("Waiting for Sunshine server on port 47989...");
        let ready = MacDisplayManager::wait_for_sunshine_ready(Duration::from_secs(5)).await;
        if !ready {
            warn!("Sunshine port 47989 not responding; attempting client launch anyway");
        }

        // 5. Send RPC to PC to launch Moonlight in fullscreen 165Hz
        let rpc = DisplayRpcRequest::StartMoonlight {
            host_ip: my_ip.to_string(),
            app_name: "Desktop".to_string(),
            width: 1920,
            height: 1200,
            fps: 165,
            bitrate_kbps: 100_000,
            audio_on_host: true,
            fullscreen: true,
        };

        Self::send_remote_rpc(&peer_ip, &rpc).await?;
        MacDisplayManager::show_notification("Second Screen Enabled", "1920x1200 @ 165Hz active on HP OMEN");

        let mut active = self.is_active.write().await;
        *active = true;
        let mut mode = self.active_mode.write().await;
        *mode = Some("Mac-to-PC".into());

        Ok(())
    }

    /// Stops Mac-as-Host extended desktop.
    pub async fn stop_mac_to_pc(&self) -> Result<()> {
        let peer_ip = self.discovery.get_peer_ip().await
            .unwrap_or_else(|| "10.99.99.1".to_string());

        info!("Stopping Mac-to-PC second screen...");

        // 1. Terminate local Mac virtual display and Sunshine
        let _ = MacDisplayManager::stop_virtual_display();
        let _ = MacDisplayManager::stop_sunshine();

        // 2. Send StopMoonlight to PC
        let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;

        MacDisplayManager::show_notification("Second Screen Disabled", "Virtual display stopped. Windows snapped back.");

        let mut active = self.is_active.write().await;
        *active = false;
        let mut mode = self.active_mode.write().await;
        *mode = None;

        Ok(())
    }

    /// Toggles PC-as-Host extended desktop to Mac.
    pub async fn toggle_pc_to_mac(&self) -> Result<String> {
        let is_running = *self.is_active.read().await || WinDisplayManager::is_vdd_active();
        if is_running {
            self.stop_pc_to_mac().await?;
            Ok("Stopped PC-to-Mac second screen display".into())
        } else {
            self.start_pc_to_mac().await?;
            Ok("Started PC-to-Mac second screen display".into())
        }
    }

    /// Starts PC-as-Host extended desktop to Mac.
    pub async fn start_pc_to_mac(&self) -> Result<()> {
        let peer_ip = self.discovery.get_peer_ip().await
            .unwrap_or_else(|| "10.99.99.2".to_string());

        let my_ip = if peer_ip.starts_with("10.99.99.") {
            "10.99.99.1"
        } else if peer_ip.starts_with("192.168.2.") {
            "192.168.2.2"
        } else {
            "192.168.137.1"
        };

        info!("Starting PC-to-Mac second screen (Host: {}, Client: {})", my_ip, peer_ip);

        // 1. Enable VDD device and Slot 1 for Mac on Windows
        WinDisplayManager::enable_vdd_device()?;

        // Wait up to 4 seconds for Sunshine port 48989 (or 47989) on Windows
        let mut ready = false;
        for _ in 0..20 {
            if tokio::net::TcpStream::connect("127.0.0.1:48989").await.is_ok()
                || tokio::net::TcpStream::connect("127.0.0.1:47989").await.is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !ready {
            warn!("Sunshine secondary port 48989 not yet responding; proceeding with RPC anyway");
        }

        // 2. Send RPC to Mac to launch Moonlight client
        let rpc = DisplayRpcRequest::StartMoonlight {
            host_ip: my_ip.to_string(),
            app_name: "Desktop".to_string(),
            width: 2560,
            height: 1600,
            fps: 60,
            bitrate_kbps: 80_000,
            audio_on_host: false,
            fullscreen: true,
        };

        Self::send_remote_rpc(&peer_ip, &rpc).await?;

        let mut active = self.is_active.write().await;
        *active = true;
        let mut mode = self.active_mode.write().await;
        *mode = Some("PC-to-Mac".into());

        Ok(())
    }

    /// Stops PC-as-Host extended desktop.
    pub async fn stop_pc_to_mac(&self) -> Result<()> {
        let peer_ip = self.discovery.get_peer_ip().await
            .unwrap_or_else(|| "10.99.99.2".to_string());

        info!("Stopping PC-to-Mac second screen...");

        // 1. Disable VDD on Windows
        let _ = WinDisplayManager::disable_vdd_device();

        // 2. Send StopMoonlight to Mac
        let _ = Self::send_remote_rpc(&peer_ip, &DisplayRpcRequest::StopMoonlight).await;

        let mut active = self.is_active.write().await;
        *active = false;
        let mut mode = self.active_mode.write().await;
        *mode = None;

        Ok(())
    }

    /// Handles an incoming DisplayRpcRequest on the local machine.
    pub async fn handle_rpc(&self, req: DisplayRpcRequest) -> DisplayRpcResponse {
        match req {
            DisplayRpcRequest::StartMoonlight { host_ip, width, height, fps, bitrate_kbps, audio_on_host, .. } => {
                info!("Handling StartMoonlight RPC from host {}", host_ip);
                if cfg!(target_os = "windows") {
                    match WinDisplayManager::start_moonlight_client(&host_ip, width, height, fps, bitrate_kbps, audio_on_host) {
                        Ok(_) => {
                            let mut active = self.is_active.write().await;
                            *active = true;
                            let mut mode = self.active_mode.write().await;
                            *mode = Some("Client".into());
                            DisplayRpcResponse {
                                success: true,
                                message: format!("Started Moonlight client on Windows for host {}", host_ip),
                                is_active: true,
                                active_mode: Some("Client".into()),
                                gpu_telemetry: None,
                                ambient_light: None,
                                storage_status: None,
                            }
                        }
                        Err(e) => DisplayRpcResponse {
                            success: false,
                            message: format!("Failed to start Moonlight on Windows: {}", e),
                            is_active: false,
                            active_mode: None,
                            gpu_telemetry: None,
                            ambient_light: None,
                            storage_status: None,
                        },
                    }
                } else {
                    let port = if MacDisplayManager::wait_for_port(&host_ip, 48989, Duration::from_secs(5)).await {
                        48989
                    } else if MacDisplayManager::wait_for_port(&host_ip, 47989, Duration::from_secs(2)).await {
                        47989
                    } else {
                        48989
                    };
                    let host_name = if port == 48989 { "HP-Omen-Mac2" } else { "HP-Omen" };
                    match MacDisplayManager::start_moonlight_client(&host_ip, port, host_name) {
                        Ok(_) => {
                            let mut active = self.is_active.write().await;
                            *active = true;
                            let mut mode = self.active_mode.write().await;
                            *mode = Some("Client".into());
                            DisplayRpcResponse {
                                success: true,
                                message: format!("Started Moonlight client on Mac for host {} on port {}", host_ip, port),
                                is_active: true,
                                active_mode: Some("Client".into()),
                                gpu_telemetry: None,
                                ambient_light: None,
                                storage_status: None,
                            }
                        }
                        Err(e) => DisplayRpcResponse {
                            success: false,
                            message: format!("Failed to start Moonlight on Mac: {}", e),
                            is_active: false,
                            active_mode: None,
                            gpu_telemetry: None,
                            ambient_light: None,
                            storage_status: None,
                        },
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
                let mut active = self.is_active.write().await;
                *active = false;
                let mut mode = self.active_mode.write().await;
                *mode = None;
                DisplayRpcResponse {
                    success: true,
                    message: "Stopped Moonlight client".into(),
                    is_active: false,
                    active_mode: None,
                    gpu_telemetry: None,
                    ambient_light: None,
                    storage_status: None,
                }
            }
            DisplayRpcRequest::ToggleMacToPc => {
                match self.toggle_mac_to_pc().await {
                    Ok(msg) => DisplayRpcResponse {
                        success: true,
                        message: msg,
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                    Err(e) => DisplayRpcResponse {
                        success: false,
                        message: format!("Error toggling Mac-to-PC: {}", e),
                        is_active: false,
                        active_mode: None,
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                }
            }
            DisplayRpcRequest::TogglePcToMac => {
                match self.toggle_pc_to_mac().await {
                    Ok(msg) => DisplayRpcResponse {
                        success: true,
                        message: msg,
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                    Err(e) => DisplayRpcResponse {
                        success: false,
                        message: format!("Error toggling PC-to-Mac: {}", e),
                        is_active: false,
                        active_mode: None,
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                }
            }
            DisplayRpcRequest::StopAll => {
                let _ = self.stop_mac_to_pc().await;
                let _ = self.stop_pc_to_mac().await;
                DisplayRpcResponse {
                    success: true,
                    message: "All display extensions stopped".into(),
                    is_active: false,
                    active_mode: None,
                    gpu_telemetry: None,
                    ambient_light: None,
                    storage_status: None,
                }
            }
            DisplayRpcRequest::GetStatus => {
                let active = *self.is_active.read().await;
                let mode = self.active_mode.read().await.clone();
                DisplayRpcResponse {
                    success: true,
                    message: format!("Status: active={}, mode={:?}", active, mode),
                    is_active: active,
                    active_mode: mode,
                    gpu_telemetry: None,
                    ambient_light: None,
                    storage_status: None,
                }
            }
            DisplayRpcRequest::GetGpuTelemetry => {
                let telemetry = crate::telemetry::query_gpu_telemetry();
                let success = telemetry.is_some();
                let msg = if success { "GPU telemetry retrieved".into() } else { "GPU telemetry unavailable".into() };
                DisplayRpcResponse {
                    success,
                    message: msg,
                    is_active: *self.is_active.read().await,
                    active_mode: self.active_mode.read().await.clone(),
                    gpu_telemetry: telemetry,
                    ambient_light: None,
                    storage_status: None,
                }
            }
            DisplayRpcRequest::PasteRemote => {
                if let Some(service) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
                    match service.paste_remote(None).await {
                        Ok(msg) => DisplayRpcResponse {
                            success: true,
                            message: msg,
                            is_active: *self.is_active.read().await,
                            active_mode: self.active_mode.read().await.clone(),
                            gpu_telemetry: None,
                            ambient_light: None,
                            storage_status: None,
                        },
                        Err(e) => DisplayRpcResponse {
                            success: false,
                            message: format!("Failed to paste remote item: {}", e),
                            is_active: *self.is_active.read().await,
                            active_mode: self.active_mode.read().await.clone(),
                            gpu_telemetry: None,
                            ambient_light: None,
                            storage_status: None,
                        },
                    }
                } else {
                    DisplayRpcResponse {
                        success: false,
                        message: "Clipboard service not initialized".to_string(),
                        is_active: false,
                        active_mode: None,
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    }
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
                DisplayRpcResponse {
                    success: true,
                    message: "Window focused".into(),
                    is_active: *self.is_active.read().await,
                    active_mode: self.active_mode.read().await.clone(),
                    gpu_telemetry: None,
                    ambient_light: None,
                    storage_status: None,
                }
            }
            DisplayRpcRequest::SyncTrueTone { lux, cct, gamma_comp } => {
                let res = crate::truetone::apply_hardware_gamma_ramp(cct, gamma_comp);
                let success = res.is_ok();
                let message = match res {
                    Ok(_) => format!("Applied True Tone LUT: CCT={}K, Lux={:.1}, Gamma={:.2}x", cct, lux, gamma_comp),
                    Err(e) => format!("Failed to apply True Tone LUT: {}", e),
                };
                DisplayRpcResponse {
                    success,
                    message,
                    is_active: *self.is_active.read().await,
                    active_mode: self.active_mode.read().await.clone(),
                    gpu_telemetry: None,
                    ambient_light: Some(crate::truetone::AmbientLightData {
                        lux,
                        cct_kelvin: cct,
                        supported: true,
                        updated_at_secs: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    }),
                    storage_status: None,
                }
            }
            DisplayRpcRequest::MountStorage => {
                let peer_ip = self.discovery.get_peer_ip().await
                    .unwrap_or_else(|| "10.99.99.1".to_string());
                match crate::storage::StorageManager::mount(&peer_ip) {
                    Ok(status) => DisplayRpcResponse {
                        success: status.is_mounted,
                        message: status.message.clone(),
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: Some(status),
                    },
                    Err(e) => DisplayRpcResponse {
                        success: false,
                        message: format!("Mount request failed: {}", e),
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                }
            }
            DisplayRpcRequest::UnmountStorage => {
                match crate::storage::StorageManager::unmount() {
                    Ok(status) => DisplayRpcResponse {
                        success: true,
                        message: status.message.clone(),
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: Some(status),
                    },
                    Err(e) => DisplayRpcResponse {
                        success: false,
                        message: format!("Unmount request failed: {}", e),
                        is_active: *self.is_active.read().await,
                        active_mode: self.active_mode.read().await.clone(),
                        gpu_telemetry: None,
                        ambient_light: None,
                        storage_status: None,
                    },
                }
            }
        }
    }

    /// Returns whether display streaming is currently active.
    pub async fn is_active(&self) -> bool {
        if cfg!(target_os = "macos") {
            MacDisplayManager::is_virtual_display_active()
        } else {
            *self.is_active.read().await
        }
    }

    /// Returns the currently active display mode, if any.
    pub async fn get_active_mode(&self) -> Option<String> {
        self.active_mode.read().await.clone()
    }

    /// Sends an RPC request to a remote peer or localhost over TCP.
    pub async fn send_remote_rpc(peer_ip: &str, req: &DisplayRpcRequest) -> Result<DisplayRpcResponse> {
        let addr = format!("{}:{}", peer_ip, CONTROL_PORT);
        let mut stream = TcpStream::connect(&addr).await
            .with_context(|| format!("Failed to connect to display control RPC at {}", addr))?;

        let payload = serde_json::to_vec(req)?;
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;

        let resp_len = stream.read_u32().await? as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        let resp: DisplayRpcResponse = serde_json::from_slice(&resp_buf)?;
        Ok(resp)
    }
}
