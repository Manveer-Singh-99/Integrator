#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod system_info;
mod trust;
mod config;
mod bridge;
mod discovery;
mod clipboard;
mod display;
mod telemetry;
mod benchmark;
mod truetone;
mod storage;
mod audio;
mod features;
mod autostart;

use std::collections::HashMap;
use std::sync::Mutex;
use anyhow::Result;
use serde::Serialize;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, State, WindowEvent,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use clipboard::ClipboardService;
use discovery::DiscoveryManager;
use display::{DisplayController, DisplayRpcRequest, DisplayServer};

pub static GLOBAL_APP_HANDLE: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

#[cfg(target_os = "macos")]
extern "C" {
    fn init_touchbar_in_app(peer_ip: *const std::os::raw::c_char);
    fn dismiss_touchbar_in_app();
    fn is_touchbar_active_in_app() -> bool;
    fn run_touchbar_cli_loop(peer_ip: *const std::os::raw::c_char);
    #[allow(dead_code)]
    fn update_touchbar_telemetry_in_app(
        temp: u32,
        power: f32,
        clock: u32,
        vram_used: u64,
        vram_total: u64,
        util: u32,
    );
}

pub struct AppState {
    pub discovery: DiscoveryManager,
    pub display_ctrl: DisplayController,
    #[allow(dead_code)]
    pub clipboard: ClipboardService,
    pub features: std::sync::Arc<features::FeatureManager>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisplayGeometry {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPeerInfo {
    pub device_id: String,
    pub hostname: String,
    pub os: String,
    pub hardware_model: String,
    pub ip: String,
    pub local_ip_used: Option<String>,
    pub transport_label: String,
    pub is_direct_cable: bool,
    pub link_speed_mbps: Option<u32>,
    pub link_description: String,
    pub rtt_ms: Option<f64>,
    pub display: DisplayGeometry,
    pub gpus: Vec<String>,
    pub share_name: Option<String>,
    pub trusted: bool,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustSnapshotInfo {
    pub pairing_pin: String,
    pub auto_trust_direct_cable: bool,
    pub require_pairing_on_lan: bool,
    pub pending_peers: Vec<trust::PendingPeerInfo>,
    pub trusted_peers: Vec<trust::TrustedPeerRecord>,
    pub blocked_device_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BridgeStatus {
    // Local machine profile
    pub device_id: String,
    pub hostname: String,
    pub os: String,
    pub local_os: String,
    pub hardware_model: String,
    pub cpu_brand: String,
    pub primary_display: system_info::PrimaryDisplayInfo,
    pub local_gpus: Vec<system_info::GpuDeviceInfo>,
    pub local_share_names: Vec<String>,
    pub has_touch_bar: bool,

    // Active / best peer & route info
    pub peer_connected: bool,
    pub peer_trusted: bool,
    pub peer_device_id: Option<String>,
    pub peer_ip: Option<String>,
    pub peer_os: Option<String>,
    pub peer_name: Option<String>,
    pub peer_hardware_model: Option<String>,
    pub peer_display: Option<DisplayGeometry>,
    pub peer_gpus: Vec<String>,
    pub peer_share_name: Option<String>,
    pub peer_local_ip_used: Option<String>,
    pub transport_label: String,
    pub is_direct_cable: bool,
    pub link_speed_mbps: Option<u32>,
    pub link_description: String,
    pub rtt_ms: Option<f64>,
    pub link_speed: String,
    pub link_type: String,

    // Display & GPU state
    pub display_active: bool,
    pub active_mode: Option<String>,
    pub is_windows_master: bool,
    pub encode_gpu: String,
    pub decode_gpu: String,
    pub gpu_controls_supported: bool,
    pub touchbar_active: bool,

    // True Tone / Ambient Light Sensor
    pub ambient_supported: bool,
    pub ambient_lux: Option<f32>,
    pub ambient_cct: Option<u32>,

    // Shared storage
    pub storage_mounted: bool,
    pub storage_status: storage::StorageStatus,
    pub preferred_peer_share: Option<String>,

    // Interfaces, discovery & trust
    pub local_interfaces: Vec<system_info::LocalInterfaceInfo>,
    pub manual_peer_ips: Vec<String>,
    pub discovered_peers: Vec<DiscoveredPeerInfo>,
    pub trust: TrustSnapshotInfo,

    // Autostart
    pub autostart_enabled: bool,
}

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

fn open_app_data_folder() {
    let cache_dir = system_info::app_data_dir();
    let _ = std::fs::create_dir_all(&cache_dir);

    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&cache_dir).spawn();

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("explorer")
            .arg(&cache_dir)
            .creation_flags(0x08000000)
            .spawn();
    }
}

async fn build_bridge_status(state: &AppState) -> Result<BridgeStatus, String> {
    let best_peer = state.discovery.get_best_peer().await;
    let all_peers = state.discovery.get_all_peers().await;
    let manual_peer_ips = state.discovery.get_manual_peer_ips().await;

    let active_mode = state.display_ctrl.get_active_mode().await;
    let is_client_mode = active_mode.as_deref() == Some("Client");
    let display_active = state.display_ctrl.is_active().await || is_client_mode;
    let is_windows_master = is_client_mode;
    let truetone_enabled = state.features.is_enabled("truetone");

    let peer_ip_opt = best_peer.as_ref().map(|p| p.addr.ip().to_string());
    let peer_share_name = best_peer.as_ref().and_then(|p| p.share_name.clone());

    let p_ip_clone = peer_ip_opt.clone();
    let p_share_clone = peer_share_name.clone();

    let (
        profile,
        local_interfaces,
        encode_gpu,
        decode_gpu,
        als,
        storage_status,
        preferred_peer_share,
        trust_cfg,
        pending_peers,
        autostart_enabled,
    ) = tokio::task::spawn_blocking(move || {
        let profile = system_info::collect_local_profile();
        let local_interfaces = system_info::list_local_ipv4_interfaces();
        let (encode_gpu, decode_gpu) = crate::display::WinDisplayManager::get_gpu_preferences();
        let als = truetone::read_ambient_light();
        let storage_status = storage::StorageManager::status_with_share(
            p_ip_clone.as_deref(),
            p_share_clone.as_deref(),
        );
        let preferred_peer_share = storage::StorageManager::get_preferred_peer_share();
        let (trust_cfg, pending_peers) = trust::get_trust_snapshot();
        let autostart_enabled = autostart::AutostartManager::is_enabled();
        (
            profile,
            local_interfaces,
            encode_gpu,
            decode_gpu,
            als,
            storage_status,
            preferred_peer_share,
            trust_cfg,
            pending_peers,
            autostart_enabled,
        )
    })
    .await
    .map_err(|e| format!("Failed to collect bridge status: {}", e))?;

    #[cfg(target_os = "macos")]
    let touchbar_active = if profile.has_touch_bar {
        unsafe { is_touchbar_active_in_app() }
    } else {
        false
    };
    #[cfg(not(target_os = "macos"))]
    let touchbar_active = false;

    let ambient_supported =
        truetone_enabled && als.supported && als.lux.is_finite() && als.lux >= 0.0;
    let ambient_lux = if ambient_supported { Some(als.lux) } else { None };
    let ambient_cct = if ambient_supported {
        Some(als.cct_kelvin)
    } else {
        None
    };

    let pending_trust_map: HashMap<String, (bool, bool)> = pending_peers
        .iter()
        .map(|p| (p.device_id.clone(), (p.trusted, p.blocked)))
        .collect();

    let discovered_peers: Vec<DiscoveredPeerInfo> = all_peers
        .into_iter()
        .map(|c| {
            let (live_trusted, live_blocked) = pending_trust_map
                .get(&c.device_id)
                .copied()
                .unwrap_or((c.trusted, false));
            DiscoveredPeerInfo {
                device_id: c.device_id,
                hostname: c.device_name,
                os: c.os,
                hardware_model: c.hardware_model,
                ip: c.addr.ip().to_string(),
                local_ip_used: c.local_ip_used,
                transport_label: c.transport.label().to_string(),
                is_direct_cable: c.transport.is_direct_cable(),
                link_speed_mbps: c.link_speed_mbps,
                link_description: c.link_description,
                rtt_ms: c.rtt_ms,
                display: DisplayGeometry {
                    width: c.display_width,
                    height: c.display_height,
                    fps: c.display_fps,
                },
                gpus: c.gpus,
                share_name: c.share_name,
                trusted: live_trusted && !live_blocked,
                blocked: live_blocked,
            }
        })
        .collect();

    let peer_connected = best_peer.is_some();
    let peer_trusted = best_peer
        .as_ref()
        .map(|p| {
            pending_trust_map
                .get(&p.device_id)
                .map(|&(trusted, blocked)| trusted && !blocked)
                .unwrap_or(p.trusted)
        })
        .unwrap_or(false);

    let (
        peer_device_id,
        peer_os,
        peer_name,
        peer_hardware_model,
        peer_display,
        peer_gpus,
        peer_local_ip_used,
        transport_label,
        is_direct_cable,
        link_speed_mbps,
        link_description,
        rtt_ms,
    ) = if let Some(ref p) = best_peer {
        let disp = if p.display_width > 0 && p.display_height > 0 {
            Some(DisplayGeometry {
                width: p.display_width,
                height: p.display_height,
                fps: if p.display_fps > 0 { p.display_fps } else { 60 },
            })
        } else {
            None
        };
        (
            Some(p.device_id.clone()),
            Some(p.os.clone()),
            Some(p.device_name.clone()),
            if p.hardware_model.is_empty() {
                None
            } else {
                Some(p.hardware_model.clone())
            },
            disp,
            p.gpus.clone(),
            p.local_ip_used.clone(),
            p.transport.label().to_string(),
            p.transport.is_direct_cable(),
            p.link_speed_mbps,
            p.link_description.clone(),
            p.rtt_ms,
        )
    } else {
        (
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            None,
            "Searching...".to_string(),
            false,
            None,
            "No peer connected".to_string(),
            None,
        )
    };

    let link_speed = format_link_speed(link_speed_mbps, peer_connected);
    let link_type = if peer_connected {
        transport_label.clone()
    } else {
        "Searching...".to_string()
    };

    let storage_mounted = storage_status.is_mounted;
    let trust_snapshot = TrustSnapshotInfo {
        pairing_pin: trust_cfg.pairing_pin,
        auto_trust_direct_cable: trust_cfg.auto_trust_direct_cable,
        require_pairing_on_lan: trust_cfg.require_pairing_on_lan,
        pending_peers,
        trusted_peers: trust_cfg.trusted_peers,
        blocked_device_ids: trust_cfg.blocked_device_ids,
    };

    Ok(BridgeStatus {
        device_id: profile.device_id,
        hostname: profile.hostname,
        os: profile.os.clone(),
        local_os: profile.os,
        hardware_model: profile.hardware_model,
        cpu_brand: profile.cpu_brand,
        primary_display: profile.primary_display,
        local_gpus: profile.gpus,
        local_share_names: profile.default_share_names,
        has_touch_bar: profile.has_touch_bar,
        peer_connected,
        peer_trusted,
        peer_device_id,
        peer_ip: peer_ip_opt,
        peer_os,
        peer_name,
        peer_hardware_model,
        peer_display,
        peer_gpus,
        peer_share_name,
        peer_local_ip_used,
        transport_label,
        is_direct_cable,
        link_speed_mbps,
        link_description,
        rtt_ms,
        link_speed,
        link_type,
        display_active,
        active_mode,
        is_windows_master,
        encode_gpu,
        decode_gpu,
        gpu_controls_supported: cfg!(target_os = "windows"),
        touchbar_active,
        ambient_supported,
        ambient_lux,
        ambient_cct,
        storage_mounted,
        storage_status,
        preferred_peer_share,
        local_interfaces,
        manual_peer_ips,
        discovered_peers,
        trust: trust_snapshot,
        autostart_enabled,
    })
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<BridgeStatus, String> {
    build_bridge_status(&state).await
}

#[tauri::command]
async fn get_bridge_status(state: State<'_, AppState>) -> Result<BridgeStatus, String> {
    build_bridge_status(&state).await
}

#[tauri::command]
async fn set_gpu_preferences(encode_gpu: String, decode_gpu: String) -> Result<String, String> {
    if !cfg!(target_os = "windows") {
        return Err("DirectX GPU preferences can only be configured on a Windows host".into());
    }
    tokio::task::spawn_blocking(move || {
        crate::display::WinDisplayManager::set_gpu_preferences(&encode_gpu, &decode_gpu)
            .map_err(|e| e.to_string())?;
        Ok(format!(
            "GPU Preferences set: Encode [{}], Decode [{}]",
            encode_gpu, decode_gpu
        ))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_speed_test(state: State<'_, AppState>) -> Result<benchmark::SpeedTestResult, String> {
    if !state.features.is_enabled("benchmark") {
        return Err("High-Speed Benchmark is disabled by master switch".into());
    }
    let peer_ip = state
        .discovery
        .get_peer_ip()
        .await
        .ok_or_else(|| "No peer connected to run speed test against".to_string())?;

    benchmark::BenchmarkClient::run_test(&peer_ip)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_gpu_telemetry(
    state: State<'_, AppState>,
) -> Result<crate::telemetry::GpuTelemetry, String> {
    if cfg!(target_os = "windows") {
        tokio::task::spawn_blocking(|| {
            crate::telemetry::query_gpu_telemetry()
                .ok_or_else(|| "GPU telemetry not available on local Windows host".to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    } else {
        let peer_ip = state
            .discovery
            .get_peer_ip()
            .await
            .ok_or_else(|| "No peer connected for GPU telemetry".to_string())?;
        let resp = DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetGpuTelemetry)
            .await
            .map_err(|e| format!("Failed to reach peer {} for GPU telemetry: {}", peer_ip, e))?;
        resp.gpu_telemetry
            .ok_or_else(|| "Peer did not return GPU telemetry".to_string())
    }
}

#[tauri::command]
async fn toggle_touchbar_hud(
    state: State<'_, AppState>,
    force: Option<bool>,
) -> Result<String, String> {
    if !state.features.is_enabled("touchbar") {
        return Err("Touch Bar GPU HUD is disabled by master switch".into());
    }
    #[cfg(target_os = "macos")]
    {
        if !system_info::has_touch_bar_hardware() {
            return Err("Touch Bar hardware was not detected on this Mac".to_string());
        }

        let is_running = unsafe { is_touchbar_active_in_app() };
        if is_running {
            unsafe { dismiss_touchbar_in_app() };
            return Ok("Touch Bar GPU HUD disabled".to_string());
        }

        let active_mode = state.display_ctrl.get_active_mode().await;
        let is_peer_master = active_mode.as_deref() == Some("Client");

        let allow_run = is_peer_master || force.unwrap_or(false);
        if !allow_run {
            return Err("Touch Bar GPU HUD requires peer-to-Mac extended display mode (when your peer extends its desktop to this Mac). Start extending from your peer first or enable override.".into());
        }

        let peer_ip = state
            .discovery
            .get_peer_ip()
            .await
            .ok_or_else(|| "No peer connected for Touch Bar telemetry".to_string())?;
        let c_ip = std::ffi::CString::new(peer_ip).map_err(|e| e.to_string())?;
        unsafe {
            init_touchbar_in_app(c_ip.as_ptr());
        }
        Ok("Touch Bar GPU Performance HUD enabled".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = state;
        let _ = force;
        Err("Touch Bar is only available on macOS hardware with a physical Touch Bar".to_string())
    }
}

#[tauri::command]
async fn toggle_display(state: State<'_, AppState>) -> Result<String, String> {
    if !state.features.is_enabled("display") {
        return Err("Extended Second Screen is disabled by master switch".into());
    }
    if cfg!(target_os = "macos") {
        state
            .display_ctrl
            .toggle_mac_to_pc()
            .await
            .map_err(|e| e.to_string())
    } else {
        state
            .display_ctrl
            .toggle_pc_to_mac()
            .await
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn toggle_mac_to_pc(state: State<'_, AppState>) -> Result<String, String> {
    if !state.features.is_enabled("display") {
        return Err("Extended Second Screen is disabled by master switch".into());
    }
    state
        .display_ctrl
        .toggle_mac_to_pc()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn toggle_pc_to_mac(state: State<'_, AppState>) -> Result<String, String> {
    if !state.features.is_enabled("display") {
        return Err("Extended Second Screen is disabled by master switch".into());
    }
    state
        .display_ctrl
        .toggle_pc_to_mac()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_cache_folder() -> Result<(), String> {
    open_app_data_folder();
    Ok(())
}

#[tauri::command]
async fn paste_remote(state: State<'_, AppState>) -> Result<String, String> {
    state
        .clipboard
        .paste_remote(None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn hide_window(app_handle: AppHandle) -> Result<(), String> {
    if let Some(win) = app_handle.get_webview_window("main") {
        let _ = win.hide();
    }
    Ok(())
}

#[tauri::command]
async fn get_feature_flags(state: State<'_, AppState>) -> Result<features::FeatureFlags, String> {
    Ok(state.features.get_flags())
}

#[tauri::command]
async fn set_feature_flag(
    state: State<'_, AppState>,
    feature: String,
    enabled: bool,
) -> Result<features::FeatureFlags, String> {
    let flags = state.features.set_flag(&feature, enabled);
    tracing::info!(
        "⚙️ Feature [{}] master switch set to: {}",
        feature,
        if enabled { "ENABLED" } else { "DISABLED" }
    );

    if !enabled {
        match feature.as_str() {
            "display" => {
                if state.display_ctrl.is_active().await
                    || state.display_ctrl.get_active_mode().await.is_some()
                {
                    let _ = state.display_ctrl.stop_mac_to_pc().await;
                    let _ = state.display_ctrl.stop_pc_to_mac().await;
                }
            }
            "storage" => {
                let _ = tokio::task::spawn_blocking(storage::StorageManager::unmount).await;
            }
            "truetone" => {
                let _ = truetone::reset_hardware_gamma_ramp();
            }
            "touchbar" => {
                #[cfg(target_os = "macos")]
                if system_info::has_touch_bar_hardware() {
                    unsafe {
                        dismiss_touchbar_in_app();
                    }
                }
            }
            _ => {}
        }
    }
    Ok(flags)
}

#[tauri::command]
async fn get_ambient_light(
    state: State<'_, AppState>,
) -> Result<truetone::AmbientLightData, String> {
    if !state.features.is_enabled("truetone") {
        return Ok(truetone::AmbientLightData {
            lux: 0.0,
            cct_kelvin: 6500,
            supported: false,
            updated_at_secs: 0,
        });
    }
    let als = truetone::read_ambient_light();
    if !als.supported || !als.lux.is_finite() || als.lux < 0.0 {
        return Ok(truetone::AmbientLightData {
            lux: 0.0,
            cct_kelvin: 6500,
            supported: false,
            updated_at_secs: 0,
        });
    }
    Ok(als)
}

#[tauri::command]
async fn apply_truetone_calibration(
    state: State<'_, AppState>,
    cct: u32,
    comp_factor: f32,
) -> Result<String, String> {
    if !state.features.is_enabled("truetone") {
        return Err("True Tone & Chromatic Sync is disabled by master switch".into());
    }
    if cfg!(target_os = "windows") {
        truetone::apply_hardware_gamma_ramp(cct, comp_factor).map_err(|e| e.to_string())?;
        Ok(format!(
            "Injected Bradford CAT Gamma LUT on Windows: {}K ({:.2}x)",
            cct, comp_factor
        ))
    } else {
        let peer_ip = state
            .discovery
            .get_peer_ip()
            .await
            .ok_or_else(|| "No peer connected to sync True Tone calibration".to_string())?;
        let als = truetone::read_ambient_light();
        let lux = if als.supported && als.lux.is_finite() && als.lux >= 0.0 {
            als.lux
        } else {
            0.0
        };
        let rpc = DisplayRpcRequest::SyncTrueTone {
            lux,
            cct,
            gamma_comp: comp_factor,
        };
        let resp = DisplayController::send_remote_rpc(&peer_ip, &rpc)
            .await
            .map_err(|e| format!("Failed to reach peer {} for True Tone sync: {}", peer_ip, e))?;
        if resp.success {
            Ok(resp.message)
        } else {
            Err(resp.message)
        }
    }
}

#[tauri::command]
async fn mount_shared_storage(
    state: State<'_, AppState>,
) -> Result<storage::StorageStatus, String> {
    if !state.features.is_enabled("storage") {
        return Err("Auto-Mounted Shared Storage is disabled by master switch".into());
    }
    let peer = state
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

    let rpc_peer = peer_ip;
    tauri::async_runtime::spawn(async move {
        let _ = DisplayController::send_remote_rpc(&rpc_peer, &DisplayRpcRequest::MountStorage).await;
    });

    Ok(status)
}

#[tauri::command]
async fn unmount_shared_storage(
    state: State<'_, AppState>,
) -> Result<storage::StorageStatus, String> {
    let status = tokio::task::spawn_blocking(storage::StorageManager::unmount)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    if let Some(peer_ip) = state.discovery.get_peer_ip().await {
        tauri::async_runtime::spawn(async move {
            let _ = DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::UnmountStorage)
                .await;
        });
    }

    Ok(status)
}

#[tauri::command]
async fn get_storage_status(state: State<'_, AppState>) -> Result<storage::StorageStatus, String> {
    let best_peer = state.discovery.get_best_peer().await;
    let peer_ip = best_peer.as_ref().map(|p| p.addr.ip().to_string());
    let peer_share_hint = best_peer.and_then(|p| p.share_name);
    tokio::task::spawn_blocking(move || {
        storage::StorageManager::status_with_share(peer_ip.as_deref(), peer_share_hint.as_deref())
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn play_spatial_chime(state: State<'_, AppState>) -> Result<String, String> {
    if !state.features.is_enabled("audio") {
        return Err("Dynamic Audio Routing is disabled by master switch".into());
    }
    audio::AudioManager::play_spatial_test_chime().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_autostart() -> Result<bool, String> {
    tokio::task::spawn_blocking(autostart::AutostartManager::is_enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_autostart(enabled: bool) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || autostart::AutostartManager::set_enabled(enabled))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_manual_peer_ip(
    state: State<'_, AppState>,
    ip: String,
) -> Result<Vec<String>, String> {
    state
        .discovery
        .add_manual_peer_ip(&ip)
        .await
        .map_err(|e| e.to_string())?;
    Ok(state.discovery.get_manual_peer_ips().await)
}

#[tauri::command]
async fn remove_manual_peer_ip(
    state: State<'_, AppState>,
    ip: String,
) -> Result<Vec<String>, String> {
    state.discovery.remove_manual_peer_ip(&ip).await;
    Ok(state.discovery.get_manual_peer_ips().await)
}

#[tauri::command]
async fn set_preferred_peer_share(share: Option<String>) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        storage::StorageManager::set_preferred_peer_share(share.as_deref())
            .map_err(|e| e.to_string())?;
        Ok(storage::StorageManager::get_preferred_peer_share())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn trust_peer_device(
    device_id: String,
    hostname: String,
    ip: String,
    via_cable: bool,
) -> Result<String, String> {
    let clean_id = device_id.trim();
    if clean_id.is_empty() {
        return Err("Device ID cannot be empty".into());
    }
    trust::trust_device(clean_id, hostname.trim(), ip.trim(), via_cable);
    Ok(format!("Trusted peer {} ({})", hostname.trim(), ip.trim()))
}

#[tauri::command]
async fn untrust_or_block_peer(device_id: String, block: bool) -> Result<String, String> {
    let clean_id = device_id.trim();
    if clean_id.is_empty() {
        return Err("Device ID cannot be empty".into());
    }
    trust::untrust_or_block_device(clean_id, block);
    if block {
        Ok(format!("Blocked device {}", clean_id))
    } else {
        Ok(format!("Removed trust for device {}", clean_id))
    }
}

#[tauri::command]
async fn regenerate_pairing_pin() -> Result<String, String> {
    Ok(trust::regenerate_pin())
}

#[tauri::command]
async fn set_trust_policy(
    auto_trust_cable: bool,
    require_lan_pairing: bool,
) -> Result<String, String> {
    trust::set_trust_policy(auto_trust_cable, require_lan_pairing);
    Ok(format!(
        "Trust policy updated (direct-cable auto-trust: {}, require LAN pairing: {})",
        auto_trust_cable, require_lan_pairing
    ))
}

#[tauri::command]
async fn pair_with_peer(ip: String, pin: String) -> Result<String, String> {
    let trimmed_ip = ip.trim().to_string();
    if !system_info::is_valid_ipv4(&trimmed_ip) {
        return Err(format!("Invalid peer IPv4 address: {}", ip));
    }
    let trimmed_pin = pin.trim().to_string();
    if trimmed_pin.len() != 6 || !trimmed_pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("Pairing PIN must be 6 digits".into());
    }
    let req = DisplayRpcRequest::PairRequest {
        device_id: system_info::get_or_create_device_id(),
        hostname: system_info::get_hostname(),
        pin: trimmed_pin,
    };
    let resp = DisplayController::send_remote_rpc(&trimmed_ip, &req)
        .await
        .map_err(|e| format!("Failed to reach peer {} for pairing: {}", trimmed_ip, e))?;
    if resp.success {
        Ok(resp.message)
    } else {
        Err(resp.message)
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // 1. Check for CLI Subcommands (e.g. `integrator display toggle`, `integrator benchmark <peer_ip>`)
    if args.len() > 1 && (args[1] == "paste-remote" || args[1] == "--paste-remote") {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            println!("📥 Requesting on-demand remote paste from daemon...");
            match DisplayController::send_remote_rpc("127.0.0.1", &DisplayRpcRequest::PasteRemote)
                .await
            {
                Ok(resp) => {
                    println!("{}", resp.message);
                    if !resp.success {
                        std::process::exit(1);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "Failed to connect to Integrator daemon: {}. Is Integrator running?",
                        e
                    );
                    std::process::exit(1);
                }
            }
        });
    }

    if args.len() > 1 && args[1] == "benchmark" {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            let Some(target_ip) = args.get(2).map(|s| s.as_str()).filter(|s| !s.trim().is_empty()) else {
                eprintln!("Missing target peer IP. Usage: integrator benchmark <peer_ip>");
                std::process::exit(1);
            };
            println!("⚡ Running live speed benchmark against {}...", target_ip);
            match benchmark::BenchmarkClient::run_test(target_ip).await {
                Ok(res) => {
                    println!("\n✅ Live Speed Test Completed Successfully:");
                    println!("   • Max Bandwidth: {:.2} Gbps", res.max_gbps);
                    println!("   • Upload:        {:.2} Gbps ({:.0} MB/s)", res.upload_gbps, res.upload_mb_s);
                    println!("   • Download:      {:.2} Gbps ({:.0} MB/s)", res.download_gbps, res.download_mb_s);
                    println!("   • RTT Latency:   {:.2} ms", res.latency_ms);
                    println!("   • Summary:       {}", res.summary);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Speed benchmark failed: {}", e);
                    std::process::exit(1);
                }
            }
        });
    }

    if args.len() > 1 && args[1] == "telemetry" {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            let Some(target_ip) = args.get(2).map(|s| s.as_str()).filter(|s| !s.trim().is_empty()) else {
                eprintln!("Missing target peer IP. Usage: integrator telemetry <peer_ip>");
                std::process::exit(1);
            };
            println!("Querying GPU telemetry from {}...", target_ip);
            match DisplayController::send_remote_rpc(
                target_ip,
                &DisplayRpcRequest::GetGpuTelemetry,
            )
            .await
            {
                Ok(resp) => {
                    if let Some(t) = resp.gpu_telemetry {
                        println!("\n🎮 GPU Telemetry:");
                        println!("   • GPU:         {}", t.gpu_name);
                        println!("   • Temperature: {}°C", t.temperature_c);
                        println!("   • Power:       {:.1} W", t.power_usage_watts);
                        println!("   • Core Clock:  {} MHz", t.core_clock_mhz);
                        println!(
                            "   • VRAM:        {} / {} MB ({}%)",
                            t.memory_used_mb, t.memory_total_mb, t.memory_utilization_percent
                        );
                        println!("   • Utilization: {}%", t.gpu_utilization_percent);
                    } else {
                        println!("No GPU telemetry returned: {}", resp.message);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Failed to query telemetry: {}", e);
                    std::process::exit(1);
                }
            }
        });
    }

    if args.len() > 1 && args[1] == "touchbar" {
        #[cfg(target_os = "macos")]
        {
            if !system_info::has_touch_bar_hardware() {
                eprintln!("No Touch Bar hardware detected on this Mac.");
                std::process::exit(1);
            }
            let Some(peer_ip) = args.get(2).map(|s| s.as_str()).filter(|s| !s.trim().is_empty()) else {
                eprintln!("Missing target peer IP. Usage: integrator touchbar <peer_ip>");
                std::process::exit(1);
            };
            let c_ip = std::ffi::CString::new(peer_ip)?;
            println!(
                "Initializing in-app Liquid Glass Touch Bar HUD for peer {}...",
                peer_ip
            );
            unsafe {
                run_touchbar_cli_loop(c_ip.as_ptr());
            }
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("Touch Bar is only available on macOS");
            return Ok(());
        }
    }

    if args.len() > 1 && args[1] == "display" {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("toggle");
            let req = match subcmd {
                "toggle" | "toggle-mac-to-pc" => DisplayRpcRequest::ToggleMacToPc,
                "toggle-pc-to-mac" => DisplayRpcRequest::TogglePcToMac,
                "stop" | "stop-all" => DisplayRpcRequest::StopAll,
                "status" => DisplayRpcRequest::GetStatus,
                _ => {
                    eprintln!(
                        "Unknown display command: {}. Usage: display [toggle | toggle-pc-to-mac | stop | status]",
                        subcmd
                    );
                    std::process::exit(1);
                }
            };

            match DisplayController::send_remote_rpc("127.0.0.1", &req).await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    if !resp.success {
                        std::process::exit(1);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "Bridge daemon not reachable on 127.0.0.1:{}: {}. Is Integrator running?",
                        config::CONTROL_PORT,
                        e
                    );
                    std::process::exit(1);
                }
            }
        });
    }

    // 2. Single Instance Check: if already running, focus existing window and exit
    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], config::CONTROL_PORT)),
        std::time::Duration::from_millis(150),
    ) {
        let req = DisplayRpcRequest::ShowWindow;
        if let Ok(bytes) = serde_json::to_vec(&req) {
            use std::io::Write;
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
        println!("Existing Integrator instance is already running. Brought window to front.");
        return Ok(());
    }

    // 3. Initialize Logging for Daemon
    let log_path = system_info::user_home_dir().join(".integrator.log");
    let file_opt = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    if let Some(f) = file_opt {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(Mutex::new(f))
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .init();
    }

    let os_name = std::env::consts::OS;
    let device_name = system_info::get_hostname();

    tracing::info!(
        "🚀 Integrator v1.0.0 initializing on {} [{}]...",
        os_name,
        device_name
    );

    // 4. Start Tokio Runtime for background services
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let _ = clipboard::TOKIO_HANDLE.set(rt.handle().clone());

    let (discovery, display_ctrl, clipboard) = rt.block_on(async {
        // Multi-Subnet Discovery
        let discovery = DiscoveryManager::new(&device_name);
        discovery.start().await.expect("Failed to start discovery");
        tracing::info!(
            "🔍 Dynamic Multi-Subnet Discovery active (broadcasting & listening across active interfaces)"
        );

        // Universal Clipboard
        let clipboard =
            ClipboardService::new(discovery.clone()).expect("Failed to initialize clipboard");
        clipboard.start().await.expect("Failed to start clipboard");
        tracing::info!(
            "📋 Universal Clipboard running (Zero-RAM file streaming, image, and text sync enabled)"
        );

        // Extended Desktop Controller & RPC Server
        let display_ctrl = DisplayController::new(discovery.clone());
        let display_server = DisplayServer::new(display_ctrl.clone());
        display_server
            .start()
            .await
            .expect("Failed to start display RPC server");
        tracing::info!(
            "🖥️ Native Extended Desktop Controller active (sub-millisecond TCP IPC enabled)"
        );

        // High-Speed Link Benchmark Server
        benchmark::BenchmarkServer::start()
            .await
            .expect("Failed to start benchmark server");
        tracing::info!(
            "⚡ Live Speed Benchmark Server active on port {}",
            config::TELEMETRY_PORT
        );

        // Dynamic Audio Sink Server
        if let Err(e) = audio::AudioManager::start_sink_server().await {
            tracing::warn!("Failed to start dynamic audio sink server: {}", e);
        }

        (discovery, display_ctrl, clipboard)
    });

    let feature_manager = std::sync::Arc::new(features::FeatureManager::new());

    let app_state = AppState {
        discovery,
        display_ctrl,
        clipboard,
        features: feature_manager.clone(),
    };

    // 5. Initialize Tauri GUI & System Tray
    let is_hidden_init = std::env::args().any(|a| a == "--hidden" || a == "--daemon");

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_bridge_status,
            toggle_display,
            toggle_mac_to_pc,
            toggle_pc_to_mac,
            open_cache_folder,
            hide_window,
            set_gpu_preferences,
            run_speed_test,
            get_gpu_telemetry,
            toggle_touchbar_hud,
            paste_remote,
            get_ambient_light,
            apply_truetone_calibration,
            mount_shared_storage,
            unmount_shared_storage,
            get_storage_status,
            play_spatial_chime,
            get_feature_flags,
            set_feature_flag,
            get_autostart,
            set_autostart,
            add_manual_peer_ip,
            remove_manual_peer_ip,
            set_preferred_peer_share,
            trust_peer_device,
            untrust_or_block_peer,
            regenerate_pairing_pin,
            set_trust_policy,
            pair_with_peer
        ])
        .setup(move |app| {
            GLOBAL_APP_HANDLE.set(app.handle().clone()).ok();

            #[cfg(target_os = "macos")]
            unsafe {
                clipboard::service::init_shortcut_interceptor();
            }

            // Setup Tray Menu
            let show_i = MenuItem::with_id(app, "show", "Show Dashboard", true, None::<&str>)?;
            let paste_i = MenuItem::with_id(
                app,
                "paste_remote",
                "📥 Paste Remote Item into Active Folder",
                true,
                None::<&str>,
            )?;
            let toggle_i = MenuItem::with_id(
                app,
                "toggle_display",
                "Toggle Extended Second Screen",
                true,
                None::<&str>,
            )?;
            let cache_i =
                MenuItem::with_id(app, "open_cache", "Open Clipboard Cache", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Integrator", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show_i, &paste_i, &toggle_i, &cache_i, &quit_i])?;

            if let Some(icon) = app.default_window_icon() {
                let _tray = TrayIconBuilder::new()
                    .icon(icon.clone())
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id().as_ref() {
                        "show" => {
                            if let Some(win) = app.get_webview_window("main") {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                        "paste_remote" => {
                            let state = app.state::<AppState>();
                            let cb = state.clipboard.clone();
                            tauri::async_runtime::spawn(async move {
                                if let Err(e) = cb.paste_remote(None).await {
                                    tracing::warn!("Remote paste error: {}", e);
                                }
                            });
                        }
                        "toggle_display" => {
                            let state = app.state::<AppState>();
                            let display_ctrl = state.display_ctrl.clone();
                            tauri::async_runtime::spawn(async move {
                                if cfg!(target_os = "macos") {
                                    let _ = display_ctrl.toggle_mac_to_pc().await;
                                } else {
                                    let _ = display_ctrl.toggle_pc_to_mac().await;
                                }
                            });
                        }
                        "open_cache" => {
                            open_app_data_folder();
                        }
                        "quit" => {
                            std::process::exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(win) = app.get_webview_window("main") {
                                if let Ok(is_visible) = win.is_visible() {
                                    if is_visible {
                                        let _ = win.hide();
                                    } else {
                                        let _ = win.show();
                                        let _ = win.set_focus();
                                    }
                                }
                            }
                        }
                    })
                    .build(app)?;
            }

            // Window visibility
            if let Some(win) = app.get_webview_window("main") {
                if is_hidden_init {
                    let _ = win.hide();
                } else {
                    let _ = win.show();
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::Reopen { .. } => {
                if let Some(win) = app_handle.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
            tauri::RunEvent::ExitRequested { .. } => {
                std::process::exit(0);
            }
            _ => {}
        });

    Ok(())
}
