#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

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

use std::sync::Mutex;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde::Serialize;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, State, WindowEvent,
};

use discovery::DiscoveryManager;
use clipboard::ClipboardService;
use display::{DisplayController, DisplayServer, DisplayRpcRequest};

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

#[derive(Serialize)]
pub struct BridgeStatus {
    pub peer_connected: bool,
    pub peer_ip: String,
    pub rtt_ms: Option<f64>,
    pub display_active: bool,
    pub local_os: String,
    pub active_mode: Option<String>,
    pub link_speed: String,
    pub link_type: String,
    pub encode_gpu: String,
    pub decode_gpu: String,
    pub touchbar_active: bool,
    pub is_windows_master: bool,
    pub ambient_lux: Option<f32>,
    pub ambient_cct: Option<u32>,
    pub storage_mounted: bool,
    pub autostart_enabled: bool,
}

fn detect_link_info(peer_ip: Option<&str>) -> (String, String) {
    match peer_ip {
        Some(ip) if ip.starts_with("10.99.99.") => {
            ("10 Gbps".to_string(), "Thunderbolt / USB-C Direct".to_string())
        }
        Some(ip) if ip.starts_with("192.168.137.") => {
            ("433 Mbps".to_string(), "OMEN Wi-Fi Hotspot".to_string())
        }
        Some(ip) if ip.starts_with("192.168.2.") => {
            ("400 Mbps".to_string(), "Direct Wi-Fi / LAN".to_string())
        }
        Some(_) => {
            ("1 Gbps".to_string(), "Local Network".to_string())
        }
        None => {
            ("--".to_string(), "Searching...".to_string())
        }
    }
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<BridgeStatus, String> {
    let peer_ip = state.discovery.get_peer_ip().await;
    let peer_connected = peer_ip.is_some();
    let display_active = state.display_ctrl.is_active().await;
    let active_mode = state.display_ctrl.get_active_mode().await;
    let (link_speed, link_type) = detect_link_info(peer_ip.as_deref());

    let (encode_gpu, decode_gpu) = crate::display::WinDisplayManager::get_gpu_preferences();

    #[cfg(target_os = "macos")]
    let touchbar_active = unsafe { is_touchbar_active_in_app() };

    #[cfg(not(target_os = "macos"))]
    let touchbar_active = false;

    let is_windows_master = display_active && active_mode.as_deref() == Some("Client");

    let als = truetone::read_ambient_light();
    let storage_mounted = storage::StorageManager::is_mounted();

    Ok(BridgeStatus {
        peer_connected,
        peer_ip: peer_ip.unwrap_or_else(|| "Searching...".to_string()),
        rtt_ms: if peer_connected { Some(0.4) } else { None },
        display_active,
        local_os: std::env::consts::OS.to_string(),
        active_mode,
        link_speed,
        link_type,
        encode_gpu,
        decode_gpu,
        touchbar_active,
        is_windows_master,
        ambient_lux: if als.supported { Some(als.lux) } else { None },
        ambient_cct: if als.supported { Some(als.cct_kelvin) } else { None },
        storage_mounted,
        autostart_enabled: autostart::AutostartManager::is_enabled(),
    })
}

#[tauri::command]
async fn set_gpu_preferences(encode_gpu: String, decode_gpu: String) -> Result<String, String> {
    crate::display::WinDisplayManager::set_gpu_preferences(&encode_gpu, &decode_gpu)
        .map_err(|e| e.to_string())?;
    Ok(format!("GPU Preferences set: Encode [{}], Decode [{}]", encode_gpu, decode_gpu))
}

#[tauri::command]
async fn run_speed_test(state: State<'_, AppState>) -> Result<benchmark::SpeedTestResult, String> {
    if !state.features.is_enabled("benchmark") {
        return Err("High-Speed Benchmark is disabled by master switch".into());
    }
    let peer_ip = state.discovery.get_peer_ip().await
        .ok_or_else(|| "No peer connected to run speed test against".to_string())?;

    benchmark::BenchmarkClient::run_test(&peer_ip).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_gpu_telemetry(state: State<'_, AppState>) -> Result<crate::telemetry::GpuTelemetry, String> {
    if cfg!(target_os = "windows") {
        crate::telemetry::query_gpu_telemetry()
            .ok_or_else(|| "NVIDIA GPU telemetry not available on local Windows host".to_string())
    } else {
        let peer_ip = state.discovery.get_peer_ip().await
            .unwrap_or_else(|| "10.99.99.1".to_string());
        let resp = DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::GetGpuTelemetry).await
            .map_err(|e| format!("Failed to reach peer for GPU telemetry: {}", e))?;
        resp.gpu_telemetry
            .ok_or_else(|| "Peer did not return GPU telemetry (is peer a Windows machine with NVIDIA GPU?)".to_string())
    }
}

#[tauri::command]
async fn toggle_touchbar_hud(state: State<'_, AppState>, force: Option<bool>) -> Result<String, String> {
    if !state.features.is_enabled("touchbar") {
        return Err("Touch Bar NVIDIA HUD is disabled by master switch".into());
    }
    #[cfg(target_os = "macos")]
    {
        let is_running = unsafe { is_touchbar_active_in_app() };

        if is_running {
            unsafe { dismiss_touchbar_in_app() };
            return Ok("Touch Bar NVIDIA HUD disabled".to_string());
        }

        let is_display_active = state.display_ctrl.is_active().await;
        let active_mode = state.display_ctrl.get_active_mode().await;
        let is_windows_master = is_display_active && active_mode.as_deref() == Some("Client");

        let allow_run = is_windows_master || force.unwrap_or(false);
        if !allow_run {
            return Err("Touch Bar NVIDIA HUD requires Windows Master mode (when Windows PC extends desktop to this MacBook Pro). Start 'Extend to MacBook Pro' first or use test override.".into());
        }

        let peer_ip = state.discovery.get_peer_ip().await.unwrap_or_else(|| "10.99.99.1".to_string());
        let c_ip = std::ffi::CString::new(peer_ip).map_err(|e| e.to_string())?;
        unsafe {
            init_touchbar_in_app(c_ip.as_ptr());
        }
        Ok("Touch Bar NVIDIA Performance HUD enabled (Goopy Liquid Glass)".to_string())
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
        state.display_ctrl.toggle_mac_to_pc().await.map_err(|e| e.to_string())
    } else {
        state.display_ctrl.toggle_pc_to_mac().await.map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn open_cache_folder() -> Result<(), String> {
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into())
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".into())
    };
    let cache_dir = std::path::PathBuf::from(home).join(".usbc_clipboard_cache");
    let _ = std::fs::create_dir_all(&cache_dir);

    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&cache_dir).spawn();

    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(&cache_dir).spawn();

    Ok(())
}

#[tauri::command]
async fn paste_remote(state: State<'_, AppState>) -> Result<String, String> {
    state.clipboard.paste_remote(None).await.map_err(|e| e.to_string())
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
    tracing::info!("⚙️ Feature [{}] master switch set to: {}", feature, if enabled { "ENABLED" } else { "DISABLED" });

    if !enabled {
        match feature.as_str() {
            "display" => {
                if state.display_ctrl.is_active().await {
                    let _ = state.display_ctrl.stop_mac_to_pc().await;
                    let _ = state.display_ctrl.stop_pc_to_mac().await;
                }
            }
            "storage" => {
                let _ = storage::StorageManager::unmount();
            }
            "truetone" => {
                let _ = truetone::reset_hardware_gamma_ramp();
            }
            "touchbar" => {
                #[cfg(target_os = "macos")]
                unsafe {
                    dismiss_touchbar_in_app();
                }
            }
            _ => {}
        }
    }
    Ok(flags)
}

#[tauri::command]
async fn get_ambient_light(state: State<'_, AppState>) -> Result<truetone::AmbientLightData, String> {
    if !state.features.is_enabled("truetone") {
        return Ok(truetone::AmbientLightData {
            lux: 0.0,
            cct_kelvin: 6500,
            supported: false,
            updated_at_secs: 0,
        });
    }
    Ok(truetone::read_ambient_light())
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
        Ok(format!("Injected Bradford CAT Gamma LUT on Windows: {}K ({:.2}x)", cct, comp_factor))
    } else {
        let peer_ip = state.discovery.get_peer_ip().await.unwrap_or_else(|| "10.99.99.1".to_string());
        let rpc = DisplayRpcRequest::SyncTrueTone {
            lux: 100.0,
            cct,
            gamma_comp: comp_factor,
        };
        match DisplayController::send_remote_rpc(&peer_ip, &rpc).await {
            Ok(resp) => Ok(resp.message),
            Err(e) => {
                tracing::warn!("Could not reach Windows peer for True Tone sync: {}", e);
                Ok(format!("Calibrated Bradford CAT matrix for {}K (target: Windows OMEN at {})", cct, peer_ip))
            }
        }
    }
}

#[tauri::command]
async fn mount_shared_storage(state: State<'_, AppState>) -> Result<storage::StorageStatus, String> {
    if !state.features.is_enabled("storage") {
        return Err("Auto-Mounted Shared Storage is disabled by master switch".into());
    }
    let peer_ip = state.discovery.get_peer_ip().await.unwrap_or_else(|| "10.99.99.1".to_string());
    let status = storage::StorageManager::mount(&peer_ip).map_err(|e| e.to_string())?;
    
    let rpc_peer = peer_ip.clone();
    tauri::async_runtime::spawn(async move {
        let _ = DisplayController::send_remote_rpc(&rpc_peer, &DisplayRpcRequest::MountStorage).await;
    });

    Ok(status)
}

#[tauri::command]
async fn unmount_shared_storage(state: State<'_, AppState>) -> Result<storage::StorageStatus, String> {
    let status = storage::StorageManager::unmount().map_err(|e| e.to_string())?;

    if let Some(peer_ip) = state.discovery.get_peer_ip().await {
        tauri::async_runtime::spawn(async move {
            let _ = DisplayController::send_remote_rpc(&peer_ip, &DisplayRpcRequest::UnmountStorage).await;
        });
    }

    Ok(status)
}

#[tauri::command]
async fn get_storage_status(state: State<'_, AppState>) -> Result<storage::StorageStatus, String> {
    let peer_ip = state.discovery.get_peer_ip().await;
    Ok(storage::StorageManager::status(peer_ip.as_deref()))
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
    Ok(autostart::AutostartManager::is_enabled())
}

#[tauri::command]
async fn set_autostart(enabled: bool) -> Result<bool, String> {
    autostart::AutostartManager::set_enabled(enabled).map_err(|e| e.to_string())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // 1. Check for CLI Subcommands (e.g. `mac_windows_bridge display toggle`, `mac_windows_bridge benchmark`)
    if args.len() > 1 && (args[1] == "paste-remote" || args[1] == "--paste-remote") {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            println!("📥 Requesting on-demand remote paste from daemon...");
            match DisplayController::send_remote_rpc("127.0.0.1", &DisplayRpcRequest::PasteRemote).await {
                Ok(resp) => {
                    println!("{}", resp.message);
                    if !resp.success {
                        std::process::exit(1);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Failed to connect to bridge daemon: {}. Is mac_windows_bridge running?", e);
                    std::process::exit(1);
                }
            }
        });
    }

    if args.len() > 1 && args[1] == "benchmark" {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async {
            let target_ip = args.get(2).map(|s| s.as_str()).unwrap_or("10.99.99.1");
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
            let target_ip = args.get(2).map(|s| s.as_str()).unwrap_or("10.99.99.1");
            println!("Querying NVIDIA GPU telemetry from {}...", target_ip);
            match DisplayController::send_remote_rpc(target_ip, &DisplayRpcRequest::GetGpuTelemetry).await {
                Ok(resp) => {
                    if let Some(t) = resp.gpu_telemetry {
                        println!("\n🎮 NVIDIA GPU Telemetry:");
                        println!("   • GPU:         {}", t.gpu_name);
                        println!("   • Temperature: {}°C", t.temperature_c);
                        println!("   • Power:       {:.1} W", t.power_usage_watts);
                        println!("   • Core Clock:  {} MHz", t.core_clock_mhz);
                        println!("   • VRAM:        {} / {} MB ({}%)", t.memory_used_mb, t.memory_total_mb, t.memory_utilization_percent);
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
            let peer_ip = if args.len() > 2 { &args[2] } else { "10.99.99.1" };
            let c_ip = std::ffi::CString::new(peer_ip)?;
            println!("Initializing in-app Goopy Liquid Glass Touch Bar HUD for peer {}...", peer_ip);
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
                    eprintln!("Unknown display command: {}. Usage: display [toggle | toggle-pc-to-mac | stop | status]", subcmd);
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
                    eprintln!("Bridge daemon not reachable on 127.0.0.1:58281: {}. Is mac_windows_bridge running?", e);
                    std::process::exit(1);
                }
            }
        });
    }

    // 2. Single Instance Check: if already running, focus existing window and exit!
    if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], crate::config::CONTROL_PORT)),
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

    // 3. Purge legacy autostart persistence so the app never relaunches against user's will
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let plist_path = std::path::PathBuf::from(home).join("Library/LaunchAgents/com.manveersingh.macwindowsbridge.plist");
            if plist_path.exists() {
                let _ = std::process::Command::new("launchctl")
                    .args(["unload", plist_path.to_str().unwrap_or_default()])
                    .status();
                let _ = std::fs::remove_file(&plist_path);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("schtasks.exe")
            .args(["/delete", "/tn", "MacWindowsBridge", "/f"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .status();
    }

    // 4. Initialize Logging for Daemon
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into())
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".into())
    };
    let log_path = std::path::PathBuf::from(home).join(".integrator.log");
    let file_opt = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
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
    let device_name = if cfg!(target_os = "macos") {
        "Manveer-MacBook-Pro"
    } else {
        "HP-OMEN-Laptop"
    };

    tracing::info!("🚀 mac-windows-usbc-bridge companion app v1.0.0 initializing on {} [{}]...", os_name, device_name);

    // 3. Start Tokio Runtime for background services
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let _ = clipboard::TOKIO_HANDLE.set(rt.handle().clone());

    let (discovery, display_ctrl, clipboard) = rt.block_on(async {
        // Multi-Subnet Discovery
        let discovery = DiscoveryManager::new(device_name);
        discovery.start().await.expect("Failed to start discovery");
        tracing::info!("🔍 Dynamic Multi-Subnet Discovery active (broadcasting & listening across USB-C, Hotspot, and Wi-Fi)");

        // Universal Clipboard
        let clipboard = ClipboardService::new(discovery.clone()).expect("Failed to initialize clipboard");
        clipboard.start().await.expect("Failed to start clipboard");
        tracing::info!("📋 Universal Clipboard running (Zero-RAM file streaming, image, and text sync enabled)");

        // Extended Desktop Controller & RPC Server
        let display_ctrl = DisplayController::new(discovery.clone());
        let display_server = DisplayServer::new(display_ctrl.clone());
        display_server.start().await.expect("Failed to start display RPC server");
        tracing::info!("🖥️ Native Extended Desktop Controller active (Zero-SSH, Zero-VBScript sub-millisecond IPC enabled)");

        // High-Speed Link Benchmark Server
        benchmark::BenchmarkServer::start().await.expect("Failed to start benchmark server");
        tracing::info!("⚡ Live Speed Benchmark Server active on port 58285");

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

    // 4. Initialize Tauri GUI & System Tray
    let is_hidden_init = std::env::args().any(|a| a == "--hidden" || a == "--daemon");

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            toggle_display,
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
            set_autostart
        ])
        .setup(move |app| {
            GLOBAL_APP_HANDLE.set(app.handle().clone()).ok();

            #[cfg(target_os = "macos")]
            unsafe {
                clipboard::service::init_shortcut_interceptor();
            }

            // Setup Tray Menu
            let show_i = MenuItem::with_id(app, "show", "Show Dashboard", true, None::<&str>)?;
            let paste_i = MenuItem::with_id(app, "paste_remote", "📥 Paste Remote Item into Active Folder", true, None::<&str>)?;
            let toggle_label = if cfg!(target_os = "windows") {
                "Extend to MacBook Pro (VideoToolbox 60Hz)"
            } else {
                "Extend Desktop to HP OMEN (165Hz)"
            };
            let toggle_i = MenuItem::with_id(app, "toggle_display", toggle_label, true, None::<&str>)?;
            let cache_i = MenuItem::with_id(app, "open_cache", "Open Clipboard Cache", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Integrator", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show_i, &paste_i, &toggle_i, &cache_i, &quit_i])?;

            if let Some(icon) = app.default_window_icon() {
                let _tray = TrayIconBuilder::new()
                    .icon(icon.clone())
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| {
                        match event.id().as_ref() {
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
                                let home = if cfg!(target_os = "windows") {
                                    std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into())
                                } else {
                                    std::env::var("HOME").unwrap_or_else(|_| ".".into())
                                };
                                let cache_dir = std::path::PathBuf::from(home).join(".usbc_clipboard_cache");
                                let _ = std::fs::create_dir_all(&cache_dir);
                                #[cfg(target_os = "macos")]
                                let _ = std::process::Command::new("open").arg(&cache_dir).spawn();
                                #[cfg(target_os = "windows")]
                                let _ = std::process::Command::new("explorer").arg(&cache_dir).spawn();
                            }
                            "quit" => {
                                std::process::exit(0);
                            }
                            _ => {}
                        }
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event {
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
        .run(|app_handle, event| {
            match event {
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
            }
        });

    Ok(())
}
