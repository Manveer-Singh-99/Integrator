use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::audio::{self, AudioRoutingStatus};
use crate::autostart;
use crate::benchmark;
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

pub type UiEventCallback = extern "C" fn(event_name: *const c_char, payload_json: *const c_char);

pub static GLOBAL_CORE: OnceLock<Arc<IntegratorCore>> = OnceLock::new();
static UI_EVENT_CALLBACK: Mutex<Option<UiEventCallback>> = Mutex::new(None);
static LOG_RING: Mutex<Option<VecDeque<LogEntry>>> = Mutex::new(None);

#[cfg(target_os = "macos")]
extern "C" {
    fn init_touchbar_in_app(peer_ip: *const c_char);
    fn dismiss_touchbar_in_app();
    fn is_touchbar_active_in_app() -> bool;
    fn run_touchbar_cli_loop(peer_ip: *const c_char);
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: String,
    pub message: String,
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
    pub storage_status: StorageStatus,
    pub preferred_peer_share: Option<String>,

    // Audio
    pub audio_status: AudioRoutingStatus,

    // Features & Universal Input KVM + Drag-Drop
    pub feature_flags: FeatureFlags,
    pub kvm: KvmStatusSnapshot,

    // Interfaces, discovery & trust
    pub local_interfaces: Vec<system_info::LocalInterfaceInfo>,
    pub manual_peer_ips: Vec<String>,
    pub discovered_peers: Vec<DiscoveredPeerInfo>,
    pub trust: TrustSnapshotInfo,

    // Autostart & diagnostics
    pub autostart_enabled: bool,
    pub recent_logs: Vec<LogEntry>,
}

pub struct IntegratorCore {
    pub rt: tokio::runtime::Runtime,
    pub discovery: DiscoveryManager,
    pub display_ctrl: DisplayController,
    pub clipboard: ClipboardService,
    pub features: Arc<FeatureManager>,
    pub kvm: Arc<KvmService>,
}

#[derive(Default)]
struct LogVisitor {
    msg: String,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.msg = format!("{:?}", value);
            if self.msg.starts_with('"') && self.msg.ends_with('"') && self.msg.len() >= 2 {
                self.msg = self.msg[1..self.msg.len() - 1].to_string();
            }
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.msg = value.to_string();
        }
    }
}

struct UiRingLogLayer;

impl<S: tracing::Subscriber> Layer<S> for UiRingLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut vis = LogVisitor::default();
        event.record(&mut vis);
        if vis.msg.is_empty() {
            return;
        }
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let entry = LogEntry {
            ts_ms,
            level: event.metadata().level().to_string(),
            message: vis.msg,
        };
        if let Ok(mut guard) = LOG_RING.lock() {
            let deque = guard.get_or_insert_with(|| VecDeque::with_capacity(200));
            if deque.len() >= 200 {
                deque.pop_front();
            }
            deque.push_back(entry.clone());
        }
        if let Ok(json) = serde_json::to_string(&entry) {
            emit_ui_event("log_entry", &json);
        }
    }
}

pub fn register_ui_callback(cb: Option<UiEventCallback>) {
    if let Ok(mut guard) = UI_EVENT_CALLBACK.lock() {
        *guard = cb;
    }
}

pub fn emit_ui_event(event_name: &str, payload_json: &str) {
    let cb_opt = UI_EVENT_CALLBACK.lock().ok().and_then(|g| *g);
    let Some(cb) = cb_opt else { return };
    let Ok(ev) = CString::new(event_name) else { return };
    let Ok(pl) = CString::new(payload_json) else { return };
    cb(ev.as_ptr(), pl.as_ptr());
}

pub fn emit_ui_toast(kind: &str, message: &str) {
    let payload = serde_json::json!({ "kind": kind, "message": message }).to_string();
    emit_ui_event("toast", &payload);
}

pub fn request_show_window() {
    emit_ui_event("show_window", "{}");
}

pub fn get_recent_logs() -> Vec<LogEntry> {
    if let Ok(guard) = LOG_RING.lock() {
        if let Some(deque) = guard.as_ref() {
            return deque.iter().cloned().collect();
        }
    }
    Vec::new()
}

pub fn open_app_data_folder() {
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

pub fn try_focus_existing_instance() -> bool {
    if let Ok(stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], config::CONTROL_PORT)),
        std::time::Duration::from_millis(150),
    ) {
        drop(stream);
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let _ = rt.block_on(DisplayController::send_remote_rpc(
                "127.0.0.1",
                &DisplayRpcRequest::ShowWindow,
            ));
        }
        return true;
    }
    false
}

pub fn run_cli_if_requested(args: &[String]) -> Option<Result<()>> {
    if args.len() <= 1 {
        return None;
    }
    match args[1].as_str() {
        "paste-remote" | "--paste-remote" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match DisplayController::send_remote_rpc(
                    "127.0.0.1",
                    &DisplayRpcRequest::PasteRemote,
                )
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
                    eprintln!("Missing target peer IP. Usage: integrator benchmark <peer_ip>");
                    std::process::exit(1);
                };
                match benchmark::BenchmarkClient::run_test(target_ip).await {
                    Ok(res) => {
                        println!("Max Bandwidth: {:.2} Gbps | Upload: {:.2} Gbps | Download: {:.2} Gbps | RTT: {:.2} ms",
                            res.max_gbps, res.upload_gbps, res.download_gbps, res.latency_ms);
                        println!("{}", res.summary);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Speed benchmark failed: {}", e);
                        std::process::exit(1);
                    }
                }
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
                    eprintln!("Missing target peer IP. Usage: integrator telemetry <peer_ip>");
                    std::process::exit(1);
                };
                match DisplayController::send_remote_rpc(
                    target_ip,
                    &DisplayRpcRequest::GetGpuTelemetry,
                )
                .await
                {
                    Ok(resp) => {
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
                    }
                    Err(e) => {
                        eprintln!("Failed to query telemetry: {}", e);
                        std::process::exit(1);
                    }
                }
            })
        })()),
        "touchbar" => Some((|| {
            #[cfg(target_os = "macos")]
            {
                if !system_info::has_touch_bar_hardware() {
                    eprintln!("No Touch Bar hardware detected on this Mac.");
                    std::process::exit(1);
                }
                let Some(peer_ip) = args
                    .get(2)
                    .map(|s| s.as_str())
                    .filter(|s| !s.trim().is_empty())
                else {
                    eprintln!("Usage: integrator touchbar <peer_ip>");
                    std::process::exit(1);
                };
                let c_ip = CString::new(peer_ip)?;
                unsafe { run_touchbar_cli_loop(c_ip.as_ptr()) };
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
                    _ => {
                        eprintln!("Unknown display subcommand: {}", subcmd);
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
                        eprintln!("Bridge daemon not reachable: {}", e);
                        std::process::exit(1);
                    }
                }
            })
        })()),
        "pin" => Some((|| {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match DisplayController::send_remote_rpc(
                    "127.0.0.1",
                    &DisplayRpcRequest::GetPairingPin,
                )
                .await
                {
                    Ok(resp) => {
                        println!("{}", resp.pairing_token.unwrap_or(resp.message));
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to query pairing PIN: {}", e);
                        std::process::exit(1);
                    }
                }
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
                    eprintln!("Usage: integrator pair <peer_ip> <6_digit_pin>");
                    std::process::exit(1);
                };
                let Some(pin) = args
                    .get(3)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                else {
                    eprintln!("Usage: integrator pair <peer_ip> <6_digit_pin>");
                    std::process::exit(1);
                };
                match DisplayController::send_remote_rpc(
                    "127.0.0.1",
                    &DisplayRpcRequest::PairWithPeer { ip, pin },
                )
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
                        eprintln!("Failed to pair via local daemon: {}", e);
                        std::process::exit(1);
                    }
                }
            })
        })()),
        _ => None,
    }
}

impl IntegratorCore {
    pub fn init_global() -> Result<Arc<Self>> {
        if let Some(existing) = GLOBAL_CORE.get() {
            return Ok(Arc::clone(existing));
        }

        // 1. Logging setup
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
            "🚀 Integrator v2.0 Native Core initializing on {} [{}]...",
            std::env::consts::OS,
            device_name
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let _ = crate::clipboard::TOKIO_HANDLE.set(rt.handle().clone());

        let feature_manager = Arc::new(FeatureManager::new());

        let (discovery, display_ctrl, clipboard, kvm) = rt.block_on(async {
            let discovery = DiscoveryManager::new(&device_name);
            discovery.start().await.expect("Failed to start discovery");

            let clipboard =
                ClipboardService::new(discovery.clone()).expect("Failed to initialize clipboard");
            clipboard.set_feature_manager(Arc::clone(&feature_manager));
            clipboard.start().await.expect("Failed to start clipboard");

            let display_ctrl = DisplayController::new(discovery.clone());
            let display_server = DisplayServer::new(display_ctrl.clone());
            display_server
                .start()
                .await
                .expect("Failed to start display RPC server");

            benchmark::BenchmarkServer::start()
                .await
                .expect("Failed to start benchmark server");

            if let Err(e) = audio::AudioManager::start_sink_server().await {
                tracing::warn!("Failed to start dynamic audio sink server: {}", e);
            }

            let kvm = KvmService::new(
                discovery.clone(),
                clipboard.clone(),
                Arc::clone(&feature_manager),
            );
            kvm.start().await.expect("Failed to start KVM engine");

            (discovery, display_ctrl, clipboard, kvm)
        });

        #[cfg(target_os = "macos")]
        unsafe {
            crate::clipboard::service::init_shortcut_interceptor();
        }

        let core = Arc::new(Self {
            rt,
            discovery,
            display_ctrl,
            clipboard,
            features: feature_manager,
            kvm,
        });
        let _ = GLOBAL_CORE.set(Arc::clone(&core));
        Ok(core)
    }

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

        let (storage_status, preferred_peer_share, autostart_enabled, (enc_gpu, dec_gpu)) =
            tokio::task::spawn_blocking({
                let bip = best_ip.clone();
                let bsh = best_share.clone();
                move || {
                    let st = storage::StorageManager::status_with_share(bip.as_deref(), bsh.as_deref());
                    let pref = storage::StorageManager::get_preferred_peer_share();
                    let auto = autostart::AutostartManager::is_enabled();
                    #[cfg(target_os = "windows")]
                    let gpus = crate::display::win_display::WinDisplayManager::get_gpu_preferences();
                    #[cfg(not(target_os = "windows"))]
                    let gpus = ("auto".to_string(), "auto".to_string());
                    (st, pref, auto, gpus)
                }
            })
            .await
            .unwrap_or_else(|_| {
                (
                    StorageStatus {
                        is_mounted: false,
                        mount_path: String::new(),
                        remote_ip: String::new(),
                        remote_share: String::new(),
                        message: String::new(),
                    },
                    None,
                    false,
                    ("auto".to_string(), "auto".to_string()),
                )
            });

        let feature_flags = self.features.get_flags();
        let als = if feature_flags.truetone {
            truetone::read_ambient_light()
        } else {
            truetone::AmbientLightData {
                lux: 0.0,
                cct_kelvin: 6500,
                supported: false,
                updated_at_secs: 0,
            }
        };

        let (trust_cfg, pending_peers) = trust::get_trust_snapshot();
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
            })
            .collect();

        #[cfg(target_os = "macos")]
        let touchbar_active = unsafe { is_touchbar_active_in_app() };
        #[cfg(not(target_os = "macos"))]
        let touchbar_active = false;

        let link_speed = best
            .as_ref()
            .map(|p| format_link_speed(p.link_speed_mbps, true))
            .unwrap_or_else(|| "--".to_string());
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
            cpu_brand: local_prof.cpu_brand,
            primary_display: local_prof.primary_display,
            local_gpus: local_prof.gpus,
            local_share_names: local_prof.default_share_names,
            has_touch_bar: local_prof.has_touch_bar,

            peer_connected: best.is_some(),
            peer_trusted: best.as_ref().map(|p| p.trusted).unwrap_or(false),
            peer_device_id: best.as_ref().map(|p| p.device_id.clone()),
            peer_ip: best_ip,
            peer_os: best.as_ref().map(|p| p.os.clone()),
            peer_name: best.as_ref().map(|p| p.device_name.clone()),
            peer_hardware_model: best.as_ref().map(|p| p.hardware_model.clone()),
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
            link_speed_mbps: best.as_ref().and_then(|p| p.link_speed_mbps),
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

            audio_status: audio::AudioManager::status(),
            feature_flags,
            kvm: self.kvm.get_status_snapshot(),

            local_interfaces,
            manual_peer_ips,
            discovered_peers,
            trust: TrustSnapshotInfo {
                pairing_pin: trust_cfg.pairing_pin,
                auto_trust_direct_cable: trust_cfg.auto_trust_direct_cable,
                require_pairing_on_lan: trust_cfg.require_pairing_on_lan,
                pending_peers,
                trusted_peers: trust_cfg.trusted_peers,
                blocked_device_ids: trust_cfg.blocked_device_ids,
            },

            autostart_enabled,
            recent_logs: get_recent_logs(),
        }
    }

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
                "get_status" => Ok(serde_json::json!("Integrator v2.0 Native Active")),
                "get_bridge_status" => {
                    let s = self.build_bridge_status().await;
                    Ok(serde_json::to_value(s).map_err(|e| e.to_string())?)
                }
                "get_logs" => Ok(serde_json::to_value(get_recent_logs()).map_err(|e| e.to_string())?),
                "toggle_display" => {
                    if !self.features.is_enabled("display") {
                        return Err("Extended Screen & GPU Acceleration is disabled".into());
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
                    let peer_ip = self
                        .discovery
                        .get_peer_ip()
                        .await
                        .ok_or_else(|| "No connected peer for speed benchmark".to_string())?;
                    let r = benchmark::BenchmarkClient::run_test(&peer_ip)
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
                        } else if let Some(peer_ip) = self.discovery.get_peer_ip().await {
                            if let Ok(c_ip) = CString::new(peer_ip) {
                                unsafe { init_touchbar_in_app(c_ip.as_ptr()) };
                                Ok(serde_json::json!(true))
                            } else {
                                Err("Invalid peer IP".into())
                            }
                        } else {
                            Err("Connect to a peer first to initialize Touch Bar HUD".into())
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
                            cct_kelvin: 6500,
                            supported: false,
                            updated_at_secs: 0,
                        }
                    } else {
                        let als = truetone::read_ambient_light();
                        if !als.supported || !als.lux.is_finite() || als.lux < 0.0 {
                            truetone::AmbientLightData {
                                lux: 0.0,
                                cct_kelvin: 6500,
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
                    if cfg!(target_os = "windows") {
                        truetone::apply_hardware_gamma_ramp(args.cct, args.comp_factor)
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
                        let als = truetone::read_ambient_light();
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
                    let msg = audio::AudioManager::play_spatial_test_chime().map_err(|e| e.to_string())?;
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
                    let flags = self.features.set_flag_checked(&args.feature, args.enabled)?;
                    if !args.enabled {
                        match args.feature.as_str() {
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
                                let _ = truetone::reset_hardware_gamma_ramp();
                            }
                            "touchbar" => {
                                #[cfg(target_os = "macos")]
                                if system_info::has_touch_bar_hardware() {
                                    unsafe { dismiss_touchbar_in_app() };
                                }
                            }
                            "input_kvm" | "dragdrop" | "clipboard" => {
                                if args.feature == "input_kvm" {
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
                            let _ = std::process::Command::new("open")
                                .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
                                .spawn();
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
                        return Err("Integrator v2.0 requires cryptographic PIN pairing (SPAKE2 + Ed25519) before trusting a peer.".into());
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
                    trust::untrust_or_block_device(cid, args.block);
                    Ok(serde_json::json!(if args.block {
                        format!("Blocked device {}", cid)
                    } else {
                        format!("Removed trust for device {}", cid)
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
                    Ok(serde_json::json!("Integrator v2.0 enforces mandatory cryptographic pairing on all interfaces"))
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
                    if tpin.len() != 6 || !tpin.chars().all(|c| c.is_ascii_digit()) {
                        return Err("Pairing PIN must be 6 digits".into());
                    }
                    let (creds, sas_6) =
                        trust::pair_with_remote_peer_v2(&tip, config::CONTROL_PORT, &tpin).await?;
                    Ok(serde_json::json!(format!(
                        "Paired with {} ({}) [SAS: {}]",
                        creds.hostname, tip, sas_6
                    )))
                }
                _ => Err(format!("Unknown native command: {}", method)),
            }
        });

        match res {
            Ok(data) => serde_json::json!({ "ok": true, "data": data }).to_string(),
            Err(err) => wrap_err(err),
        }
    }

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
            "open_cache" => open_app_data_folder(),
            "quit" => {
                self.kvm.force_release_all(true);
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

fn wrap_err(msg: String) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

pub fn c_str_to_rust(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}
