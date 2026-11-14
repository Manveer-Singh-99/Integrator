//! Dynamic hardware, display, network, GPU, and application-path discovery.
//!
//! Replaces all setup-specific assumptions (IPs, hostnames, GPUs, monitors,
//! share names, install paths) with live runtime enumeration across macOS and Windows.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrimaryDisplayInfo {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub scale_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuDeviceInfo {
    pub index: u32,
    pub name: String,
    pub vendor: String,
    pub is_discrete: bool,
    pub vram_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalHardwareProfile {
    pub device_id: String,
    pub hostname: String,
    pub os: String,
    pub hardware_model: String,
    pub cpu_brand: String,
    pub has_touch_bar: bool,
    pub primary_display: PrimaryDisplayInfo,
    pub gpus: Vec<GpuDeviceInfo>,
    pub preferred_gpu_name: Option<String>,
    pub sunshine_name: Option<String>,
    pub sunshine_port: u16,
    pub default_share_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkTransport {
    DirectUsb,
    Thunderbolt,
    Ethernet,
    Wifi,
    Unknown,
}

impl LinkTransport {
    pub fn label(self) -> &'static str {
        match self {
            LinkTransport::DirectUsb => "USB-C Direct",
            LinkTransport::Thunderbolt => "Thunderbolt Bridge",
            LinkTransport::Ethernet => "Wired Ethernet",
            LinkTransport::Wifi => "Wi-Fi / LAN",
            LinkTransport::Unknown => "Network Link",
        }
    }

    pub fn is_direct_cable(self) -> bool {
        matches!(self, LinkTransport::DirectUsb | LinkTransport::Thunderbolt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInterfaceInfo {
    pub name: String,
    pub friendly_name: String,
    pub ip: String,
    pub netmask: String,
    pub broadcast: String,
    pub cidr_prefix: u8,
    pub transport: LinkTransport,
    pub link_speed_mbps: Option<u32>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppPathPreferences {
    pub smb_share_name: Option<String>,
    pub peer_smb_share_name: Option<String>,
    pub sunshine_conf_path: Option<String>,
    pub moonlight_path: Option<String>,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn get_primary_display_info_mac(out_w: *mut u32, out_h: *mut u32, out_fps: *mut u32);
    fn CGDisplayScreenSize(display: u32) -> CGSize;
    fn CGMainDisplayID() -> u32;
    fn CGDisplayPixelsWide(display: u32) -> usize;
    fn CGDisplayModeGetPixelWidth(mode: *const std::ffi::c_void) -> usize;
    fn CGDisplayCopyDisplayMode(display: u32) -> *const std::ffi::c_void;
    fn CGDisplayModeRelease(mode: *const std::ffi::c_void);
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Copy, Clone)]
struct CGSize {
    width: f64,
    height: f64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinIfAddrs {
    ifa_next: *mut DarwinIfAddrs,
    ifa_name: *mut std::ffi::c_char,
    ifa_flags: u32,
    ifa_addr: *mut DarwinSockAddr,
    ifa_netmask: *mut DarwinSockAddr,
    ifa_dstaddr: *mut DarwinSockAddr,
    ifa_data: *mut std::ffi::c_void,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinSockAddr {
    sa_len: u8,
    sa_family: u8,
    sa_data: [u8; 14],
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinSockAddrIn {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[cfg(target_os = "macos")]
extern "C" {
    fn getifaddrs(ifap: *mut *mut DarwinIfAddrs) -> std::ffi::c_int;
    fn freeifaddrs(ifa: *mut DarwinIfAddrs);
}

pub fn user_home_dir() -> PathBuf {
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(h) = std::env::var("HOME") {
            if !h.trim().is_empty() {
                return PathBuf::from(h);
            }
        }
        std::env::temp_dir()
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("USERPROFILE") {
            if !h.trim().is_empty() {
                return PathBuf::from(h);
            }
        }
        if let (Ok(d), Ok(p)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            let combined = format!("{}{}", d, p);
            if !combined.trim().is_empty() {
                return PathBuf::from(combined);
            }
        }
        if let Ok(app) = std::env::var("LOCALAPPDATA") {
            if !app.trim().is_empty() {
                return PathBuf::from(app);
            }
        }
        std::env::temp_dir()
    }
}

/// Persistent app state directory (`~/.usbc_clipboard_cache`), preserving existing settings.
pub fn app_data_dir() -> PathBuf {
    let dir = user_home_dir().join(".usbc_clipboard_cache");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn load_path_preferences() -> AppPathPreferences {
    let path = app_data_dir().join("app_config.json");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<AppPathPreferences>(&s).ok())
        .unwrap_or_default()
}

pub fn save_path_preferences(prefs: &AppPathPreferences) -> std::io::Result<()> {
    let path = app_data_dir().join("app_config.json");
    let json = serde_json::to_string_pretty(prefs).unwrap_or_else(|_| "{}".into());
    std::fs::write(path, json)
}

/// Resolve the active user's Desktop (falling back to Downloads or home dir) dynamically.
pub fn user_desktop_or_downloads_dir() -> PathBuf {
    #[cfg(not(target_os = "windows"))]
    {
        let home = user_home_dir();
        let desktop = home.join("Desktop");
        if desktop.is_dir() {
            return desktop;
        }
        let downloads = home.join("Downloads");
        if downloads.is_dir() {
            return downloads;
        }
        home
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(reg_desktop) = query_windows_shell_folder("Desktop") {
            let p = PathBuf::from(reg_desktop);
            if p.is_dir() {
                return p;
            }
        }
        let home = user_home_dir();
        let desktop = home.join("Desktop");
        if desktop.is_dir() {
            return desktop;
        }
        if let Some(reg_dl) = query_windows_shell_folder("{374DE290-123F-4565-9164-39C4925E467B}") {
            let p = PathBuf::from(reg_dl);
            if p.is_dir() {
                return p;
            }
        }
        let downloads = home.join("Downloads");
        if downloads.is_dir() {
            return downloads;
        }
        home
    }
}

#[cfg(target_os = "windows")]
fn win_cmd(program: &str) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(target_os = "windows")]
fn query_windows_shell_folder(value_name: &str) -> Option<String> {
    let out = win_cmd("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "/v",
            value_name,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(value_name) {
            if let Some(pos) = trimmed.find("REG_") {
                let rest = &trimmed[pos..];
                if let Some(ws) = rest.find(char::is_whitespace) {
                    let raw = rest[ws..].trim();
                    let expanded = expand_windows_env_vars(raw);
                    if !expanded.is_empty() {
                        return Some(expanded);
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn expand_windows_env_vars(input: &str) -> String {
    let mut out = input.to_string();
    for var in ["USERPROFILE", "LOCALAPPDATA", "APPDATA", "OneDrive", "OneDriveConsumer"] {
        if let Ok(val) = std::env::var(var) {
            let token = format!("%{}%", var);
            if out.to_ascii_lowercase().contains(&token.to_ascii_lowercase()) {
                // Case-insensitive single-pass replace
                let lower = out.to_ascii_lowercase();
                let tok_lower = token.to_ascii_lowercase();
                if let Some(idx) = lower.find(&tok_lower) {
                    out = format!("{}{}{}", &out[..idx], val, &out[idx + token.len()..]);
                }
            }
        }
    }
    out
}

/// Stable device identifier persisted in `~/.usbc_clipboard_cache/device_id`.
pub fn get_or_create_device_id() -> String {
    static DEVICE_ID: OnceLock<String> = OnceLock::new();
    DEVICE_ID
        .get_or_init(|| {
            let path = app_data_dir().join("device_id");
            if let Ok(existing) = std::fs::read_to_string(&path) {
                let clean = existing.trim().to_string();
                if clean.len() >= 12 {
                    return clean;
                }
            }
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let host = get_hostname();
            let pid = std::process::id();
            let mut hasher = Sha256::new();
            hasher.update(host.as_bytes());
            hasher.update(now_ns.to_le_bytes());
            hasher.update(pid.to_le_bytes());
            hasher.update(std::env::consts::OS.as_bytes());
            hasher.update(std::env::consts::ARCH.as_bytes());
            let hash = hasher.finalize();
            let hex: String = hash[..16].iter().map(|b| format!("{:02x}", b)).collect();
            let formatted = format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            );
            let _ = std::fs::write(&path, &formatted);
            formatted
        })
        .clone()
}

pub fn get_hostname() -> String {
    #[cfg(target_os = "macos")]
    {
        for key in ["ComputerName", "LocalHostName"] {
            if let Ok(out) = Command::new("scutil").args(["--get", key]).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
        if let Ok(out) = Command::new("hostname").arg("-s").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        "Mac".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        if let Ok(out) = win_cmd("hostname").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        "Windows-PC".to_string()
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Host".into())
    }
}

pub fn get_hardware_model_and_cpu() -> (String, String) {
    #[cfg(target_os = "macos")]
    {
        let model = Command::new("sysctl")
            .args(["-n", "hw.model"])
            .output()
            .ok()
            .and_then(|o| {
                o.status
                    .success()
                    .then_some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Mac".into());

        let cpu = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| {
                o.status
                    .success()
                    .then_some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| std::env::consts::ARCH.into());

        (model, cpu)
    }
    #[cfg(target_os = "windows")]
    {
        let model = reg_query_sz(
            r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
            "SystemProductName",
        )
        .or_else(|| {
            reg_query_sz(
                r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
                "BaseBoardProduct",
            )
        })
        .unwrap_or_else(|| "Windows PC".into());

        let cpu = reg_query_sz(
            r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        )
        .unwrap_or_else(|| std::env::consts::ARCH.into());

        (model, cpu)
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        ("Linux".into(), std::env::consts::ARCH.into())
    }
}

#[cfg(target_os = "windows")]
fn reg_query_sz(key: &str, value: &str) -> Option<String> {
    let out = win_cmd("reg")
        .args(["query", key, "/v", value])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with(&value.to_ascii_lowercase()) {
            if let Some(pos) = trimmed.find("REG_") {
                let rest = &trimmed[pos..];
                if let Some(ws) = rest.find(char::is_whitespace) {
                    let v = rest[ws..].trim().to_string();
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Detect whether this Mac actually has Touch Bar hardware / daemon active.
pub fn has_touch_bar_hardware() -> bool {
    #[cfg(target_os = "macos")]
    {
        static HAS_TB: OnceLock<bool> = OnceLock::new();
        *HAS_TB.get_or_init(|| {
            for proc_name in ["ControlStrip", "TouchBarServer"] {
                if let Ok(out) = Command::new("pgrep").args(["-x", proc_name]).output() {
                    if out.status.success() && !out.stdout.is_empty() {
                        return true;
                    }
                }
            }
            if let Ok(out) = Command::new("ioreg")
                .args(["-rc", "AppleEmbeddedOSSupportHost"])
                .output()
            {
                if out.status.success() && !out.stdout.is_empty() {
                    return true;
                }
            }
            false
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

pub fn get_primary_display_info() -> PrimaryDisplayInfo {
    #[cfg(target_os = "macos")]
    {
        let mut w: u32 = 0;
        let mut h: u32 = 0;
        let mut fps: u32 = 0;
        unsafe {
            get_primary_display_info_mac(&mut w, &mut h, &mut fps);
        }
        let scale = unsafe {
            let main_id = CGMainDisplayID();
            let logical_w = CGDisplayPixelsWide(main_id) as f64;
            let mode = CGDisplayCopyDisplayMode(main_id);
            let px_w = if !mode.is_null() {
                let pw = CGDisplayModeGetPixelWidth(mode) as f64;
                CGDisplayModeRelease(mode);
                pw
            } else {
                logical_w
            };
            let _ = CGDisplayScreenSize(main_id);
            if logical_w > 0.0 && px_w > logical_w {
                (px_w / logical_w).max(1.0)
            } else {
                1.0
            }
        };
        PrimaryDisplayInfo {
            width: if w > 0 { w } else { 1920 },
            height: if h > 0 { h } else { 1080 },
            fps: if fps > 0 { fps } else { 60 },
            scale_factor: scale,
        }
    }
    #[cfg(target_os = "windows")]
    {
        win_primary_display_info().unwrap_or(PrimaryDisplayInfo {
            width: 1920,
            height: 1080,
            fps: 60,
            scale_factor: 1.0,
        })
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        PrimaryDisplayInfo {
            width: 1920,
            height: 1080,
            fps: 60,
            scale_factor: 1.0,
        }
    }
}

#[cfg(target_os = "windows")]
fn win_primary_display_info() -> Option<PrimaryDisplayInfo> {
    #[repr(C)]
    struct DevModeW {
        dm_device_name: [u16; 32],
        dm_spec_version: u16,
        dm_driver_version: u16,
        dm_size: u16,
        dm_driver_extra: u16,
        dm_fields: u32,
        dm_union: [u8; 16],
        dm_color: i16,
        dm_duplex: i16,
        dm_y_resolution: i16,
        dm_tt_option: i16,
        dm_collate: i16,
        dm_form_name: [u16; 32],
        dm_log_pixels: u16,
        dm_bits_per_pel: u32,
        dm_pels_width: u32,
        dm_pels_height: u32,
        dm_display_flags: u32,
        dm_display_frequency: u32,
        dm_icm_method: u32,
        dm_icm_intent: u32,
        dm_media_type: u32,
        dm_dither_type: u32,
        dm_reserved1: u32,
        dm_reserved2: u32,
        dm_panning_width: u32,
        dm_panning_height: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn EnumDisplaySettingsW(
            lpsz_device_name: *const u16,
            i_mode_num: u32,
            lp_dev_mode: *mut DevModeW,
        ) -> i32;
    }

    const ENUM_CURRENT_SETTINGS: u32 = u32::MAX;
    let mut dm: DevModeW = unsafe { std::mem::zeroed() };
    dm.dm_size = std::mem::size_of::<DevModeW>() as u16;
    let ok = unsafe { EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, &mut dm) };
    if ok != 0 && dm.dm_pels_width > 0 && dm.dm_pels_height > 0 {
        let scale = if dm.dm_log_pixels >= 96 {
            dm.dm_log_pixels as f64 / 96.0
        } else {
            1.0
        };
        Some(PrimaryDisplayInfo {
            width: dm.dm_pels_width,
            height: dm.dm_pels_height,
            fps: if dm.dm_display_frequency > 0 {
                dm.dm_display_frequency
            } else {
                60
            },
            scale_factor: scale,
        })
    } else {
        None
    }
}

/// Enumerate GPUs on the local machine dynamically without assuming vendor or model.
pub fn enumerate_gpus() -> Vec<GpuDeviceInfo> {
    static GPU_CACHE: OnceLock<Mutex<(Instant, Vec<GpuDeviceInfo>)>> = OnceLock::new();
    let cache = GPU_CACHE.get_or_init(|| Mutex::new((Instant::now() - std::time::Duration::from_secs(120), Vec::new())));
    if let Ok(guard) = cache.lock() {
        if !guard.1.is_empty() && guard.0.elapsed() < std::time::Duration::from_secs(30) {
            return guard.1.clone();
        }
    }

    let gpus = enumerate_gpus_uncached();
    if let Ok(mut guard) = cache.lock() {
        *guard = (Instant::now(), gpus.clone());
    }
    gpus
}

fn enumerate_gpus_uncached() -> Vec<GpuDeviceInfo> {
    let mut out = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Ok(cmd) = Command::new("system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .output()
        {
            if cmd.status.success() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&cmd.stdout) {
                    if let Some(items) = val.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
                        for (idx, item) in items.iter().enumerate() {
                            let name = item
                                .get("sppci_model")
                                .or_else(|| item.get("_name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("GPU")
                                .trim()
                                .to_string();
                            let vendor = item
                                .get("spdisplays_vendor")
                                .and_then(|v| v.as_str())
                                .unwrap_or_else(|| infer_vendor(&name))
                                .trim()
                                .to_string();
                            let bus = item
                                .get("sppci_bus")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let is_discrete = !bus.contains("Built-In")
                                && !name.to_ascii_lowercase().contains("apple m");
                            let vram_mb = item
                                .get("spdisplays_vram")
                                .or_else(|| item.get("spdisplays_vram_shared"))
                                .and_then(|v| v.as_str())
                                .and_then(parse_vram_mb);
                            out.push(GpuDeviceInfo {
                                index: idx as u32,
                                name,
                                vendor,
                                is_discrete,
                                vram_mb,
                            });
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // First collect any NVIDIA GPUs via nvidia-smi for exact model + VRAM.
        if let Ok(cmd) = win_cmd("nvidia-smi")
            .args(["--query-gpu=index,name,memory.total", "--format=csv,noheader,nounits"])
            .output()
        {
            if cmd.status.success() {
                let txt = String::from_utf8_lossy(&cmd.stdout);
                for line in txt.lines() {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 && !parts[1].is_empty() {
                        let idx = parts[0].parse::<u32>().unwrap_or(out.len() as u32);
                        let vram = parts.get(2).and_then(|s| s.parse::<u64>().ok());
                        out.push(GpuDeviceInfo {
                            index: idx,
                            name: parts[1].to_string(),
                            vendor: "NVIDIA".into(),
                            is_discrete: true,
                            vram_mb: vram,
                        });
                    }
                }
            }
        }

        // Also inspect Windows Display class registry keys for all adapters (Intel, AMD, NVIDIA, etc.).
        if let Ok(cmd) = win_cmd("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
                "/s",
                "/v",
                "DriverDesc",
            ])
            .output()
        {
            if cmd.status.success() {
                let txt = String::from_utf8_lossy(&cmd.stdout);
                let mut seen: HashSet<String> =
                    out.iter().map(|g| g.name.to_ascii_lowercase()).collect();
                for line in txt.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("DriverDesc") {
                        if let Some(pos) = trimmed.find("REG_SZ") {
                            let name = trimmed[pos + 6..].trim().to_string();
                            let lower = name.to_ascii_lowercase();
                            if name.is_empty()
                                || lower.contains("virtual")
                                || lower.contains("microsoft basic")
                                || lower.contains("idd")
                                || lower.contains("parsec")
                                || seen.contains(&lower)
                            {
                                continue;
                            }
                            seen.insert(lower.clone());
                            let vendor = infer_vendor(&name).to_string();
                            let is_discrete = (vendor == "NVIDIA"
                                && !lower.contains("integrated"))
                                || lower.contains("radeon rx")
                                || lower.contains("arc a")
                                || lower.contains("arc b");
                            out.push(GpuDeviceInfo {
                                index: out.len() as u32,
                                name,
                                vendor,
                                is_discrete,
                                vram_mb: None,
                            });
                        }
                    }
                }
            }
        }
    }

    if out.is_empty() {
        out.push(GpuDeviceInfo {
            index: 0,
            name: "Default System GPU".into(),
            vendor: "System".into(),
            is_discrete: false,
            vram_mb: None,
        });
    }
    out
}

fn infer_vendor(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("nvidia") || lower.contains("geforce") || lower.contains("rtx") || lower.contains("gtx") || lower.contains("quadro") {
        "NVIDIA"
    } else if lower.contains("amd") || lower.contains("radeon") {
        "AMD"
    } else if lower.contains("intel") || lower.contains("arc") || lower.contains("iris") || lower.contains("uhd") {
        "Intel"
    } else if lower.contains("apple") {
        "Apple"
    } else {
        "Unknown"
    }
}

fn parse_vram_mb(s: &str) -> Option<u64> {
    let mut digits = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else if !digits.is_empty() {
            break;
        }
    }
    let num: u64 = digits.parse().ok()?;
    if s.to_ascii_lowercase().contains("gb") {
        Some(num * 1024)
    } else {
        Some(num)
    }
}

/// Locate a helper executable or script relative to the running binary, bundle, repo, or PATH.
pub fn find_app_helper(name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(name));
            candidates.push(dir.join("helpers").join(name));
            // macOS .app bundle: Contents/MacOS/exe -> Contents/Resources/<name>
            if let Some(contents) = dir.parent() {
                candidates.push(contents.join("Resources").join(name));
            }
            // Cargo target/{debug,release}/exe -> app/<name>
            for ancestor in dir.ancestors().take(4) {
                candidates.push(ancestor.join(name));
                candidates.push(ancestor.join("app").join(name));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(name));
        candidates.push(cwd.join("app").join(name));
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name));

    for path in candidates {
        if path.is_file() {
            return Some(path);
        }
    }
    find_in_path(name)
}

pub fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let p = dir.join(binary);
        if p.is_file() {
            return Some(p);
        }
        #[cfg(target_os = "windows")]
        if !binary.to_ascii_lowercase().ends_with(".exe") {
            let p_exe = dir.join(format!("{}.exe", binary));
            if p_exe.is_file() {
                return Some(p_exe);
            }
        }
    }
    None
}

pub fn find_sunshine_conf() -> Option<PathBuf> {
    let prefs = load_path_preferences();
    if let Some(custom) = prefs.sunshine_conf_path {
        let p = PathBuf::from(custom);
        if p.is_file() {
            return Some(p);
        }
    }

    let mut candidates = Vec::new();
    #[cfg(target_os = "windows")]
    {
        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA", "APPDATA"] {
            if let Ok(base) = std::env::var(env_key) {
                candidates.push(PathBuf::from(&base).join("Sunshine").join("config").join("sunshine.conf"));
                candidates.push(PathBuf::from(&base).join("Sunshine").join("sunshine.conf"));
                candidates.push(PathBuf::from(&base).join("Apollo").join("config").join("sunshine.conf"));
            }
        }
        if let Ok(prog_data) = std::env::var("ProgramData") {
            candidates.push(PathBuf::from(&prog_data).join("Sunshine").join("sunshine.conf"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let home = user_home_dir();
        candidates.push(home.join(".config").join("sunshine").join("sunshine.conf"));
        candidates.push(
            home.join("Library")
                .join("Application Support")
                .join("Sunshine")
                .join("sunshine.conf"),
        );
        candidates.push(PathBuf::from("/opt/homebrew/etc/sunshine/sunshine.conf"));
        candidates.push(PathBuf::from("/usr/local/etc/sunshine/sunshine.conf"));
    }

    candidates.into_iter().find(|p| p.is_file())
}

pub fn find_sunshine_binary() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut candidates = Vec::new();
        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"] {
            if let Ok(base) = std::env::var(env_key) {
                candidates.push(PathBuf::from(&base).join("Sunshine").join("sunshine.exe"));
                candidates.push(PathBuf::from(&base).join("Apollo").join("sunshine.exe"));
            }
        }
        if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
            return Some(p);
        }
        find_in_path("sunshine.exe")
    }
    #[cfg(target_os = "macos")]
    {
        for p in [
            PathBuf::from("/Applications/Sunshine.app/Contents/MacOS/sunshine"),
            user_home_dir().join("Applications/Sunshine.app/Contents/MacOS/sunshine"),
            PathBuf::from("/opt/homebrew/bin/sunshine"),
            PathBuf::from("/usr/local/bin/sunshine"),
        ] {
            if p.is_file() {
                return Some(p);
            }
        }
        find_in_path("sunshine")
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        find_in_path("sunshine")
    }
}

pub fn find_moonlight_binary() -> Option<PathBuf> {
    let prefs = load_path_preferences();
    if let Some(custom) = prefs.moonlight_path {
        let p = PathBuf::from(custom);
        if p.exists() {
            return Some(p);
        }
    }

    #[cfg(target_os = "macos")]
    {
        for p in [
            PathBuf::from("/Applications/Moonlight.app/Contents/MacOS/Moonlight"),
            user_home_dir().join("Applications/Moonlight.app/Contents/MacOS/Moonlight"),
        ] {
            if p.is_file() {
                return Some(p);
            }
        }
        // Spotlight bundle ID fallback if installed anywhere else on disk.
        if let Ok(out) = Command::new("mdfind")
            .arg("kMDItemCFBundleIdentifier == 'com.moonlight-stream.Moonlight'")
            .output()
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let candidate = PathBuf::from(line.trim()).join("Contents/MacOS/Moonlight");
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
        find_in_path("Moonlight")
    }
    #[cfg(target_os = "windows")]
    {
        let mut candidates = Vec::new();
        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"] {
            if let Ok(base) = std::env::var(env_key) {
                candidates.push(PathBuf::from(&base).join("Moonlight Game Streaming Project").join("Moonlight.exe"));
                candidates.push(PathBuf::from(&base).join("Moonlight").join("Moonlight.exe"));
            }
        }
        if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
            return Some(p);
        }
        find_in_path("Moonlight.exe")
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        find_in_path("moonlight")
    }
}

pub fn read_sunshine_config_info() -> (Option<String>, u16, Option<String>) {
    let Some(conf_path) = find_sunshine_conf() else {
        return (None, 47989, None);
    };
    let Ok(content) = std::fs::read_to_string(&conf_path) else {
        return (None, 47989, None);
    };
    let mut name = None;
    let mut port: u16 = 47989;
    let mut adapter = None;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "sunshine_name" if !val.is_empty() => name = Some(val.to_string()),
                "port" => {
                    if let Ok(p) = val.parse::<u16>() {
                        port = p;
                    }
                }
                "adapter_name" if !val.is_empty() => adapter = Some(val.to_string()),
                _ => {}
            }
        }
    }
    (name, port, adapter)
}

/// Update `adapter_name` inside `sunshine.conf` safely; returns `Ok(true)` if changed.
pub fn write_sunshine_adapter_name(adapter_name: &str) -> anyhow::Result<bool> {
    let conf_path = find_sunshine_conf()
        .ok_or_else(|| anyhow::anyhow!("sunshine.conf not found on this machine"))?;
    let content = std::fs::read_to_string(&conf_path)?;
    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    let mut changed = false;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == "adapter_name" {
                found = true;
                if v.trim() != adapter_name {
                    changed = true;
                }
                lines.push(format!("adapter_name = {}", adapter_name));
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    if !found {
        lines.push(format!("adapter_name = {}", adapter_name));
        changed = true;
    }

    if changed {
        std::fs::write(&conf_path, lines.join("\n") + "\n")?;
    }
    Ok(changed)
}

/// Discover local SMB shares dynamically. First entry is user-preferred or highest priority non-admin share.
pub fn list_local_smb_shares() -> Vec<String> {
    let mut shares = Vec::new();
    let prefs = load_path_preferences();
    if let Some(custom) = prefs.smb_share_name {
        if !custom.trim().is_empty() {
            shares.push(custom);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("sharing").arg("-l").output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut current_name: Option<String> = None;
                let mut current_shared = false;
                let mut public_shares = Vec::new();
                let mut custom_shares = Vec::new();
                for line in text.lines() {
                    let t = line.trim();
                    if let Some(rest) = t.strip_prefix("name:") {
                        if let Some(n) = current_name.take() {
                            if current_shared {
                                if n.contains("Public Folder") {
                                    public_shares.push(n);
                                } else {
                                    custom_shares.push(n);
                                }
                            }
                        }
                        current_name = Some(rest.trim().to_string());
                        current_shared = false;
                    } else if t.starts_with("shared:") {
                        current_shared = t.contains('1');
                    }
                }
                if let Some(n) = current_name {
                    if current_shared {
                        if n.contains("Public Folder") {
                            public_shares.push(n);
                        } else {
                            custom_shares.push(n);
                        }
                    }
                }
                for s in custom_shares.into_iter().chain(public_shares) {
                    if !shares.contains(&s) {
                        shares.push(s);
                    }
                }
            }
        }
        // Check legacy common share name if user shared their home folder
        if shares.is_empty() {
            shares.push(get_hostname());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = win_cmd("net").arg("share").output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut in_rows = false;
                for line in text.lines() {
                    let t = line.trim();
                    if t.starts_with("----") {
                        in_rows = true;
                        continue;
                    }
                    if !in_rows || t.is_empty() || t.starts_with("The command completed") {
                        continue;
                    }
                    // Columns: Share name | Resource | Remark
                    if let Some(share_name) = t.split_whitespace().next() {
                        if share_name.ends_with('$')
                            || share_name.eq_ignore_ascii_case("IPC$")
                            || share_name.eq_ignore_ascii_case("ADMIN$")
                        {
                            continue;
                        }
                        let s = share_name.to_string();
                        if !shares.contains(&s) {
                            shares.push(s);
                        }
                    }
                }
            }
        }
        if shares.is_empty() {
            shares.push(get_hostname());
        }
    }

    shares
}

pub fn collect_local_profile() -> LocalHardwareProfile {
    let device_id = get_or_create_device_id();
    let hostname = get_hostname();
    let (hardware_model, cpu_brand) = get_hardware_model_and_cpu();
    let has_touch_bar = has_touch_bar_hardware();
    let primary_display = get_primary_display_info();
    let gpus = enumerate_gpus();
    let (sunshine_name, sunshine_port, adapter_name) = read_sunshine_config_info();
    let preferred_gpu_name = adapter_name.or_else(|| {
        gpus.iter()
            .find(|g| g.is_discrete)
            .or_else(|| gpus.first())
            .map(|g| g.name.clone())
    });
    let default_share_names = list_local_smb_shares();

    LocalHardwareProfile {
        device_id,
        hostname,
        os: std::env::consts::OS.to_string(),
        hardware_model,
        cpu_brand,
        has_touch_bar,
        primary_display,
        gpus,
        preferred_gpu_name,
        sunshine_name,
        sunshine_port,
        default_share_names,
    }
}

/// Ask the OS routing table which local IPv4 address will be used to reach `peer_ip`.
pub fn local_ip_for_peer(peer_ip: &str) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((peer_ip, 58281)).ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Look up which local interface owns `local_ip`.
pub fn interface_for_local_ip(local_ip: &str) -> Option<LocalInterfaceInfo> {
    list_local_ipv4_interfaces()
        .into_iter()
        .find(|iface| iface.ip == local_ip)
}

/// Determine transport class + friendly description + link speed for a route to `peer_ip`.
pub fn describe_route_to_peer(peer_ip: &str) -> (LinkTransport, Option<u32>, String, Option<String>) {
    let local_ip = local_ip_for_peer(peer_ip);
    if let Some(ref lip) = local_ip {
        if let Some(iface) = interface_for_local_ip(lip) {
            return (
                iface.transport,
                iface.link_speed_mbps,
                iface.description,
                Some(iface.ip),
            );
        }
    }
    (
        LinkTransport::Unknown,
        None,
        "Network Link".into(),
        local_ip,
    )
}

pub fn is_direct_cable_route(peer_ip: &str) -> bool {
    if peer_ip == "127.0.0.1" {
        return true;
    }
    let (transport, _, _, _) = describe_route_to_peer(peer_ip);
    transport.is_direct_cable()
}

/// Directed broadcast targets across all active local IPv4 interfaces plus `255.255.255.255`.
pub fn discovery_broadcast_targets() -> Vec<String> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for iface in list_local_ipv4_interfaces() {
        if !iface.broadcast.is_empty() && seen.insert(iface.broadcast.clone()) {
            targets.push(iface.broadcast);
        }
    }
    let global = "255.255.255.255".to_string();
    if seen.insert(global.clone()) {
        targets.push(global);
    }
    targets
}

/// Enumerate all active non-loopback IPv4 interfaces with mask, broadcast, transport type, and link speed.
pub fn list_local_ipv4_interfaces() -> Vec<LocalInterfaceInfo> {
    #[cfg(target_os = "macos")]
    {
        list_mac_ipv4_interfaces()
    }
    #[cfg(target_os = "windows")]
    {
        list_windows_ipv4_interfaces()
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        Vec::new()
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn compute_broadcast(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let ip_u = u32::from(ip);
    let mask_u = u32::from(mask);
    Ipv4Addr::from((ip_u & mask_u) | !mask_u)
}

#[cfg(target_os = "macos")]
fn list_mac_ipv4_interfaces() -> Vec<LocalInterfaceInfo> {
    let port_map = cached_mac_hardware_ports();
    let mut ifap: *mut DarwinIfAddrs = std::ptr::null_mut();
    let rc = unsafe { getifaddrs(&mut ifap) };
    if rc != 0 || ifap.is_null() {
        return Vec::new();
    }

    const IFF_UP: u32 = 0x1;
    const IFF_LOOPBACK: u32 = 0x8;
    const AF_INET: u8 = 2;

    let mut out = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;

        if (entry.ifa_flags & IFF_UP) == 0 || (entry.ifa_flags & IFF_LOOPBACK) != 0 {
            continue;
        }
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        let sa = unsafe { &*entry.ifa_addr };
        if sa.sa_family != AF_INET {
            continue;
        }
        let sin = unsafe { &*(entry.ifa_addr as *const DarwinSockAddrIn) };
        let ip = Ipv4Addr::from(sin.sin_addr.to_ne_bytes());
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }

        let mask = if !entry.ifa_netmask.is_null() {
            let nsa = unsafe { &*entry.ifa_netmask };
            if nsa.sa_family == AF_INET {
                let nsin = unsafe { &*(entry.ifa_netmask as *const DarwinSockAddrIn) };
                Ipv4Addr::from(nsin.sin_addr.to_ne_bytes())
            } else {
                Ipv4Addr::new(255, 255, 255, 0)
            }
        } else {
            Ipv4Addr::new(255, 255, 255, 0)
        };

        let broadcast = compute_broadcast(ip, mask);
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        // Skip virtual utun / awdl / llw tunnels unless no real interfaces exist
        if name.starts_with("utun")
            || name.starts_with("awdl")
            || name.starts_with("llw")
            || name.starts_with("anpi")
        {
            continue;
        }

        let friendly = port_map
            .get(&name)
            .cloned()
            .unwrap_or_else(|| name.clone());
        let (transport, speed) = classify_mac_interface(&name, &friendly);
        let desc = match speed {
            Some(mbps) if mbps >= 1000 => {
                format!("{} ({} Gbps {})", transport.label(), mbps / 1000, friendly)
            }
            Some(mbps) => format!("{} ({} Mbps {})", transport.label(), mbps, friendly),
            None => format!("{} ({})", transport.label(), friendly),
        };

        out.push(LocalInterfaceInfo {
            name,
            friendly_name: friendly,
            ip: ip.to_string(),
            netmask: mask.to_string(),
            broadcast: broadcast.to_string(),
            cidr_prefix: mask_to_prefix(mask),
            transport,
            link_speed_mbps: speed,
            description: desc,
        });
    }

    unsafe { freeifaddrs(ifap) };

    // Sort best wired / direct links before Wi-Fi
    out.sort_by_key(|i| i.transport);
    out
}

#[cfg(target_os = "macos")]
fn cached_mac_hardware_ports() -> std::collections::HashMap<String, String> {
    static PORT_CACHE: OnceLock<Mutex<(Instant, std::collections::HashMap<String, String>)>> =
        OnceLock::new();
    let cache = PORT_CACHE.get_or_init(|| {
        Mutex::new((
            Instant::now() - std::time::Duration::from_secs(60),
            std::collections::HashMap::new(),
        ))
    });
    if let Ok(guard) = cache.lock() {
        if !guard.1.is_empty() && guard.0.elapsed() < std::time::Duration::from_secs(15) {
            return guard.1.clone();
        }
    }

    let mut map = std::collections::HashMap::new();
    if let Ok(out) = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut current_port: Option<String> = None;
            for line in text.lines() {
                let t = line.trim();
                if let Some(p) = t.strip_prefix("Hardware Port:") {
                    current_port = Some(p.trim().to_string());
                } else if let Some(dev) = t.strip_prefix("Device:") {
                    if let Some(p) = current_port.take() {
                        map.insert(dev.trim().to_string(), p);
                    }
                }
            }
        }
    }

    if let Ok(mut guard) = cache.lock() {
        *guard = (Instant::now(), map.clone());
    }
    map
}

#[cfg(target_os = "macos")]
fn classify_mac_interface(iface: &str, friendly: &str) -> (LinkTransport, Option<u32>) {
    let lower_friendly = friendly.to_ascii_lowercase();
    let lower_iface = iface.to_ascii_lowercase();

    let mut transport = if lower_friendly.contains("wi-fi") || lower_friendly.contains("airport") {
        LinkTransport::Wifi
    } else if lower_friendly.contains("thunderbolt") || lower_iface.starts_with("bridge") {
        LinkTransport::Thunderbolt
    } else if lower_friendly.contains("usb")
        || lower_friendly.contains("cdc")
        || lower_friendly.contains("ncm")
        || lower_friendly.contains("rndis")
        || lower_friendly.contains("iphone")
        || lower_friendly.contains("ipad")
        || lower_friendly.contains("ethernet adapter")
    {
        LinkTransport::DirectUsb
    } else if lower_friendly.contains("ethernet") || lower_friendly.contains("lan") {
        LinkTransport::Ethernet
    } else {
        LinkTransport::Unknown
    };

    let mut speed_mbps = None;
    if let Ok(out) = Command::new("ifconfig").arg(iface).output() {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                let t = line.trim();
                if let Some(media) = t.strip_prefix("media:") {
                    let ml = media.to_ascii_lowercase();
                    if ml.contains("10gbase") || ml.contains("10000") {
                        speed_mbps = Some(10000);
                    } else if ml.contains("5000base") {
                        speed_mbps = Some(5000);
                    } else if ml.contains("2500base") {
                        speed_mbps = Some(2500);
                    } else if ml.contains("1000base") {
                        speed_mbps = Some(1000);
                    } else if ml.contains("100base") {
                        speed_mbps = Some(100);
                    } else if ml.contains("10base") {
                        speed_mbps = Some(10);
                    }
                    if ml.contains("cdc") && transport == LinkTransport::Unknown {
                        transport = LinkTransport::DirectUsb;
                    }
                }
            }
        }
    }

    if speed_mbps.is_none() {
        speed_mbps = match transport {
            LinkTransport::Thunderbolt => Some(10000),
            LinkTransport::DirectUsb => Some(5000),
            _ => None,
        };
    }

    (transport, speed_mbps)
}

#[cfg(target_os = "windows")]
fn list_windows_ipv4_interfaces() -> Vec<LocalInterfaceInfo> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibIpAddrRow {
        dw_addr: u32,
        dw_index: u32,
        dw_mask: u32,
        dw_bcast_addr: u32,
        dw_reasm_size: u32,
        unused1: u16,
        w_type: u16,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIpAddrTable(p_ip_addr_table: *mut u8, pdw_size: *mut u32, b_order: i32) -> u32;
    }

    let mut size: u32 = 0;
    let _ = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if size < 4 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr(), &mut size, 1) };
    if rc != 0 {
        return Vec::new();
    }

    let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<MibIpAddrRow>();
    let adapter_meta = cached_windows_adapter_meta();

    let mut out = Vec::new();
    for i in 0..num_entries {
        let offset = 4 + i * row_size;
        if offset + row_size > buf.len() {
            break;
        }
        let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const MibIpAddrRow) };
        let ip = Ipv4Addr::from(row.dw_addr.to_ne_bytes());
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let mask = Ipv4Addr::from(row.dw_mask.to_ne_bytes());
        let mask_u = u32::from(mask);
        let eff_mask = if mask_u == 0 {
            Ipv4Addr::new(255, 255, 255, 0)
        } else {
            mask
        };
        let broadcast = compute_broadcast(ip, eff_mask);
        let (name, friendly, transport, speed) = adapter_meta
            .get(&row.dw_index)
            .cloned()
            .unwrap_or_else(|| {
                (
                    format!("if{}", row.dw_index),
                    format!("Interface {}", row.dw_index),
                    LinkTransport::Ethernet,
                    None,
                )
            });

        let desc = match speed {
            Some(mbps) if mbps >= 1000 => {
                format!("{} ({} Gbps {})", transport.label(), mbps / 1000, friendly)
            }
            Some(mbps) => format!("{} ({} Mbps {})", transport.label(), mbps, friendly),
            None => format!("{} ({})", transport.label(), friendly),
        };

        out.push(LocalInterfaceInfo {
            name,
            friendly_name: friendly,
            ip: ip.to_string(),
            netmask: eff_mask.to_string(),
            broadcast: broadcast.to_string(),
            cidr_prefix: mask_to_prefix(eff_mask),
            transport,
            link_speed_mbps: speed,
            description: desc,
        });
    }

    out.sort_by_key(|i| i.transport);
    out
}

#[cfg(target_os = "windows")]
fn cached_windows_adapter_meta() -> std::collections::HashMap<u32, (String, String, LinkTransport, Option<u32>)> {
    static META_CACHE: OnceLock<
        Mutex<(
            Instant,
            std::collections::HashMap<u32, (String, String, LinkTransport, Option<u32>)>,
        )>,
    > = OnceLock::new();
    let cache = META_CACHE.get_or_init(|| {
        Mutex::new((
            Instant::now() - std::time::Duration::from_secs(60),
            std::collections::HashMap::new(),
        ))
    });
    if let Ok(guard) = cache.lock() {
        if !guard.1.is_empty() && guard.0.elapsed() < std::time::Duration::from_secs(20) {
            return guard.1.clone();
        }
    }

    let mut map = std::collections::HashMap::new();
    if let Ok(out) = win_cmd("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetAdapter | ForEach-Object { \"$($_.ifIndex)|$($_.Name)|$($_.InterfaceDescription)|$($_.LinkSpeed)|$($_.NdisPhysicalMedium)\" }",
        ])
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() < 4 {
                    continue;
                }
                let Ok(idx) = parts[0].trim().parse::<u32>() else {
                    continue;
                };
                let name = parts[1].trim().to_string();
                let desc = parts[2].trim().to_string();
                let speed = parse_windows_link_speed(parts[3].trim());
                let medium = parts.get(4).map(|s| s.trim()).unwrap_or("");
                let combined = format!("{} {} {}", name, desc, medium).to_ascii_lowercase();

                let transport = if combined.contains("wi-fi")
                    || combined.contains("wireless")
                    || combined.contains("wlan")
                    || combined.contains("802.11")
                    || combined.contains("native802_11")
                {
                    LinkTransport::Wifi
                } else if combined.contains("thunderbolt") || combined.contains("usb4") {
                    LinkTransport::Thunderbolt
                } else if combined.contains("ncm")
                    || combined.contains("cdc")
                    || combined.contains("rndis")
                    || combined.contains("usb")
                {
                    LinkTransport::DirectUsb
                } else {
                    LinkTransport::Ethernet
                };
                map.insert(idx, (name, desc, transport, speed));
            }
        }
    }

    if let Ok(mut guard) = cache.lock() {
        *guard = (Instant::now(), map.clone());
    }
    map
}

#[cfg(target_os = "windows")]
fn parse_windows_link_speed(raw: &str) -> Option<u32> {
    let lower = raw.to_ascii_lowercase();
    let num_str: String = lower
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let val: f64 = num_str.parse().ok()?;
    if lower.contains("gbps") {
        Some((val * 1000.0).round() as u32)
    } else if lower.contains("mbps") {
        Some(val.round() as u32)
    } else {
        None
    }
}

/// Normalize a user-supplied display or host path safely without hardcoding any machine names.
pub fn is_valid_ipv4(ip: &str) -> bool {
    ip.trim().parse::<Ipv4Addr>().is_ok()
}

pub fn is_local_file_path(path: &Path) -> bool {
    path.exists()
}
