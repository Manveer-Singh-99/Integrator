//! Dynamic hardware, display, network, GPU, and application-path discovery.
//!
//! Replaces all setup-specific assumptions (IPs, hostnames, GPUs, monitors,
//! share names, install paths) with live runtime enumeration across macOS and Windows.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static APP_CONFIG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static SYSTEM_INFO_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn app_config_lock() -> &'static Mutex<()> {
    APP_CONFIG_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(target_os = "windows")]
pub(crate) fn system32_exe(name: &str) -> PathBuf {
    if let Ok(root) = std::env::var("SystemRoot") {
        let p = PathBuf::from(root).join("System32").join(name);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from(r"C:\Windows\System32").join(name)
}

pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Refusing to overwrite symlink",
            ));
        }
    }

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing parent path")
    })?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let seq = SYSTEM_INFO_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(".{}.{}.{}.tmp", fname, std::process::id(), seq));

    let write_res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn find_nvidia_smi_path() -> Option<PathBuf> {
    let sys = system32_exe("nvidia-smi.exe");
    if sys.is_file() {
        return Some(sys);
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        let p = PathBuf::from(pf)
            .join("NVIDIA Corporation")
            .join("NVSMI")
            .join("nvidia-smi.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

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

pub fn try_user_home_dir() -> Option<PathBuf> {
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(h) = std::env::var("HOME") {
            let trimmed = h.trim();
            if !trimmed.is_empty() && !trimmed.contains('\0') {
                let p = PathBuf::from(trimmed);
                if p.is_absolute() {
                    return Some(p);
                }
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("USERPROFILE") {
            let trimmed = h.trim();
            if !trimmed.is_empty() && !trimmed.contains('\0') {
                return Some(PathBuf::from(trimmed));
            }
        }
        if let (Ok(d), Ok(p)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            let combined = format!("{}{}", d.trim(), p.trim());
            if !combined.is_empty() && !combined.contains('\0') {
                return Some(PathBuf::from(combined));
            }
        }
        if let Ok(app) = std::env::var("LOCALAPPDATA") {
            let trimmed = app.trim();
            if !trimmed.is_empty() && !trimmed.contains('\0') {
                return Some(PathBuf::from(trimmed));
            }
        }
        None
    }
}

pub fn user_home_dir() -> PathBuf {
    try_user_home_dir().unwrap_or_else(|| {
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from("/var/empty/integrator_no_home")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\IntegratorInvalidHome")
        }
    })
}

/// Persistent app state directory (`~/.usbc_clipboard_cache`), never falling back to `/tmp`.
pub fn app_data_dir() -> PathBuf {
    let dir = user_home_dir().join(".usbc_clipboard_cache");
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            tracing::error!("Refusing symlinked app_data_dir: {}", dir.display());
            return dir;
        }
    }
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir
}

pub fn load_path_preferences() -> AppPathPreferences {
    let _guard = app_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = app_data_dir().join("app_config.json");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<AppPathPreferences>(&s).ok())
        .unwrap_or_default()
}

pub fn save_path_preferences(prefs: &AppPathPreferences) -> std::io::Result<()> {
    let _guard = app_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = app_data_dir();
    if try_user_home_dir().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Home directory environment variables are unset; refusing insecure temp fallback",
        ));
    }
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = dir.join("app_config.json");
    let json = serde_json::to_string_pretty(prefs).unwrap_or_else(|_| "{}".into());
    atomic_write_private(&path, json.as_bytes())
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
fn win_cmd(program: &Path) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(target_os = "windows")]
fn query_windows_shell_folder(value_name: &str) -> Option<String> {
    let out = win_cmd(&system32_exe("reg.exe"))
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

/// Returns the canonical v2 device identifier (`HEX(SHA256("integrator-device-id-v2" || local_ed25519_pubkey)[0..16])`)
/// bound to the installation's persistent Ed25519 identity key in `KeystoreV2`.
pub fn get_or_create_device_id() -> String {
    static DEVICE_ID: OnceLock<String> = OnceLock::new();
    DEVICE_ID
        .get_or_init(|| {
            let guard = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.local_device_id_hex().to_string()
        })
        .clone()
}

pub fn get_hostname() -> String {
    #[cfg(target_os = "macos")]
    {
        for key in ["ComputerName", "LocalHostName"] {
            if let Ok(out) = Command::new("/usr/sbin/scutil").args(["--get", key]).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
        if let Ok(out) = Command::new("/bin/hostname").arg("-s").output() {
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
        if let Ok(out) = win_cmd(&system32_exe("hostname.exe")).output() {
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
        let model = Command::new("/usr/sbin/sysctl")
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

        let cpu = Command::new("/usr/sbin/sysctl")
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
    let out = win_cmd(&system32_exe("reg.exe"))
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
            for class_name in ["AppleDFR", "AppleTouchBar"] {
                if let Ok(out) = Command::new("/usr/sbin/ioreg").args(["-rc", class_name]).output() {
                    if out.status.success() && !out.stdout.is_empty() {
                        return true;
                    }
                }
            }
            if let Ok(out) = Command::new("/usr/sbin/ioreg").args(["-n", "dispdfr", "-r"]).output() {
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
        fn GetDpiForSystem() -> u32;
    }

    const ENUM_CURRENT_SETTINGS: u32 = u32::MAX;
    let mut dm: DevModeW = unsafe { std::mem::zeroed() };
    dm.dm_size = std::mem::size_of::<DevModeW>() as u16;
    let ok = unsafe { EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, &mut dm) };
    if ok != 0 && dm.dm_pels_width > 0 && dm.dm_pels_height > 0 {
        let sys_dpi = unsafe { GetDpiForSystem() };
        let scale = if dm.dm_log_pixels >= 96 {
            dm.dm_log_pixels as f64 / 96.0
        } else if sys_dpi >= 96 {
            sys_dpi as f64 / 96.0
        } else {
            1.0
        };
        Some(PrimaryDisplayInfo {
            width: dm.dm_pels_width,
            height: dm.dm_pels_height,
            fps: if dm.dm_display_frequency > 1 {
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
        if let Ok(cmd) = Command::new("/usr/sbin/system_profiler")
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
                            let bus_lower = bus.to_ascii_lowercase();
                            let name_lower = name.to_ascii_lowercase();
                            let is_discrete = !bus_lower.contains("built-in")
                                && !bus_lower.contains("builtin")
                                && !name_lower.contains("apple m")
                                && !name_lower.contains("intel hd")
                                && !name_lower.contains("intel iris")
                                && !name_lower.contains("intel uhd");
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
        if let Some(nvidia_smi_path) = find_nvidia_smi_path() {
            if let Ok(cmd) = win_cmd(&nvidia_smi_path)
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
        }

        // Also inspect Windows Display class registry keys for all adapters (Intel, AMD, NVIDIA, etc.).
        if let Ok(cmd) = win_cmd(&system32_exe("reg.exe"))
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

#[allow(dead_code)]
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
            #[cfg(debug_assertions)]
            for ancestor in dir.ancestors().take(4) {
                candidates.push(ancestor.join(name));
                candidates.push(ancestor.join("app").join(name));
            }
        }
    }
    #[cfg(debug_assertions)]
    {
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join(name));
            candidates.push(cwd.join("app").join(name));
        }
        candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name));
    }

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
        if let Ok(out) = Command::new("/usr/bin/mdfind")
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

fn validate_sunshine_adapter_name(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
        anyhow::bail!("Invalid Sunshine adapter_name value");
    }
    Ok(trimmed.to_string())
}

/// Update `adapter_name` inside `sunshine.conf` safely; returns `Ok(true)` if changed.
#[allow(dead_code)]
pub fn write_sunshine_adapter_name(adapter_name: &str) -> anyhow::Result<bool> {
    let clean_name = validate_sunshine_adapter_name(adapter_name)?;
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
                if v.trim() != clean_name {
                    changed = true;
                }
                lines.push(format!("adapter_name = {}", clean_name));
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    if !found {
        lines.push(format!("adapter_name = {}", clean_name));
        changed = true;
    }

    if changed {
        let payload = lines.join("\n") + "\n";
        atomic_write_private(&conf_path, payload.as_bytes())?;
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
        if let Ok(out) = Command::new("/usr/bin/sharing").arg("-l").output() {
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
        if let Ok(out) = win_cmd(&system32_exe("net.exe")).arg("share").output() {
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

#[inline]
pub(crate) fn ipv4_in_subnet(iface_ip: Ipv4Addr, netmask: Ipv4Addr, target_ip: Ipv4Addr) -> bool {
    let mask_u = u32::from(netmask);
    if mask_u == 0 {
        return false;
    }
    (u32::from(iface_ip) & mask_u) == (u32::from(target_ip) & mask_u)
}

/// Returns true if `peer_ip` shares an on-link subnet with `local_ip` (or any active local IPv4 interface
/// when `local_ip` is `None`), distinguishing directly attached links (e.g., USB-C `10.99.99.x`,
/// Thunderbolt `169.254.x.x`, Direct Ethernet, or PC Mobile Hotspot `192.168.137.x`) from unconfigured
/// alias IPs routed out an unrelated default gateway.
pub fn is_same_subnet_as_peer(local_ip: Option<&str>, peer_ip: &str) -> bool {
    let Ok(peer_v4) = peer_ip.trim().parse::<Ipv4Addr>() else {
        return false;
    };
    for iface in list_local_ipv4_interfaces() {
        if let Some(expected_lip) = local_ip {
            if iface.ip != expected_lip {
                continue;
            }
        }
        if let (Ok(ip_v4), Ok(mask_v4)) = (
            iface.ip.parse::<Ipv4Addr>(),
            iface.netmask.parse::<Ipv4Addr>(),
        ) {
            if ipv4_in_subnet(ip_v4, mask_v4, peer_v4) {
                return true;
            }
        }
    }
    false
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
#[allow(dead_code)]
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

/// Enumerates `(iface_name, local_ip, broadcast_ip, transport)` across all active IPv4 interfaces
/// so UDP discovery can bind per-interface sockets (vital for Thunderbolt Bridge, Direct Ethernet
/// `169.254.x.x`, and Windows Mobile Hotspot `192.168.137.x` when Wi-Fi is also active).
pub fn discovery_interface_endpoints() -> Vec<(String, String, String, LinkTransport)> {
    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();
    for iface in list_local_ipv4_interfaces() {
        if iface.ip.is_empty() || iface.broadcast.is_empty() {
            continue;
        }
        let key = (iface.name.clone(), iface.ip.clone(), iface.broadcast.clone());
        if seen.insert(key) {
            endpoints.push((iface.name, iface.ip, iface.broadcast, iface.transport));
        }
    }
    endpoints
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
struct IfAddrsGuard(*mut DarwinIfAddrs);

#[cfg(target_os = "macos")]
impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { freeifaddrs(self.0) };
        }
    }
}

#[cfg(target_os = "macos")]
fn list_mac_ipv4_interfaces() -> Vec<LocalInterfaceInfo> {
    let port_map = cached_mac_hardware_ports();
    let mut ifap: *mut DarwinIfAddrs = std::ptr::null_mut();
    let rc = unsafe { getifaddrs(&mut ifap) };
    if rc != 0 || ifap.is_null() {
        return Vec::new();
    }
    let _guard = IfAddrsGuard(ifap);

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
        if sa.sa_family != AF_INET
            || (sa.sa_len as usize) < std::mem::size_of::<DarwinSockAddrIn>()
        {
            continue;
        }
        let sin = unsafe { &*(entry.ifa_addr as *const DarwinSockAddrIn) };
        let ip = Ipv4Addr::from(sin.sin_addr.to_ne_bytes());
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }

        let mask = if !entry.ifa_netmask.is_null() {
            let nsa = unsafe { &*entry.ifa_netmask };
            let nlen = nsa.sa_len as usize;
            if nlen >= 5 && (nsa.sa_family == AF_INET || nsa.sa_family == 0) {
                let copy_len = (nlen - 4).min(4);
                let mut mask_bytes = [0u8; 4];
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        (entry.ifa_netmask as *const u8).add(4),
                        mask_bytes.as_mut_ptr(),
                        copy_len,
                    );
                }
                Ipv4Addr::from(mask_bytes)
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

        // Skip virtual utun / awdl / llw / point-to-point tunnel interfaces unless no real interfaces exist
        if name.starts_with("utun")
            || name.starts_with("awdl")
            || name.starts_with("llw")
            || name.starts_with("anpi")
            || name.starts_with("gif")
            || name.starts_with("stf")
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

    // IfAddrsGuard frees `ifap` on drop.
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
    if let Ok(out) = Command::new("/usr/sbin/networksetup")
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

#[cfg(any(target_os = "macos", test))]
fn classify_mac_friendly_name(friendly: &str) -> LinkTransport {
    let lower_friendly = friendly.to_ascii_lowercase();
    if lower_friendly.contains("wi-fi") || lower_friendly.contains("airport") {
        LinkTransport::Wifi
    } else if lower_friendly.contains("thunderbolt") {
        LinkTransport::Thunderbolt
    } else if lower_friendly.contains("iphone")
        || lower_friendly.contains("ipad")
        || lower_friendly.contains("rndis")
        || lower_friendly.contains("useth")
    {
        LinkTransport::DirectUsb
    } else if lower_friendly.contains("ethernet")
        || lower_friendly.contains("lan")
        || lower_friendly.contains("ax88")
        || lower_friendly.contains("realtek")
        || lower_friendly.contains("gbe")
        || lower_friendly.contains("2.5g")
        || lower_friendly.contains("5gbe")
        || lower_friendly.contains("10g")
        || lower_friendly.contains("usb-c")
        || lower_friendly.contains("type-c")
        || lower_friendly.contains("belkin")
        || lower_friendly.contains("anker")
        || lower_friendly.contains("plugable")
        || lower_friendly.contains("caldigit")
        || lower_friendly.contains("dock")
        || lower_friendly.contains("usb")
    {
        LinkTransport::Ethernet
    } else if lower_friendly.contains("cdc") || lower_friendly.contains("ncm") {
        LinkTransport::DirectUsb
    } else {
        LinkTransport::Unknown
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_mac_ifconfig_media(txt: &str) -> (Option<u32>, bool, bool) {
    let mut speed_mbps = None;
    let mut is_ncm_media = false;
    let mut is_wired_media = false;
    for line in txt.lines() {
        let t = line.trim();
        if let Some(media) = t.strip_prefix("media:") {
            let ml = media.to_ascii_lowercase();
            if ml.contains("10gbase") || ml.contains("10000") {
                speed_mbps = Some(10000);
                is_wired_media = true;
            } else if ml.contains("5000base") {
                speed_mbps = Some(5000);
                is_wired_media = true;
            } else if ml.contains("2500base") {
                speed_mbps = Some(2500);
                is_wired_media = true;
            } else if ml.contains("1000base") {
                speed_mbps = Some(1000);
                is_wired_media = true;
            } else if ml.contains("100base") {
                speed_mbps = Some(100);
                is_wired_media = true;
            } else if ml.contains("10base") {
                speed_mbps = Some(10);
                is_wired_media = true;
            } else if ml.contains("base") || ml.contains("ethernet") || ml.contains("full-duplex") {
                is_wired_media = true;
            }
            if ml.contains("cdc") || ml.contains("ncm") {
                is_ncm_media = true;
            }
        }
    }
    (speed_mbps, is_ncm_media, is_wired_media)
}

#[cfg(target_os = "macos")]
fn classify_mac_interface(iface: &str, friendly: &str) -> (LinkTransport, Option<u32>) {
    let lower_friendly = friendly.to_ascii_lowercase();

    // Only classify as Thunderbolt if `networksetup` explicitly maps this device to Thunderbolt.
    // Never classify arbitrary `bridge*` (e.g., Internet Sharing `bridge100` or VM bridges) as Thunderbolt.
    // Likewise, only classify as DirectUsb for genuine point-to-point USB CDC/NCM/RNDIS/Apple bridges,
    // not generic USB-C-to-RJ45 Ethernet LAN adapters used on Intel & Apple Silicon Macs.
    let mut transport = classify_mac_friendly_name(friendly);

    // macOS presents Apple Silicon host-to-host USB-C NCM links (`AppleUSBDeviceNCM11Data`) as generic
    // "Ethernet Adapter (enN)" with `100baseTX` media. Confirm NCM backing via IORegistry so
    // Apple Silicon USB-C links get DirectUsb prioritization and full streaming bitrates.
    if !lower_friendly.contains("wi-fi")
        && !lower_friendly.contains("airport")
        && !lower_friendly.contains("thunderbolt")
        && mac_is_usb_ncm_interface(iface)
    {
        transport = LinkTransport::DirectUsb;
    }

    let mut speed_mbps = None;
    if let Ok(out) = Command::new("/sbin/ifconfig").arg(iface).output() {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            let (parsed_speed, is_ncm_media, is_wired_media) = parse_mac_ifconfig_media(&txt);
            speed_mbps = parsed_speed;
            if is_ncm_media && transport == LinkTransport::Unknown {
                transport = LinkTransport::DirectUsb;
            } else if transport == LinkTransport::Unknown && is_wired_media {
                // Ensure USB-C Ethernet adapters missing from cached `networksetup` never rank behind Wi-Fi
                transport = LinkTransport::Ethernet;
            }
        }
    }

    (transport, speed_mbps)
}

#[cfg(target_os = "macos")]
fn mac_is_usb_ncm_interface(iface: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    static CACHE: OnceLock<Mutex<Option<(Instant, HashSet<String>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if let Some((captured_at, ifaces)) = &*guard {
        if now.duration_since(*captured_at) < Duration::from_secs(3) {
            return ifaces.contains(iface);
        }
    }

    let mut fresh = HashSet::new();
    if let Ok(out) = Command::new("/usr/sbin/ioreg")
        .args(["-r", "-c", "AppleUSBDeviceNCMData", "-l"])
        .output()
    {
        if out.status.success() {
            fresh = parse_ioreg_usb_ncm_bsd_names(&String::from_utf8_lossy(&out.stdout));
        }
    }
    let matched = fresh.contains(iface);
    *guard = Some((now, fresh));
    matched
}

#[cfg(any(target_os = "macos", test))]
fn parse_ioreg_usb_ncm_bsd_names(ioreg_output: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let mut in_ncm_node = false;
    for line in ioreg_output.lines() {
        let trimmed = line.trim();
        let is_top_level_node =
            line.starts_with("+-o ") || trimmed.starts_with("+-o ") && !line.starts_with(' ') && !line.starts_with('|');
        if is_top_level_node {
            in_ncm_node = trimmed.contains("AppleUSBDeviceNCM");
        }
        if in_ncm_node {
            if let Some(rest) = trimmed.split("\"BSD Name\"").nth(1) {
                if let Some(eq_rest) = rest.split('=').nth(1) {
                    let bsd = eq_rest.trim().trim_matches('"').trim();
                    if !bsd.is_empty() && !bsd.starts_with("anpi") {
                        names.insert(bsd.to_string());
                    }
                }
            }
        }
    }
    names
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

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    let mut size: u32 = 0;
    let _ = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if size < 4 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize];
    let mut succeeded = false;
    for _ in 0..3 {
        let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr(), &mut size, 1) };
        if rc == 0 {
            succeeded = true;
            break;
        }
        if rc == ERROR_INSUFFICIENT_BUFFER && (size as usize) > buf.len() && (size as usize) <= 4 * 1024 * 1024 {
            buf.resize(size as usize, 0);
        } else {
            return Vec::new();
        }
    }
    if !succeeded || buf.len() < 4 {
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
        // Skip disconnected (0x0008) or being-deleted (0x0040) IPv4 rows
        if (row.w_type & (0x0008 | 0x0040)) != 0 {
            continue;
        }
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

#[cfg(any(target_os = "windows", test))]
fn classify_windows_adapter(name: &str, desc: &str, medium: &str) -> (bool, LinkTransport, bool) {
    let combined = format!("{} {} {}", name, desc, medium).to_ascii_lowercase();
    let is_apple_usb_ncm =
        combined.contains("apple usb-c ncm") || combined.contains("appleusbncm");
    let is_vpn = !is_apple_usb_ncm
        && (combined.contains("wintun")
            || combined.contains("wireguard")
            || combined.contains("tailscale")
            || combined.contains("zerotier")
            || combined.contains("tap-windows")
            || combined.contains("openvpn")
            || combined.contains("vpn"));
    let is_hotspot = combined.contains("wi-fi direct");

    let transport = if is_vpn {
        LinkTransport::Unknown
    } else if combined.contains("wi-fi")
        || combined.contains("wireless")
        || combined.contains("wlan")
        || combined.contains("802.11")
        || combined.contains("native802_11")
    {
        LinkTransport::Wifi
    } else if combined.contains("thunderbolt") || combined.contains("usb4") {
        LinkTransport::Thunderbolt
    } else if is_apple_usb_ncm || combined.contains("rndis") || combined.contains("apple mobile") {
        LinkTransport::DirectUsb
    } else if combined.contains("ethernet")
        || combined.contains("gbe")
        || combined.contains("lan")
        || combined.contains("ax88")
        || combined.contains("realtek")
    {
        LinkTransport::Ethernet
    } else if combined.contains("ncm") || combined.contains("cdc") {
        LinkTransport::DirectUsb
    } else {
        LinkTransport::Ethernet
    };

    (is_vpn, transport, is_hotspot)
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
    let ps_exe = system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");
    if let Ok(out) = win_cmd(&ps_exe)
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
                let raw_desc = parts[2].trim().to_string();
                let speed = parse_windows_link_speed(parts[3].trim());
                let medium = parts.get(4).map(|s| s.trim()).unwrap_or("");
                let (_is_vpn, transport, is_hotspot) = classify_windows_adapter(&name, &raw_desc, medium);
                let desc = if is_hotspot && !raw_desc.to_ascii_lowercase().contains("hotspot") {
                    format!("PC Wireless Hotspot - {}", raw_desc)
                } else {
                    raw_desc
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

#[cfg(any(target_os = "windows", test))]
fn parse_windows_link_speed(raw: &str) -> Option<u32> {
    let lower = raw.trim().to_ascii_lowercase();
    let num_token: String = lower
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',' || *c == '.')
        .collect();
    if num_token.is_empty() {
        return None;
    }

    let is_gbps = lower.contains("gbps") || lower.contains("gbit");
    let is_mbps = lower.contains("mbps") || lower.contains("mbit");
    if !is_gbps && !is_mbps {
        return None;
    }

    // Distinguish English thousands separators ("1,000 Mbps", "10,000 Mbps")
    // from locale decimal commas ("2,5 Gbps").
    let normalized = if num_token.contains('.') {
        num_token.replace(',', "")
    } else if num_token.contains(',') {
        let parts: Vec<&str> = num_token.split(',').collect();
        let is_thousands_grouping = parts.len() >= 2
            && parts.iter().skip(1).all(|p| p.len() == 3 && p.chars().all(|c| c.is_ascii_digit()));
        if is_thousands_grouping && is_mbps {
            num_token.replace(',', "")
        } else {
            num_token.replacen(',', ".", 1).replace(',', "")
        }
    } else {
        num_token
    };

    let val: f64 = normalized.parse().ok()?;
    if !val.is_finite() || val <= 0.0 {
        return None;
    }
    if is_gbps {
        Some((val * 1000.0).round() as u32)
    } else {
        Some(val.round() as u32)
    }
}

/// Normalize a user-supplied display or host path safely without hardcoding any machine names.
pub fn is_valid_ipv4(ip: &str) -> bool {
    ip.trim().parse::<Ipv4Addr>().is_ok()
}

#[allow(dead_code)]
pub fn is_local_file_path(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::{
        parse_ioreg_usb_ncm_bsd_names, parse_windows_link_speed, validate_sunshine_adapter_name,
    };

    #[test]
    fn test_parse_ioreg_usb_ncm_bsd_names() {
        let sample = r#"
+-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data, id 0x1>
  |   "IOClass" = "AppleUSBDeviceNCM11Data"
  +-o en3  <class IOEthernetInterface, id 0x1a>
    |   "BSD Name" = "en3"
+-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data, id 0x2>
  +-o anpi0  <class AppleUSBDeviceNCMPrivateEthernetInterface, id 0x3>
    |   "BSD Name" = "anpi0"
+-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data, id 0x4>
  +-o en5  <class IOEthernetInterface, id 0x4a>
    |   "BSD Name" = "en5"
+-o AppleBCMWLANCore  <class AppleBCMWLANCore, id 0x5>
  +-o en0  <class IO80211Interface, id 0x5a>
    |   "BSD Name" = "en0"
"#;
        let parsed = parse_ioreg_usb_ncm_bsd_names(sample);
        assert!(parsed.contains("en3"));
        assert!(parsed.contains("en5"));
        assert!(!parsed.contains("anpi0"));
        assert!(!parsed.contains("en0"));
    }

    #[test]
    fn test_windows_link_speed_thousands_and_decimals() {
        assert_eq!(parse_windows_link_speed("1,000 Mbps"), Some(1000));
        assert_eq!(parse_windows_link_speed("10,000 Mbps"), Some(10000));
        assert_eq!(parse_windows_link_speed("2.5 Gbps"), Some(2500));
        assert_eq!(parse_windows_link_speed("2,5 Gbps"), Some(2500));
        assert_eq!(parse_windows_link_speed("100 Mbps"), Some(100));
        assert_eq!(parse_windows_link_speed("Disconnected"), None);
    }

    #[test]
    fn test_sunshine_adapter_name_rejects_control_chars() {
        assert!(validate_sunshine_adapter_name("NVIDIA GeForce RTX 4090\nport = 1").is_err());
        assert!(validate_sunshine_adapter_name("NVIDIA GeForce RTX 4090").is_ok());
    }

    #[test]
    fn test_mac_classify_intel_usbc_ethernet_tb_wifi_and_ncm() {
        use super::{classify_mac_friendly_name, parse_mac_ifconfig_media, LinkTransport};

        assert_eq!(classify_mac_friendly_name("Thunderbolt Bridge"), LinkTransport::Thunderbolt);
        assert_eq!(classify_mac_friendly_name("USB 10/100/1000 LAN"), LinkTransport::Ethernet);
        assert_eq!(classify_mac_friendly_name("AX88179A"), LinkTransport::Ethernet);
        assert_eq!(classify_mac_friendly_name("Belkin USB-C LAN"), LinkTransport::Ethernet);
        assert_eq!(classify_mac_friendly_name("Wi-Fi"), LinkTransport::Wifi);
        assert_eq!(classify_mac_friendly_name("en4"), LinkTransport::Unknown);

        let ifc_sample = "en4: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tmedia: autoselect (2500base-T <full-duplex>)\n\tstatus: active\n";
        assert_eq!(parse_mac_ifconfig_media(ifc_sample), (Some(2500), false, true));
    }

    #[test]
    fn test_windows_classify_tb_usb4_ethernet_hotspot_and_apple_ncm() {
        use super::{classify_windows_adapter, LinkTransport};

        assert_eq!(
            classify_windows_adapter("Apple USB-C NCM", "Wintun Userspace Tunnel", ""),
            (false, LinkTransport::DirectUsb, false)
        );
        assert_eq!(
            classify_windows_adapter("Ethernet 3", "Thunderbolt(TM) Networking", ""),
            (false, LinkTransport::Thunderbolt, false)
        );
        assert_eq!(
            classify_windows_adapter("Ethernet 4", "USB4(TM) P2P Network Adapter", ""),
            (false, LinkTransport::Thunderbolt, false)
        );
        assert_eq!(
            classify_windows_adapter("Ethernet 2", "Realtek USB GbE Family Controller", "802.3"),
            (false, LinkTransport::Ethernet, false)
        );
        assert_eq!(
            classify_windows_adapter("Local Area Connection* 10", "Microsoft Wi-Fi Direct Virtual Adapter #2", "Native802_11"),
            (false, LinkTransport::Wifi, true)
        );
        assert_eq!(
            classify_windows_adapter("Tailscale", "Tailscale Tunnel Wintun", ""),
            (true, LinkTransport::Unknown, false)
        );
    }

    #[test]
    fn test_ipv4_in_subnet_covers_link_local_hotspot_and_usbc() {
        use super::ipv4_in_subnet;
        use std::net::Ipv4Addr;

        assert!(ipv4_in_subnet(
            Ipv4Addr::new(169, 254, 12, 5),
            Ipv4Addr::new(255, 255, 0, 0),
            Ipv4Addr::new(169, 254, 240, 9),
        ));
        assert!(ipv4_in_subnet(
            Ipv4Addr::new(192, 168, 137, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 137, 88),
        ));
        assert!(!ipv4_in_subnet(
            Ipv4Addr::new(10, 99, 99, 2),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 2, 2),
        ));
    }
}
