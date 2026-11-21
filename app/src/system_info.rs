//! # Dynamic Hardware, Display, Network, GPU, & System Path Discovery (`system_info.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `system_info.rs` provides comprehensive, live runtime operating system and hardware discovery
//! across macOS (Apple Silicon and Intel) and Windows 11 (x86_64 and ARM64).
//!
//! Rather than relying on static configuration or hardcoded network parameters, this module dynamically
//! discovers:
//! - **Network Topology & Routing**: Enumerates physical and virtual IPv4 interfaces (MAC addresses,
//!   netmasks, broadcast addresses, CIDR prefixes), classifies physical transport media (Thunderbolt,
//!   USB-C CDC-NCM, Ethernet, Wi-Fi), and inspects the OS routing table to determine exact egress interfaces.
//! - **Display Geometry & Scaling**: Reads primary display resolution, refresh rate (60Hz–240Hz ProMotion/FreeSync),
//!   and HiDPI scale factors using CoreGraphics (macOS) and Win32 `EnumDisplaySettingsW` (Windows).
//! - **Graphics Processing Units (GPUs)**: Enumerates all active discrete, integrated, and unified memory
//!   graphics hardware across NVIDIA, AMD, Intel, and Apple architectures, extracting VRAM capacities and
//!   identifying dedicated streaming encoders.
//! - **Hardware Product Identity & Sensors**: Resolves machine product model, CPU brand string, Touch Bar
//!   hardware presence, and unique cryptographic device identifiers.
//! - **File Sharing & Companion Tools**: Automatically locates local SMB file shares, user desktop/download
//!   directories, and companion installations (Sunshine streaming server, Moonlight client).
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`: Queries host profile (`collect_local_profile`), builds comprehensive diagnostic
//!   snapshots (`build_bridge_status`), and resolves persistent application cache directories (`app_data_dir`).
//! - `discovery::DiscoveryManager`: Uses `discovery_interface_endpoints` to bind UDP broadcast sockets to
//!   individual physical interfaces and calls `describe_route_to_peer` and `is_same_subnet_as_peer` to rank candidates.
//! - `bridge::LinkMonitor`: Invokes `describe_route_to_peer` to classify whether latency transitions involve
//!   Thunderbolt or Wi-Fi links.
//! - `telemetry::query_gpu_telemetry`: Reads GPU enumeration lists and active Sunshine adapter preferences.
//!
//! ### Downstream Callees:
//! - **macOS Frameworks & APIs**: CoreGraphics (`CGMainDisplayID`, `CGDisplayPixelsWide`, `CGDisplayCopyDisplayMode`),
//!   Darwin Libc (`getifaddrs`, `freeifaddrs`), and system utilities (`/usr/sbin/networksetup`, `/sbin/ifconfig`,
//!   `/usr/sbin/ioreg`, `/usr/bin/sharing`, `/usr/sbin/scutil`, `/usr/sbin/sysctl`, `/usr/sbin/system_profiler`).
//! - **Windows System APIs & Registry**: Win32 `user32.dll` (`EnumDisplaySettingsW`, `GetDpiForSystem`),
//!   `iphlpapi.dll` (`GetIpAddrTable`), registry inspection via `reg.exe`, PowerShell `Get-NetAdapter`, and `net.exe`.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! The metrics gathered by this file form the foundational payload of Integrator's discovery beacons and
//! capability negotiations. Display resolutions enable asymmetric mouse coordinate mapping in `kvm/`, GPU
//! architectures govern hardware video encoder selection in `display/`, and interface speeds dictate adaptive
//! bitrate limits.
//!
//! ## 3. Threading & Concurrency Model
//! - **Thread-Safe In-Memory Caches**: Hardware queries that incur process spawning overhead (e.g. `networksetup`,
//!   `system_profiler`, PowerShell) are cached with monotonic Time-To-Live expiration:
//!   - `GPU_CACHE`: 30-second TTL.
//!   - `PORT_CACHE` (macOS): 15-second TTL.
//!   - `META_CACHE` (Windows): 20-second TTL.
//! - **Locking**: `APP_CONFIG_LOCK` ensures serialized access to `app_config.json`.
//! - **Offloading**: Upstream callers dispatch methods in this file via `tokio::task::spawn_blocking` to prevent
//!   blocking the Tokio asynchronous worker pool.
//!
//! ## 4. Security & Safety Invariants
//! - **Symlink Attack Prevention**: `atomic_write_private` explicitly checks `symlink_metadata` and refuses
//!   to overwrite symlinks, mitigating privilege escalation attacks.
//! - **Hardened Permissions**: Directories are created with POSIX mode `0o700` and files with `0o600`.
//! - **No Insecure Temp Fallback**: `app_data_dir()` and `save_path_preferences()` strictly reject falling back
//!   to world-writable `/tmp` or unverified temp locations if user home environment variables are unset.
//! - **Path & Name Sanitization**: Text arguments for Sunshine adapter names and paths are checked for control
//!   characters and bounded in length.
//! - **Synthetic Speed Rejection**: `sanitize_adapter_link_speed` filters out bogus virtual driver speeds
//!   (e.g. Windows USB NCM drivers reporting `100 Gbps` or macOS reporting `100baseTX`).

use crate::config;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Environment variable overriding the Sunshine REST API username.
const ENV_SUNSHINE_API_USER: &str = "INTEGRATOR_SUNSHINE_USER";

/// Environment variable overriding the Sunshine REST API password.
const ENV_SUNSHINE_API_PASS: &str = "INTEGRATOR_SUNSHINE_PASS";

/// Maximum permitted length in bytes for a Sunshine GPU `adapter_name` setting.
const MAX_SUNSHINE_ADAPTER_NAME_LEN: usize = 256;

/// Time-to-live for cached GPU adapter enumeration results.
const GPU_CACHE_TTL: Duration = Duration::from_secs(30);

/// Upper threshold in Mbps above which USB-C NCM reported link speeds are rejected as synthetic.
const SYNTHETIC_USB_NCM_MAX_VALID_MBPS: u32 = 40_000;

/// Known bogus placeholder speed in Mbps reported by macOS/Windows USB-C NCM drivers.
const SYNTHETIC_USB_NCM_PLACEHOLDER_MBPS: u32 = 100;

/// Fallback SMB share directory name when no user shares are configured.
const DEFAULT_PUBLIC_SHARE_NAME: &str = "Public";

/// Fallback hostname label used on macOS when `scutil` and `hostname` are unavailable.
#[cfg(target_os = "macos")]
const FALLBACK_HOSTNAME_MACOS: &str = "Mac";

/// Fallback hardware model string used on macOS when `sysctl hw.model` fails.
#[cfg(target_os = "macos")]
const FALLBACK_MODEL_MACOS: &str = "Mac";

/// Fallback sentinel path used on Unix when `HOME` is unset to prevent writing to `/tmp`.
#[cfg(not(target_os = "windows"))]
const INVALID_HOME_SENTINEL_UNIX: &str = "/var/empty/integrator_no_home";

/// Fallback hostname label used on non-macOS, non-Windows platforms.
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const FALLBACK_HOSTNAME_OTHER: &str = "Host";

/// Fallback hardware model label used on non-macOS, non-Windows platforms.
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const FALLBACK_MODEL_OTHER: &str = "Linux";

/// Time-to-live for cached macOS `networksetup -listallhardwareports` results.
#[cfg(target_os = "macos")]
const MAC_HARDWARE_PORTS_CACHE_TTL: Duration = Duration::from_secs(15);

/// Time-to-live for cached macOS IOKit USB-C NCM BSD interface checks.
#[cfg(target_os = "macos")]
const MAC_USB_NCM_CACHE_TTL: Duration = Duration::from_secs(3);

/// Secondary path for macOS `sharing` utility when `/usr/sbin/sharing` is absent.
#[cfg(target_os = "macos")]
const MACOS_SHARING_FALLBACK_BIN: &str = "/usr/bin/sharing";

/// System-wide configuration directories checked for `sunshine.conf` on macOS.
#[cfg(target_os = "macos")]
const MACOS_SUNSHINE_CONF_SYSTEM_DIRS: [&str; 2] =
    ["/opt/homebrew/etc/sunshine", "/usr/local/etc/sunshine"];

/// Relative path under `$HOME` for the default XDG Sunshine configuration directory on macOS.
#[cfg(target_os = "macos")]
const MACOS_SUNSHINE_CONF_HOME_REL_DIRS: [&str; 2] =
    [".config/sunshine", "Library/Application Support/Sunshine"];

/// System-wide installation paths searched for the `sunshine` binary on macOS.
#[cfg(target_os = "macos")]
const MACOS_SUNSHINE_SYSTEM_BIN_CANDIDATES: [&str; 3] = [
    "/Applications/Sunshine.app/Contents/MacOS/sunshine",
    "/opt/homebrew/bin/sunshine",
    "/usr/local/bin/sunshine",
];

/// Relative path under `$HOME` for a user-installed `Sunshine.app` binary on macOS.
#[cfg(target_os = "macos")]
const MACOS_SUNSHINE_USER_BIN_REL_PATH: &str = "Applications/Sunshine.app/Contents/MacOS/sunshine";

/// System-wide installation path for `Moonlight.app` binary on macOS.
#[cfg(target_os = "macos")]
const MACOS_MOONLIGHT_SYSTEM_BIN_PATH: &str =
    "/Applications/Moonlight.app/Contents/MacOS/Moonlight";

/// Relative path under `$HOME` for a user-installed `Moonlight.app` binary on macOS.
#[cfg(target_os = "macos")]
const MACOS_MOONLIGHT_USER_BIN_REL_PATH: &str =
    "Applications/Moonlight.app/Contents/MacOS/Moonlight";

/// Relative executable path inside any Spotlight-discovered `Moonlight.app` bundle.
#[cfg(target_os = "macos")]
const MACOS_MOONLIGHT_BUNDLE_BIN_REL_PATH: &str = "Contents/MacOS/Moonlight";

/// Fallback Windows system drive letter used only if `%SystemDrive%` and Win32 APIs fail.
#[cfg(target_os = "windows")]
const DEFAULT_WINDOWS_SYSTEM_DRIVE: &str = "C:";

/// Win32 `MAX_PATH` wide-character buffer length used for `GetWindowsDirectoryW`/`GetSystemDirectoryW`.
#[cfg(target_os = "windows")]
const WINDOWS_MAX_PATH_BUF_LEN: usize = 260;

/// Relative sentinel directory under the system drive when Windows user profile env vars are unset.
#[cfg(target_os = "windows")]
const INVALID_HOME_SENTINEL_WINDOWS_REL: &str = r"ProgramData\IntegratorInvalidHome";

/// Fallback relative path under the system drive for Windows `Users\Public` when `%PUBLIC%` is unset.
#[cfg(target_os = "windows")]
const WINDOWS_PUBLIC_USERS_REL_PATH: &str = r"Users\Public";

/// Relative path under `%ProgramFiles%` for the NVIDIA System Management Interface CLI.
#[cfg(target_os = "windows")]
const NVIDIA_SMI_REL_PATH: &str = r"NVIDIA Corporation\NVSMI\nvidia-smi.exe";

/// Windows Known Folder GUID for the user's Downloads shell directory (`FOLDERID_Downloads`).
#[cfg(target_os = "windows")]
const KNOWNFOLDERID_DOWNLOADS: &str = "{374DE290-123F-4565-9164-39C4925E467B}";

/// Windows PnP device setup class GUID for Display adapters (`GUID_DEVCLASS_DISPLAY`).
#[cfg(target_os = "windows")]
const GUID_DEVCLASS_DISPLAY: &str = "{4d36e968-e325-11ce-bfc1-08002be10318}";

/// Windows Registry key storing per-user special shell folder paths.
#[cfg(target_os = "windows")]
const WINDOWS_USER_SHELL_FOLDERS_REG_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// Windows Registry key storing system BIOS and motherboard product metadata.
#[cfg(target_os = "windows")]
const WINDOWS_BIOS_REG_KEY: &str = r"HKLM\HARDWARE\DESCRIPTION\System\BIOS";

/// Windows Registry key storing primary CPU processor brand metadata.
#[cfg(target_os = "windows")]
const WINDOWS_CPU0_REG_KEY: &str = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0";

/// Windows Registry root under which device setup class subkeys reside.
#[cfg(target_os = "windows")]
const WINDOWS_CONTROL_CLASS_REG_ROOT: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Class";

/// Standard 100% baseline DPI on Windows (`USER_DEFAULT_SCREEN_DPI`).
#[cfg(target_os = "windows")]
const WINDOWS_STANDARD_DPI: u32 = 96;

/// Floating-point representation of [`WINDOWS_STANDARD_DPI`] for scale factor division.
#[cfg(target_os = "windows")]
const WINDOWS_STANDARD_DPI_F64: f64 = 96.0;

/// Fallback hostname label used on Windows when `%COMPUTERNAME%` and `hostname.exe` fail.
#[cfg(target_os = "windows")]
const FALLBACK_HOSTNAME_WINDOWS: &str = "Windows-PC";

/// Fallback hardware model string used on Windows when BIOS registry queries fail.
#[cfg(target_os = "windows")]
const FALLBACK_MODEL_WINDOWS: &str = "Windows PC";

/// Upper safety bound in bytes for `GetIpAddrTable` buffer growth retries (4 MiB).
#[cfg(target_os = "windows")]
const MAX_IP_ADDR_TABLE_BYTES: usize = 4 * 1024 * 1024;

/// Time-to-live for cached Windows `Get-NetAdapter` PowerShell metadata.
#[cfg(target_os = "windows")]
const WIN_ADAPTER_META_CACHE_TTL: Duration = Duration::from_secs(20);

/// Environment variables searched for Sunshine/Apollo configuration files on Windows.
#[cfg(target_os = "windows")]
const WINDOWS_CONF_ENV_KEYS: [&str; 5] = [
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "LOCALAPPDATA",
    "APPDATA",
];

/// Environment variables searched for companion app binaries (Sunshine/Moonlight) on Windows.
#[cfg(target_os = "windows")]
const WINDOWS_APP_ENV_KEYS: [&str; 4] = [
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "LOCALAPPDATA",
];

/// Candidate installation folder names for Sunshine-compatible streaming hosts on Windows.
#[cfg(target_os = "windows")]
const WINDOWS_SUNSHINE_APP_DIRS: [&str; 2] = ["Sunshine", "Apollo"];

/// Candidate installation folder names for Moonlight clients on Windows.
#[cfg(target_os = "windows")]
const WINDOWS_MOONLIGHT_APP_DIRS: [&str; 2] = ["Moonlight Game Streaming Project", "Moonlight"];

/// Global mutex serializing concurrent disk operations on `app_config.json`.
static APP_CONFIG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Monotonic atomic counter for generating unique temporary filenames safely across threads.
static SYSTEM_INFO_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Returns the static mutex guarding application configuration file access.
fn app_config_lock() -> &'static Mutex<()> {
    APP_CONFIG_LOCK.get_or_init(|| Mutex::new(()))
}

/// Resolves the Windows installation root directory dynamically via `GetWindowsDirectoryW`,
/// falling back to `%SystemRoot%` / `%WINDIR%` environment variables.
#[cfg(target_os = "windows")]
pub(crate) fn windows_root_dir() -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    extern "system" {
        fn GetWindowsDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    }

    let mut buf = [0u16; WINDOWS_MAX_PATH_BUF_LEN];
    let len = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 && (len as usize) < buf.len() {
        let p = PathBuf::from(OsString::from_wide(&buf[..len as usize]));
        if p.exists() {
            return p;
        }
    }
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(val) = std::env::var_os(key) {
            let p = PathBuf::from(val);
            if p.exists() {
                return p;
            }
        }
    }
    let drive = std::env::var("SystemDrive")
        .unwrap_or_else(|_| DEFAULT_WINDOWS_SYSTEM_DRIVE.to_string());
    PathBuf::from(format!(r"{}\Windows", drive.trim_end_matches('\\')))
}

/// Resolves the Windows system drive root (e.g., `C:`) dynamically from `%SystemDrive%`
/// or the resolved Windows installation directory.
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub(crate) fn windows_system_drive() -> String {
    if let Ok(drive) = std::env::var("SystemDrive") {
        let trimmed = drive.trim().trim_end_matches('\\');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let root = windows_root_dir();
    if let Some(std::path::Component::Prefix(prefix)) = root.components().next() {
        return prefix.as_os_str().to_string_lossy().to_string();
    }
    DEFAULT_WINDOWS_SYSTEM_DRIVE.to_string()
}

/// Resolves an executable path in the Windows System32 directory dynamically via
/// `GetSystemDirectoryW`, falling back to `windows_root_dir().join("System32")`.
#[cfg(target_os = "windows")]
pub(crate) fn system32_exe(name: &str) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    extern "system" {
        fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    }

    let mut buf = [0u16; WINDOWS_MAX_PATH_BUF_LEN];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 && (len as usize) < buf.len() {
        let p = PathBuf::from(OsString::from_wide(&buf[..len as usize])).join(name);
        if p.exists() {
            return p;
        }
    }
    windows_root_dir().join("System32").join(name)
}

/// Atomically writes a private file to disk with strict permissions, symlink rejection, and atomic replacement.
///
/// # Security Guarantees:
/// 1. Rejects symlinked target paths to prevent symlink traversal attacks.
/// 2. Sets directory permissions to `0o700` (Unix).
/// 3. Writes content to a hidden temporary file with mode `0o600` (Unix).
/// 4. Atomically renames temporary file over the target destination via `std::fs::rename`.
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    // Check if target path exists and is a symlink
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
        // Restrict parent directory access to owner only (rwx------)
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
            // Restrict file permissions to owner read/write only (rw-------)
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

    // Atomically replace target path
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Locates `nvidia-smi.exe` in trusted Windows system directories.
#[cfg(target_os = "windows")]
fn find_nvidia_smi_path() -> Option<PathBuf> {
    let sys = system32_exe("nvidia-smi.exe");
    if sys.is_file() {
        return Some(sys);
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        let p = PathBuf::from(pf).join(NVIDIA_SMI_REL_PATH);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Physical pixel dimensions, refresh rate, and scaling factor of the primary display.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrimaryDisplayInfo {
    /// Horizontal resolution in physical pixels.
    pub width: u32,
    /// Vertical resolution in physical pixels.
    pub height: u32,
    /// Refresh rate in Hertz (FPS).
    pub fps: u32,
    /// Display scale factor (e.g. 2.0 for Retina / 200% Windows DPI scaling).
    pub scale_factor: f64,
}

/// Hardware description and capabilities of a detected graphics processing unit.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuDeviceInfo {
    /// Zero-based adapter enumeration index.
    pub index: u32,
    /// Human-readable marketing model name (e.g. `"NVIDIA GeForce RTX 4080"`).
    pub name: String,
    /// Hardware vendor brand string (`"NVIDIA"`, `"AMD"`, `"Intel"`, `"Apple"`, `"Unknown"`).
    pub vendor: String,
    /// `true` if adapter is a discrete PCIe card; `false` if integrated or unified memory SoC.
    pub is_discrete: bool,
    /// Total dedicated video memory in Megabytes (MB), if reportable.
    pub vram_mb: Option<u64>,
}

/// Complete hardware and system configuration profile of the local workstation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalHardwareProfile {
    /// Unique 32-character hexadecimal device identifier derived from local Ed25519 public key.
    pub device_id: String,
    /// Workstation computer hostname.
    pub hostname: String,
    /// Operating system platform name (`"macos"`, `"windows"`).
    pub os: String,
    /// Hardware model identifier (e.g. `"MacBookPro18,1"` or motherboard product name).
    pub hardware_model: String,
    /// CPU brand string (e.g. `"Apple M1 Max"` or `"13th Gen Intel(R) Core(TM) i9-13900K"`).
    pub cpu_brand: String,
    /// `true` if MacBook Touch Bar hardware is present.
    pub has_touch_bar: bool,
    /// Primary display resolution, refresh rate, and HiDPI scale factor.
    pub primary_display: PrimaryDisplayInfo,
    /// Enumerated graphics adapters.
    pub gpus: Vec<GpuDeviceInfo>,
    /// Preferred GPU name for hardware display encoding/decoding.
    pub preferred_gpu_name: Option<String>,
    /// Sunshine game-streaming service name, if installed.
    pub sunshine_name: Option<String>,
    /// Sunshine web service port (defaults to 47989).
    pub sunshine_port: u16,
    /// Published SMB share names discovered on local machine.
    pub default_share_names: Vec<String>,
}

/// Physical transport medium classification for a network communication route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkTransport {
    /// Direct point-to-point USB-C CDC-NCM virtual Ethernet link.
    DirectUsb,
    /// Direct point-to-point Thunderbolt 3/4 or USB4 networking bridge.
    Thunderbolt,
    /// Standard wired Local Area Network (1GbE / 2.5GbE / 10GbE RJ45).
    Ethernet,
    /// 802.11 Wi-Fi wireless infrastructure network or PC Mobile Hotspot.
    Wifi,
    /// Unclassified or routed network transport.
    Unknown,
}

impl LinkTransport {
    /// Returns a human-friendly label describing the transport medium.
    pub fn label(self) -> &'static str {
        match self {
            LinkTransport::DirectUsb => "USB-C Direct",
            LinkTransport::Thunderbolt => "Thunderbolt Bridge",
            LinkTransport::Ethernet => "Wired Ethernet",
            LinkTransport::Wifi => "Wi-Fi / LAN",
            LinkTransport::Unknown => "Network Link",
        }
    }

    /// Returns `true` if the transport is a direct high-bandwidth cable (Thunderbolt or Direct USB-C).
    pub fn is_direct_cable(self) -> bool {
        matches!(self, LinkTransport::DirectUsb | LinkTransport::Thunderbolt)
    }
}

/// Configuration snapshot of an active local IPv4 network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInterfaceInfo {
    /// OS interface device name (e.g. `"en0"` on macOS, `"Ethernet 2"` on Windows).
    pub name: String,
    /// User-friendly hardware port description (e.g. `"Thunderbolt Bridge"` or `"Wi-Fi"`).
    pub friendly_name: String,
    /// Assigned IPv4 address string (e.g. `"192.168.1.10"`).
    pub ip: String,
    /// IPv4 subnet mask string (e.g. `"255.255.255.0"`).
    pub netmask: String,
    /// Subnet directed broadcast address string (e.g. `"192.168.1.255"`).
    pub broadcast: String,
    /// CIDR subnet prefix length (e.g. 24 for `/24`).
    pub cidr_prefix: u8,
    /// Physical transport medium classification.
    pub transport: LinkTransport,
    /// Reported link speed in Megabits per second.
    pub link_speed_mbps: Option<u32>,
    /// Formatted route and speed description string.
    pub description: String,
}

/// User path and runtime configuration overrides stored in `app_config.json`.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AppPathPreferences {
    /// Preferred local SMB share name.
    #[serde(default)]
    pub smb_share_name: Option<String>,
    /// Preferred remote peer SMB share name.
    #[serde(default)]
    pub peer_smb_share_name: Option<String>,
    /// User-specified custom directory path for local SMB file sharing (overriding user home folder default).
    #[serde(default)]
    pub local_shared_folder: Option<String>,
    /// Custom path to `sunshine.conf`.
    #[serde(default)]
    pub sunshine_conf_path: Option<String>,
    /// Custom path to `Moonlight` executable.
    #[serde(default)]
    pub moonlight_path: Option<String>,
    /// Optional Sunshine REST API username (overridden by `INTEGRATOR_SUNSHINE_USER`).
    #[serde(default)]
    pub sunshine_api_user: Option<String>,
    /// Optional Sunshine REST API password (overridden by `INTEGRATOR_SUNSHINE_PASS`).
    #[serde(default)]
    pub sunshine_api_password: Option<String>,
    /// Optional override for the secondary Sunshine base port (default: [`config::SUNSHINE_SECONDARY_PORT`]).
    #[serde(default)]
    pub sunshine_secondary_port: Option<u16>,
    /// Optional override for the secondary Sunshine config filename (default: [`config::SUNSHINE_SECONDARY_CONF_NAME`]).
    #[serde(default)]
    pub sunshine_secondary_conf_name: Option<String>,
    /// Optional override for the Windows secondary Sunshine scheduled task name.
    #[serde(default)]
    pub sunshine_secondary_task_name: Option<String>,
    /// Optional override for the Windows primary Sunshine service name.
    #[serde(default)]
    pub sunshine_service_name: Option<String>,
    /// Optional override for the Windows VDD dynamic watcher scheduled task name.
    #[serde(default)]
    pub vdd_watcher_task_name: Option<String>,
    /// Optional override for the VDD slot identifier passed to `VddCtl.exe`.
    #[serde(default)]
    pub vdd_slot: Option<String>,
    /// Optional override for the maximum VDD stream width in pixels.
    #[serde(default)]
    pub vdd_max_width: Option<u32>,
    /// Optional override for the maximum VDD stream height in pixels.
    #[serde(default)]
    pub vdd_max_height: Option<u32>,
    /// Optional override for the Moonlight streaming application profile name (default: `"Desktop"`).
    #[serde(default)]
    pub moonlight_app_name: Option<String>,
    /// Optional manual stream video bitrate override in kilobits per second.
    #[serde(default)]
    pub display_bitrate_override_kbps: Option<u32>,
    /// Additional user-authorized IPv4 CIDRs or hosts appended to Windows Defender Firewall scopes.
    #[serde(default)]
    pub firewall_extra_subnets: Vec<String>,
    /// Custom path to the `sunshine` executable binary.
    #[serde(default)]
    pub sunshine_binary_path: Option<String>,
}

impl fmt::Debug for AppPathPreferences {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppPathPreferences")
            .field("smb_share_name", &self.smb_share_name)
            .field("peer_smb_share_name", &self.peer_smb_share_name)
            .field("local_shared_folder", &self.local_shared_folder)
            .field("sunshine_conf_path", &self.sunshine_conf_path)
            .field("moonlight_path", &self.moonlight_path)
            .field("sunshine_api_user", &self.sunshine_api_user)
            .field(
                "sunshine_api_password",
                &self.sunshine_api_password.as_ref().map(|_| "<REDACTED>"),
            )
            .field("sunshine_secondary_port", &self.sunshine_secondary_port)
            .field(
                "sunshine_secondary_conf_name",
                &self.sunshine_secondary_conf_name,
            )
            .field(
                "sunshine_secondary_task_name",
                &self.sunshine_secondary_task_name,
            )
            .field("sunshine_service_name", &self.sunshine_service_name)
            .field("vdd_watcher_task_name", &self.vdd_watcher_task_name)
            .field("vdd_slot", &self.vdd_slot)
            .field("vdd_max_width", &self.vdd_max_width)
            .field("vdd_max_height", &self.vdd_max_height)
            .field("moonlight_app_name", &self.moonlight_app_name)
            .field(
                "display_bitrate_override_kbps",
                &self.display_bitrate_override_kbps,
            )
            .field("firewall_extra_subnets", &self.firewall_extra_subnets)
            .field("sunshine_binary_path", &self.sunshine_binary_path)
            .finish()
    }
}

/// Validates a Sunshine API credential token, rejecting empty values and any control/NUL characters.
fn validate_sunshine_credential(raw: &str, is_username: bool) -> Option<String> {
    if raw.contains('\0') || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let candidate = if is_username { raw.trim() } else { raw };
    if candidate.is_empty() {
        return None;
    }
    if is_username && candidate.contains(':') {
        return None;
    }
    Some(candidate.to_string())
}

/// Pure helper resolving Sunshine REST API credentials from optional environment variables
/// first, then falling back to `AppPathPreferences`. Never supplies hardcoded credentials.
fn resolve_sunshine_api_credentials_from(
    env_user: Option<&str>,
    env_pass: Option<&str>,
    prefs: &AppPathPreferences,
) -> Option<(String, String)> {
    if env_user.is_some() || env_pass.is_some() {
        let user = validate_sunshine_credential(env_user?, true)?;
        let pass = validate_sunshine_credential(env_pass?, false)?;
        return Some((user, pass));
    }
    let user = validate_sunshine_credential(prefs.sunshine_api_user.as_deref()?, true)?;
    let pass = validate_sunshine_credential(prefs.sunshine_api_password.as_deref()?, false)?;
    Some((user, pass))
}

/// Resolves Sunshine REST API Basic Auth credentials dynamically from environment variables
/// (`INTEGRATOR_SUNSHINE_USER`, `INTEGRATOR_SUNSHINE_PASS`) first, then `app_config.json`.
///
/// Rejects values containing control characters, newlines, or NUL bytes, and returns `None`
/// when unconfigured (no hardcoded fallback credentials exist in source).
pub fn resolve_sunshine_api_credentials() -> Option<(String, String)> {
    let env_user = std::env::var(ENV_SUNSHINE_API_USER).ok();
    let env_pass = std::env::var(ENV_SUNSHINE_API_PASS).ok();
    if env_user.is_some() || env_pass.is_some() {
        return resolve_sunshine_api_credentials_from(
            env_user.as_deref(),
            env_pass.as_deref(),
            &AppPathPreferences::default(),
        );
    }
    let prefs = load_path_preferences();
    resolve_sunshine_api_credentials_from(None, None, &prefs)
}

/// Formats validated Sunshine Basic Auth credentials into a `curl -K -` stdin config directive
/// with `\\` and `"` properly escaped so secrets never leak onto process `argv`.
pub(crate) fn format_curl_basic_auth_config(user: &str, pass: &str) -> String {
    let raw = format!("{}:{}", user, pass);
    let mut escaped = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    format!("user = \"{}\"\n", escaped)
}

/// Resolves the Moonlight streaming application profile name from user preferences,
/// falling back to [`config::MOONLIGHT_DEFAULT_APP_NAME`].
pub(crate) fn resolve_moonlight_app_name() -> String {
    let prefs = load_path_preferences();
    if let Some(ref custom) = prefs.moonlight_app_name {
        if !custom.chars().any(|c| c.is_control()) {
            let trimmed = custom.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('-') {
                return trimmed.to_string();
            }
        }
    }
    config::MOONLIGHT_DEFAULT_APP_NAME.to_string()
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

/// Safely inspects environment variables to locate the user's home directory.
///
/// Verifies that paths are non-empty, contain no NUL bytes, and represent absolute paths.
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

/// Returns the user's home directory, or an unmapped sentinel directory if environment variables are missing.
pub fn user_home_dir() -> PathBuf {
    try_user_home_dir().unwrap_or_else(|| {
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from(INVALID_HOME_SENTINEL_UNIX)
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(windows_system_drive()).join(INVALID_HOME_SENTINEL_WINDOWS_REL)
        }
    })
}

/// Returns the persistent application data directory (`~/.usbc_clipboard_cache`).
///
/// Explicitly rejects symlinks to prevent directory traversal and sets Unix permissions to `0o700`.
pub fn app_data_dir() -> PathBuf {
    let dir = user_home_dir().join(config::APP_DATA_DIR_NAME);
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

/// Loads user application path preferences from `app_config.json`.
pub fn load_path_preferences() -> AppPathPreferences {
    let _guard = app_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = app_data_dir().join(config::APP_CONFIG_FILENAME);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<AppPathPreferences>(&s).ok())
        .unwrap_or_default()
}

/// Persists user application path preferences to `app_config.json` atomically.
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
    let path = dir.join(config::APP_CONFIG_FILENAME);
    let json = serde_json::to_string_pretty(prefs).unwrap_or_else(|_| "{}".into());
    atomic_write_private(&path, json.as_bytes())
}

/// Resolves the user's Desktop directory dynamically, falling back to Downloads or Home.
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
        if let Some(reg_dl) = query_windows_shell_folder(KNOWNFOLDERID_DOWNLOADS) {
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

/// Helper building a windowless `std::process::Command` on Windows.
#[cfg(target_os = "windows")]
fn win_cmd(program: &Path) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Queries Windows Shell Folders in the registry to locate special user directories (e.g. Desktop, Downloads).
#[cfg(target_os = "windows")]
fn query_windows_shell_folder(value_name: &str) -> Option<String> {
    let out = win_cmd(&system32_exe("reg.exe"))
        .args([
            "query",
            WINDOWS_USER_SHELL_FOLDERS_REG_KEY,
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

/// Expands `%USERPROFILE%`, `%APPDATA%`, and `%OneDrive%` placeholders in registry strings.
#[cfg(target_os = "windows")]
fn expand_windows_env_vars(input: &str) -> String {
    let mut out = input.to_string();
    for var in ["USERPROFILE", "LOCALAPPDATA", "APPDATA", "OneDrive", "OneDriveConsumer"] {
        if let Ok(val) = std::env::var(var) {
            let token = format!("%{}%", var);
            if out.to_ascii_lowercase().contains(&token.to_ascii_lowercase()) {
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

/// Returns the persistent canonical v2 device identifier hex string bound to `KeystoreV2`.
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

/// Queries the local operating system hostname.
pub fn get_hostname() -> String {
    #[cfg(target_os = "macos")]
    {
        for key in ["ComputerName", "LocalHostName"] {
            if let Ok(out) = Command::new(config::MACOS_SCUTIL_BIN)
                .args(["--get", key])
                .output()
            {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
        if let Ok(out) = Command::new(config::MACOS_HOSTNAME_BIN).arg("-s").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        FALLBACK_HOSTNAME_MACOS.to_string()
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
        FALLBACK_HOSTNAME_WINDOWS.to_string()
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| FALLBACK_HOSTNAME_OTHER.into())
    }
}

/// Resolves hardware product model name and CPU processor brand.
pub fn get_hardware_model_and_cpu() -> (String, String) {
    #[cfg(target_os = "macos")]
    {
        let model = Command::new(config::MACOS_SYSCTL_BIN)
            .args(["-n", "hw.model"])
            .output()
            .ok()
            .and_then(|o| {
                o.status
                    .success()
                    .then_some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| FALLBACK_MODEL_MACOS.into());

        let cpu = Command::new(config::MACOS_SYSCTL_BIN)
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
        let model = reg_query_sz(WINDOWS_BIOS_REG_KEY, "SystemProductName")
            .or_else(|| reg_query_sz(WINDOWS_BIOS_REG_KEY, "BaseBoardProduct"))
            .unwrap_or_else(|| FALLBACK_MODEL_WINDOWS.into());

        let cpu = reg_query_sz(WINDOWS_CPU0_REG_KEY, "ProcessorNameString")
            .unwrap_or_else(|| std::env::consts::ARCH.into());

        (model, cpu)
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        (FALLBACK_MODEL_OTHER.into(), std::env::consts::ARCH.into())
    }
}

/// Reads a string value from the Windows registry.
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

/// Detects whether this Mac has physical Touch Bar hardware or its daemon active.
pub fn has_touch_bar_hardware() -> bool {
    #[cfg(target_os = "macos")]
    {
        static HAS_TB: OnceLock<bool> = OnceLock::new();
        *HAS_TB.get_or_init(|| {
            for class_name in ["AppleDFR", "AppleTouchBar"] {
                if let Ok(out) = Command::new(config::MACOS_IOREG_BIN)
                    .args(["-rc", class_name])
                    .output()
                {
                    if out.status.success() && !out.stdout.is_empty() {
                        return true;
                    }
                }
            }
            if let Ok(out) = Command::new(config::MACOS_IOREG_BIN)
                .args(["-n", "dispdfr", "-r"])
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

/// Queries the primary display physical resolution, refresh rate, and scale factor.
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
            width: if w > 0 { w } else { config::DEFAULT_DISPLAY_WIDTH },
            height: if h > 0 { h } else { config::DEFAULT_DISPLAY_HEIGHT },
            fps: if fps > 0 { fps } else { config::DEFAULT_DISPLAY_FPS },
            scale_factor: scale,
        }
    }
    #[cfg(target_os = "windows")]
    {
        win_primary_display_info().unwrap_or(PrimaryDisplayInfo {
            width: config::DEFAULT_DISPLAY_WIDTH,
            height: config::DEFAULT_DISPLAY_HEIGHT,
            fps: config::DEFAULT_DISPLAY_FPS,
            scale_factor: 1.0,
        })
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        PrimaryDisplayInfo {
            width: config::DEFAULT_DISPLAY_WIDTH,
            height: config::DEFAULT_DISPLAY_HEIGHT,
            fps: config::DEFAULT_DISPLAY_FPS,
            scale_factor: 1.0,
        }
    }
}

/// Windows implementation querying primary display metrics via `EnumDisplaySettingsW` and `GetDpiForSystem`.
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
        let scale = if (dm.dm_log_pixels as u32) >= WINDOWS_STANDARD_DPI {
            dm.dm_log_pixels as f64 / WINDOWS_STANDARD_DPI_F64
        } else if sys_dpi >= WINDOWS_STANDARD_DPI {
            sys_dpi as f64 / WINDOWS_STANDARD_DPI_F64
        } else {
            1.0
        };
        Some(PrimaryDisplayInfo {
            width: dm.dm_pels_width,
            height: dm.dm_pels_height,
            fps: if dm.dm_display_frequency > 1 {
                dm.dm_display_frequency
            } else {
                config::DEFAULT_DISPLAY_FPS
            },
            scale_factor: scale,
        })
    } else {
        None
    }
}

/// Enumerates graphics adapters with a [`GPU_CACHE_TTL`] in-memory cache to prevent frequent OS subprocess calls.
pub fn enumerate_gpus() -> Vec<GpuDeviceInfo> {
    static GPU_CACHE: OnceLock<Mutex<Option<(Instant, Vec<GpuDeviceInfo>)>>> = OnceLock::new();
    let cache = GPU_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((captured_at, ref cached)) = *guard {
            if !cached.is_empty() && captured_at.elapsed() < GPU_CACHE_TTL {
                return cached.clone();
            }
        }
    }

    let gpus = enumerate_gpus_uncached();
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((Instant::now(), gpus.clone()));
    }
    gpus
}

/// Executes un-cached GPU enumeration across macOS `system_profiler` or Windows registry + `nvidia-smi`.
fn enumerate_gpus_uncached() -> Vec<GpuDeviceInfo> {
    let mut out = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Ok(cmd) = Command::new(config::MACOS_SYSTEM_PROFILER_BIN)
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
        // First collect any NVIDIA GPUs via nvidia-smi for exact model + VRAM
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

        // Also inspect Windows Display class registry keys for all adapters (Intel, AMD, NVIDIA, etc.)
        let display_class_key = format!(
            r"{}\{}",
            WINDOWS_CONTROL_CLASS_REG_ROOT, GUID_DEVCLASS_DISPLAY
        );
        if let Ok(cmd) = win_cmd(&system32_exe("reg.exe"))
            .args(["query", &display_class_key, "/s", "/v", "DriverDesc"])
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
            name: config::DEFAULT_SYSTEM_GPU_NAME.into(),
            vendor: "System".into(),
            is_discrete: false,
            vram_mb: None,
        });
    }
    out
}

/// Infers GPU vendor from adapter model name string.
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

/// Parses video memory size string in MB or GB into integer Megabytes.
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

/// Locates a helper executable or script relative to the running binary, bundle, repository, or PATH.
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

/// Searches the system PATH environment variable for a given binary name.
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

/// Locates the `sunshine.conf` configuration file in standard installation locations or user preferences.
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
        for env_key in WINDOWS_CONF_ENV_KEYS {
            if let Ok(base) = std::env::var(env_key) {
                for app_dir in WINDOWS_SUNSHINE_APP_DIRS {
                    candidates.push(
                        PathBuf::from(&base)
                            .join(app_dir)
                            .join("config")
                            .join(config::SUNSHINE_CONF_FILENAME),
                    );
                }
                candidates.push(
                    PathBuf::from(&base)
                        .join("Sunshine")
                        .join(config::SUNSHINE_CONF_FILENAME),
                );
            }
        }
        if let Ok(prog_data) = std::env::var("ProgramData") {
            candidates.push(
                PathBuf::from(&prog_data)
                    .join("Sunshine")
                    .join(config::SUNSHINE_CONF_FILENAME),
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        let home = user_home_dir();
        for rel_dir in MACOS_SUNSHINE_CONF_HOME_REL_DIRS {
            candidates.push(home.join(rel_dir).join(config::SUNSHINE_CONF_FILENAME));
        }
        for sys_dir in MACOS_SUNSHINE_CONF_SYSTEM_DIRS {
            candidates.push(PathBuf::from(sys_dir).join(config::SUNSHINE_CONF_FILENAME));
        }
    }

    candidates.into_iter().find(|p| p.is_file())
}

/// Locates the `sunshine` streaming server executable binary.
pub fn find_sunshine_binary() -> Option<PathBuf> {
    let prefs = load_path_preferences();
    if let Some(custom) = prefs.sunshine_binary_path {
        let trimmed = custom.trim();
        if !trimmed.is_empty() && !trimmed.chars().any(|c| c.is_control()) {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut candidates = Vec::new();
        for env_key in WINDOWS_APP_ENV_KEYS {
            if let Ok(base) = std::env::var(env_key) {
                for app_dir in WINDOWS_SUNSHINE_APP_DIRS {
                    candidates.push(PathBuf::from(&base).join(app_dir).join("sunshine.exe"));
                }
            }
        }
        if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
            return Some(p);
        }
        find_in_path("sunshine.exe")
    }
    #[cfg(target_os = "macos")]
    {
        let mut candidates: Vec<PathBuf> = vec![
            PathBuf::from(MACOS_SUNSHINE_SYSTEM_BIN_CANDIDATES[0]),
            user_home_dir().join(MACOS_SUNSHINE_USER_BIN_REL_PATH),
        ];
        candidates.extend(
            MACOS_SUNSHINE_SYSTEM_BIN_CANDIDATES[1..]
                .iter()
                .map(PathBuf::from),
        );
        for p in candidates {
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

/// Locates the `Moonlight` game streaming client binary.
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
            PathBuf::from(MACOS_MOONLIGHT_SYSTEM_BIN_PATH),
            user_home_dir().join(MACOS_MOONLIGHT_USER_BIN_REL_PATH),
        ] {
            if p.is_file() {
                return Some(p);
            }
        }
        // Spotlight bundle ID fallback if installed anywhere else on disk
        let query = format!(
            "kMDItemCFBundleIdentifier == '{}'",
            config::MOONLIGHT_MACOS_PREFS_DOMAIN
        );
        if let Ok(out) = Command::new(config::MACOS_MDFIND_BIN).arg(&query).output() {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let candidate =
                        PathBuf::from(line.trim()).join(MACOS_MOONLIGHT_BUNDLE_BIN_REL_PATH);
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
        for env_key in WINDOWS_APP_ENV_KEYS {
            if let Ok(base) = std::env::var(env_key) {
                for app_dir in WINDOWS_MOONLIGHT_APP_DIRS {
                    candidates.push(PathBuf::from(&base).join(app_dir).join("Moonlight.exe"));
                }
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

/// Parses Sunshine server name, port, and configured adapter name from `sunshine.conf`.
pub fn read_sunshine_config_info() -> (Option<String>, u16, Option<String>) {
    let Some(conf_path) = find_sunshine_conf() else {
        return (None, config::SUNSHINE_DEFAULT_PORT, None);
    };
    let Ok(content) = std::fs::read_to_string(&conf_path) else {
        return (None, config::SUNSHINE_DEFAULT_PORT, None);
    };
    let mut name = None;
    let mut port: u16 = config::SUNSHINE_DEFAULT_PORT;
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

/// Validates that a Sunshine GPU adapter name contains no control characters and is within
/// [`MAX_SUNSHINE_ADAPTER_NAME_LEN`] bytes.
fn validate_sunshine_adapter_name(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_SUNSHINE_ADAPTER_NAME_LEN
        || trimmed.chars().any(|c| c.is_control())
    {
        anyhow::bail!("Invalid Sunshine adapter_name value");
    }
    Ok(trimmed.to_string())
}

/// Modifies `adapter_name` inside `sunshine.conf` atomically.
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

/// Resolves the default shared folder on the local machine (e.g. `~/Public` on macOS, `%PUBLIC%` on Windows).
pub fn default_local_shared_folder() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let pub_dir = user_home_dir().join(DEFAULT_PUBLIC_SHARE_NAME);
        if pub_dir.exists() {
            Some(pub_dir.to_string_lossy().to_string())
        } else {
            Some(user_home_dir().to_string_lossy().to_string())
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(public_env) = std::env::var("PUBLIC") {
            let trimmed = public_env.trim();
            if !trimmed.is_empty() && !trimmed.contains('\0') {
                let p = PathBuf::from(trimmed);
                if p.exists() {
                    return Some(p.to_string_lossy().to_string());
                }
            }
        }
        let pub_dir = PathBuf::from(windows_system_drive()).join(WINDOWS_PUBLIC_USERS_REL_PATH);
        if pub_dir.exists() {
            Some(pub_dir.to_string_lossy().to_string())
        } else {
            Some(
                user_home_dir()
                    .join(DEFAULT_PUBLIC_SHARE_NAME)
                    .to_string_lossy()
                    .to_string(),
            )
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Discovers published local SMB shares dynamically using native tools (`sharing -l` on macOS, `net share` on Windows).
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
        let sharing_bin = if Path::new(config::MACOS_SHARING_BIN).exists() {
            config::MACOS_SHARING_BIN
        } else {
            MACOS_SHARING_FALLBACK_BIN
        };
        let mut got_shares = false;
        // 1. Structured JSON parsing via /usr/sbin/sharing -l -f json
        if let Ok(out) = Command::new(sharing_bin).args(["-l", "-f", "json"]).output() {
            if out.status.success() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                    if let Some(obj) = val.as_object() {
                        let pref_folder = prefs.local_shared_folder.as_deref();
                        let mut folder_matched_share = None;
                        for (share_label, item) in obj {
                            let smb_shared = item.get("smb_shared").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
                            if !smb_shared {
                                continue;
                            }
                            let smb_name = item.get("smb_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(share_label.as_str())
                                .trim();
                            let share_path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            if let Some(pf) = pref_folder {
                                if share_path == pf || share_path.trim_end_matches('/') == pf.trim_end_matches('/') {
                                    folder_matched_share = Some(smb_name.to_string());
                                }
                            }
                            if !smb_name.is_empty() && !shares.contains(&smb_name.to_string()) {
                                shares.push(smb_name.to_string());
                            }
                            got_shares = true;
                        }
                        if let Some(matched) = folder_matched_share {
                            if let Some(pos) = shares.iter().position(|s| s == &matched) {
                                shares.remove(pos);
                            }
                            shares.insert(0, matched);
                        }
                    }
                }
            }
        }
        // 2. Fallback text parsing if JSON query failed or was unsupported
        if !got_shares {
            if let Ok(out) = Command::new(sharing_bin).arg("-l").output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let mut current_name: Option<String> = None;
                    let mut current_shared = false;
                    for line in text.lines() {
                        let t = line.trim();
                        if let Some(rest) = t.strip_prefix("name:") {
                            if let Some(n) = current_name.take() {
                                if current_shared && !shares.contains(&n) {
                                    shares.push(n);
                                }
                            }
                            current_name = Some(rest.trim().to_string());
                            current_shared = false;
                        } else if t.starts_with("shared:") {
                            current_shared = t.contains('1');
                        }
                    }
                    if let Some(n) = current_name {
                        if current_shared && !shares.contains(&n) {
                            shares.push(n);
                        }
                    }
                }
            }
        }
        if shares.is_empty() {
            if let Some(ref custom_folder) = prefs.local_shared_folder {
                if let Some(name) = std::path::Path::new(custom_folder).file_name().and_then(|n| n.to_str()) {
                    shares.push(name.to_string());
                }
            } else {
                shares.push(DEFAULT_PUBLIC_SHARE_NAME.to_string());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(ref custom_folder) = prefs.local_shared_folder {
            if let Some(name) = std::path::Path::new(custom_folder).file_name().and_then(|n| n.to_str()) {
                if !shares.contains(&name.to_string()) {
                    shares.insert(0, name.to_string());
                }
            }
        }
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
                    if let Some(share_name) = t.split_whitespace().next() {
                        // Skip administrative shares (C$, IPC$, ADMIN$)
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
            shares.push(DEFAULT_PUBLIC_SHARE_NAME.to_string());
        }
    }

    shares
}

/// Gathers a full snapshot of the local machine's identity, display, GPU, and sharing configuration.
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

/// Asks the OS routing table which local IPv4 interface will be used to route packets to `peer_ip`.
pub fn local_ip_for_peer(peer_ip: &str) -> Option<String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((peer_ip, config::CONTROL_PORT)).ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Bitwise subnet membership check: returns `true` if `iface_ip` and `target_ip` match under `netmask`.
#[inline]
pub(crate) fn ipv4_in_subnet(iface_ip: Ipv4Addr, netmask: Ipv4Addr, target_ip: Ipv4Addr) -> bool {
    let mask_u = u32::from(netmask);
    if mask_u == 0 {
        return false;
    }
    (u32::from(iface_ip) & mask_u) == (u32::from(target_ip) & mask_u)
}

/// Checks whether `peer_ip` resides on the exact same on-link CIDR subnet as `local_ip`.
///
/// Distinguishes directly connected links (Thunderbolt `169.254.x.x`, USB-C `10.99.99.x`,
/// Mobile Hotspot `192.168.137.x`) from unconfigured alias IPs routed via a default gateway.
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

/// Looks up which local network interface owns the specified `local_ip`.
pub fn interface_for_local_ip(local_ip: &str) -> Option<LocalInterfaceInfo> {
    list_local_ipv4_interfaces()
        .into_iter()
        .find(|iface| iface.ip == local_ip)
}

/// Resolves physical transport medium, link speed, description, and local egress IP for a route to `peer_ip`.
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

/// Returns `true` if the route to `peer_ip` is a direct physical bridge cable (Thunderbolt or USB-C).
pub fn is_direct_cable_route(peer_ip: &str) -> bool {
    if peer_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
    {
        return true;
    }
    let (transport, _, _, _) = describe_route_to_peer(peer_ip);
    transport.is_direct_cable()
}

/// Returns a deduplicated list of directed broadcast target addresses across all active interfaces plus `255.255.255.255`.
#[allow(dead_code)]
pub fn discovery_broadcast_targets() -> Vec<String> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for iface in list_local_ipv4_interfaces() {
        if !iface.broadcast.is_empty() && seen.insert(iface.broadcast.clone()) {
            targets.push(iface.broadcast);
        }
    }
    let global = Ipv4Addr::BROADCAST.to_string();
    if seen.insert(global.clone()) {
        targets.push(global);
    }
    targets
}

/// Enumerates `(iface_name, local_ip, broadcast_ip, transport)` tuples across all active physical and virtual interfaces.
///
/// Enables per-interface UDP discovery socket binding so direct Thunderbolt, USB-C, and Wi-Fi links
/// transmit their beacons onto their respective physical media.
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

/// Enumerates all active non-loopback IPv4 network interfaces on the local operating system.
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

/// Converts an IPv4 subnet mask into its CIDR prefix count (e.g. 255.255.255.0 -> 24).
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Calculates the subnet-directed broadcast address for a given IP and subnet mask.
fn compute_broadcast(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let ip_u = u32::from(ip);
    let mask_u = u32::from(mask);
    Ipv4Addr::from((ip_u & mask_u) | !mask_u)
}

/// RAII cleanup guard invoking `freeifaddrs` on a linked list returned by `getifaddrs`.
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

/// macOS network interface enumerator using `getifaddrs` and hardware port mapping.
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

        // Skip down or loopback interfaces
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
                config::DEFAULT_IPV4_FALLBACK_NETMASK
            }
        } else {
            config::DEFAULT_IPV4_FALLBACK_NETMASK
        };

        let broadcast = compute_broadcast(ip, mask);
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        // Skip virtual point-to-point tunnel interfaces
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

    out.sort_by_key(|i| i.transport);
    out
}

/// Caches macOS network hardware port mappings (`networksetup -listallhardwareports`)
/// with a [`MAC_HARDWARE_PORTS_CACHE_TTL`] lifetime.
#[cfg(target_os = "macos")]
fn cached_mac_hardware_ports() -> std::collections::HashMap<String, String> {
    static PORT_CACHE: OnceLock<Mutex<Option<(Instant, std::collections::HashMap<String, String>)>>> =
        OnceLock::new();
    let cache = PORT_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((captured_at, ref cached)) = *guard {
            if !cached.is_empty() && captured_at.elapsed() < MAC_HARDWARE_PORTS_CACHE_TTL {
                return cached.clone();
            }
        }
    }

    let mut map = std::collections::HashMap::new();
    if let Ok(out) = Command::new(config::MACOS_NETWORKSETUP_BIN)
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
        *guard = Some((Instant::now(), map.clone()));
    }
    map
}

/// Classifies macOS network interface friendly names into `LinkTransport` categories.
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

/// Parses speed and media type flags from `ifconfig` output lines on macOS.
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

/// Classifies physical transport and link speed for macOS network adapters.
#[cfg(target_os = "macos")]
fn classify_mac_interface(iface: &str, friendly: &str) -> (LinkTransport, Option<u32>) {
    let lower_friendly = friendly.to_ascii_lowercase();
    let mut transport = classify_mac_friendly_name(friendly);

    // Confirm Apple Silicon host-to-host USB-C NCM backing via IORegistry
    if !lower_friendly.contains("wi-fi")
        && !lower_friendly.contains("airport")
        && !lower_friendly.contains("thunderbolt")
        && mac_is_usb_ncm_interface(iface)
    {
        transport = LinkTransport::DirectUsb;
    }

    let mut speed_mbps = None;
    if let Ok(out) = Command::new(config::MACOS_IFCONFIG_BIN).arg(iface).output() {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            let (parsed_speed, is_ncm_media, is_wired_media) = parse_mac_ifconfig_media(&txt);
            speed_mbps = parsed_speed;
            if is_ncm_media && transport == LinkTransport::Unknown {
                transport = LinkTransport::DirectUsb;
            } else if transport == LinkTransport::Unknown && is_wired_media {
                transport = LinkTransport::Ethernet;
            }
        }
    }

    (transport, sanitize_adapter_link_speed(transport, speed_mbps))
}

/// Inspects IOKit registry to determine if `iface` represents an Apple Silicon USB-C NCM virtual adapter.
#[cfg(target_os = "macos")]
fn mac_is_usb_ncm_interface(iface: &str) -> bool {
    static CACHE: OnceLock<Mutex<Option<(Instant, HashSet<String>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if let Some((captured_at, ifaces)) = &*guard {
        if now.duration_since(*captured_at) < MAC_USB_NCM_CACHE_TTL {
            return ifaces.contains(iface);
        }
    }

    let mut fresh = HashSet::new();
    if let Ok(out) = Command::new(config::MACOS_IOREG_BIN)
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

/// Parses BSD interface names from `ioreg -r -c AppleUSBDeviceNCMData -l` output.
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

/// Windows network interface enumerator using `GetIpAddrTable` and PowerShell metadata cache.
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
        if rc == ERROR_INSUFFICIENT_BUFFER
            && (size as usize) > buf.len()
            && (size as usize) <= MAX_IP_ADDR_TABLE_BYTES
        {
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
            config::DEFAULT_IPV4_FALLBACK_NETMASK
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

/// Classifies Windows network adapters, filtering VPN tunnels and recognizing USB4/Thunderbolt/Hotspots.
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

/// Caches Windows PowerShell `Get-NetAdapter` results with a [`WIN_ADAPTER_META_CACHE_TTL`] lifetime.
#[cfg(target_os = "windows")]
fn cached_windows_adapter_meta() -> std::collections::HashMap<u32, (String, String, LinkTransport, Option<u32>)> {
    static META_CACHE: OnceLock<
        Mutex<
            Option<(
                Instant,
                std::collections::HashMap<u32, (String, String, LinkTransport, Option<u32>)>,
            )>,
        >,
    > = OnceLock::new();
    let cache = META_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((captured_at, ref cached)) = *guard {
            if !cached.is_empty() && captured_at.elapsed() < WIN_ADAPTER_META_CACHE_TTL {
                return cached.clone();
            }
        }
    }

    let mut map = std::collections::HashMap::new();
    let ps_exe = system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
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
                let speed = sanitize_adapter_link_speed(transport, speed);
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
        *guard = Some((Instant::now(), map.clone()));
    }
    map
}

/// Discards synthetic placeholder link speeds reported by virtual USB-C NCM drivers.
fn sanitize_adapter_link_speed(transport: LinkTransport, speed_mbps: Option<u32>) -> Option<u32> {
    match (transport, speed_mbps) {
        (LinkTransport::DirectUsb, Some(mbps))
            if mbps >= SYNTHETIC_USB_NCM_MAX_VALID_MBPS
                || mbps == SYNTHETIC_USB_NCM_PLACEHOLDER_MBPS =>
        {
            None
        }
        (_, other) => other,
    }
}

/// Parses Windows link speed strings (e.g. `"1,000 Mbps"`, `"2.5 Gbps"`).
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

/// Validates whether the given string is a valid IPv4 address.
pub fn is_valid_ipv4(ip: &str) -> bool {
    ip.trim().parse::<Ipv4Addr>().is_ok()
}

/// Checks whether a given path exists on the local filesystem.
#[allow(dead_code)]
pub fn is_local_file_path(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::{
        parse_ioreg_usb_ncm_bsd_names, parse_windows_link_speed, sanitize_adapter_link_speed,
        validate_sunshine_adapter_name, LinkTransport,
    };

    #[test]
    fn test_sanitize_synthetic_usb_ncm_speed() {
        assert_eq!(sanitize_adapter_link_speed(LinkTransport::DirectUsb, Some(100_000)), None);
        assert_eq!(sanitize_adapter_link_speed(LinkTransport::DirectUsb, Some(100)), None);
        assert_eq!(sanitize_adapter_link_speed(LinkTransport::DirectUsb, Some(5_000)), Some(5_000));
        assert_eq!(sanitize_adapter_link_speed(LinkTransport::Ethernet, Some(100)), Some(100));
    }

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

    #[test]
    fn test_sunshine_api_credentials_resolution_and_validation() {
        use super::{
            format_curl_basic_auth_config, resolve_sunshine_api_credentials_from,
            AppPathPreferences,
        };

        // Never returns hardcoded fallback credentials when unconfigured
        let empty = AppPathPreferences::default();
        assert_eq!(resolve_sunshine_api_credentials_from(None, None, &empty), None);

        // Falls back to AppPathPreferences when env vars are unset
        let prefs = AppPathPreferences {
            sunshine_api_user: Some("studio".into()),
            sunshine_api_password: Some("s3cr\"et\\pw".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_sunshine_api_credentials_from(None, None, &prefs),
            Some(("studio".into(), "s3cr\"et\\pw".into()))
        );

        // Environment variables take precedence over preferences
        assert_eq!(
            resolve_sunshine_api_credentials_from(Some("envuser"), Some("envpass"), &prefs),
            Some(("envuser".into(), "envpass".into()))
        );

        // Rejects control chars, newlines, NUL bytes, and colons in username
        assert_eq!(
            resolve_sunshine_api_credentials_from(Some("user\n"), Some("pass"), &prefs),
            None
        );
        assert_eq!(
            resolve_sunshine_api_credentials_from(Some("user"), Some("pass\0word"), &prefs),
            None
        );
        assert_eq!(
            resolve_sunshine_api_credentials_from(Some("bad:user"), Some("pass"), &prefs),
            None
        );

        // Escapes quotes and backslashes for `curl -K -` stdin auth config
        assert_eq!(
            format_curl_basic_auth_config("studio", "s3cr\"et\\pw"),
            "user = \"studio:s3cr\\\"et\\\\pw\"\n"
        );

        // Debug representation redacts Sunshine API password
        let dbg = format!("{:?}", prefs);
        assert!(dbg.contains("<REDACTED>"));
        assert!(!dbg.contains("s3cr"));

        // Backward-compatible deserialization of legacy app_config.json without new fields
        let legacy: AppPathPreferences =
            serde_json::from_str(r#"{"smb_share_name":"Public"}"#).unwrap();
        assert_eq!(legacy.smb_share_name.as_deref(), Some("Public"));
        assert!(legacy.firewall_extra_subnets.is_empty());
        assert_eq!(legacy.sunshine_api_user, None);
    }
}
