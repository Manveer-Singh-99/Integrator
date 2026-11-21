//! # Guided Dependency Installer & Cross-Platform Permissions Audit Engine (`setup.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `setup.rs` implements Integrator's security-hardened **Setup, Drivers & Permissions Assistant**.
//! It audits operating system privacy permissions and companion streaming/driver dependencies
//! across macOS (12.0+ through Sequoia) and Windows 11 (x86_64 & ARM64), driving:
//! - **App-Launch Permissions & Driver Readiness Evaluation**: Automatically detects missing
//!   required OS permissions or companion streaming tools at startup so native frontends
//!   (`ui-macos/`, `ui-windows/`) can present a non-blocking setup sheet/dialog once per launch.
//! - **1-Click Native OS Permission Requests & Deep Links**: Triggers native TCC prompts on macOS
//!   (`AXIsProcessTrustedWithOptions`, `CGRequestListenEventAccess`, `CGRequestScreenCaptureAccess`,
//!   `AVCaptureDevice.requestAccess`) or on-demand elevated fixes / `ms-settings:` deep links on Windows.
//! - **Guided Companion Tool & Driver Installation**: Detects and guides installation for:
//!   - **Sunshine** (or Apollo) streaming host (`brew` on macOS, `winget` on Windows, or GitHub release).
//!   - **Moonlight** streaming client (`brew` on macOS, `winget` on Windows, or GitHub release).
//!   - **Windows Virtual Display Driver** (`IddSampleDriver` / `MttVDD` / `VddCtl.exe`).
//!   - **Apple USB-C NCM Direct-Link Bridge & Watchdog** (`Install-AppleUsbNcm.ps1` + `wintun.dll`
//!     on Windows; `/Library/LaunchDaemons/com.integrator.usbncm.plist` + `macos/install-macos.sh` on macOS).
//!   - **Windows 11 Virtual Camera COM Driver** (`integrator_vcam.dll`, CLSID `{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}`).
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`:
//!   - Embeds [`SetupHealthSnapshot`] in `BridgeStatus.setup_status` on every status refresh.
//!   - Dispatches JSON-RPC actions: `"get_setup_status"`, `"request_permission"`,
//!     `"request_all_missing_permissions"`, `"open_permission_settings"`, `"install_dependency"`,
//!     and `"set_suppress_launch_setup_prompt"`.
//!   - Executes CLI subcommand `integrator setup` / `integrator setup status`.
//!
//! ### Downstream Callees:
//! - **macOS Native FFI (`permissions_macos.swift`, `camera_macos.swift`)**:
//!   `integrator_mac_perm_accessibility_granted`, `integrator_mac_perm_accessibility_request`,
//!   `integrator_mac_perm_input_monitoring_granted`, `integrator_mac_perm_input_monitoring_request`,
//!   `integrator_mac_perm_screen_recording_granted`, `integrator_mac_perm_screen_recording_request`,
//!   `integrator_mac_perm_camera_status`, `integrator_mac_perm_camera_request`,
//!   `integrator_mac_camera_has_hardware`.
//! - **Windows System Utilities & Win32 APIs**:
//!   Win32 `OpenProcessToken` + `GetTokenInformation(TokenElevation)`, `netsh.exe`, `sc.exe`,
//!   `reg.exe`, `schtasks.exe`, `regsvr32.exe`, `explorer.exe`, `winget.exe`, and `powershell.exe`
//!   resolved dynamically via `system_info::system32_exe(...)` and `system_info::windows_root_dir()`.
//! - **Configuration & Path Discovery**:
//!   `config::*` canonical constants and `system_info::*` binary/path locators.
//!
//! ## 3. Threading & Concurrency Model
//! - **Subprocess Probe Cache (`SETUP_CACHE`)**: Expensive OS subprocess and filesystem probes
//!   (`netsh`, `sc.exe`, `Get-NetConnectionProfile`, `sharing -l`, `pgrep`, `schtasks`) are cached
//!   in a thread-safe `Mutex<Option<(Instant, CachedSubprocessProbes)>>` with a 10-second TTL
//!   ([`SETUP_PROBE_CACHE_TTL`]).
//! - **Immediate Native FFI Probes**: Fast in-process macOS TCC checks (`AXIsProcessTrusted`,
//!   `CGPreflightListenEventAccess`, `CGPreflightScreenCaptureAccess`, `AVCaptureDevice.authorizationStatus`)
//!   are evaluated live on every snapshot without caching delay.
//! - **Deterministic Cache Invalidation**: [`invalidate_setup_cache`] is invoked immediately
//!   whenever a user requests a permission, opens OS settings, triggers a dependency install,
//!   or forces a status refresh.
//!
//! ## 4. Security & Safety Invariants
//! - **Strict Allowlist Enums ([`PermissionId`], [`DependencyId`])**: Every RPC/FFI action parses
//!   its target identifier through a closed enum allowlist. Unknown IDs, arbitrary URLs, file paths,
//!   or shell metacharacters are rejected before any OS API or process is invoked.
//! - **Zero Arbitrary URL or Command Execution**: OS Settings panes and download links are mapped
//!   exclusively from compile-time constants in `config.rs`.
//! - **Qualified Binary Paths**: macOS utilities use SIP-protected `/usr/bin/*`, `/usr/sbin/*`,
//!   `/bin/*`, `/sbin/*` constants (`config::MACOS_*_BIN`); Windows system tools use
//!   `system_info::system32_exe(...)`.
//! - **On-Demand Principle of Least Privilege**: Never auto-runs `sudo` on macOS and never forces
//!   always-Administrator execution on Windows; UAC elevation (`-Verb RunAs`) is requested only
//!   when the user explicitly clicks a Windows Fix or Install action that requires elevation.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{config, system_info};

/// Time-to-live (10 seconds) for cached OS subprocess probes (`netsh`, `sc.exe`, `sharing -l`, etc.).
pub const SETUP_PROBE_CACHE_TTL: Duration = Duration::from_secs(10);

/// Local TCP connect timeout (120 milliseconds) when probing whether Sunshine's local port is listening.
const LOCAL_PORT_PROBE_TIMEOUT: Duration = Duration::from_millis(120);

/// Windows process creation flag suppressing console window flashes (`CREATE_NO_WINDOW`).
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Secondary fallback path for macOS `sharing` binary when `/usr/sbin/sharing` is absent.
#[cfg(target_os = "macos")]
const MACOS_SHARING_FALLBACK_BIN: &str = "/usr/bin/sharing";

/// Relative path under `%LOCALAPPDATA%` where the Windows App Installer (`winget.exe`) alias resides.
#[cfg(target_os = "windows")]
const WINDOWS_WINGET_LOCALAPPDATA_REL_PATH: &str = r"Microsoft\WindowsApps\winget.exe";

/// Windows Registry subkey under `WINDOWS_CAMERA_CONSENT_REG_KEY` controlling Win32 desktop app camera access.
#[allow(dead_code)]
const WINDOWS_CAMERA_CONSENT_NONPACKAGED_SUBKEY: &str = "NonPackaged";

/// Expected registry value data indicating camera access is permitted in Windows CapabilityAccessManager.
#[cfg(any(target_os = "windows", test))]
const WINDOWS_CONSENT_ALLOW_TOKEN: &str = "allow";

/// Expected registry value data indicating camera access is blocked in Windows CapabilityAccessManager.
#[cfg(any(target_os = "windows", test))]
const WINDOWS_CONSENT_DENY_TOKEN: &str = "deny";

/// Guided terminal command for running the macOS USB-C NCM LaunchDaemon installer script.
#[allow(dead_code)]
const MACOS_USBNCM_DEFAULT_INSTALL_CMD: &str = "sudo bash macos/install-macos.sh";

/// Guided PowerShell command for running the Windows USB-C NCM WinTun bridge installer script.
#[allow(dead_code)]
const WINDOWS_USBNCM_DEFAULT_INSTALL_CMD: &str =
    r"powershell -ExecutionPolicy Bypass -File .\windows\Install-AppleUsbNcm.ps1";

/// Guided command for registering the Windows 11 Virtual Camera COM server DLL.
#[allow(dead_code)]
const WINDOWS_VCAM_DEFAULT_INSTALL_CMD: &str = r#"regsvr32 /s "integrator_vcam.dll""#;

/// Guided manual installation summary for the Windows Virtual Display Driver.
#[allow(dead_code)]
const WINDOWS_VDD_INSTALL_CMD: &str =
    "Download & run the signed Virtual Display Driver (VDD) installer from GitHub Releases";

#[cfg(target_os = "macos")]
extern "C" {
    fn integrator_mac_perm_accessibility_granted() -> bool;
    fn integrator_mac_perm_accessibility_request() -> bool;
    fn integrator_mac_perm_input_monitoring_granted() -> bool;
    fn integrator_mac_perm_input_monitoring_request() -> bool;
    fn integrator_mac_perm_screen_recording_granted() -> bool;
    fn integrator_mac_perm_screen_recording_request() -> bool;
    fn integrator_mac_perm_camera_status() -> i32;
    fn integrator_mac_perm_camera_request();
    fn integrator_mac_camera_has_hardware() -> i32;
}

// ============================================================================
// Strict Allowlist Identifiers (`PermissionId` & `DependencyId`)
// ============================================================================

/// Closed allowlist of operating system permission identifiers across macOS and Windows.
///
/// All incoming RPC parameters for `"request_permission"` and `"open_permission_settings"`
/// are validated against this enum before any OS call is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionId {
    /// macOS Accessibility permission (`AXIsProcessTrusted`) for KVM input capture and injection.
    Accessibility,
    /// macOS Input Monitoring permission (`CGPreflightListenEventAccess`) for global event taps.
    InputMonitoring,
    /// macOS Screen Recording permission (`CGPreflightScreenCaptureAccess`) for display streaming.
    ScreenRecording,
    /// macOS Camera permission (`AVCaptureDevice`) for Mac -> PC Shared Camera.
    Camera,
    /// macOS Sequoia+ Local Network privacy permission for LAN/Thunderbolt/USB-C discovery.
    LocalNetwork,
    /// macOS SMB File Sharing (`sharing -l`) for shared storage auto-mounting.
    FileSharing,
    /// Windows Defender Firewall inbound TCP/UDP/SMB rules for Integrator.
    Firewall,
    /// Windows active network connection profile category (`Private` vs `Public`).
    NetworkProfile,
    /// Windows webcam privacy consent (`ConsentStore\webcam`).
    CameraPrivacy,
    /// Windows SMB Server (`LanmanServer`) service status.
    SmbServer,
    /// Windows Administrator token elevation status (`TokenElevation`).
    AdminElevation,
}

impl PermissionId {
    /// Strictly parses a permission identifier string against the canonical allowlist.
    ///
    /// Rejects unknown identifiers, empty strings, control characters, URLs, and shell metacharacters.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.chars().any(|c| c.is_control()) {
            return Err("Invalid permission identifier".to_string());
        }
        match raw.trim() {
            "accessibility" => Ok(Self::Accessibility),
            "input_monitoring" => Ok(Self::InputMonitoring),
            "screen_recording" => Ok(Self::ScreenRecording),
            "camera" => Ok(Self::Camera),
            "local_network" => Ok(Self::LocalNetwork),
            "file_sharing" => Ok(Self::FileSharing),
            "firewall" => Ok(Self::Firewall),
            "network_profile" => Ok(Self::NetworkProfile),
            "camera_privacy" => Ok(Self::CameraPrivacy),
            "smb_server" => Ok(Self::SmbServer),
            "admin_elevation" => Ok(Self::AdminElevation),
            other => Err(format!("Unsupported or unknown permission ID: '{}'", other)),
        }
    }

    /// Returns the canonical wire string identifier for this permission.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accessibility => "accessibility",
            Self::InputMonitoring => "input_monitoring",
            Self::ScreenRecording => "screen_recording",
            Self::Camera => "camera",
            Self::LocalNetwork => "local_network",
            Self::FileSharing => "file_sharing",
            Self::Firewall => "firewall",
            Self::NetworkProfile => "network_profile",
            Self::CameraPrivacy => "camera_privacy",
            Self::SmbServer => "smb_server",
            Self::AdminElevation => "admin_elevation",
        }
    }

    /// Returns the allowlisted, compile-time OS System Settings deep-link URI for this permission, if any.
    pub const fn settings_url(self) -> Option<&'static str> {
        match self {
            Self::Accessibility => Some(config::MACOS_SETTINGS_ACCESSIBILITY_URL),
            Self::InputMonitoring => Some(config::MACOS_SETTINGS_INPUT_MONITORING_URL),
            Self::ScreenRecording => Some(config::MACOS_SETTINGS_SCREEN_RECORDING_URL),
            Self::Camera => Some(config::MACOS_SETTINGS_CAMERA_URL),
            Self::LocalNetwork => Some(config::MACOS_SETTINGS_LOCAL_NETWORK_URL),
            Self::FileSharing => Some(config::MACOS_SETTINGS_FILE_SHARING_URL),
            Self::Firewall => Some(config::WINDOWS_SETTINGS_FIREWALL_URL),
            Self::NetworkProfile => Some(config::WINDOWS_SETTINGS_NETWORK_STATUS_URL),
            Self::CameraPrivacy => Some(config::WINDOWS_SETTINGS_CAMERA_PRIVACY_URL),
            Self::SmbServer => Some(config::WINDOWS_SETTINGS_ADVANCED_SHARING_URL),
            Self::AdminElevation => None,
        }
    }
}

impl fmt::Display for PermissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed allowlist of companion tool and driver dependency identifiers.
///
/// All incoming RPC parameters for `"install_dependency"` are validated against this enum
/// so arbitrary commands or URLs can never be executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyId {
    /// Sunshine (or Apollo) hardware-accelerated display streaming host.
    Sunshine,
    /// Moonlight hardware-accelerated display streaming client.
    Moonlight,
    /// Windows Virtual Display Driver (`IddSampleDriver` / `MttVDD` / `VddCtl.exe`).
    Vdd,
    /// Apple USB-C CDC-NCM Direct-Link Bridge & Watchdog (`Install-AppleUsbNcm.ps1` / `install-macos.sh`).
    UsbNcm,
    /// Windows 11 Media Foundation Virtual Camera COM Server (`integrator_vcam.dll`).
    Vcam,
}

impl DependencyId {
    /// Strictly parses a dependency identifier string against the canonical allowlist.
    ///
    /// Rejects unknown identifiers, empty strings, control characters, URLs, and shell metacharacters.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.chars().any(|c| c.is_control()) {
            return Err("Invalid dependency identifier".to_string());
        }
        match raw.trim() {
            "sunshine" => Ok(Self::Sunshine),
            "moonlight" => Ok(Self::Moonlight),
            "vdd" => Ok(Self::Vdd),
            "usb_ncm" => Ok(Self::UsbNcm),
            "vcam" => Ok(Self::Vcam),
            other => Err(format!("Unsupported or unknown dependency ID: '{}'", other)),
        }
    }

    /// Returns the canonical wire string identifier for this dependency.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sunshine => "sunshine",
            Self::Moonlight => "moonlight",
            Self::Vdd => "vdd",
            Self::UsbNcm => "usb_ncm",
            Self::Vcam => "vcam",
        }
    }

    /// Returns the official compile-time fallback download/documentation URL for this dependency.
    pub const fn download_url(self) -> &'static str {
        match self {
            Self::Sunshine => config::SUNSHINE_DOWNLOAD_URL,
            Self::Moonlight => config::MOONLIGHT_DOWNLOAD_URL,
            Self::Vdd => config::VDD_DOWNLOAD_URL,
            Self::UsbNcm => config::USBNCM_GUIDE_URL,
            Self::Vcam => config::SUNSHINE_DOWNLOAD_URL,
        }
    }
}

impl fmt::Display for DependencyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// Serializable Data Models (`PermissionStatus`, `DependencyStatus`, `SetupHealthSnapshot`)
// ============================================================================

/// Status record for an individual operating system permission or security prerequisite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PermissionStatus {
    /// Canonical allowlisted identifier (e.g. `"accessibility"`, `"firewall"`).
    #[serde(default)]
    pub id: String,
    /// Human-readable permission title displayed in UI cards and sheets.
    #[serde(default)]
    pub title: String,
    /// Concise explanation of why Integrator uses this permission.
    #[serde(default)]
    pub description: String,
    /// `true` if the permission or prerequisite is currently satisfied/granted.
    #[serde(default)]
    pub granted: bool,
    /// `true` if missing this permission should trigger the launch Setup Assistant prompt.
    #[serde(default)]
    pub required: bool,
    /// `true` if Integrator can trigger an interactive OS dialog or automated fix directly.
    #[serde(default)]
    pub can_request_directly: bool,
    /// Optional deep-link URI to the corresponding OS System Settings pane.
    #[serde(default)]
    pub settings_url: Option<String>,
    /// Live diagnostic detail string describing current status or next steps.
    #[serde(default)]
    pub detail: String,
}

/// Status record for a required or optional companion tool or driver dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DependencyStatus {
    /// Canonical allowlisted identifier (`"sunshine"`, `"moonlight"`, `"vdd"`, `"usb_ncm"`, `"vcam"`).
    #[serde(default)]
    pub id: String,
    /// Human-readable name of the tool or driver.
    #[serde(default)]
    pub name: String,
    /// Concise explanation of what subsystem relies on this dependency.
    #[serde(default)]
    pub description: String,
    /// `true` if the binary, driver, or service is detected on disk / in the OS registry.
    #[serde(default)]
    pub installed: bool,
    /// Optional runtime state indicating whether the background service/daemon is currently active.
    #[serde(default)]
    pub running: Option<bool>,
    /// `true` if missing this dependency should trigger the launch Setup Assistant prompt.
    #[serde(default)]
    pub required: bool,
    /// Resolved filesystem path or registry location where the dependency was detected.
    #[serde(default)]
    pub detected_path: Option<String>,
    /// Primary installation mechanism label (e.g. `"Homebrew"`, `"WinGet"`, `"PowerShell Installer"`, `"GitHub Release"`).
    #[serde(default)]
    pub install_method: String,
    /// Copyable CLI installation command shown to the user.
    #[serde(default)]
    pub install_command: String,
    /// Official download or documentation URL opened when automated package managers are unavailable.
    #[serde(default)]
    pub download_url: String,
    /// `true` if clicking Install can launch a guided package manager, script, or download automatically.
    #[serde(default)]
    pub can_auto_install: bool,
}

/// Aggregate cross-platform permissions and dependencies health snapshot sent to native UI frontends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SetupHealthSnapshot {
    /// Operating system identifier (`"macos"`, `"windows"`).
    #[serde(default)]
    pub os: String,
    /// `true` if the current process holds Administrator / root privileges.
    #[serde(default)]
    pub is_elevated: bool,
    /// `true` if at least one required permission or required dependency is missing.
    #[serde(default)]
    pub needs_attention: bool,
    /// Count of permissions with `required == true && !granted`.
    #[serde(default)]
    pub missing_required_permissions: usize,
    /// Count of dependencies with `required == true && !installed`.
    #[serde(default)]
    pub missing_required_dependencies: usize,
    /// User-persisted preference (`AppPathPreferences.suppress_launch_setup_prompt`) suppressing automatic launch popups.
    #[serde(default)]
    pub suppress_launch_prompt: bool,
    /// Audited operating system permissions for the local platform.
    #[serde(default)]
    pub permissions: Vec<PermissionStatus>,
    /// Audited companion tools and drivers for the local platform.
    #[serde(default)]
    pub dependencies: Vec<DependencyStatus>,
}

impl SetupHealthSnapshot {
    /// Constructs a [`SetupHealthSnapshot`] and computes missing counts and `needs_attention` deterministically.
    pub fn from_parts(
        os: String,
        is_elevated: bool,
        suppress_launch_prompt: bool,
        permissions: Vec<PermissionStatus>,
        dependencies: Vec<DependencyStatus>,
    ) -> Self {
        let missing_required_permissions = permissions
            .iter()
            .filter(|p| p.required && !p.granted)
            .count();
        let missing_required_dependencies = dependencies
            .iter()
            .filter(|d| d.required && !d.installed)
            .count();
        let needs_attention =
            missing_required_permissions > 0 || missing_required_dependencies > 0;
        Self {
            os,
            is_elevated,
            needs_attention,
            missing_required_permissions,
            missing_required_dependencies,
            suppress_launch_prompt,
            permissions,
            dependencies,
        }
    }
}

// ============================================================================
// Subprocess Probe Cache (`SETUP_CACHE`)
// ============================================================================

/// Cached results of expensive OS subprocess probes with a [`SETUP_PROBE_CACHE_TTL`] lifetime.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct CachedSubprocessProbes {
    /// Whether the current process token is elevated.
    is_elevated: bool,
    /// Cached platform-specific non-FFI permission statuses (or supplementary probe flags).
    mac_file_sharing_granted: bool,
    mac_file_sharing_detail: String,
    win_permissions: Vec<PermissionStatus>,
    /// Cached companion dependencies list.
    dependencies: Vec<DependencyStatus>,
}

/// Global mutex holding the timestamped [`CachedSubprocessProbes`].
static SETUP_CACHE: OnceLock<Mutex<Option<(Instant, CachedSubprocessProbes)>>> = OnceLock::new();

/// Returns a reference to the global setup probe cache mutex.
fn setup_cache_lock() -> &'static Mutex<Option<(Instant, CachedSubprocessProbes)>> {
    SETUP_CACHE.get_or_init(|| Mutex::new(None))
}

/// Immediately invalidates the cached setup probe state so the next query performs a fresh OS audit.
pub fn invalidate_setup_cache() {
    if let Ok(mut guard) = setup_cache_lock().lock() {
        *guard = None;
    }
}

/// Spawns a child process and detaches a background thread to reap its exit status cleanly.
fn spawn_and_reap_setup(mut cmd: Command, label: &'static str) -> std::io::Result<()> {
    let mut child = cmd.spawn()?;
    let _ = std::thread::Builder::new()
        .name(format!("setup-reap-{}", label))
        .spawn(move || {
            let _ = child.wait();
        });
    Ok(())
}

/// Creates a windowless `Command` on Windows (`CREATE_NO_WINDOW`).
#[cfg(target_os = "windows")]
fn win_hidden_cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

// ============================================================================
// Pure Output Parsers (Cross-Platform Unit-Testable)
// ============================================================================

/// Parses `netsh advfirewall firewall show rule name=... verbose` output to verify that a rule
/// exists, is enabled (`Enabled: Yes`), allows inbound traffic (`Action: Allow`), and covers all
/// required `ports`.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_netsh_firewall_rule_ok(
    netsh_output: &str,
    required_ports: &[u16],
) -> bool {
    let lower = netsh_output.to_ascii_lowercase();
    if lower.trim().is_empty()
        || lower.contains("no rules match")
        || !lower.contains("allow")
    {
        return false;
    }
    let enabled_ok = lower.lines().any(|line| {
        let t = line.trim();
        t.starts_with("enabled:") && t.contains("yes")
    }) || !lower.contains("enabled:");
    if !enabled_ok {
        return false;
    }
    required_ports
        .iter()
        .all(|port| lower.contains(&port.to_string()))
}

/// Verifies whether all three Integrator Windows Defender Firewall rules (Core TCP, Core UDP, SMB TCP)
/// pass validation from their respective `netsh` outputs.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_firewall_all_rules_ok(
    tcp_rule_out: &str,
    udp_rule_out: &str,
    smb_rule_out: &str,
) -> bool {
    parse_windows_netsh_firewall_rule_ok(tcp_rule_out, &config::TCP_SERVICE_PORTS)
        && parse_windows_netsh_firewall_rule_ok(udp_rule_out, &config::UDP_SERVICE_PORTS)
        && parse_windows_netsh_firewall_rule_ok(smb_rule_out, &config::SMB_SERVICE_PORTS)
}

/// Parses `sc.exe query <ServiceName>` output to determine whether a Windows service is in the `RUNNING` state.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_sc_query_running(sc_output: &str) -> bool {
    for line in sc_output.lines() {
        let upper = line.trim().to_ascii_uppercase();
        if upper.starts_with("STATE") && upper.contains("RUNNING") {
            return true;
        }
    }
    false
}

/// Parses `reg.exe query HKCU\...\ConsentStore\webcam` output to determine whether camera access is allowed.
///
/// Returns `false` if any queried `Value` line explicitly states `Deny`; returns `true` if `Allow` is present.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_camera_consent_reg(reg_output: &str) -> bool {
    let mut saw_allow = false;
    for line in reg_output.lines() {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("value") && lower.contains("reg_sz") {
            if lower.ends_with(WINDOWS_CONSENT_DENY_TOKEN) {
                return false;
            }
            if lower.ends_with(WINDOWS_CONSENT_ALLOW_TOKEN) {
                saw_allow = true;
            }
        }
    }
    saw_allow
}

/// Parses `reg.exe query HKCR\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912} /s` output to determine
/// whether the Windows 11 Virtual Camera COM server is registered and extracts its DLL path if present.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_vcam_clsid_reg(reg_output: &str) -> (bool, Option<String>) {
    let lower = reg_output.to_ascii_lowercase();
    let clsid_lower = config::WINDOWS_VCAM_CLSID.to_ascii_lowercase();
    if !lower.contains(&clsid_lower) {
        return (false, None);
    }
    for line in reg_output.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find("REG_SZ") {
            let val = trimmed[pos + 6..].trim();
            if val
                .to_ascii_lowercase()
                .ends_with(config::WINDOWS_VCAM_DLL_FILENAME)
            {
                return (true, Some(val.to_string()));
            }
        }
    }
    (true, None)
}

/// Parses PowerShell `Get-NetConnectionProfile` pipe-delimited output (`Name|InterfaceAlias|NetworkCategory`).
///
/// Returns `(all_private_or_domain, profiles_list)` where `all_private_or_domain` is `true` when at least
/// one profile exists and no active profile is set to `Public`.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_net_connection_profiles(
    ps_output: &str,
) -> (bool, Vec<(String, String)>) {
    let mut profiles = Vec::new();
    let mut has_public = false;
    for line in ps_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            let alias = if !parts[1].is_empty() {
                parts[1].to_string()
            } else {
                parts[0].to_string()
            };
            let category = parts[2].to_string();
            if category.eq_ignore_ascii_case("Public") {
                has_public = true;
            }
            profiles.push((alias, category));
        }
    }
    let all_ok = !profiles.is_empty() && !has_public;
    (all_ok, profiles)
}

/// Parses PowerShell `Get-PnpDevice -Class Display` pipe-delimited output (`InstanceId|FriendlyName|Name|Status`)
/// to detect whether a Virtual Display Driver (IddSampleDriver, MttVDD, Virtual Display Driver, Apollo) is installed.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_vdd_pnp_output(ps_output: &str) -> Option<(String, bool)> {
    for line in ps_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').map(|s| s.trim()).collect();
        if parts.len() < 4 {
            continue;
        }
        let instance_id = parts[0];
        let friendly = parts[1];
        let name = parts[2];
        let status = parts[3];
        let combined = format!("{} {} {}", instance_id, friendly, name).to_ascii_lowercase();
        if combined.contains("basicdisplay") || combined.contains("microsoft basic display") {
            continue;
        }
        let is_vdd = combined.contains("iddsampledriver")
            || combined.contains("virtual display")
            || combined.contains("mttvdd")
            || combined.contains("vdd")
            || combined.contains("apollo")
            || combined.contains("amyuni")
            || combined.contains("parsec virtual")
            || instance_id.to_ascii_uppercase().starts_with(r"ROOT\DISPLAY\");
        if is_vdd {
            let label = if !friendly.is_empty() {
                friendly.to_string()
            } else if !name.is_empty() {
                name.to_string()
            } else {
                instance_id.to_string()
            };
            let is_ok = status.eq_ignore_ascii_case("OK");
            return Some((format!("{} ({})", label, instance_id), is_ok));
        }
    }
    None
}

/// Parses macOS `sharing -l -f json` or plain-text `sharing -l` output to determine whether at least
/// one SMB shared folder (`smb_shared == 1` or `shared: 1`) is actively published.
#[allow(dead_code)]
pub(crate) fn parse_macos_sharing_active(sharing_output: &str) -> (bool, Vec<String>) {
    let trimmed = sharing_output.trim();
    if trimmed.is_empty() {
        return (false, Vec::new());
    }
    let mut shares = Vec::new();
    if trimmed.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = val.as_object() {
                for (label, item) in obj {
                    let smb_shared = item
                        .get("smb_shared")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        == 1;
                    if smb_shared {
                        let name = item
                            .get("smb_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(label.as_str())
                            .trim();
                        if !name.is_empty() && !shares.contains(&name.to_string()) {
                            shares.push(name.to_string());
                        }
                    }
                }
                return (!shares.is_empty(), shares);
            }
        }
    }

    let mut current_name: Option<String> = None;
    let mut current_shared = false;
    for line in trimmed.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("name:") {
            if let Some(prev) = current_name.take() {
                if current_shared && !shares.contains(&prev) {
                    shares.push(prev);
                }
            }
            let n = rest.trim().to_string();
            current_name = if n.is_empty() { None } else { Some(n) };
            current_shared = false;
        } else if t.starts_with("shared:") || t.starts_with("smb_shared:") {
            current_shared = t.contains('1') || t.to_ascii_lowercase().contains("true");
        }
    }
    if let Some(last) = current_name {
        if current_shared && !shares.contains(&last) {
            shares.push(last);
        }
    }
    (!shares.is_empty(), shares)
}

/// Validates whether a macOS LaunchDaemon plist content string defines the `com.integrator.usbncm` watchdog service.
#[allow(dead_code)]
pub(crate) fn parse_macos_usbncm_plist_installed(plist_content: &str) -> bool {
    let trimmed = plist_content.trim();
    trimmed.contains("<plist")
        && (trimmed.contains("com.integrator.usbncm")
            || trimmed.contains("apple-usb-ncm-watchdog.sh"))
}

// ============================================================================
// Runtime Privilege, Port, and Package Manager Probes
// ============================================================================

/// Returns `true` if the current process holds root (macOS/Unix) or Administrator (Windows) privileges.
pub fn is_current_process_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is an async-signal-safe POSIX syscall taking no arguments.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        struct TokenElevation {
            token_is_elevated: u32,
        }

        #[link(name = "advapi32")]
        extern "system" {
            fn OpenProcessToken(
                process_handle: *mut std::ffi::c_void,
                desired_access: u32,
                token_handle: *mut *mut std::ffi::c_void,
            ) -> i32;
            fn GetTokenInformation(
                token_handle: *mut std::ffi::c_void,
                token_information_class: u32,
                token_information: *mut std::ffi::c_void,
                token_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ELEVATION_CLASS: u32 = 20;

        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: Queries current process handle and opens a read-only query token handle.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 || token.is_null() {
            return false;
        }
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut ret_len: u32 = 0;
        // SAFETY: Passes valid stack buffer sized to `TokenElevation` and closes `token` handle.
        let ok = unsafe {
            let res = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                (&mut elevation as *mut TokenElevation).cast::<std::ffi::c_void>(),
                std::mem::size_of::<TokenElevation>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            res
        };
        ok != 0 && elevation.token_is_elevated != 0
    }
    #[cfg(all(not(unix), not(target_os = "windows")))]
    {
        false
    }
}

/// Checks if a local TCP port is actively accepting connections on `127.0.0.1`.
fn is_local_tcp_port_open(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&addr, LOCAL_PORT_PROBE_TIMEOUT).is_ok()
}

/// Locates the Homebrew executable (`brew`) on macOS in standard Apple Silicon, Intel, or `PATH` locations.
#[allow(dead_code)]
pub(crate) fn find_homebrew_binary() -> Option<PathBuf> {
    for candidate in [
        config::MACOS_BREW_APPLE_SILICON_BIN,
        config::MACOS_BREW_INTEL_BIN,
    ] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    system_info::find_in_path("brew")
}

/// Locates the WinGet executable (`winget.exe`) on Windows in `%LOCALAPPDATA%\Microsoft\WindowsApps` or `PATH`.
#[cfg(target_os = "windows")]
fn find_winget_binary() -> Option<PathBuf> {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let candidate = PathBuf::from(local_app_data).join(WINDOWS_WINGET_LOCALAPPDATA_REL_PATH);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    system_info::find_in_path("winget.exe")
}

/// Locates a repository or bundle helper script (such as `macos/install-macos.sh` or `windows\Install-AppleUsbNcm.ps1`).
fn find_bundled_script(rel_path: &str) -> Option<PathBuf> {
    if let Some(p) = system_info::find_app_helper(rel_path) {
        return Some(p);
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().skip(1).take(5) {
            candidates.push(ancestor.join(rel_path));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors().take(4) {
            candidates.push(ancestor.join(rel_path));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

// ============================================================================
// Platform Probes: macOS & Windows Permissions + Dependencies
// ============================================================================

/// Queries whether macOS SMB file sharing is actively publishing at least one SMB share.
#[cfg(target_os = "macos")]
fn probe_macos_file_sharing() -> (bool, String) {
    let sharing_bin = if Path::new(config::MACOS_SHARING_BIN).exists() {
        config::MACOS_SHARING_BIN
    } else {
        MACOS_SHARING_FALLBACK_BIN
    };

    if let Ok(out) = Command::new(sharing_bin)
        .args(["-l", "-f", "json"])
        .output()
    {
        if out.status.success() {
            let (active, shares) =
                parse_macos_sharing_active(&String::from_utf8_lossy(&out.stdout));
            if active {
                return (
                    true,
                    format!("Active — Publishing SMB shares: {}", shares.join(", ")),
                );
            }
        }
    }
    if let Ok(out) = Command::new(sharing_bin).arg("-l").output() {
        if out.status.success() {
            let (active, shares) =
                parse_macos_sharing_active(&String::from_utf8_lossy(&out.stdout));
            if active {
                return (
                    true,
                    format!("Active — Publishing SMB shares: {}", shares.join(", ")),
                );
            }
        }
    }
    (
        false,
        "Optional — Enable File Sharing in System Settings > General > Sharing to expose Mac folders over SMB".to_string(),
    )
}

#[cfg(not(target_os = "macos"))]
fn probe_macos_file_sharing() -> (bool, String) {
    (false, String::new())
}

/// Checks whether a named process is running on macOS via `/usr/bin/pgrep`.
#[cfg(target_os = "macos")]
fn is_macos_process_running(proc_name: &str) -> bool {
    Command::new(config::MACOS_PGREP_BIN)
        .args(["-i", proc_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks whether a process image is running on Windows via `tasklist.exe`.
#[cfg(target_os = "windows")]
fn is_windows_process_running(image_name: &str) -> bool {
    let filter = format!("IMAGENAME eq {}", image_name);
    win_hidden_cmd(system_info::system32_exe("tasklist.exe"))
        .args(["/FI", &filter, "/NH"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_ascii_lowercase()
                .contains(&image_name.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

/// Audits all 5 Windows permissions (`firewall`, `network_profile`, `camera_privacy`, `smb_server`, `admin_elevation`).
#[cfg(target_os = "windows")]
fn probe_windows_permissions_uncached(is_elevated: bool) -> Vec<PermissionStatus> {
    let netsh = system_info::system32_exe("netsh.exe");
    let query_rule = |rule_name: &str| -> String {
        win_hidden_cmd(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", rule_name),
                "verbose",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };

    let tcp_out = query_rule(config::WIN_FW_RULE_CORE_TCP);
    let udp_out = query_rule(config::WIN_FW_RULE_CORE_UDP);
    let smb_out = query_rule(config::WIN_FW_RULE_SMB_TCP);
    let fw_granted = parse_windows_firewall_all_rules_ok(&tcp_out, &udp_out, &smb_out);
    let fw_detail = if fw_granted {
        "Granted — Inbound Defender Firewall rules active for Integrator TCP, UDP, and SMB ports"
            .to_string()
    } else {
        "Missing — Click Fix / Request to configure Windows Defender Firewall rules (requests UAC elevation if needed)".to_string()
    };

    // 2. Network Profile Category (Get-NetConnectionProfile)
    let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
    let net_prof_out = win_hidden_cmd(&ps_exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.Name)|$($_.InterfaceAlias)|$($_.NetworkCategory)\" }",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let (net_prof_ok, profiles) = parse_windows_net_connection_profiles(&net_prof_out);
    let net_prof_detail = if profiles.is_empty() {
        "No active network connection profile reported".to_string()
    } else if net_prof_ok {
        let summary: Vec<String> = profiles
            .iter()
            .map(|(alias, cat)| format!("{} ({})", alias, cat))
            .collect();
        format!("Private/Trusted profile active: {}", summary.join(", "))
    } else {
        let pub_list: Vec<String> = profiles
            .iter()
            .filter(|(_, cat)| cat.eq_ignore_ascii_case("Public"))
            .map(|(alias, _)| alias.clone())
            .collect();
        format!(
            "Advisory — Public network profile on [{}]; switch to Private for seamless LAN discovery & SMB sharing",
            pub_list.join(", ")
        )
    };

    // 3. Camera Privacy (HKCU\...\ConsentStore\webcam)
    let reg_exe = system_info::system32_exe("reg.exe");
    let cam_reg_out = win_hidden_cmd(&reg_exe)
        .args(["query", config::WINDOWS_CAMERA_CONSENT_REG_KEY, "/v", "Value"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let nonpkg_key = format!(
        r"{}\{}",
        config::WINDOWS_CAMERA_CONSENT_REG_KEY,
        WINDOWS_CAMERA_CONSENT_NONPACKAGED_SUBKEY
    );
    let cam_nonpkg_out = win_hidden_cmd(&reg_exe)
        .args(["query", &nonpkg_key, "/v", "Value"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let combined_cam_reg = format!("{}\n{}", cam_reg_out, cam_nonpkg_out);
    let cam_privacy_ok = if combined_cam_reg.trim().is_empty() {
        true
    } else {
        parse_windows_camera_consent_reg(&combined_cam_reg)
    };
    let cam_privacy_detail = if cam_privacy_ok {
        "Allowed — Windows desktop & camera apps can access the virtual webcam".to_string()
    } else {
        "Blocked — Enable Camera access in Windows Settings > Privacy & security > Camera"
            .to_string()
    };

    // 4. SMB Server (sc.exe query LanmanServer)
    let sc_exe = system_info::system32_exe("sc.exe");
    let smb_sc_out = win_hidden_cmd(&sc_exe)
        .args(["query", config::WINDOWS_LANMAN_SERVER_SERVICE])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let smb_running = parse_windows_sc_query_running(&smb_sc_out);
    let smb_detail = if smb_running {
        "Running — Windows LanmanServer SMB service is active".to_string()
    } else {
        "Stopped — Click Fix or enable File and Printer Sharing in Advanced Network Settings"
            .to_string()
    };

    // 5. Admin Elevation (informational)
    let admin_detail = if is_elevated {
        "Elevated — Running with Administrator privileges".to_string()
    } else {
        "Standard User — UAC elevation is requested on-demand only when fixing firewall rules or installing drivers".to_string()
    };

    vec![
        PermissionStatus {
            id: PermissionId::Firewall.as_str().to_string(),
            title: "Windows Defender Firewall Rules".to_string(),
            description: "Permits inbound Integrator TCP (58281–58287), UDP (58280, 58284), and SMB ports across local & direct-cable subnets.".to_string(),
            granted: fw_granted,
            required: true,
            can_request_directly: true,
            settings_url: PermissionId::Firewall.settings_url().map(str::to_string),
            detail: fw_detail,
        },
        PermissionStatus {
            id: PermissionId::NetworkProfile.as_str().to_string(),
            title: "Active Network Profile Category".to_string(),
            description: "Private network profile ensures Windows allows mDNS/UDP discovery and local SMB file sharing.".to_string(),
            granted: net_prof_ok,
            required: false,
            can_request_directly: true,
            settings_url: PermissionId::NetworkProfile.settings_url().map(str::to_string),
            detail: net_prof_detail,
        },
        PermissionStatus {
            id: PermissionId::CameraPrivacy.as_str().to_string(),
            title: "Windows Camera Privacy Consent".to_string(),
            description: "Allows Teams, Zoom, OBS, and desktop apps to use the Integrator Mac Camera virtual webcam.".to_string(),
            granted: cam_privacy_ok,
            required: false,
            can_request_directly: false,
            settings_url: PermissionId::CameraPrivacy.settings_url().map(str::to_string),
            detail: cam_privacy_detail,
        },
        PermissionStatus {
            id: PermissionId::SmbServer.as_str().to_string(),
            title: "Windows SMB Server (LanmanServer)".to_string(),
            description: "Required for sharing local Windows folders so your paired Mac can auto-mount them over SMB.".to_string(),
            granted: smb_running,
            required: false,
            can_request_directly: true,
            settings_url: PermissionId::SmbServer.settings_url().map(str::to_string),
            detail: smb_detail,
        },
        PermissionStatus {
            id: PermissionId::AdminElevation.as_str().to_string(),
            title: "Administrator Elevation (On-Demand)".to_string(),
            description: "Informational token status. Integrator runs safely without always-Admin privileges.".to_string(),
            granted: is_elevated,
            required: false,
            can_request_directly: false,
            settings_url: None,
            detail: admin_detail,
        },
    ]
}

#[cfg(not(target_os = "windows"))]
fn probe_windows_permissions_uncached(_is_elevated: bool) -> Vec<PermissionStatus> {
    Vec::new()
}

/// Audits companion dependencies (`sunshine`, `moonlight`, and platform-specific drivers) on the local machine.
fn probe_dependencies_uncached() -> Vec<DependencyStatus> {
    let mut deps = Vec::new();

    // 1. Sunshine (or Apollo) Streaming Host
    let sunshine_bin = system_info::find_sunshine_binary();
    let (_, sunshine_cfg_port, _) = system_info::read_sunshine_config_info();
    let sunshine_port_open = is_local_tcp_port_open(sunshine_cfg_port)
        || is_local_tcp_port_open(config::SUNSHINE_DEFAULT_PORT)
        || is_local_tcp_port_open(config::SUNSHINE_DEFAULT_WEB_PORT)
        || is_local_tcp_port_open(config::SUNSHINE_SECONDARY_PORT);

    #[cfg(target_os = "macos")]
    let (sunshine_running, sunshine_method, sunshine_cmd) = {
        let proc_up = sunshine_port_open || is_macos_process_running("sunshine");
        let method = if find_homebrew_binary().is_some() {
            "Homebrew"
        } else {
            "GitHub Release"
        };
        (
            proc_up,
            method.to_string(),
            config::BREW_INSTALL_SUNSHINE_CMD.to_string(),
        )
    };

    #[cfg(target_os = "windows")]
    let (sunshine_running, sunshine_method, sunshine_cmd) = {
        let proc_up = sunshine_port_open || is_windows_process_running("sunshine.exe");
        let method = if find_winget_binary().is_some() {
            "WinGet"
        } else {
            "GitHub Release"
        };
        (
            proc_up,
            method.to_string(),
            config::WINGET_INSTALL_SUNSHINE_CMD.to_string(),
        )
    };

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let (sunshine_running, sunshine_method, sunshine_cmd) = (
        sunshine_port_open,
        "GitHub Release".to_string(),
        config::BREW_INSTALL_SUNSHINE_CMD.to_string(),
    );

    let sunshine_installed = sunshine_bin.is_some() || sunshine_running;
    deps.push(DependencyStatus {
        id: DependencyId::Sunshine.as_str().to_string(),
        name: "Sunshine / Apollo Display Host".to_string(),
        description: "Hardware-accelerated low-latency video encoder host (VideoToolbox on Mac; NVENC/AMF/QuickSync on Windows) for screen extension.".to_string(),
        installed: sunshine_installed,
        running: Some(sunshine_running),
        required: true,
        detected_path: sunshine_bin.map(|p| p.to_string_lossy().into_owned()),
        install_method: sunshine_method,
        install_command: sunshine_cmd,
        download_url: DependencyId::Sunshine.download_url().to_string(),
        can_auto_install: true,
    });

    // 2. Moonlight Streaming Client
    let moonlight_bin = system_info::find_moonlight_binary();
    #[cfg(target_os = "macos")]
    let (moonlight_running, moonlight_method, moonlight_cmd) = {
        let proc_up = is_macos_process_running("Moonlight");
        let method = if find_homebrew_binary().is_some() {
            "Homebrew"
        } else {
            "GitHub Release"
        };
        (
            proc_up,
            method.to_string(),
            config::BREW_INSTALL_MOONLIGHT_CMD.to_string(),
        )
    };

    #[cfg(target_os = "windows")]
    let (moonlight_running, moonlight_method, moonlight_cmd) = {
        let proc_up = is_windows_process_running("Moonlight.exe");
        let method = if find_winget_binary().is_some() {
            "WinGet"
        } else {
            "GitHub Release"
        };
        (
            proc_up,
            method.to_string(),
            config::WINGET_INSTALL_MOONLIGHT_CMD.to_string(),
        )
    };

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let (moonlight_running, moonlight_method, moonlight_cmd) = (
        false,
        "GitHub Release".to_string(),
        config::BREW_INSTALL_MOONLIGHT_CMD.to_string(),
    );

    deps.push(DependencyStatus {
        id: DependencyId::Moonlight.as_str().to_string(),
        name: "Moonlight Streaming Client".to_string(),
        description: "Hardware-accelerated low-latency stream viewer rendering extended displays at up to 4K 120Hz/240Hz.".to_string(),
        installed: moonlight_bin.is_some(),
        running: Some(moonlight_running),
        required: true,
        detected_path: moonlight_bin.map(|p| p.to_string_lossy().into_owned()),
        install_method: moonlight_method,
        install_command: moonlight_cmd,
        download_url: DependencyId::Moonlight.download_url().to_string(),
        can_auto_install: true,
    });

    // 3. macOS USB-C NCM Direct-Link LaunchDaemon Watchdog
    #[cfg(target_os = "macos")]
    {
        let plist_path = Path::new(config::MACOS_USBNCM_PLIST_PATH);
        let watchdog_path = Path::new(config::MACOS_USBNCM_WATCHDOG_PATH);
        let plist_ok = std::fs::read_to_string(plist_path)
            .map(|c| parse_macos_usbncm_plist_installed(&c))
            .unwrap_or_else(|_| plist_path.is_file());
        let installed = plist_ok && watchdog_path.is_file();
        let script_path = find_bundled_script(config::MACOS_INSTALL_SCRIPT_REL_PATH);
        let cmd_str = script_path
            .as_ref()
            .map(|p| format!("sudo bash \"{}\"", p.display()))
            .unwrap_or_else(|| MACOS_USBNCM_DEFAULT_INSTALL_CMD.to_string());
        deps.push(DependencyStatus {
            id: DependencyId::UsbNcm.as_str().to_string(),
            name: "Apple USB-C NCM Direct-Link Watchdog".to_string(),
            description: "Zero-polling event-driven LaunchDaemon that auto-configures 10.99.99.2/24 over any direct Mac-to-PC USB-C cable.".to_string(),
            installed,
            running: Some(installed),
            required: false,
            detected_path: if installed {
                Some(config::MACOS_USBNCM_PLIST_PATH.to_string())
            } else {
                script_path.map(|p| p.to_string_lossy().into_owned())
            },
            install_method: "Guided Terminal Script".to_string(),
            install_command: cmd_str,
            download_url: DependencyId::UsbNcm.download_url().to_string(),
            can_auto_install: true,
        });
    }

    // 3–5. Windows Drivers: Virtual Display Driver (VDD), Apple USB-C NCM Bridge, Virtual Camera COM DLL
    #[cfg(target_os = "windows")]
    {
        // 3. Windows Virtual Display Driver (IddSampleDriver / VDD / VddCtl)
        let sys_drive = system_info::windows_system_drive();
        let vdd_ctl_primary = PathBuf::from(&sys_drive).join(config::VDD_CTL_REL_PATH);
        let vdd_ctl_path = if vdd_ctl_primary.is_file() {
            Some(vdd_ctl_primary)
        } else {
            ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
                .iter()
                .filter_map(|k| std::env::var(k).ok())
                .map(|base| PathBuf::from(base).join(config::VDD_CTL_REL_PATH))
                .find(|p| p.is_file())
        };
        let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
        let pnp_out = win_hidden_cmd(&ps_exe)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.InstanceId)|$($_.FriendlyName)|$($_.Name)|$($_.Status)\" }",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let pnp_vdd = parse_windows_vdd_pnp_output(&pnp_out);
        let vdd_installed = vdd_ctl_path.is_some() || pnp_vdd.is_some();
        let vdd_running = pnp_vdd
            .as_ref()
            .map(|(_, ok)| *ok)
            .or_else(|| vdd_ctl_path.as_ref().map(|_| true));
        let vdd_detected = vdd_ctl_path
            .map(|p| p.to_string_lossy().into_owned())
            .or_else(|| pnp_vdd.map(|(label, _)| label));

        deps.push(DependencyStatus {
            id: DependencyId::Vdd.as_str().to_string(),
            name: "Windows Virtual Display Driver (VDD)".to_string(),
            description: "Creates virtual high-refresh-rate monitors on Windows when extending your PC desktop to a Mac.".to_string(),
            installed: vdd_installed,
            running: vdd_running,
            required: false,
            detected_path: vdd_detected,
            install_method: "GitHub Release Installer".to_string(),
            install_command: WINDOWS_VDD_INSTALL_CMD.to_string(),
            download_url: DependencyId::Vdd.download_url().to_string(),
            can_auto_install: true,
        });

        // 4. Windows Apple USB-C NCM Direct-Link Bridge (Scheduled Task + wintun.dll)
        let schtasks = system_info::system32_exe("schtasks.exe");
        let ncm_task_ok = win_hidden_cmd(&schtasks)
            .args(["/Query", "/TN", config::WINDOWS_USBNCM_TASK_NAME])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let prog_data = std::env::var("ProgramData")
            .unwrap_or_else(|_| format!(r"{}\ProgramData", sys_drive));
        let wintun_path = PathBuf::from(&prog_data)
            .join(config::WINDOWS_USBNCM_PROGRAMDATA_SUBDIR)
            .join(config::WINDOWS_WINTUN_DLL_FILENAME);
        let ncm_installed = ncm_task_ok && wintun_path.is_file();
        let ps_script = find_bundled_script(config::WINDOWS_INSTALL_USBNCM_REL_PATH);
        let ncm_cmd = ps_script
            .as_ref()
            .map(|p| {
                format!(
                    "powershell -ExecutionPolicy Bypass -File \"{}\"",
                    p.display()
                )
            })
            .unwrap_or_else(|| WINDOWS_USBNCM_DEFAULT_INSTALL_CMD.to_string());

        deps.push(DependencyStatus {
            id: DependencyId::UsbNcm.as_str().to_string(),
            name: "Apple USB-C NCM Direct-Link Bridge".to_string(),
            description: "Installs the signed WinUSB driver for Apple Silicon USB-C CDC-NCM (VID_05AC&PID_1902) and zero-polling WinTun bridge.".to_string(),
            installed: ncm_installed,
            running: Some(ncm_task_ok),
            required: false,
            detected_path: if ncm_installed {
                Some(wintun_path.to_string_lossy().into_owned())
            } else {
                ps_script.map(|p| p.to_string_lossy().into_owned())
            },
            install_method: "Elevated PowerShell Installer".to_string(),
            install_command: ncm_cmd,
            download_url: DependencyId::UsbNcm.download_url().to_string(),
            can_auto_install: true,
        });

        // 5. Windows 11 Virtual Camera COM Driver (integrator_vcam.dll)
        let reg_exe = system_info::system32_exe("reg.exe");
        let vcam_reg_out = win_hidden_cmd(&reg_exe)
            .args(["query", config::WINDOWS_VCAM_HKCR_CLSID_KEY, "/s"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_else(|| {
                win_hidden_cmd(&reg_exe)
                    .args(["query", config::WINDOWS_VCAM_HKLM_CLSID_KEY, "/s"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                    .unwrap_or_default()
            });
        let (vcam_registered, reg_dll_path) = parse_windows_vcam_clsid_reg(&vcam_reg_out);
        let bundled_dll = find_windows_vcam_dll();
        let vcam_detected = reg_dll_path
            .or_else(|| bundled_dll.as_ref().map(|p| p.to_string_lossy().into_owned()));
        let vcam_cmd = bundled_dll
            .as_ref()
            .map(|p| format!("regsvr32 /s \"{}\"", p.display()))
            .unwrap_or_else(|| WINDOWS_VCAM_DEFAULT_INSTALL_CMD.to_string());

        deps.push(DependencyStatus {
            id: DependencyId::Vcam.as_str().to_string(),
            name: "Windows 11 Virtual Camera COM Driver".to_string(),
            description: "Standalone Media Foundation FrameServer COM source ('Integrator Mac Camera', CLSID {8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}).".to_string(),
            installed: vcam_registered,
            running: Some(vcam_registered),
            required: false,
            detected_path: vcam_detected,
            install_method: "Elevated COM Registration (regsvr32)".to_string(),
            install_command: vcam_cmd,
            download_url: DependencyId::Vcam.download_url().to_string(),
            can_auto_install: bundled_dll.is_some(),
        });
    }

    deps
}

/// Locates `integrator_vcam.dll` beside the running executable or in `%ProgramFiles%\Integrator`.
#[cfg(target_os = "windows")]
fn find_windows_vcam_dll() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(config::WINDOWS_VCAM_DLL_FILENAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for env_key in ["ProgramFiles", "ProgramW6432"] {
        if let Ok(base) = std::env::var(env_key) {
            let candidate = PathBuf::from(base)
                .join(config::WINDOWS_INTEGRATOR_INSTALL_SUBDIR)
                .join(config::WINDOWS_VCAM_DLL_FILENAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    system_info::find_app_helper(config::WINDOWS_VCAM_DLL_FILENAME)
}

/// Returns cached subprocess probe results or runs a fresh audit if the [`SETUP_PROBE_CACHE_TTL`] has expired.
fn get_or_refresh_cached_probes() -> CachedSubprocessProbes {
    if let Ok(guard) = setup_cache_lock().lock() {
        if let Some((captured_at, ref cached)) = *guard {
            if captured_at.elapsed() < SETUP_PROBE_CACHE_TTL {
                return cached.clone();
            }
        }
    }

    let is_elevated = is_current_process_elevated();
    let (mac_file_sharing_granted, mac_file_sharing_detail) = probe_macos_file_sharing();
    let win_permissions = probe_windows_permissions_uncached(is_elevated);
    let dependencies = probe_dependencies_uncached();

    let probes = CachedSubprocessProbes {
        is_elevated,
        mac_file_sharing_granted,
        mac_file_sharing_detail,
        win_permissions,
        dependencies,
    };

    if let Ok(mut guard) = setup_cache_lock().lock() {
        *guard = Some((Instant::now(), probes.clone()));
    }
    probes
}

/// Collects a complete [`SetupHealthSnapshot`] combining fresh native FFI permission checks
/// with TTL-cached subprocess/driver probes.
///
/// # Arguments
/// * `camera_feature_enabled` - Whether the Shared Camera feature flag is currently enabled.
/// * `peer_discovered` - Whether at least one peer has been discovered over the local network.
pub fn collect_setup_health_snapshot(
    camera_feature_enabled: bool,
    peer_discovered: bool,
) -> SetupHealthSnapshot {
    let prefs = system_info::load_path_preferences();
    let cached = get_or_refresh_cached_probes();

    #[cfg(target_os = "macos")]
    let permissions = {
        let ax_granted = unsafe { integrator_mac_perm_accessibility_granted() };
        let im_granted = unsafe { integrator_mac_perm_input_monitoring_granted() };
        let sr_granted = unsafe { integrator_mac_perm_screen_recording_granted() };
        let cam_status = unsafe { integrator_mac_perm_camera_status() };
        let has_cam_hw = unsafe { integrator_mac_camera_has_hardware() } != 0;
        let cam_granted = cam_status == 2;
        let cam_required = camera_feature_enabled && has_cam_hw;

        let cam_detail = match cam_status {
            2 => "Granted — AVFoundation camera capture authorized".to_string(),
            0 if has_cam_hw => {
                "Not Determined — Click Request to prompt for macOS camera access".to_string()
            }
            0 => "No camera hardware detected on this Mac (optional)".to_string(),
            _ => "Denied/Restricted — Enable Integrator in System Settings > Privacy & Security > Camera".to_string(),
        };

        let local_net_detail = if peer_discovered {
            "Active — Local network peer beacon traffic verified".to_string()
        } else {
            "Advisory — On macOS Sequoia+, ensure Integrator is allowed in System Settings > Privacy & Security > Local Network".to_string()
        };

        vec![
            PermissionStatus {
                id: PermissionId::Accessibility.as_str().to_string(),
                title: "Accessibility (KVM Input Control)".to_string(),
                description: "Required to capture keyboard/mouse screen-edge transitions and inject remote input via Quartz CGEventTap.".to_string(),
                granted: ax_granted,
                required: true,
                can_request_directly: true,
                settings_url: PermissionId::Accessibility.settings_url().map(str::to_string),
                detail: if ax_granted {
                    "Granted — Quartz CGEventTap input hook trusted".to_string()
                } else {
                    "Missing — Click Request or toggle Integrator ON in System Settings > Privacy & Security > Accessibility".to_string()
                },
            },
            PermissionStatus {
                id: PermissionId::InputMonitoring.as_str().to_string(),
                title: "Input Monitoring (Global Event Listen)".to_string(),
                description: "Required by macOS to observe keyboard shortcuts and pointer movement across background apps.".to_string(),
                granted: im_granted,
                required: true,
                can_request_directly: true,
                settings_url: PermissionId::InputMonitoring.settings_url().map(str::to_string),
                detail: if im_granted {
                    "Granted — Global event listen access authorized".to_string()
                } else {
                    "Missing — Click Request or toggle Integrator ON in System Settings > Privacy & Security > Input Monitoring".to_string()
                },
            },
            PermissionStatus {
                id: PermissionId::ScreenRecording.as_str().to_string(),
                title: "Screen Recording (Extended Display Host)".to_string(),
                description: "Required when extending or mirroring a Mac display to Windows via Sunshine & CGVirtualDisplay.".to_string(),
                granted: sr_granted,
                required: true,
                can_request_directly: true,
                settings_url: PermissionId::ScreenRecording.settings_url().map(str::to_string),
                detail: if sr_granted {
                    "Granted — Screen capture access authorized".to_string()
                } else {
                    "Missing — Click Request or toggle Integrator & Sunshine ON in System Settings > Privacy & Security > Screen Recording".to_string()
                },
            },
            PermissionStatus {
                id: PermissionId::Camera.as_str().to_string(),
                title: "Camera (Mac → PC Shared Webcam)".to_string(),
                description: "Streams your Mac FaceTime HD, USB, or Continuity Camera to Windows 11 as a virtual webcam.".to_string(),
                granted: cam_granted,
                required: cam_required,
                can_request_directly: has_cam_hw,
                settings_url: PermissionId::Camera.settings_url().map(str::to_string),
                detail: cam_detail,
            },
            PermissionStatus {
                id: PermissionId::LocalNetwork.as_str().to_string(),
                title: "Local Network (Peer Discovery & Transport)".to_string(),
                description: "macOS Sequoia+ privacy setting allowing UDP discovery and encrypted TCP/UDP streams to your paired PC.".to_string(),
                granted: true,
                required: false,
                can_request_directly: false,
                settings_url: PermissionId::LocalNetwork.settings_url().map(str::to_string),
                detail: local_net_detail,
            },
            PermissionStatus {
                id: PermissionId::FileSharing.as_str().to_string(),
                title: "SMB File Sharing (Shared Storage)".to_string(),
                description: "Optional macOS File Sharing service allowing your paired Windows PC to mount shared Mac folders.".to_string(),
                granted: cached.mac_file_sharing_granted,
                required: false,
                can_request_directly: false,
                settings_url: PermissionId::FileSharing.settings_url().map(str::to_string),
                detail: cached.mac_file_sharing_detail,
            },
        ]
    };

    #[cfg(target_os = "windows")]
    let permissions = {
        let _ = (camera_feature_enabled, peer_discovered);
        cached.win_permissions
    };

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let permissions = {
        let _ = (
            camera_feature_enabled,
            peer_discovered,
            cached.mac_file_sharing_granted,
            cached.mac_file_sharing_detail,
            cached.win_permissions,
        );
        Vec::new()
    };

    SetupHealthSnapshot::from_parts(
        std::env::consts::OS.to_string(),
        cached.is_elevated,
        prefs.suppress_launch_setup_prompt,
        permissions,
        cached.dependencies,
    )
}

// ============================================================================
// Action Handlers: Permissions, Settings Deep-Links, Dependency Installers
// ============================================================================

/// Opens an allowlisted OS System Settings pane (`x-apple.systempreferences:...` on macOS,
/// `ms-settings:...` on Windows) for the specified [`PermissionId`].
pub fn open_permission_settings(raw_id: &str) -> Result<String, String> {
    let perm_id = PermissionId::parse(raw_id)?;
    let url = perm_id
        .settings_url()
        .ok_or_else(|| format!("Permission '{}' does not have a dedicated OS Settings pane", perm_id))?;

    open_allowlisted_uri(url)?;
    invalidate_setup_cache();
    Ok(format!("Opened OS Settings for '{}'", perm_id))
}

/// Opens a compile-time allowlisted URI (`x-apple.systempreferences:`, `ms-settings:`, or `https://`)
/// using the native OS launcher (`/usr/bin/open` on macOS, `explorer.exe` on Windows).
fn open_allowlisted_uri(uri: &'static str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new(config::MACOS_OPEN_BIN);
        cmd.arg(uri);
        spawn_and_reap_setup(cmd, "open-uri")
            .map_err(|e| format!("Failed to launch {}: {}", config::MACOS_OPEN_BIN, e))
    }
    #[cfg(target_os = "windows")]
    {
        let explorer = system_info::windows_root_dir().join("explorer.exe");
        let mut cmd = win_hidden_cmd(explorer);
        cmd.arg(uri);
        spawn_and_reap_setup(cmd, "open-uri")
            .map_err(|e| format!("Failed to open URI via explorer.exe: {}", e))
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let _ = uri;
        Ok(())
    }
}

/// Triggers an interactive OS permission request or on-demand elevated fix for the given [`PermissionId`].
pub fn request_permission(raw_id: &str) -> Result<String, String> {
    let perm_id = PermissionId::parse(raw_id)?;
    let result = request_permission_by_id(perm_id);
    invalidate_setup_cache();
    result
}

/// Internal dispatcher executing the platform-native request or elevated remediation for a validated [`PermissionId`].
fn request_permission_by_id(perm_id: PermissionId) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        match perm_id {
            PermissionId::Accessibility => {
                let granted = unsafe { integrator_mac_perm_accessibility_request() };
                if granted {
                    Ok("Accessibility permission is granted.".to_string())
                } else {
                    let _ = open_allowlisted_uri(config::MACOS_SETTINGS_ACCESSIBILITY_URL);
                    Ok("Triggered macOS Accessibility prompt and opened System Settings > Accessibility.".to_string())
                }
            }
            PermissionId::InputMonitoring => {
                let granted = unsafe { integrator_mac_perm_input_monitoring_request() };
                if granted {
                    Ok("Input Monitoring permission is granted.".to_string())
                } else {
                    let _ = open_allowlisted_uri(config::MACOS_SETTINGS_INPUT_MONITORING_URL);
                    Ok("Triggered macOS Input Monitoring prompt and opened System Settings > Input Monitoring.".to_string())
                }
            }
            PermissionId::ScreenRecording => {
                let granted = unsafe { integrator_mac_perm_screen_recording_request() };
                if granted {
                    Ok("Screen Recording permission is granted.".to_string())
                } else {
                    let _ = open_allowlisted_uri(config::MACOS_SETTINGS_SCREEN_RECORDING_URL);
                    Ok("Triggered macOS Screen Recording prompt and opened System Settings > Screen Recording.".to_string())
                }
            }
            PermissionId::Camera => {
                let status_before = unsafe { integrator_mac_perm_camera_status() };
                if status_before == 0 {
                    unsafe { integrator_mac_perm_camera_request() };
                }
                let status_after = unsafe { integrator_mac_perm_camera_status() };
                if status_after == 2 {
                    Ok("Camera permission is granted.".to_string())
                } else {
                    let _ = open_allowlisted_uri(config::MACOS_SETTINGS_CAMERA_URL);
                    Ok("Opened macOS System Settings > Camera — toggle Integrator ON.".to_string())
                }
            }
            PermissionId::LocalNetwork | PermissionId::FileSharing => {
                open_permission_settings(perm_id.as_str())
            }
            _ => Err(format!(
                "Permission '{}' is only applicable on Windows",
                perm_id
            )),
        }
    }

    #[cfg(target_os = "windows")]
    {
        match perm_id {
            PermissionId::Firewall => request_windows_firewall_fix(),
            PermissionId::NetworkProfile => request_windows_private_network_profile(),
            PermissionId::SmbServer => request_windows_start_smb_server(),
            PermissionId::CameraPrivacy => open_permission_settings(perm_id.as_str()),
            PermissionId::AdminElevation => {
                if is_current_process_elevated() {
                    Ok("Integrator is already running with Administrator privileges.".to_string())
                } else {
                    Ok("Integrator runs safely as a standard user and requests UAC elevation on-demand when needed.".to_string())
                }
            }
            _ => Err(format!(
                "Permission '{}' is only applicable on macOS",
                perm_id
            )),
        }
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        Err(format!(
            "Permission requests not supported on this OS for '{}'",
            perm_id
        ))
    }
}

/// Prompts all missing requestable required permissions cleanly in a single user-initiated action.
pub fn request_all_missing_permissions(
    camera_feature_enabled: bool,
    peer_discovered: bool,
) -> Result<String, String> {
    invalidate_setup_cache();
    let snap = collect_setup_health_snapshot(camera_feature_enabled, peer_discovered);
    let mut actions_run = Vec::new();

    for perm in &snap.permissions {
        if perm.required && !perm.granted && perm.can_request_directly {
            if let Ok(pid) = PermissionId::parse(&perm.id) {
                match request_permission_by_id(pid) {
                    Ok(msg) => actions_run.push(format!("{}: {}", perm.title, msg)),
                    Err(err) => actions_run.push(format!("{}: {}", perm.title, err)),
                }
            }
        }
    }

    invalidate_setup_cache();
    if actions_run.is_empty() {
        Ok("All required OS permissions are already granted.".to_string())
    } else {
        Ok(actions_run.join(" | "))
    }
}

/// Persists the user's preference to suppress or enable the automatic Setup & Permissions prompt on app launch.
pub fn set_suppress_launch_setup_prompt(suppress: bool) -> Result<bool, String> {
    let mut prefs = system_info::load_path_preferences();
    prefs.suppress_launch_setup_prompt = suppress;
    system_info::save_path_preferences(&prefs)
        .map_err(|e| format!("Failed to save setup launch preference: {}", e))?;
    invalidate_setup_cache();
    Ok(suppress)
}

/// Configures Windows Defender Firewall rules for Integrator, requesting UAC elevation via
/// PowerShell `Start-Process -Verb RunAs` if the current process is not elevated.
#[cfg(target_os = "windows")]
fn request_windows_firewall_fix() -> Result<String, String> {
    if is_current_process_elevated() {
        crate::core::ensure_windows_firewall_rules();
        return Ok("Configured Windows Defender Firewall inbound rules for Integrator.".to_string());
    }

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Could not resolve current executable path: {}", e))?;
    let exe_str = exe_path.to_string_lossy().trim().to_string();
    if exe_str.is_empty() || exe_str.contains('"') || exe_str.chars().any(|c| c.is_control()) {
        return Err("Executable path contains invalid characters".to_string());
    }

    let remote_scopes = crate::core::build_windows_firewall_remote_scopes();
    let tcp_ports = crate::core::format_firewall_ports(&config::TCP_SERVICE_PORTS);
    let udp_ports = crate::core::format_firewall_ports(&config::UDP_SERVICE_PORTS);
    let smb_ports = crate::core::format_firewall_ports(&config::SMB_SERVICE_PORTS);

    let netsh_cmds = format!(
        "netsh advfirewall firewall delete rule name=\"{tcp_rule}\" >nul 2>&1 & \
         netsh advfirewall firewall add rule name=\"{tcp_rule}\" dir=in action=allow program=\"{exe}\" protocol=TCP localport={tcp_ports} remoteip={scopes} profile=any enable=yes & \
         netsh advfirewall firewall delete rule name=\"{udp_rule}\" >nul 2>&1 & \
         netsh advfirewall firewall add rule name=\"{udp_rule}\" dir=in action=allow program=\"{exe}\" protocol=UDP localport={udp_ports} remoteip={scopes} profile=any enable=yes & \
         netsh advfirewall firewall delete rule name=\"{smb_rule}\" >nul 2>&1 & \
         netsh advfirewall firewall add rule name=\"{smb_rule}\" dir=in action=allow protocol=TCP localport={smb_ports} remoteip={scopes} profile=any enable=yes",
        tcp_rule = config::WIN_FW_RULE_CORE_TCP,
        udp_rule = config::WIN_FW_RULE_CORE_UDP,
        smb_rule = config::WIN_FW_RULE_SMB_TCP,
        exe = exe_str,
        tcp_ports = tcp_ports,
        udp_ports = udp_ports,
        smb_ports = smb_ports,
        scopes = remote_scopes,
    );

    let cmd_exe = system_info::system32_exe("cmd.exe");
    let escaped_cmd = netsh_cmds.replace('\'', "''");
    let ps_script = format!(
        "Start-Process -FilePath '{}' -ArgumentList '/c','{}' -Verb RunAs -WindowStyle Hidden -Wait",
        cmd_exe.to_string_lossy().replace('\'', "''"),
        escaped_cmd
    );

    let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
    let status = win_hidden_cmd(&ps_exe)
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .status()
        .map_err(|e| format!("Failed to invoke elevated firewall setup: {}", e))?;

    if status.success() {
        Ok("Applied Windows Defender Firewall rules for Integrator (UAC elevated).".to_string())
    } else {
        let _ = open_allowlisted_uri(config::WINDOWS_SETTINGS_FIREWALL_URL);
        Err("UAC elevation was cancelled or failed; opened Windows Defender Firewall settings.".to_string())
    }
}

/// Switches active `Public` Windows connection profiles to `Private` via elevated PowerShell,
/// or opens `ms-settings:network-status`.
#[cfg(target_os = "windows")]
fn request_windows_private_network_profile() -> Result<String, String> {
    let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
    let inner_cmd = "Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | Set-NetConnectionProfile -NetworkCategory Private";
    let status = if is_current_process_elevated() {
        win_hidden_cmd(&ps_exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", inner_cmd])
            .status()
    } else {
        let elevate_cmd = format!(
            "Start-Process -FilePath '{}' -ArgumentList '-NoProfile','-NonInteractive','-Command',\"{}\" -Verb RunAs -WindowStyle Hidden -Wait",
            ps_exe.to_string_lossy().replace('\'', "''"),
            inner_cmd
        );
        win_hidden_cmd(&ps_exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", &elevate_cmd])
            .status()
    };

    if status.map(|s| s.success()).unwrap_or(false) {
        Ok("Switched active Windows network connection profile to Private.".to_string())
    } else {
        let _ = open_allowlisted_uri(config::WINDOWS_SETTINGS_NETWORK_STATUS_URL);
        Ok("Opened Windows Network Status settings — set your active network profile to Private.".to_string())
    }
}

/// Starts the Windows `LanmanServer` SMB service via elevated `sc.exe start LanmanServer` or opens Advanced Sharing settings.
#[cfg(target_os = "windows")]
fn request_windows_start_smb_server() -> Result<String, String> {
    let sc_exe = system_info::system32_exe("sc.exe");
    let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
    let status = if is_current_process_elevated() {
        win_hidden_cmd(&sc_exe)
            .args(["start", config::WINDOWS_LANMAN_SERVER_SERVICE])
            .status()
    } else {
        let elevate_cmd = format!(
            "Start-Process -FilePath '{}' -ArgumentList 'start','{}' -Verb RunAs -WindowStyle Hidden -Wait",
            sc_exe.to_string_lossy().replace('\'', "''"),
            config::WINDOWS_LANMAN_SERVER_SERVICE
        );
        win_hidden_cmd(&ps_exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", &elevate_cmd])
            .status()
    };

    if status.map(|s| s.success()).unwrap_or(false) {
        Ok("Started Windows SMB Server (LanmanServer) service.".to_string())
    } else {
        let _ = open_allowlisted_uri(config::WINDOWS_SETTINGS_ADVANCED_SHARING_URL);
        Ok("Opened Windows Advanced Sharing Settings — enable File and Printer Sharing.".to_string())
    }
}

/// Triggers guided installation for an allowlisted [`DependencyId`].
///
/// - On macOS: uses Homebrew (`brew install --cask ...`) for Sunshine/Moonlight if `brew` is installed,
///   otherwise opens the official GitHub releases page; for `usb_ncm`, reveals `macos/install-macos.sh`
///   and returns the exact `sudo bash ...` command (never running silent root scripts).
/// - On Windows: uses `winget install --id ...` for Sunshine/Moonlight if `winget` is installed,
///   otherwise opens the official GitHub releases page; for `vdd`, opens the official VDD releases URL;
///   for `usb_ncm`, launches `windows\Install-AppleUsbNcm.ps1` with UAC elevation if present;
///   for `vcam`, registers `integrator_vcam.dll` via elevated `regsvr32.exe`.
pub fn install_dependency(raw_id: &str) -> Result<String, String> {
    let dep_id = DependencyId::parse(raw_id)?;
    let res = install_dependency_by_id(dep_id);
    invalidate_setup_cache();
    res
}

/// Internal dispatcher executing the guided installer for a validated [`DependencyId`].
fn install_dependency_by_id(dep_id: DependencyId) -> Result<String, String> {
    match dep_id {
        DependencyId::Sunshine => {
            #[cfg(target_os = "macos")]
            {
                if let Some(brew) = find_homebrew_binary() {
                    let mut cmd = Command::new(&brew);
                    cmd.args(["install", "--cask", config::BREW_CASK_SUNSHINE]);
                    if spawn_and_reap_setup(cmd, "brew-sunshine").is_ok() {
                        return Ok(format!(
                            "Started Homebrew installation (`{}`) in background. Refresh status once completed.",
                            config::BREW_INSTALL_SUNSHINE_CMD
                        ));
                    }
                }
                open_allowlisted_uri(config::SUNSHINE_DOWNLOAD_URL)?;
                Ok(format!(
                    "Opened Sunshine releases page ({}). You can also install via `{}`.",
                    config::SUNSHINE_DOWNLOAD_URL,
                    config::BREW_INSTALL_SUNSHINE_CMD
                ))
            }
            #[cfg(target_os = "windows")]
            {
                if let Some(winget) = find_winget_binary() {
                    let mut cmd = Command::new(&winget);
                    cmd.args([
                        "install",
                        "--id",
                        config::WINGET_PACKAGE_SUNSHINE,
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]);
                    if spawn_and_reap_setup(cmd, "winget-sunshine").is_ok() {
                        return Ok(format!(
                            "Started WinGet installation (`{}`). Approve the installer prompt if shown.",
                            config::WINGET_INSTALL_SUNSHINE_CMD
                        ));
                    }
                }
                open_allowlisted_uri(config::SUNSHINE_DOWNLOAD_URL)?;
                Ok(format!(
                    "Opened Sunshine releases page ({}).",
                    config::SUNSHINE_DOWNLOAD_URL
                ))
            }
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            {
                Ok(format!("Download Sunshine from {}", config::SUNSHINE_DOWNLOAD_URL))
            }
        }
        DependencyId::Moonlight => {
            #[cfg(target_os = "macos")]
            {
                if let Some(brew) = find_homebrew_binary() {
                    let mut cmd = Command::new(&brew);
                    cmd.args(["install", "--cask", config::BREW_CASK_MOONLIGHT]);
                    if spawn_and_reap_setup(cmd, "brew-moonlight").is_ok() {
                        return Ok(format!(
                            "Started Homebrew installation (`{}`) in background. Refresh status once completed.",
                            config::BREW_INSTALL_MOONLIGHT_CMD
                        ));
                    }
                }
                open_allowlisted_uri(config::MOONLIGHT_DOWNLOAD_URL)?;
                Ok(format!(
                    "Opened Moonlight releases page ({}). You can also install via `{}`.",
                    config::MOONLIGHT_DOWNLOAD_URL,
                    config::BREW_INSTALL_MOONLIGHT_CMD
                ))
            }
            #[cfg(target_os = "windows")]
            {
                if let Some(winget) = find_winget_binary() {
                    let mut cmd = Command::new(&winget);
                    cmd.args([
                        "install",
                        "--id",
                        config::WINGET_PACKAGE_MOONLIGHT,
                        "-e",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ]);
                    if spawn_and_reap_setup(cmd, "winget-moonlight").is_ok() {
                        return Ok(format!(
                            "Started WinGet installation (`{}`). Approve the installer prompt if shown.",
                            config::WINGET_INSTALL_MOONLIGHT_CMD
                        ));
                    }
                }
                open_allowlisted_uri(config::MOONLIGHT_DOWNLOAD_URL)?;
                Ok(format!(
                    "Opened Moonlight releases page ({}).",
                    config::MOONLIGHT_DOWNLOAD_URL
                ))
            }
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            {
                Ok(format!("Download Moonlight from {}", config::MOONLIGHT_DOWNLOAD_URL))
            }
        }
        DependencyId::Vdd => {
            open_allowlisted_uri(config::VDD_DOWNLOAD_URL)?;
            Ok(format!(
                "Opened Windows Virtual Display Driver (VDD) releases page ({}). Download and run the signed driver installer.",
                config::VDD_DOWNLOAD_URL
            ))
        }
        DependencyId::UsbNcm => {
            #[cfg(target_os = "macos")]
            {
                if let Some(script_path) = find_bundled_script(config::MACOS_INSTALL_SCRIPT_REL_PATH)
                {
                    let mut cmd = Command::new(config::MACOS_OPEN_BIN);
                    cmd.args(["-R", &script_path.to_string_lossy()]);
                    let _ = spawn_and_reap_setup(cmd, "reveal-usbncm-mac");
                    Ok(format!(
                        "Revealed installer in Finder. Run in Terminal: sudo bash \"{}\"",
                        script_path.display()
                    ))
                } else {
                    Ok(format!(
                        "Run in Terminal from the Integrator folder: {}",
                        MACOS_USBNCM_DEFAULT_INSTALL_CMD
                    ))
                }
            }
            #[cfg(target_os = "windows")]
            {
                if let Some(script_path) =
                    find_bundled_script(config::WINDOWS_INSTALL_USBNCM_REL_PATH)
                {
                    let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
                    let script_str = script_path.to_string_lossy().replace('\'', "''");
                    let elevate_cmd = format!(
                        "Start-Process -FilePath '{}' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{}' -Verb RunAs",
                        ps_exe.to_string_lossy().replace('\'', "''"),
                        script_str
                    );
                    let mut cmd = win_hidden_cmd(&ps_exe);
                    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &elevate_cmd]);
                    if spawn_and_reap_setup(cmd, "install-usbncm-win").is_ok() {
                        return Ok(format!(
                            "Launched elevated PowerShell installer ({}) — approve UAC prompt to deploy Apple USB-C NCM WinUSB & WinTun bridge.",
                            script_path.display()
                        ));
                    }
                }
                open_allowlisted_uri(config::USBNCM_GUIDE_URL)?;
                Ok(format!(
                    "Run in an Administrator PowerShell prompt: {}",
                    WINDOWS_USBNCM_DEFAULT_INSTALL_CMD
                ))
            }
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            {
                Ok(MACOS_USBNCM_DEFAULT_INSTALL_CMD.to_string())
            }
        }
        DependencyId::Vcam => {
            #[cfg(target_os = "windows")]
            {
                let Some(dll_path) = find_windows_vcam_dll() else {
                    return Err(format!(
                        "{} not found beside Integrator.exe or in Program Files\\Integrator.",
                        config::WINDOWS_VCAM_DLL_FILENAME
                    ));
                };
                let regsvr32 = system_info::system32_exe("regsvr32.exe");
                let ps_exe = system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
                let status = if is_current_process_elevated() {
                    win_hidden_cmd(&regsvr32)
                        .args(["/s", &dll_path.to_string_lossy()])
                        .status()
                } else {
                    let elevate_cmd = format!(
                        "Start-Process -FilePath '{}' -ArgumentList '/s','{}' -Verb RunAs -WindowStyle Hidden -Wait",
                        regsvr32.to_string_lossy().replace('\'', "''"),
                        dll_path.to_string_lossy().replace('\'', "''")
                    );
                    win_hidden_cmd(&ps_exe)
                        .args(["-NoProfile", "-NonInteractive", "-Command", &elevate_cmd])
                        .status()
                };
                if status.map(|s| s.success()).unwrap_or(false) {
                    Ok(format!(
                        "Registered Windows 11 Virtual Camera COM driver ({}).",
                        dll_path.display()
                    ))
                } else {
                    Err("Virtual Camera COM registration was cancelled or failed (Administrator privileges required).".to_string())
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err("Windows Virtual Camera COM driver is only applicable on Windows 11.".to_string())
            }
        }
    }
}

/// Formats a [`SetupHealthSnapshot`] into a human-readable CLI summary table for `integrator setup` / `integrator setup status`.
pub fn format_setup_cli_table(snap: &SetupHealthSnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "=== Integrator Setup, Drivers & Permissions Assistant ({}) ===\n",
        snap.os
    ));
    out.push_str(&format!(
        "Process Elevated: {} | Needs Attention: {} | Missing Required Perms: {} | Missing Required Deps: {} | Launch Prompt Suppressed: {}\n\n",
        if snap.is_elevated { "Yes" } else { "No" },
        if snap.needs_attention { "YES" } else { "No" },
        snap.missing_required_permissions,
        snap.missing_required_dependencies,
        if snap.suppress_launch_prompt { "Yes" } else { "No" }
    ));

    out.push_str("--- Operating System Permissions ---\n");
    for p in &snap.permissions {
        let badge = if p.granted {
            "[OK]     "
        } else if p.required {
            "[MISSING]"
        } else {
            "[WARN]   "
        };
        let req_tag = if p.required { "Required" } else { "Optional" };
        out.push_str(&format!(
            "{} {:<18} ({:<8}) {} — {}\n",
            badge, p.id, req_tag, p.title, p.detail
        ));
    }

    out.push_str("\n--- Companion Drivers & Streaming Tools ---\n");
    for d in &snap.dependencies {
        let badge = if d.installed {
            "[INSTALLED]"
        } else if d.required {
            "[MISSING]  "
        } else {
            "[OPTIONAL] "
        };
        let run_tag = match d.running {
            Some(true) => "Running",
            Some(false) => "Stopped",
            None => "N/A",
        };
        let loc = d.detected_path.as_deref().unwrap_or("Not detected");
        out.push_str(&format!(
            "{} {:<10} ({:<7}) {} | Path: {} | Install ({}) : {}\n",
            badge, d.id, run_tag, d.name, loc, d.install_method, d.install_command
        ));
    }
    out
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_id_strict_allowlist_parsing() {
        let valid_ids = [
            ("accessibility", PermissionId::Accessibility),
            ("  input_monitoring ", PermissionId::InputMonitoring),
            ("screen_recording", PermissionId::ScreenRecording),
            ("camera", PermissionId::Camera),
            ("local_network", PermissionId::LocalNetwork),
            ("file_sharing", PermissionId::FileSharing),
            ("firewall", PermissionId::Firewall),
            ("network_profile", PermissionId::NetworkProfile),
            ("camera_privacy", PermissionId::CameraPrivacy),
            ("smb_server", PermissionId::SmbServer),
            ("admin_elevation", PermissionId::AdminElevation),
        ];
        for (raw, expected) in valid_ids {
            let parsed = PermissionId::parse(raw).expect("valid PermissionId should parse");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), raw.trim());
        }

        // Rejects unknown IDs, arbitrary URLs, shell metacharacters, and control chars
        let invalid_inputs = [
            "",
            "   ",
            "unknown_perm",
            "sudo",
            "root",
            "https://evil.example.com",
            "ms-settings:windowsdefender",
            "x-apple.systempreferences:com.apple.preference.security",
            "accessibility; rm -rf /",
            "firewall && calc.exe",
            "camera\n",
            "camera\0",
            "../etc/passwd",
        ];
        for bad in invalid_inputs {
            assert!(
                PermissionId::parse(bad).is_err(),
                "expected PermissionId::parse({:?}) to fail",
                bad
            );
        }
    }

    #[test]
    fn test_dependency_id_strict_allowlist_parsing() {
        let valid_ids = [
            ("sunshine", DependencyId::Sunshine),
            (" moonlight ", DependencyId::Moonlight),
            ("vdd", DependencyId::Vdd),
            ("usb_ncm", DependencyId::UsbNcm),
            ("vcam", DependencyId::Vcam),
        ];
        for (raw, expected) in valid_ids {
            let parsed = DependencyId::parse(raw).expect("valid DependencyId should parse");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), raw.trim());
            assert!(parsed.download_url().starts_with("https://"));
        }

        let invalid_inputs = [
            "",
            "unknown_dep",
            "brew install evil",
            "winget install evil",
            "https://evil.example.com/payload.exe",
            "sunshine; calc.exe",
            "moonlight|sh",
            "vcam\0",
            "usb_ncm\r\n",
        ];
        for bad in invalid_inputs {
            assert!(
                DependencyId::parse(bad).is_err(),
                "expected DependencyId::parse({:?}) to fail",
                bad
            );
        }
    }

    #[test]
    fn test_setup_health_snapshot_missing_counts_and_serde_roundtrip() {
        let perms = vec![
            PermissionStatus {
                id: "accessibility".into(),
                title: "Accessibility".into(),
                description: "KVM".into(),
                granted: false,
                required: true,
                can_request_directly: true,
                settings_url: Some(config::MACOS_SETTINGS_ACCESSIBILITY_URL.into()),
                detail: "Missing".into(),
            },
            PermissionStatus {
                id: "file_sharing".into(),
                title: "File Sharing".into(),
                description: "SMB".into(),
                granted: false,
                required: false,
                can_request_directly: false,
                settings_url: Some(config::MACOS_SETTINGS_FILE_SHARING_URL.into()),
                detail: "Optional".into(),
            },
        ];
        let deps = vec![
            DependencyStatus {
                id: "sunshine".into(),
                name: "Sunshine".into(),
                description: "Host".into(),
                installed: true,
                running: Some(true),
                required: true,
                detected_path: Some("/Applications/Sunshine.app".into()),
                install_method: "Homebrew".into(),
                install_command: config::BREW_INSTALL_SUNSHINE_CMD.into(),
                download_url: config::SUNSHINE_DOWNLOAD_URL.into(),
                can_auto_install: true,
            },
            DependencyStatus {
                id: "moonlight".into(),
                name: "Moonlight".into(),
                description: "Client".into(),
                installed: false,
                running: Some(false),
                required: true,
                detected_path: None,
                install_method: "Homebrew".into(),
                install_command: config::BREW_INSTALL_MOONLIGHT_CMD.into(),
                download_url: config::MOONLIGHT_DOWNLOAD_URL.into(),
                can_auto_install: true,
            },
            DependencyStatus {
                id: "usb_ncm".into(),
                name: "USB-C NCM".into(),
                description: "Optional cable".into(),
                installed: false,
                running: Some(false),
                required: false,
                detected_path: None,
                install_method: "Script".into(),
                install_command: MACOS_USBNCM_DEFAULT_INSTALL_CMD.into(),
                download_url: config::USBNCM_GUIDE_URL.into(),
                can_auto_install: true,
            },
        ];

        let snap = SetupHealthSnapshot::from_parts("macos".into(), false, false, perms, deps);
        assert!(snap.needs_attention);
        assert_eq!(snap.missing_required_permissions, 1);
        assert_eq!(snap.missing_required_dependencies, 1);

        let json = serde_json::to_string(&snap).expect("serialize SetupHealthSnapshot");
        let decoded: SetupHealthSnapshot =
            serde_json::from_str(&json).expect("deserialize SetupHealthSnapshot");
        assert_eq!(decoded, snap);

        // Backward-compatible empty JSON deserialization via #[serde(default)]
        let empty_decoded: SetupHealthSnapshot =
            serde_json::from_str("{}").expect("empty object deserializes cleanly");
        assert!(!empty_decoded.needs_attention);
        assert_eq!(empty_decoded.missing_required_permissions, 0);
        assert_eq!(empty_decoded.missing_required_dependencies, 0);

        // When all required items are satisfied, needs_attention is false even if optional items are missing
        let mut all_req_ok = snap.clone();
        all_req_ok.permissions[0].granted = true;
        all_req_ok.dependencies[1].installed = true;
        let recomputed = SetupHealthSnapshot::from_parts(
            all_req_ok.os,
            all_req_ok.is_elevated,
            true,
            all_req_ok.permissions,
            all_req_ok.dependencies,
        );
        assert!(!recomputed.needs_attention);
        assert_eq!(recomputed.missing_required_permissions, 0);
        assert_eq!(recomputed.missing_required_dependencies, 0);
        assert!(recomputed.suppress_launch_prompt);
    }

    #[test]
    fn test_windows_netsh_firewall_parser() {
        let valid_tcp = r#"
Rule Name:                            Integrator Core (TCP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Action:                               Allow
LocalPort:                            58281,58283,58285,58286,58287
"#;
        let valid_udp = r#"
Rule Name:                            Integrator Core (UDP)
Enabled:                              Yes
Action:                               Allow
LocalPort:                            58280,58284
"#;
        let valid_smb = r#"
Rule Name:                            Integrator SMB File Sharing (TCP)
Enabled:                              Yes
Action:                               Allow
LocalPort:                            139,445
"#;
        assert!(parse_windows_netsh_firewall_rule_ok(
            valid_tcp,
            &config::TCP_SERVICE_PORTS
        ));
        assert!(parse_windows_netsh_firewall_rule_ok(
            valid_udp,
            &config::UDP_SERVICE_PORTS
        ));
        assert!(parse_windows_netsh_firewall_rule_ok(
            valid_smb,
            &config::SMB_SERVICE_PORTS
        ));
        assert!(parse_windows_firewall_all_rules_ok(
            valid_tcp, valid_udp, valid_smb
        ));

        let disabled_tcp = valid_tcp.replace("Enabled:                              Yes", "Enabled:                              No");
        assert!(!parse_windows_netsh_firewall_rule_ok(
            &disabled_tcp,
            &config::TCP_SERVICE_PORTS
        ));
        assert!(!parse_windows_netsh_firewall_rule_ok(
            "No rules match the specified criteria.",
            &config::TCP_SERVICE_PORTS
        ));
    }

    #[test]
    fn test_windows_sc_query_lanmanserver_parser() {
        let running_out = r#"
SERVICE_NAME: LanmanServer
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
"#;
        let stopped_out = r#"
SERVICE_NAME: LanmanServer
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 1  STOPPED
"#;
        assert!(parse_windows_sc_query_running(running_out));
        assert!(!parse_windows_sc_query_running(stopped_out));
        assert!(!parse_windows_sc_query_running(""));
    }

    #[test]
    fn test_windows_camera_consent_and_vcam_clsid_reg_parsers() {
        let allow_reg = r#"
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
    Value    REG_SZ    Allow

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged
    Value    REG_SZ    Allow
"#;
        let deny_reg = r#"
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
    Value    REG_SZ    Allow

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged
    Value    REG_SZ    Deny
"#;
        assert!(parse_windows_camera_consent_reg(allow_reg));
        assert!(!parse_windows_camera_consent_reg(deny_reg));

        let vcam_reg = r#"
HKEY_CLASSES_ROOT\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}
    (Default)    REG_SZ    Integrator Mac Camera

HKEY_CLASSES_ROOT\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\Integrator\integrator_vcam.dll
    ThreadingModel    REG_SZ    Both
"#;
        let (registered, dll_path) = parse_windows_vcam_clsid_reg(vcam_reg);
        assert!(registered);
        assert_eq!(
            dll_path.as_deref(),
            Some(r"C:\Program Files\Integrator\integrator_vcam.dll")
        );
        assert_eq!(parse_windows_vcam_clsid_reg("ERROR: The system was unable to find the specified registry key"), (false, None));
    }

    #[test]
    fn test_windows_net_connection_profile_and_vdd_pnp_parsers() {
        let all_private = "HomeWiFi|Wi-Fi|Private\nApple USB-C NCM|Apple USB-C NCM|Private\n";
        let (ok, list) = parse_windows_net_connection_profiles(all_private);
        assert!(ok);
        assert_eq!(list.len(), 2);

        let with_public = "CoffeeShop|Wi-Fi|Public\nEthernet|Ethernet 2|Private\n";
        let (ok_pub, list_pub) = parse_windows_net_connection_profiles(with_public);
        assert!(!ok_pub);
        assert_eq!(list_pub.len(), 2);

        let pnp_sample = "\
PCI\\VEN_10DE&DEV_2684|NVIDIA GeForce RTX 4090|NVIDIA GeForce RTX 4090|OK\n\
ROOT\\DISPLAY\\0001|IddSampleDriver Device|Virtual Display Driver|OK\n";
        let vdd = parse_windows_vdd_pnp_output(pnp_sample);
        assert_eq!(
            vdd,
            Some((r"IddSampleDriver Device (ROOT\DISPLAY\0001)".to_string(), true))
        );
    }

    #[test]
    fn test_macos_sharing_and_launchdaemon_parsers() {
        let json_sharing = r#"{
            "Manveer's Public Folder": {
                "path": "/Users/manveer/Public",
                "smb_name": "Public",
                "smb_shared": 1
            }
        }"#;
        let (active_json, shares_json) = parse_macos_sharing_active(json_sharing);
        assert!(active_json);
        assert_eq!(shares_json, vec!["Public".to_string()]);

        let text_sharing = "\
name:       Public
path:       /Users/manveer/Public
            smb:    {
                name:   Public
                shared: 1
            }
";
        let (active_txt, shares_txt) = parse_macos_sharing_active(text_sharing);
        assert!(active_txt);
        assert_eq!(shares_txt, vec!["Public".to_string()]);

        let (inactive, _) = parse_macos_sharing_active("");
        assert!(!inactive);

        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.integrator.usbncm</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/Library/PrivilegedHelperTools/apple-usb-ncm-watchdog.sh</string>
    </array>
</dict>
</plist>"#;
        assert!(parse_macos_usbncm_plist_installed(plist_xml));
        assert!(!parse_macos_usbncm_plist_installed("invalid"));
    }

    #[test]
    fn test_format_setup_cli_table_renders_cleanly() {
        let snap = collect_setup_health_snapshot(false, false);
        let table = format_setup_cli_table(&snap);
        assert!(table.contains("Integrator Setup, Drivers & Permissions Assistant"));
        assert!(table.contains("Operating System Permissions"));
        assert!(table.contains("Companion Drivers & Streaming Tools"));
        assert!(table.contains("sunshine"));
        assert!(table.contains("moonlight"));
    }
}
