//! # Storage Subsystem: Dynamic Cross-Platform SMB Shared Storage Mounter
//!
//! ## Architectural Overview & Design Intent
//!
//! The `storage` module provides zero-configuration, secure, cross-platform SMB network share
//! mounting and lifecycle management between macOS and Windows peers in an Integrator session.
//! Traditional network sharing setups frequently suffer from brittle assumptions: hardcoded
//! NetBIOS/mDNS hostnames (e.g., `"HP-OMEN"`, `"MacBook"`), fixed drive letters (e.g., `"M:\"`),
//! or privileged `/Volumes` mount directory manipulation requiring `sudo`.
//!
//! This subsystem completely eliminates hardcoded mount configurations in favor of:
//! 1. **Cryptographic Peer Verification**: Prior to initiating any network mount or discovery probes,
//!    the remote IPv4 address is authenticated via [`trust::has_paired_peer_at_ip`](crate::trust::has_paired_peer_at_ip).
//!    Unpaired, untrusted, or blocked peers are rejected outright to prevent SMB relay attacks or
//!    rogue share enumeration.
//! 2. **Dynamic Share Discovery & Fallback Cascade**: If the user has not configured an explicit
//!    override or preference in [`system_info::load_path_preferences`](crate::system_info::load_path_preferences),
//!    the module dynamically queries the remote peer for available disk shares using native platform tools:
//!    - macOS: `/usr/bin/smbutil view -N //peer_ip` (querying guest/anonymous share listings).
//!    - Windows: `net.exe view \\peer_ip` (querying NetBIOS/SMB share enumeration).
//! 3. **Native Non-Privileged OS Mount Orchestration**:
//!    - **macOS**: Leverages NetFS via AppleScript (`/usr/bin/osascript -e 'mount volume "smb://..."'`).
//!      This mounts the volume directly into `/Volumes/<ShareName>` within the user's active login
//!      session, utilizing existing macOS Keychain / Kerberos SSO credentials or guest access without
//!      requiring root/sudo privileges.
//!    - **Windows**: Executes `C:\Windows\System32\net.exe use * \\peer_ip\share /persistent:no` using
//!      `CREATE_NO_WINDOW` (0x08000000). The operating system automatically allocates the next available
//!      drive letter in reverse alphabetical order (e.g., `Z:`, `Y:`, `X:`), completely avoiding drive
//!      letter collision issues.
//! 4. **Strict Path & Metacharacter Sanitization**: All share names, whether discovered remotely or
//!    supplied by user input, are validated through [`validate_smb_share_name`] against directory traversal
//!    (`..`), administrative hidden shares (`C$`, `ADMIN$`, `IPC$`), control characters, and shell injection
//!    delimiters (`;`, `|`, `&`, `"`, etc.).
//! 5. **Atomic State Persistence**: The active mount status is tracked on disk at `<app_data_dir>/active_mount.json`
//!    using atomic write-and-rename mechanics with restrictive permissions (`0o600` on Unix), protected by
//!    a process-wide mutex to avoid race conditions.
//!
//! ---
//!
//! ## Cross-Platform Execution Flow
//!
//! ```text
//!  +-------------------------------------------------------------------------------+
//!  |                      Integrator UI / Core Storage Command                     |
//!  +-------------------------------------------------------------------------------+
//!                                         |
//!                                         v
//!                       StorageManager::mount_with_share(ip, hint)
//!                                         |
//!                     +-------------------+-------------------+
//!                     | Verify IPv4 format & trust status     |
//!                     | trust::has_paired_peer_at_ip(peer_ip) |
//!                     +-------------------+-------------------+
//!                                         |
//!                     +-------------------+-------------------+
//!                     | Resolve Share Name:                   |
//!                     | 1. Stored preference                  |
//!                     | 2. Explicit share_hint                |
//!                     | 3. Dynamic discovery (smbutil/net)    |
//!                     +-------------------+-------------------+
//!                                         |
//!                     +-------------------+-------------------+
//!                     | validate_smb_share_name()             |
//!                     | Reject "..", "$", shell metachars     |
//!                     +-------------------+-------------------+
//!                                         |
//!                +------------------------+------------------------+
//!                |                                                 |
//!     [target_os = "macos"]                             [target_os = "windows"]
//!                |                                                 |
//!                v                                                 v
//!     osascript mount volume                            net.exe use * \\ip\share
//!     smb://<ip>/<encoded_share>                        /persistent:no (CREATE_NO_WINDOW)
//!                |                                                 |
//!                v                                                 v
//!     Mounts to /Volumes/<Share>                        Assigns dynamic letter (e.g. Z:\)
//!                |                                                 |
//!                +------------------------+------------------------+
//!                                         |
//!                                         v
//!                     ActiveMountRecord saved atomically
//!                     to <app_data_dir>/active_mount.json
//!                                         |
//!                                         v
//!                             Return StorageStatus { ... }
//! ```
//!
//! ---
//!
//! ## Upstream Callers and Downstream Callees
//!
//! - **Upstream Callers**:
//!   - `src/core.rs`: Coordinates system state transitions, peer connection events, and mounts.
//!   - Tauri IPC / Frontend: Storage settings pane and file explorer integration triggers.
//! - **Downstream Callees**:
//!   - [`crate::trust`]: Validates peer identity prior to issuing SMB commands.
//!   - [`crate::system_info`]: Loads and saves user path preferences.
//!   - System binaries: `/usr/bin/osascript`, `/usr/sbin/diskutil`, `/sbin/umount`, `/usr/bin/smbutil`,
//!     `/sbin/mount`, `C:\Windows\System32\net.exe`.
//!
//! ---
//!
//! ## Threading & Concurrency Model
//!
//! - **Blocking Offload**: All mount, unmount, and status queries invoke synchronous OS subprocesses
//!   (`osascript`, `smbutil`, `mount`, `diskutil`, `umount`, `net.exe`) and must be executed inside
//!   `tokio::task::spawn_blocking` by upstream callers (`core.rs`, `display/controller.rs`).
//! - **macOS Mount Watchdog**: `mount_with_share` polls `osascript` child completion and live OS mount
//!   tables every 250 ms up to a 25-second deadline, unconditionally terminating/reaping orphaned children.
//! - **Serialized Disk State**: `MOUNT_STATE_LOCK` serializes all reads, atomic writes, and removals of
//!   `active_mount.json`.
//!
//! ---
//!
//! ## Safety & Concurrency Invariants
//!
//! - **Locking**: Active mount disk operations are guarded by [`MOUNT_STATE_LOCK`], ensuring concurrent
//!   mount/unmount requests do not corrupt the on-disk JSON metadata.
//! - **Atomic Persistence**: Files are persisted via `system_info::atomic_write_private` (symlink check,
//!   `O_EXCL` temp file, POSIX `0o600`/`0o700` permissions, atomic rename).
//! - **Subprocess Isolation**: On Windows, all child processes are spawned with `CREATE_NO_WINDOW`
//!   to avoid GUI console flashes or interactive prompts hanging the runtime.

#[cfg(target_os = "macos")]
use crate::config::{
    MACOS_DISKUTIL_BIN, MACOS_MOUNT_BIN, MACOS_OPEN_BIN, MACOS_OSASCRIPT_BIN, MACOS_SMBUTIL_BIN,
    MACOS_UMOUNT_BIN,
};
use crate::{system_info, trust};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// Default fallback SMB share name used when anonymous peer share enumeration is unavailable.
#[cfg(any(target_os = "macos", target_os = "windows"))]
const DEFAULT_SMB_FALLBACK_SHARE: &str = "Public";

/// Canonical macOS mount prefix for user-session NetFS SMB volumes when mount-table lookup is pending.
#[cfg(target_os = "macos")]
const MACOS_VOLUMES_PREFIX: &str = "/Volumes";

/// Process-wide mutual exclusion lock for active mount state file operations.
static MOUNT_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Returns the shared process-wide lock for serializing active mount state reads and writes.
fn mount_state_lock() -> &'static Mutex<()> {
    MOUNT_STATE_LOCK.get_or_init(|| Mutex::new(()))
}

/// Represents the real-time status of an Integrator SMB network share mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    /// Whether an active SMB share is currently mounted and accessible on the local system.
    pub is_mounted: bool,
    /// Local filesystem path where the remote share is mounted (e.g., `/Volumes/Workspace` or `Z:\`).
    pub mount_path: String,
    /// IPv4 address of the remote peer hosting the SMB share.
    pub remote_ip: String,
    /// Validated name of the remote SMB share (e.g., `"Workspace"` or `"Public"`).
    pub remote_share: String,
    /// Human-readable descriptive status or diagnostic error message for display in UI.
    pub message: String,
}

/// On-disk persistence record tracking the active SMB mount details.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ActiveMountRecord {
    /// IPv4 address of the remote peer.
    peer_ip: String,
    /// Name of the remote SMB share.
    remote_share: String,
    /// Local path or drive letter where the share is mounted.
    mount_path: String,
}

/// High-level static coordinator for managing SMB shared storage lifecycle.
pub struct StorageManager;

/// Validates an SMB share name against path-traversal, shell/AppleScript metacharacters,
/// administrative `$` shares, and length bounds.
///
/// # Security Invariants
/// - Rejects empty or whitespace-only names.
/// - Caps maximum length at 80 characters to prevent buffer overruns or abnormal path expansion.
/// - Prohibits `.` and `..` path segments to prevent directory traversal attacks.
/// - Rejects administrative shares ending in `$` (such as `C$`, `ADMIN$`, `IPC$`) to guard against
///   accidental administrative root volume exposure.
/// - Rejects control characters and forbidden shell delimiters: `['/', '\\', ':', '"', ';', '|', '<', '>', '*', '?']`.
pub fn validate_smb_share_name(raw: &str) -> std::result::Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("SMB share name cannot be empty".into());
    }
    if trimmed.len() > 80 {
        return Err("SMB share name exceeds maximum length (80 characters)".into());
    }
    if trimmed == "." || trimmed == ".." || trimmed.contains("..") {
        return Err("SMB share name cannot contain '..'".into());
    }
    if trimmed.ends_with('$') {
        return Err("Administrative '$' SMB shares are not permitted".into());
    }
    let forbidden = ['/', '\\', ':', '"', ';', '|', '<', '>', '*', '?'];
    if trimmed
        .chars()
        .any(|c| c.is_control() || forbidden.contains(&c))
    {
        return Err(format!("SMB share name '{}' contains invalid characters", trimmed));
    }
    Ok(trimmed.to_string())
}

/// Derives a safe default SMB share name from a local filesystem path.
///
/// Handles Windows drive roots (e.g. `D:\`, `D:/`, `D:`) where `Path::file_name()` returns `None`
/// by returning the uppercase drive letter (`"D"`), rather than falling back to a generic `"Shared"`
/// name that does not match any OS drive share.
pub(crate) fn derive_smb_share_name(path_str: &str) -> String {
    let trimmed = path_str.trim();
    let stripped = trimmed
        .strip_prefix(r"\\?\")
        .unwrap_or(trimmed)
        .trim_end_matches(['\\', '/']);
    // Windows drive root such as "D:" (after stripping trailing slashes from "D:\")
    let bytes = stripped.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return (bytes[0] as char).to_ascii_uppercase().to_string();
    }
    if let Some(name) = stripped
        .rsplit(['\\', '/'])
        .map(str::trim)
        .find(|s| !s.is_empty())
    {
        return name.to_string();
    }
    "Shared".to_string()
}

/// Normalizes a filesystem path string for case-insensitive Windows or exact Unix share-path comparison.
#[cfg(any(target_os = "windows", target_os = "macos", test))]
fn normalize_share_dir_path(path_str: &str) -> String {
    let trimmed = path_str.trim().strip_prefix(r"\\?\").unwrap_or(path_str.trim());
    let without_trailing = trimmed.trim_end_matches(['\\', '/']);
    let bytes = without_trailing.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return format!("{}:\\", (bytes[0] as char).to_ascii_uppercase());
    }
    if without_trailing.is_empty() && !trimmed.is_empty() {
        return "/".to_string();
    }
    without_trailing.to_string()
}

/// Checks Windows SMB shares via PowerShell `Get-SmbShare` and returns the existing non-admin share
/// name pointing at `folder_path`, if any.
#[cfg(target_os = "windows")]
fn find_existing_windows_smb_share_for_path(folder_path: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let target_norm = normalize_share_dir_path(folder_path);
    let ps = system_info::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");
    let out = Command::new(ps)
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-SmbShare | Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and -not $_.Name.EndsWith('$') } | ForEach-Object { \"$($_.Name)`t$($_.Path)\" }",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some((name, path)) = line.split_once('\t') {
            if normalize_share_dir_path(path).eq_ignore_ascii_case(&target_norm) {
                if let Ok(valid) = validate_smb_share_name(name) {
                    return Some(valid);
                }
            }
        }
    }
    None
}

/// Encodes raw bytes using standard RFC 4648 Base64 (used for PowerShell `-EncodedCommand`).
#[cfg(any(target_os = "windows", test))]
fn encode_base64_std(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

/// Creates a Windows SMB share for `folder_path` named `share_name` (trying direct `New-SmbShare`
/// first, then triggering a UAC-elevated prompt if running as a standard non-admin user).
#[cfg(target_os = "windows")]
fn ensure_windows_smb_share(share_name: &str, folder_path: &str) -> std::io::Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    if let Some(existing) = find_existing_windows_smb_share_for_path(folder_path) {
        return Ok(existing);
    }

    let clean_path = normalize_share_dir_path(folder_path);
    let escaped_name = share_name.replace('\'', "''");
    let escaped_path = clean_path.replace('\'', "''");
    let create_script = format!(
        "if (-not (Get-SmbShare -Name '{0}' -ErrorAction SilentlyContinue)) {{ New-SmbShare -Name '{0}' -Path '{1}' -FullAccess 'Authenticated Users' -ErrorAction Stop | Out-Null }}",
        escaped_name, escaped_path
    );
    let ps = system_info::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");

    // 1. Try direct creation (succeeds immediately when elevated or delegated).
    let direct = Command::new(&ps)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", &create_script])
        .output();
    if let Ok(out) = direct {
        if out.status.success() {
            return Ok(share_name.to_string());
        }
    }

    // 2. If non-elevated, request UAC elevation so Windows can publish the SMB share cleanly.
    let utf16_bytes: Vec<u8> = create_script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = encode_base64_std(&utf16_bytes);
    let elevate_script = format!(
        "$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','{}'); exit $p.ExitCode",
        encoded
    );
    let elevated = Command::new(&ps)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", &elevate_script])
        .output();
    if let Ok(out) = elevated {
        if out.status.success() {
            if let Some(verified) = find_existing_windows_smb_share_for_path(folder_path) {
                return Ok(verified);
            }
            return Ok(share_name.to_string());
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "Failed to publish Windows SMB share '{}' for '{}' (administrator elevation is required to create a new Windows network share)",
            share_name, clean_path
        ),
    ))
}

/// Checks macOS `sharing -l -f json` and returns the published SMB share name for `folder_path`, if any.
#[cfg(target_os = "macos")]
fn find_existing_macos_smb_share_for_path(folder_path: &str) -> Option<String> {
    let target_norm = normalize_share_dir_path(folder_path);
    let sharing_bin = if std::path::Path::new(crate::config::MACOS_SHARING_BIN).exists() {
        crate::config::MACOS_SHARING_BIN
    } else {
        "sharing"
    };
    let out = Command::new(sharing_bin)
        .args(["-l", "-f", "json"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let val = serde_json::from_slice::<serde_json::Value>(&out.stdout).ok()?;
    let obj = val.as_object()?;
    for (share_label, item) in obj {
        let smb_shared = item.get("smb_shared").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
        if !smb_shared {
            continue;
        }
        let share_path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if normalize_share_dir_path(share_path) == target_norm {
            let smb_name = item
                .get("smb_name")
                .and_then(|v| v.as_str())
                .unwrap_or(share_label.as_str())
                .trim();
            if let Ok(valid) = validate_smb_share_name(smb_name) {
                return Some(valid);
            }
        }
    }
    None
}

impl StorageManager {
    /// Returns the currently active local shared folder path (user preference or default Public folder).
    pub fn get_local_shared_folder() -> Option<String> {
        system_info::load_path_preferences()
            .local_shared_folder
            .or_else(system_info::default_local_shared_folder)
    }

    /// Sets or clears the user-specified local folder path to share with peers.
    pub fn set_local_shared_folder(folder: Option<&str>) -> std::io::Result<()> {
        let mut prefs = system_info::load_path_preferences();
        let validated = match folder.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            Some(path_str) => {
                if path_str.chars().any(|c| c.is_control() || c == '"') {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Shared folder path contains invalid control or quote characters",
                    ));
                }
                let path = std::path::Path::new(path_str);
                if !path.exists() || !path.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Specified shared folder does not exist or is not a directory: {}", path_str),
                    ));
                }
                let derived = derive_smb_share_name(path_str);
                let valid_name = validate_smb_share_name(&derived)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

                #[cfg(target_os = "windows")]
                {
                    let published_name = ensure_windows_smb_share(&valid_name, path_str)?;
                    prefs.smb_share_name = Some(published_name);
                }
                #[cfg(target_os = "macos")]
                {
                    // Only advertise a macOS share name if File Sharing actually publishes this folder;
                    // otherwise leave `smb_share_name` unset so real published shares remain discoverable.
                    prefs.smb_share_name = find_existing_macos_smb_share_for_path(path_str);
                    if prefs.smb_share_name.is_none() {
                        tracing::info!(
                            "Selected local folder '{}' is not yet published in macOS File Sharing (System Settings -> General -> Sharing -> File Sharing); keeping live published SMB shares advertised",
                            path_str
                        );
                    }
                    let _ = valid_name;
                }
                #[cfg(not(any(target_os = "windows", target_os = "macos")))]
                {
                    prefs.smb_share_name = Some(valid_name);
                }
                Some(path_str.to_string())
            }
            None => {
                prefs.smb_share_name = None;
                None
            }
        };
        prefs.local_shared_folder = validated;
        system_info::save_path_preferences(&prefs)
    }

    /// Opens the mounted shared storage directory in the platform-native file manager (Finder or File Explorer).
    pub fn open_mounted_storage() -> Result<()> {
        let active = detect_active_mount(None);
        let Some(rec) = active else {
            anyhow::bail!("No shared storage volume is currently mounted");
        };
        let path = rec.mount_path.trim();
        if path.is_empty() || path.chars().any(|c| c.is_control()) {
            anyhow::bail!("Mounted storage path is empty or invalid");
        }
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new(MACOS_OPEN_BIN).arg(path).status()?;
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let explorer = system_info::windows_root_dir().join("explorer.exe");
            let _ = Command::new(explorer)
                .arg(path)
                .creation_flags(0x08000000)
                .status()?;
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = path;
            anyhow::bail!("Unsupported OS for opening storage")
        }
    }

    /// Updates the user's preferred remote SMB share name in persistent application preferences.
    ///
    /// Validates the share name using [`validate_smb_share_name`] before saving. Passing `None`
    /// or an empty string clears the preferred share name.
    pub fn set_preferred_peer_share(share: Option<&str>) -> std::io::Result<()> {
        let validated = match share.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            Some(raw) => Some(
                validate_smb_share_name(raw)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
            ),
            None => None,
        };
        let mut prefs = system_info::load_path_preferences();
        prefs.peer_smb_share_name = validated;
        system_info::save_path_preferences(&prefs)
    }

    /// Retrieves the user's preferred remote SMB share name if configured and valid.
    pub fn get_preferred_peer_share() -> Option<String> {
        system_info::load_path_preferences()
            .peer_smb_share_name
            .and_then(|s| validate_smb_share_name(&s).ok())
    }

    /// Checks whether automatic SMB share mounting on peer detection is enabled.
    pub fn is_auto_mount_on_peer_detect() -> bool {
        system_info::load_path_preferences().auto_mount_on_peer_detect
    }

    /// Enables or disables automatic SMB share mounting on peer detection.
    pub fn set_auto_mount_on_peer_detect(enabled: bool) -> std::io::Result<()> {
        let mut prefs = system_info::load_path_preferences();
        prefs.auto_mount_on_peer_detect = enabled;
        system_info::save_path_preferences(&prefs)
    }

    /// Mounts an SMB share from the given peer IP, with an optional explicit share hint.
    ///
    /// # Workflow
    /// 1. Validates peer IP as a valid IPv4 address.
    /// 2. Verifies cryptographic pairing with the peer via [`trust::has_paired_peer_at_ip`].
    /// 3. Checks if the target share is already mounted locally; if so, returns existing mount info.
    /// 4. Resolves target share name (preferred override -> hint -> dynamic discovery via smbutil/net view).
    /// 5. Executes platform-native non-privileged mount:
    ///    - macOS: AppleScript `mount volume "smb://<ip>/<encoded_share>"`.
    ///    - Windows: `net use * \\<ip>\<share> /persistent:no` with `CREATE_NO_WINDOW`.
    /// 6. Records the active mount atomically to `active_mount.json`.
    pub fn mount_with_share(peer_ip: &str, share_hint: Option<&str>) -> Result<StorageStatus> {
        let clean_ip = peer_ip.trim();
        if !system_info::is_valid_ipv4(clean_ip) {
            anyhow::bail!("Invalid peer IPv4 address for SMB mount: '{}'", peer_ip);
        }
        let parsed_ip: IpAddr = clean_ip
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid peer IP address for SMB mount: '{}'", peer_ip))?;
        if !trust::has_paired_peer_at_ip(parsed_ip) {
            anyhow::bail!(
                "Refusing SMB mount: peer {} is not cryptographically paired or is blocked.",
                clean_ip
            );
        }

        let requested_share = Self::get_preferred_peer_share().or_else(|| {
            share_hint.and_then(|s| validate_smb_share_name(s).ok())
        });

        // Fast-path: check if target is already mounted at this exact peer IP
        if let Some(existing) = detect_active_mount_matching(Some(clean_ip), requested_share.as_deref()) {
            return Ok(StorageStatus {
                is_mounted: true,
                mount_path: existing.mount_path.clone(),
                remote_ip: if existing.peer_ip.is_empty() {
                    clean_ip.to_string()
                } else {
                    existing.peer_ip
                },
                remote_share: existing.remote_share,
                message: format!("Shared drive already mounted at {}", existing.mount_path),
            });
        }

        // Topology transition cleanup: if a stale Integrator mount exists from an older topology IP
        // (e.g. switching from USB-C 10.99.99.x to Phone Hotspot 172.20.10.x or LAN 192.168.1.x),
        // unmount the stale route first so /Volumes/<share> or the drive mapping does not collide.
        if let Some(stale) = detect_active_mount(None) {
            if !stale.peer_ip.is_empty() && !stale.peer_ip.eq_ignore_ascii_case(clean_ip) {
                tracing::info!(
                    "Unmounting stale SMB share from previous topology IP {} at {} before mounting {}",
                    stale.peer_ip,
                    stale.mount_path,
                    clean_ip
                );
                let _ = Self::unmount();
            }
        }

        let target_share = resolve_remote_share(clean_ip, share_hint);

        #[cfg(target_os = "macos")]
        {
            let Some(raw_share) = target_share else {
                anyhow::bail!(
                    "No SMB share discovered on {} — set a peer share name in Settings or enable Windows File Sharing.",
                    clean_ip
                );
            };
            let share = validate_smb_share_name(&raw_share)
                .map_err(|e| anyhow::anyhow!("Rejected SMB share name: {}", e))?;

            let encoded_share = percent_encode_path_segment(&share);
            let smb_url = format!("smb://{}/{}", clean_ip, encoded_share);

            tracing::info!("📂 Mounting macOS SMB volume via NetFS: {}", smb_url);
            let mut child = Command::new(MACOS_OSASCRIPT_BIN)
                .args([
                    "-e",
                    "on run argv",
                    "-e",
                    "mount volume (item 1 of argv)",
                    "-e",
                    "end run",
                    "--",
                    &smb_url,
                ])
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            let start = std::time::Instant::now();
            let mut mount_succeeded = false;
            while start.elapsed() < std::time::Duration::from_secs(25) {
                if let Ok(Some(status)) = child.try_wait() {
                    mount_succeeded = status.success();
                    break;
                }
                if detect_active_mount_matching(Some(clean_ip), Some(&share)).is_some() {
                    let _ = child.kill();
                    let _ = child.wait();
                    mount_succeeded = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }

            let mut err = String::new();
            if !mount_succeeded {
                let _ = child.kill();
                if let Ok(output) = child.wait_with_output() {
                    err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                }
                if err.is_empty() {
                    err = "mount operation timed out after 25s".to_string();
                }
            }

            if mount_succeeded {
                // Query the live macOS mount table first so suffixed volume paths (e.g. /Volumes/Share-1)
                // are captured accurately, falling back to MACOS_VOLUMES_PREFIX if not yet listed.
                let detected = detect_active_mount_matching(Some(clean_ip), Some(&share))
                    .unwrap_or_else(|| ActiveMountRecord {
                        peer_ip: clean_ip.to_string(),
                        remote_share: share.clone(),
                        mount_path: format!("{}/{}", MACOS_VOLUMES_PREFIX, share),
                    });
                save_active_mount(&detected);
                return Ok(StorageStatus {
                    is_mounted: true,
                    mount_path: detected.mount_path.clone(),
                    remote_ip: clean_ip.to_string(),
                    remote_share: detected.remote_share.clone(),
                    message: format!("Mounted //{}/{} at {}", clean_ip, share, detected.mount_path),
                });
            }

            tracing::warn!("SMB mount failed for {}: {}", smb_url, err);
            anyhow::bail!(
                "Failed to mount SMB share '{}' on {}: {}. Verify the share name in Settings and peer SMB sharing permissions.",
                share,
                clean_ip,
                err
            );
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let Some(raw_share) = target_share else {
                anyhow::bail!(
                    "No SMB share discovered on {} — enable SMB File Sharing on Mac or set peer share name in Settings.",
                    clean_ip
                );
            };
            let share = validate_smb_share_name(&raw_share)
                .map_err(|e| anyhow::anyhow!("Rejected SMB share name: {}", e))?;

            let unc_path = format!(r"\\{}\{}", clean_ip, share);
            tracing::info!("📂 Mounting Windows network drive via dynamic letter: {}", unc_path);

            let mut cmd = Command::new(crate::system_info::system32_exe("net.exe"));
            cmd.creation_flags(CREATE_NO_WINDOW);
            cmd.args(["use", "*", &unc_path, "/persistent:no"]);
            let out = cmd.output()?;

            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let drive = parse_assigned_windows_drive(&stdout)
                    .or_else(|| find_windows_drive_for_unc(&unc_path))
                    .unwrap_or_else(|| unc_path.clone());
                let mount_path = if drive.ends_with(':') {
                    format!("{}\\", drive)
                } else {
                    drive
                };

                let rec = ActiveMountRecord {
                    peer_ip: clean_ip.to_string(),
                    remote_share: share.clone(),
                    mount_path: mount_path.clone(),
                };
                save_active_mount(&rec);

                return Ok(StorageStatus {
                    is_mounted: true,
                    mount_path: mount_path.clone(),
                    remote_ip: clean_ip.to_string(),
                    remote_share: share,
                    message: format!("Mounted {} at {}", unc_path, mount_path),
                });
            }

            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let out_s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            tracing::warn!("Windows net use * failed for {}: {} {}", unc_path, err, out_s);
            anyhow::bail!(
                "Failed to mount {}: {}. If Mac requires login, open {} once in Explorer or check File Sharing settings.",
                unc_path,
                if err.is_empty() { out_s } else { err },
                unc_path
            );
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (target_share, requested_share);
            anyhow::bail!("Storage mounting not supported on this OS")
        }
    }

    /// Unmounts any currently active Integrator SMB network share.
    ///
    /// On macOS, issues `/usr/sbin/diskutil unmount <mount_path>` (falling back to `/sbin/umount`).
    /// On Windows, issues `net.exe use <drive> /delete /yes`.
    /// On successful unmount, removes the active mount record from disk.
    pub fn unmount() -> Result<StorageStatus> {
        let active = detect_active_mount(None);
        let Some(rec) = active else {
            clear_active_mount();
            return Ok(StorageStatus {
                is_mounted: false,
                mount_path: String::new(),
                remote_ip: String::new(),
                remote_share: String::new(),
                message: "No Integrator SMB share is currently mounted".into(),
            });
        };

        #[cfg(target_os = "macos")]
        {
            let diskutil_out = Command::new(MACOS_DISKUTIL_BIN)
                .args(["unmount", &rec.mount_path])
                .output();
            let mut ok = diskutil_out.map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                ok = Command::new(MACOS_DISKUTIL_BIN)
                    .args(["unmount", "force", &rec.mount_path])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            }
            if !ok {
                ok = Command::new(MACOS_UMOUNT_BIN)
                    .arg(&rec.mount_path)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            }
            if !ok {
                ok = Command::new(MACOS_UMOUNT_BIN)
                    .args(["-f", &rec.mount_path])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            }
            if ok {
                clear_active_mount();
                return Ok(StorageStatus {
                    is_mounted: false,
                    mount_path: String::new(),
                    remote_ip: rec.peer_ip,
                    remote_share: rec.remote_share,
                    message: format!("Unmounted {}", rec.mount_path),
                });
            }
            anyhow::bail!("Failed to unmount {}", rec.mount_path);
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let target = rec.mount_path.trim_end_matches('\\');
            let mut cmd = Command::new(crate::system_info::system32_exe("net.exe"));
            cmd.creation_flags(0x08000000);
            cmd.args(["use", target, "/delete", "/yes"]);
            let out = cmd.output()?;
            if out.status.success() {
                clear_active_mount();
                return Ok(StorageStatus {
                    is_mounted: false,
                    mount_path: String::new(),
                    remote_ip: rec.peer_ip,
                    remote_share: rec.remote_share,
                    message: format!("Disconnected {}", rec.mount_path),
                });
            }
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            anyhow::bail!("Failed to disconnect {}: {}", rec.mount_path, err);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(StorageStatus {
                is_mounted: false,
                mount_path: String::new(),
                remote_ip: String::new(),
                remote_share: String::new(),
                message: "Unsupported OS".into(),
            })
        }
    }

    /// Queries current storage mount status with optional peer IP and share hint filters.
    pub fn status_with_share(peer_ip: Option<&str>, share_hint: Option<&str>) -> StorageStatus {
        let valid_hint = share_hint.and_then(|h| validate_smb_share_name(h).ok());
        let expected_share = Self::get_preferred_peer_share().or_else(|| valid_hint.clone());

        if let Some(rec) = detect_active_mount_matching(peer_ip, expected_share.as_deref()) {
            return StorageStatus {
                is_mounted: true,
                mount_path: rec.mount_path,
                remote_ip: if rec.peer_ip.is_empty() {
                    peer_ip.unwrap_or("").to_string()
                } else {
                    rec.peer_ip
                },
                remote_share: rec.remote_share,
                message: "Shared storage mounted".into(),
            };
        }

        let ip = peer_ip.unwrap_or("").trim();
        let planned_share = expected_share.unwrap_or_else(|| "Not configured".to_string());

        StorageStatus {
            is_mounted: false,
            mount_path: String::new(),
            remote_ip: ip.to_string(),
            remote_share: planned_share,
            message: "Ready to mount peer shared folder".into(),
        }
    }
}

/// Returns the path to the persistent `active_mount.json` state file in the application data directory.
fn active_mount_file() -> std::path::PathBuf {
    system_info::app_data_dir().join("active_mount.json")
}

/// Loads and validates the persisted active mount record from disk under [`MOUNT_STATE_LOCK`].
fn load_active_mount() -> Option<ActiveMountRecord> {
    let _guard = mount_state_lock().lock().unwrap_or_else(|e| e.into_inner());
    let rec = std::fs::read_to_string(active_mount_file())
        .ok()
        .and_then(|s| serde_json::from_str::<ActiveMountRecord>(&s).ok())?;
    let valid_ip = rec.peer_ip.trim().parse::<IpAddr>().is_ok();
    let valid_share =
        rec.remote_share.is_empty() || validate_smb_share_name(&rec.remote_share).is_ok();
    if valid_ip && valid_share && !rec.mount_path.trim().is_empty() {
        Some(rec)
    } else {
        None
    }
}

/// Atomically saves the active mount record to disk under [`MOUNT_STATE_LOCK`] via [`system_info::atomic_write_private`].
fn save_active_mount(rec: &ActiveMountRecord) {
    let _guard = mount_state_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = active_mount_file();
    if let Ok(json) = serde_json::to_string_pretty(rec) {
        if let Err(e) = system_info::atomic_write_private(&path, json.as_bytes()) {
            tracing::warn!("Failed to persist active mount state to {}: {}", path.display(), e);
        }
    }
}

/// Deletes the active mount record file from disk under [`MOUNT_STATE_LOCK`].
fn clear_active_mount() {
    let _guard = mount_state_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = active_mount_file();
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!("Failed to remove active mount state {}: {}", path.display(), e);
        }
    }
}

/// Parses standard `smbutil view` stdout output to extract available disk share names.
///
/// Skips header lines, dashes, IPC shares, and footer summaries.
fn parse_smbutil_disk_shares(stdout: &str) -> Vec<String> {
    let mut shares = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty()
            || (t.starts_with("Share ") && t.contains("Type"))
            || t.starts_with("---")
            || t.contains("shares listed")
        {
            continue;
        }
        // `smbutil view` formats rows as: `<Share Name>   Disk   <Comment>`
        for marker in ["  Disk", "\tDisk"] {
            if let Some((name_part, _rest)) = t.split_once(marker) {
                if let Ok(valid) = validate_smb_share_name(name_part) {
                    shares.push(valid);
                }
                break;
            }
        }
    }
    shares
}

/// Resolves the remote SMB share name for a given peer using preference, hint, or dynamic discovery.
fn resolve_remote_share(peer_ip: &str, share_hint: Option<&str>) -> Option<String> {
    let parsed_ip: IpAddr = peer_ip.trim().parse().ok()?;
    if !trust::has_paired_peer_at_ip(parsed_ip) {
        return None;
    }

    if let Some(pref) = StorageManager::get_preferred_peer_share() {
        return Some(pref);
    }
    if let Some(hint) = share_hint {
        if let Ok(valid) = validate_smb_share_name(hint) {
            return Some(valid);
        }
    }

    // Dynamic remote SMB browse if no hint/override was set
    #[cfg(target_os = "macos")]
    {
        for target in [format!("//{}", peer_ip), format!("//guest@{}", peer_ip)] {
            if let Ok(out) = Command::new(MACOS_SMBUTIL_BIN)
                .args(["view", "-N", &target])
                .output()
            {
                if out.status.success() {
                    let txt = String::from_utf8_lossy(&out.stdout);
                    if let Some(first) = parse_smbutil_disk_shares(&txt).into_iter().next() {
                        return Some(first);
                    }
                }
            }
        }
        // Fallback default share if anonymous enumeration was rejected
        Some(DEFAULT_SMB_FALLBACK_SHARE.to_string())
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new(crate::system_info::system32_exe("net.exe"));
        cmd.creation_flags(0x08000000);
        cmd.args(["view", &format!(r"\\{}", peer_ip)]);
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                if let Some(first) = parse_smbutil_disk_shares(&txt).into_iter().next() {
                    return Some(first);
                }
            }
        }
        // Fallback default share if NetBIOS view was rejected
        Some(DEFAULT_SMB_FALLBACK_SHARE.to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = peer_ip;
        None
    }
}

/// Detects an active mount matching an optional peer IP filter.
fn detect_active_mount(peer_ip_filter: Option<&str>) -> Option<ActiveMountRecord> {
    detect_active_mount_matching(peer_ip_filter, None)
}

/// Detects an active mount matching optional peer IP and share name filters by querying OS mount tables.
fn detect_active_mount_matching(
    peer_ip_filter: Option<&str>,
    share_filter: Option<&str>,
) -> Option<ActiveMountRecord> {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new(MACOS_MOUNT_BIN).output().ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let saved = load_active_mount();

        for line in stdout.lines() {
            if !line.contains("(smbfs") {
                continue;
            }
            // Format: "//user@10.x.x.x/Share%20Name on /Volumes/Share Name (smbfs, ...)"
            let Some((left, _opts)) = line.rsplit_once(" (smbfs") else {
                continue;
            };
            let Some((src, raw_mount_path)) = left.split_once(" on ") else {
                continue;
            };
            let mount_path = raw_mount_path.trim();
            let (ip_part, share_part) = parse_smbfs_source(src);
            if validate_smb_share_name(&share_part).is_err() {
                continue;
            }
            if let Some(filter_ip) = peer_ip_filter {
                if ip_part.is_empty() || !ip_part.eq_ignore_ascii_case(filter_ip.trim()) {
                    continue;
                }
                if let Some(req_share) = share_filter {
                    if !share_part.eq_ignore_ascii_case(req_share.trim()) {
                        continue;
                    }
                }
            } else if let Some(ref s) = saved {
                let matches_saved_path =
                    !s.mount_path.is_empty() && mount_path == s.mount_path.trim();
                let matches_saved_ip_share = !ip_part.is_empty()
                    && ip_part.eq_ignore_ascii_case(&s.peer_ip)
                    && (s.remote_share.is_empty()
                        || share_part.eq_ignore_ascii_case(&s.remote_share));
                if !matches_saved_path && !matches_saved_ip_share {
                    let is_paired = ip_part.parse::<IpAddr>().map(trust::has_paired_peer_at_ip).unwrap_or(false);
                    if !is_paired {
                        continue;
                    }
                }
            } else {
                let is_paired = ip_part.parse::<IpAddr>().map(trust::has_paired_peer_at_ip).unwrap_or(false);
                if !is_paired {
                    continue;
                }
            }

            let rec = ActiveMountRecord {
                peer_ip: ip_part,
                remote_share: share_part,
                mount_path: mount_path.to_string(),
            };
            save_active_mount(&rec);
            return Some(rec);
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let saved = load_active_mount();
        let mut cmd = Command::new(crate::system_info::system32_exe("net.exe"));
        cmd.creation_flags(0x08000000);
        cmd.arg("use");
        let out = cmd.output().ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);

        for line in stdout.lines() {
            let Some((drive_opt, host, share_root, full_unc)) = parse_windows_net_use_line(line)
            else {
                continue;
            };

            if let Some(filter_ip) = peer_ip_filter {
                if !host.eq_ignore_ascii_case(filter_ip.trim()) {
                    continue;
                }
                if let Some(req_share) = share_filter {
                    if !share_root.eq_ignore_ascii_case(req_share.trim()) {
                        continue;
                    }
                }
            } else if let Some(ref s) = saved {
                let matches_saved_ip_share = host.eq_ignore_ascii_case(&s.peer_ip)
                    && (s.remote_share.is_empty()
                        || share_root.eq_ignore_ascii_case(&s.remote_share));
                if !matches_saved_ip_share {
                    let is_paired = host.parse::<IpAddr>().map(trust::has_paired_peer_at_ip).unwrap_or(false);
                    if !is_paired {
                        continue;
                    }
                }
            } else {
                let is_paired = host.parse::<IpAddr>().map(trust::has_paired_peer_at_ip).unwrap_or(false);
                if !is_paired {
                    continue;
                }
            }

            let mount_path = drive_opt
                .map(|d| format!("{}\\", d))
                .unwrap_or(full_unc);

            let rec = ActiveMountRecord {
                peer_ip: host,
                remote_share: share_root,
                mount_path,
            };
            save_active_mount(&rec);
            return Some(rec);
        }
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (peer_ip_filter, share_filter);
        None
    }
}

/// Parses a line of `net.exe use` output on Windows into (Drive, Host, ShareName, FullUNC).
#[cfg(any(target_os = "windows", test))]
fn parse_windows_net_use_line(line: &str) -> Option<(Option<String>, String, String, String)> {
    let unc_pos = line.find(r"\\")?;
    let prefix = &line[..unc_pos];
    let after_unc = &line[unc_pos..];
    // SMB provider column on `net use` is separated by 2+ spaces or tab.
    let unc_end = after_unc
        .find("  ")
        .into_iter()
        .chain(after_unc.find('\t'))
        .min()
        .unwrap_or(after_unc.len());
    let full_unc = after_unc[..unc_end].trim_end();
    let trimmed_unc = full_unc.trim_start_matches('\\');
    let (host, share) = trimmed_unc.split_once('\\')?;
    let share_root = share.split('\\').next().unwrap_or("").trim();
    if host.is_empty() || validate_smb_share_name(share_root).is_err() {
        return None;
    }
    let drive = prefix
        .split_whitespace()
        .find(|t| t.len() == 2 && t.ends_with(':') && t.as_bytes()[0].is_ascii_alphabetic())
        .map(|d| d.to_string());
    Some((
        drive,
        host.to_string(),
        share_root.to_string(),
        full_unc.to_string(),
    ))
}

/// Parses a macOS `mount` command source string (e.g., `//user@172.20.10.7/Share%20Name`) into `(IP, ShareName)`.
#[cfg(any(target_os = "macos", test))]
fn parse_smbfs_source(src: &str) -> (String, String) {
    let cleaned = src.trim().trim_start_matches('/');
    let after_at = cleaned.rsplit_once('@').map(|(_, r)| r).unwrap_or(cleaned);
    if let Some((host, share)) = after_at.split_once('/') {
        let decoded_share = percent_decode(share);
        let clean_host = host.split(':').next().unwrap_or(host);
        (clean_host.to_string(), decoded_share)
    } else {
        (after_at.to_string(), String::new())
    }
}

/// Percent-encodes path segments for inclusion in macOS `smb://` URLs.
#[cfg(any(target_os = "macos", test))]
fn percent_encode_path_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Decodes percent-encoded hex sequences from macOS mount table entries.
#[cfg(any(target_os = "macos", test))]
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extracts assigned Windows drive letter from `net use *` command stdout.
#[cfg(target_os = "windows")]
fn parse_assigned_windows_drive(stdout: &str) -> Option<String> {
    for tok in stdout.split_whitespace() {
        let clean = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':');
        if clean.len() == 2 && clean.ends_with(':') && clean.as_bytes()[0].is_ascii_alphabetic() {
            return Some(clean.to_string());
        }
    }
    None
}

/// Finds the Windows drive letter assigned to an existing UNC network path.
#[cfg(target_os = "windows")]
fn find_windows_drive_for_unc(unc: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(crate::system_info::system32_exe("net.exe"));
    cmd.creation_flags(0x08000000);
    cmd.arg("use");
    let out = cmd.output().ok()?;
    let txt = String::from_utf8_lossy(&out.stdout);
    for line in txt.lines() {
        if let Some((Some(drive), _, _, full_unc)) = parse_windows_net_use_line(line) {
            if full_unc.eq_ignore_ascii_case(unc.trim()) {
                return Some(drive);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_share_validator_rejects_traversal_and_admin_shares() {
        assert!(validate_smb_share_name("Users").is_ok());
        assert!(validate_smb_share_name("Public Folder").is_ok());
        assert!(validate_smb_share_name("C$").is_err());
        assert!(validate_smb_share_name("IPC$").is_err());
        assert!(validate_smb_share_name("../etc").is_err());
        assert!(validate_smb_share_name("foo/bar").is_err());
        assert!(validate_smb_share_name("foo\"bar").is_err());
    }

    #[test]
    fn smbutil_parser_preserves_spaces_and_skips_admin_and_footer() {
        let sample = "\
Share                                           Type    Comments
----------------------------------------------------------------
IPC$                                            Pipe    Remote IPC
ADMIN$                                          Disk    Remote Admin
Shared Public Folder                            Disk    macOS Public Share
Workspace Drive                                 Disk    Shared SSD

4 shares listed from 4 available
";
        let shares = parse_smbutil_disk_shares(sample);
        assert_eq!(
            shares,
            vec![
                "Shared Public Folder".to_string(),
                "Workspace Drive".to_string()
            ]
        );
    }

    #[test]
    fn windows_net_use_parser_handles_spaced_shares_and_skips_ipc() {
        for topo_ip in [
            "10.99.99.1",
            "169.254.10.1",
            "192.168.137.1",
            "172.20.10.7",
            "192.168.1.50",
        ] {
            assert!(parse_windows_net_use_line(&format!(
                r"OK                     \\{}\IPC$              Microsoft Windows Network",
                topo_ip
            ))
            .is_none());
            let parsed = parse_windows_net_use_line(&format!(
                r"OK           Z:        \\{}\Shared Public Folder  Microsoft Windows Network",
                topo_ip
            ))
            .unwrap();
            assert_eq!(parsed.0.as_deref(), Some("Z:"));
            assert_eq!(parsed.1, topo_ip);
            assert_eq!(parsed.2, "Shared Public Folder");

            let encoded = percent_encode_path_segment("Shared Public Folder");
            let mac_src = format!("//guest@{}:445/{}", topo_ip, encoded);
            let (mac_ip, mac_share) = parse_smbfs_source(&mac_src);
            assert_eq!(mac_ip, topo_ip);
            assert_eq!(mac_share, "Shared Public Folder");
        }
    }

    #[test]
    fn status_with_share_rejects_invalid_hint() {
        let st = StorageManager::status_with_share(Some("203.0.113.55"), Some("../C$"));
        assert!(!st.is_mounted);
        if StorageManager::get_preferred_peer_share().is_none() {
            assert_eq!(st.remote_share, "Not configured");
        }
    }

    #[test]
    fn derive_smb_share_name_handles_windows_drive_roots_and_folders() {
        assert_eq!(derive_smb_share_name(r"D:\"), "D");
        assert_eq!(derive_smb_share_name("d:/"), "D");
        assert_eq!(derive_smb_share_name("C:"), "C");
        assert_eq!(derive_smb_share_name(r"\\?\D:\"), "D");
        assert_eq!(derive_smb_share_name(r"C:\Users\Manveer Singh\Projects\"), "Projects");
        assert_eq!(derive_smb_share_name("/Users/manveersingh/Public"), "Public");
        assert_eq!(normalize_share_dir_path("d:/"), r"D:\");
        assert_eq!(encode_base64_std(b"hi"), "aGk=");
    }
}
