//! Dynamic cross-platform SMB shared storage mounter.
//!
//! Eliminates hardcoded share names ("HP-OMEN", "MacBook") and fixed drive letters ("M:\")
//! or sudo `/Volumes` directories in favor of discovered/configured share names,
//! NetFS `mount volume` on macOS, and dynamic `net use *` drive assignment on Windows.

use crate::{system_info, trust};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "macos")]
const OSASCRIPT_BIN: &str = "/usr/bin/osascript";
#[cfg(target_os = "macos")]
const DISKUTIL_BIN: &str = "/usr/sbin/diskutil";
#[cfg(target_os = "macos")]
const UMOUNT_BIN: &str = "/sbin/umount";
#[cfg(target_os = "macos")]
const SMBUTIL_BIN: &str = "/usr/bin/smbutil";
#[cfg(target_os = "macos")]
const MOUNT_BIN: &str = "/sbin/mount";
#[cfg(target_os = "windows")]
const NET_EXE_BIN: &str = r"C:\Windows\System32\net.exe";

static MOUNT_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static MOUNT_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn mount_state_lock() -> &'static Mutex<()> {
    MOUNT_STATE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    pub is_mounted: bool,
    pub mount_path: String,
    pub remote_ip: String,
    pub remote_share: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ActiveMountRecord {
    peer_ip: String,
    remote_share: String,
    mount_path: String,
}

pub struct StorageManager;

/// Validates an SMB share name against path-traversal, shell/AppleScript metacharacters,
/// administrative `$` shares, and length bounds.
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

impl StorageManager {
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

    pub fn get_preferred_peer_share() -> Option<String> {
        system_info::load_path_preferences()
            .peer_smb_share_name
            .and_then(|s| validate_smb_share_name(&s).ok())
    }

    #[allow(dead_code)]
    pub fn is_mounted() -> bool {
        detect_active_mount(None).is_some()
    }

    #[allow(dead_code)]
    pub fn mount(peer_ip: &str) -> Result<StorageStatus> {
        Self::mount_with_share(peer_ip, None)
    }

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
            let output = Command::new(OSASCRIPT_BIN)
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
                .output()?;

            if output.status.success() {
                let detected = detect_active_mount_matching(Some(clean_ip), Some(&share))
                    .unwrap_or(ActiveMountRecord {
                        peer_ip: clean_ip.to_string(),
                        remote_share: share.clone(),
                        mount_path: format!("/Volumes/{}", share),
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

            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
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

            let mut cmd = Command::new(NET_EXE_BIN);
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
            let diskutil_out = Command::new(DISKUTIL_BIN)
                .args(["unmount", &rec.mount_path])
                .output();
            let mut ok = diskutil_out.map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                ok = Command::new(UMOUNT_BIN)
                    .arg(&rec.mount_path)
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
            let mut cmd = Command::new(NET_EXE_BIN);
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

    #[allow(dead_code)]
    pub fn status(peer_ip: Option<&str>) -> StorageStatus {
        Self::status_with_share(peer_ip, None)
    }

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

fn active_mount_file() -> std::path::PathBuf {
    system_info::app_data_dir().join("active_mount.json")
}

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

fn save_active_mount(rec: &ActiveMountRecord) {
    let _guard = mount_state_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = active_mount_file();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(rec) {
        let seq = MOUNT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.{}.{}.tmp", std::process::id(), seq));
        if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!("Failed to write temp active mount state {}: {}", tmp.display(), e);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!("Failed to persist active mount state to {}: {}", path.display(), e);
        }
    }
}

fn clear_active_mount() {
    let _guard = mount_state_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = active_mount_file();
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!("Failed to remove active mount state {}: {}", path.display(), e);
        }
    }
}

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
            if let Ok(out) = Command::new(SMBUTIL_BIN)
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
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new(NET_EXE_BIN);
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
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = peer_ip;
        None
    }
}

fn detect_active_mount(peer_ip_filter: Option<&str>) -> Option<ActiveMountRecord> {
    detect_active_mount_matching(peer_ip_filter, None)
}

fn detect_active_mount_matching(
    peer_ip_filter: Option<&str>,
    share_filter: Option<&str>,
) -> Option<ActiveMountRecord> {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new(MOUNT_BIN).output().ok()?;
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
                    continue;
                }
            } else {
                continue;
            }

            return Some(ActiveMountRecord {
                peer_ip: ip_part,
                remote_share: share_part,
                mount_path: mount_path.to_string(),
            });
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let saved = load_active_mount();
        let mut cmd = Command::new(NET_EXE_BIN);
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
                if !host.eq_ignore_ascii_case(&s.peer_ip)
                    || (!s.remote_share.is_empty()
                        && !share_root.eq_ignore_ascii_case(&s.remote_share))
                {
                    continue;
                }
            } else {
                continue;
            }

            let mount_path = drive_opt
                .map(|d| format!("{}\\", d))
                .unwrap_or(full_unc);

            return Some(ActiveMountRecord {
                peer_ip: host,
                remote_share: share_root,
                mount_path,
            });
        }
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (peer_ip_filter, share_filter);
        None
    }
}

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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "windows")]
fn find_windows_drive_for_unc(unc: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(NET_EXE_BIN);
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
        assert!(parse_windows_net_use_line(
            r"OK                     \\10.0.0.2\IPC$              Microsoft Windows Network"
        )
        .is_none());
        let parsed = parse_windows_net_use_line(
            r"OK           Z:        \\10.0.0.2\Shared Public Folder  Microsoft Windows Network",
        )
        .unwrap();
        assert_eq!(parsed.0.as_deref(), Some("Z:"));
        assert_eq!(parsed.1, "10.0.0.2");
        assert_eq!(parsed.2, "Shared Public Folder");
    }

    #[test]
    fn status_with_share_rejects_invalid_hint() {
        let st = StorageManager::status_with_share(Some("203.0.113.55"), Some("../C$"));
        assert!(!st.is_mounted);
        if StorageManager::get_preferred_peer_share().is_none() {
            assert_eq!(st.remote_share, "Not configured");
        }
    }
}

