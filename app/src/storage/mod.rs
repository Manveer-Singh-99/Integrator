//! Dynamic cross-platform SMB shared storage mounter.
//!
//! Eliminates hardcoded share names ("HP-OMEN", "MacBook") and fixed drive letters ("M:\")
//! or sudo `/Volumes` directories in favor of discovered/configured share names,
//! NetFS `mount volume` on macOS, and dynamic `net use *` drive assignment on Windows.

use crate::system_info;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

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

impl StorageManager {
    pub fn set_preferred_peer_share(share: Option<&str>) -> std::io::Result<()> {
        let mut prefs = system_info::load_path_preferences();
        prefs.peer_smb_share_name = share
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        system_info::save_path_preferences(&prefs)
    }

    pub fn get_preferred_peer_share() -> Option<String> {
        system_info::load_path_preferences().peer_smb_share_name
    }

    pub fn is_mounted() -> bool {
        detect_active_mount(None).is_some()
    }

    pub fn mount(peer_ip: &str) -> Result<StorageStatus> {
        Self::mount_with_share(peer_ip, None)
    }

    pub fn mount_with_share(peer_ip: &str, share_hint: Option<&str>) -> Result<StorageStatus> {
        if let Some(existing) = detect_active_mount(Some(peer_ip)) {
            return Ok(StorageStatus {
                is_mounted: true,
                mount_path: existing.mount_path.clone(),
                remote_ip: if existing.peer_ip.is_empty() {
                    peer_ip.to_string()
                } else {
                    existing.peer_ip
                },
                remote_share: existing.remote_share,
                message: format!("Shared drive already mounted at {}", existing.mount_path),
            });
        }

        let target_share = resolve_remote_share(peer_ip, share_hint);

        #[cfg(target_os = "macos")]
        {
            let Some(share) = target_share else {
                anyhow::bail!(
                    "No SMB share discovered on {} — set a peer share name in Settings or enable Windows File Sharing.",
                    peer_ip
                );
            };

            let encoded_share = percent_encode_path_segment(&share);
            let smb_url = format!("smb://{}/{}", peer_ip, encoded_share);
            let escaped_url = smb_url.replace('"', "\\\"");
            let script = format!("mount volume \"{}\"", escaped_url);

            tracing::info!("📂 Mounting macOS SMB volume via NetFS: {}", smb_url);
            let output = Command::new("osascript")
                .args(["-e", &script])
                .output()?;

            if output.status.success() {
                let detected = detect_active_mount(Some(peer_ip)).unwrap_or(ActiveMountRecord {
                    peer_ip: peer_ip.to_string(),
                    remote_share: share.clone(),
                    mount_path: format!("/Volumes/{}", share),
                });
                save_active_mount(&detected);
                return Ok(StorageStatus {
                    is_mounted: true,
                    mount_path: detected.mount_path.clone(),
                    remote_ip: peer_ip.to_string(),
                    remote_share: detected.remote_share.clone(),
                    message: format!("Mounted //{} / {} at {}", peer_ip, share, detected.mount_path),
                });
            }

            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::warn!("SMB mount failed for {}: {}", smb_url, err);
            anyhow::bail!(
                "Failed to mount SMB share '{}' on {}: {}. Verify the share name in Settings and peer SMB sharing permissions.",
                share,
                peer_ip,
                err
            );
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let Some(share) = target_share else {
                anyhow::bail!(
                    "No SMB share discovered on {} — enable SMB File Sharing on Mac or set peer share name in Settings.",
                    peer_ip
                );
            };

            let unc_path = format!(r"\\{}\{}", peer_ip, share);
            tracing::info!("📂 Mounting Windows network drive via dynamic letter: {}", unc_path);

            let mut cmd = Command::new("net");
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
                    peer_ip: peer_ip.to_string(),
                    remote_share: share.clone(),
                    mount_path: mount_path.clone(),
                };
                save_active_mount(&rec);

                return Ok(StorageStatus {
                    is_mounted: true,
                    mount_path: mount_path.clone(),
                    remote_ip: peer_ip.to_string(),
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
            let _ = target_share;
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
            let diskutil_out = Command::new("diskutil")
                .args(["unmount", &rec.mount_path])
                .output();
            let mut ok = diskutil_out.map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                ok = Command::new("umount")
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
            let mut cmd = Command::new("net");
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

    pub fn status(peer_ip: Option<&str>) -> StorageStatus {
        Self::status_with_share(peer_ip, None)
    }

    pub fn status_with_share(peer_ip: Option<&str>, share_hint: Option<&str>) -> StorageStatus {
        if let Some(rec) = detect_active_mount(peer_ip) {
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

        let ip = peer_ip.unwrap_or("");
        let planned_share = if let Some(pref) = Self::get_preferred_peer_share() {
            pref
        } else if let Some(hint) = share_hint {
            hint.to_string()
        } else {
            "Not configured".to_string()
        };

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
    std::fs::read_to_string(active_mount_file())
        .ok()
        .and_then(|s| serde_json::from_str::<ActiveMountRecord>(&s).ok())
}

fn save_active_mount(rec: &ActiveMountRecord) {
    if let Ok(json) = serde_json::to_string_pretty(rec) {
        let _ = std::fs::write(active_mount_file(), json);
    }
}

fn clear_active_mount() {
    let _ = std::fs::remove_file(active_mount_file());
}

fn resolve_remote_share(peer_ip: &str, share_hint: Option<&str>) -> Option<String> {
    if let Some(pref) = StorageManager::get_preferred_peer_share() {
        return Some(pref);
    }
    if let Some(hint) = share_hint {
        let trimmed = hint.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // Dynamic remote SMB browse if no hint/override was set
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("smbutil")
            .args(["view", "-N", &format!("//guest@{}", peer_ip)])
            .output()
        {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                for line in txt.lines() {
                    let t = line.trim();
                    if t.is_empty()
                        || t.starts_with("Share")
                        || t.starts_with("---")
                        || t.contains("IPC$")
                    {
                        continue;
                    }
                    if let Some(name) = t.split_whitespace().next() {
                        if !name.ends_with('$') {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new("net");
        cmd.creation_flags(0x08000000);
        cmd.args(["view", &format!(r"\\{}", peer_ip)]);
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                let mut rows = false;
                for line in txt.lines() {
                    let t = line.trim();
                    if t.starts_with("----") {
                        rows = true;
                        continue;
                    }
                    if !rows || t.is_empty() || t.starts_with("The command") {
                        continue;
                    }
                    if let Some((name, _rest)) = t.split_once("Disk") {
                        let clean = name.trim();
                        if !clean.is_empty() && !clean.ends_with('$') {
                            return Some(clean.to_string());
                        }
                    }
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
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/sbin/mount").output().ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let saved = load_active_mount();

        for line in stdout.lines() {
            if !line.contains("(smbfs") {
                continue;
            }
            // Format: "//user@10.x.x.x/Share on /Volumes/Share (smbfs, ...)"
            let Some((src, rest)) = line.split_once(" on ") else {
                continue;
            };
            let Some((mount_path, _opts)) = rest.split_once(" (smbfs") else {
                continue;
            };
            let (ip_part, share_part) = parse_smbfs_source(src);
            if let Some(filter_ip) = peer_ip_filter {
                if !ip_part.is_empty() && ip_part != filter_ip {
                    continue;
                }
            } else if let Some(ref s) = saved {
                if mount_path != s.mount_path && ip_part != s.peer_ip {
                    continue;
                }
            } else {
                continue;
            }

            return Some(ActiveMountRecord {
                peer_ip: ip_part,
                remote_share: share_part,
                mount_path: mount_path.trim().to_string(),
            });
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let saved = load_active_mount();
        let mut cmd = Command::new("net");
        cmd.creation_flags(0x08000000);
        cmd.arg("use");
        let out = cmd.output().ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);

        for line in stdout.lines() {
            // Typical line: "OK           Z:        \\10.0.0.2\Public  ..."
            if !line.contains(r"\\") {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let Some(unc_idx) = tokens.iter().position(|t| t.starts_with(r"\\")) else {
                continue;
            };
            let unc = tokens[unc_idx];
            let trimmed_unc = unc.trim_start_matches('\\');
            let (host, share) = trimmed_unc.split_once('\\').unwrap_or((trimmed_unc, ""));
            let share_root = share.split('\\').next().unwrap_or("");
            if host.is_empty()
                || share_root.is_empty()
                || share_root.eq_ignore_ascii_case("IPC$")
                || share_root.ends_with('$')
            {
                continue;
            }

            if let Some(filter_ip) = peer_ip_filter {
                if host != filter_ip {
                    continue;
                }
            } else if let Some(ref s) = saved {
                if host != s.peer_ip {
                    continue;
                }
            } else {
                continue;
            }

            let drive = tokens
                .iter()
                .take(unc_idx)
                .find(|t| t.len() == 2 && t.ends_with(':'))
                .map(|d| format!("{}\\", d))
                .unwrap_or_else(|| unc.to_string());

            return Some(ActiveMountRecord {
                peer_ip: host.to_string(),
                remote_share: share.to_string(),
                mount_path: drive,
            });
        }
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = peer_ip_filter;
        None
    }
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
    let mut cmd = Command::new("net");
    cmd.creation_flags(0x08000000);
    cmd.arg("use");
    let out = cmd.output().ok()?;
    let txt = String::from_utf8_lossy(&out.stdout);
    for line in txt.lines() {
        if line.to_ascii_lowercase().contains(&unc.to_ascii_lowercase()) {
            for tok in line.split_whitespace() {
                if tok.len() == 2 && tok.ends_with(':') && tok.as_bytes()[0].is_ascii_alphabetic() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}
