//! Peer trust and pairing store (`~/.usbc_clipboard_cache/trusted_peers.json`).
//!
//! Ensures arbitrary LAN/Wi-Fi devices on public networks cannot trigger
//! display changes, file transfers, or clipboard pushes without user trust,
//! while keeping direct USB-C / Thunderbolt cable links ergonomic by default.

use crate::system_info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecord {
    pub device_id: String,
    pub hostname: String,
    pub last_ip: String,
    pub paired_at_epoch: u64,
    pub via_direct_cable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfigFile {
    pub auto_trust_direct_cable: bool,
    pub require_pairing_on_lan: bool,
    pub pairing_pin: String,
    pub trusted_peers: Vec<TrustedPeerRecord>,
    pub blocked_device_ids: Vec<String>,
}

impl Default for TrustConfigFile {
    fn default() -> Self {
        Self {
            auto_trust_direct_cable: true,
            require_pairing_on_lan: true,
            pairing_pin: generate_pin(),
            trusted_peers: Vec::new(),
            blocked_device_ids: Vec::new(),
        }
    }
}

struct TrustState {
    config: TrustConfigFile,
    /// Maps active peer IP -> observed remote device_id from discovery/RPC.
    ip_to_device: HashMap<String, String>,
    /// Tracks LAN peers seen via discovery that await user approval.
    pending_peers: HashMap<String, PendingPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPeerInfo {
    pub device_id: String,
    pub hostname: String,
    pub ip: String,
    pub is_direct_cable: bool,
    pub trusted: bool,
    pub blocked: bool,
}

fn generate_pin() -> String {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(ns.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let digest = hasher.finalize();
    let n = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) % 900_000 + 100_000;
    format!("{:06}", n)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn config_path() -> std::path::PathBuf {
    system_info::app_data_dir().join("trusted_peers.json")
}

fn load_from_disk() -> TrustConfigFile {
    let p = config_path();
    if let Ok(txt) = std::fs::read_to_string(&p) {
        if let Ok(mut cfg) = serde_json::from_str::<TrustConfigFile>(&txt) {
            if cfg.pairing_pin.len() != 6 {
                cfg.pairing_pin = generate_pin();
            }
            return cfg;
        }
    }
    let cfg = TrustConfigFile::default();
    save_to_disk(&cfg);
    cfg
}

fn save_to_disk(cfg: &TrustConfigFile) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(config_path(), json);
    }
}

fn state() -> &'static Mutex<TrustState> {
    static TRUST: OnceLock<Mutex<TrustState>> = OnceLock::new();
    TRUST.get_or_init(|| {
        Mutex::new(TrustState {
            config: load_from_disk(),
            ip_to_device: HashMap::new(),
            pending_peers: HashMap::new(),
        })
    })
}

/// Record a discovered peer beacon and apply direct-cable auto-trust if enabled and not blocked.
pub fn observe_discovered_peer(device_id: &str, hostname: &str, ip: &str, via_direct_cable: bool) -> bool {
    if device_id.trim().is_empty() || ip.trim().is_empty() {
        return false;
    }
    let mut guard = state().lock().unwrap();
    guard.ip_to_device.insert(ip.to_string(), device_id.to_string());

    let blocked = guard.config.blocked_device_ids.iter().any(|id| id == device_id);
    if blocked {
        guard.pending_peers.insert(
            device_id.to_string(),
            PendingPeerInfo {
                device_id: device_id.to_string(),
                hostname: hostname.to_string(),
                ip: ip.to_string(),
                is_direct_cable: via_direct_cable,
                trusted: false,
                blocked: true,
            },
        );
        return false;
    }

    let already_trusted = if let Some(rec) = guard
        .config
        .trusted_peers
        .iter_mut()
        .find(|p| p.device_id == device_id)
    {
        if rec.last_ip != ip || rec.hostname != hostname {
            rec.last_ip = ip.to_string();
            rec.hostname = hostname.to_string();
            save_to_disk(&guard.config);
        }
        true
    } else {
        false
    };

    let auto_trusted = !already_trusted
        && guard.config.auto_trust_direct_cable
        && via_direct_cable;

    if auto_trusted {
        guard.config.trusted_peers.push(TrustedPeerRecord {
            device_id: device_id.to_string(),
            hostname: hostname.to_string(),
            last_ip: ip.to_string(),
            paired_at_epoch: epoch_secs(),
            via_direct_cable: true,
        });
        save_to_disk(&guard.config);
    }

    let trusted = already_trusted || auto_trusted || !guard.config.require_pairing_on_lan;
    guard.pending_peers.insert(
        device_id.to_string(),
        PendingPeerInfo {
            device_id: device_id.to_string(),
            hostname: hostname.to_string(),
            ip: ip.to_string(),
            is_direct_cable: via_direct_cable,
            trusted,
            blocked: false,
        },
    );
    trusted
}

pub fn trust_device(device_id: &str, hostname: &str, ip: &str, via_direct_cable: bool) {
    let mut guard = state().lock().unwrap();
    guard.config.blocked_device_ids.retain(|id| id != device_id);
    if let Some(rec) = guard
        .config
        .trusted_peers
        .iter_mut()
        .find(|p| p.device_id == device_id)
    {
        rec.hostname = hostname.to_string();
        rec.last_ip = ip.to_string();
    } else {
        guard.config.trusted_peers.push(TrustedPeerRecord {
            device_id: device_id.to_string(),
            hostname: hostname.to_string(),
            last_ip: ip.to_string(),
            paired_at_epoch: epoch_secs(),
            via_direct_cable,
        });
    }
    guard.ip_to_device.insert(ip.to_string(), device_id.to_string());
    if let Some(p) = guard.pending_peers.get_mut(device_id) {
        p.trusted = true;
        p.blocked = false;
    }
    save_to_disk(&guard.config);
}

pub fn verify_pin_and_trust(device_id: &str, hostname: &str, ip: &str, pin: &str) -> bool {
    let matches = {
        let guard = state().lock().unwrap();
        guard.config.pairing_pin == pin.trim()
    };
    if matches && !device_id.trim().is_empty() {
        let cable = system_info::is_direct_cable_route(ip);
        trust_device(device_id, hostname, ip, cable);
        true
    } else {
        false
    }
}

pub fn untrust_or_block_device(device_id: &str, block: bool) {
    let mut guard = state().lock().unwrap();
    guard.config.trusted_peers.retain(|p| p.device_id != device_id);
    if block && !guard.config.blocked_device_ids.iter().any(|id| id == device_id) {
        guard.config.blocked_device_ids.push(device_id.to_string());
    }
    if let Some(p) = guard.pending_peers.get_mut(device_id) {
        p.trusted = false;
        p.blocked = block;
    }
    save_to_disk(&guard.config);
}

pub fn set_trust_policy(auto_trust_direct_cable: bool, require_pairing_on_lan: bool) {
    let mut guard = state().lock().unwrap();
    guard.config.auto_trust_direct_cable = auto_trust_direct_cable;
    guard.config.require_pairing_on_lan = require_pairing_on_lan;
    save_to_disk(&guard.config);
}

pub fn regenerate_pin() -> String {
    let mut guard = state().lock().unwrap();
    guard.config.pairing_pin = generate_pin();
    save_to_disk(&guard.config);
    guard.config.pairing_pin.clone()
}

pub fn get_trust_snapshot() -> (TrustConfigFile, Vec<PendingPeerInfo>) {
    let guard = state().lock().unwrap();
    let peers: Vec<PendingPeerInfo> = guard.pending_peers.values().cloned().collect();
    (guard.config.clone(), peers)
}

/// Check whether an incoming TCP connection from `remote_addr` is authorized.
pub fn is_remote_addr_authorized(remote_addr: IpAddr) -> bool {
    if remote_addr.is_loopback() {
        return true;
    }
    let ip_str = remote_addr.to_string();
    let guard = state().lock().unwrap();

    if let Some(dev_id) = guard.ip_to_device.get(&ip_str) {
        if guard.config.blocked_device_ids.iter().any(|id| id == dev_id) {
            return false;
        }
        if guard.config.trusted_peers.iter().any(|p| &p.device_id == dev_id) {
            return true;
        }
    }

    if !guard.config.require_pairing_on_lan {
        return true;
    }

    drop(guard);
    let via_cable = system_info::is_direct_cable_route(&ip_str);
    let guard = state().lock().unwrap();
    guard.config.auto_trust_direct_cable && via_cable
}

pub fn is_device_trusted(device_id: &str) -> bool {
    let guard = state().lock().unwrap();
    if guard.config.blocked_device_ids.iter().any(|id| id == device_id) {
        return false;
    }
    guard.config.trusted_peers.iter().any(|p| p.device_id == device_id)
}
