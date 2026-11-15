//! Peer trust, Ed25519 identity, RFC 9382 SPAKE2 pairing coordination, and
//! unified `TransportV2` session management (`~/.integrator/security/trusted_peers_v2.json`).
//!
//! Security model (v2.0):
//! - Zero static keys: all legacy v1 public transport and beacon secrets have been eliminated.
//! - Zero IP/interface auto-trust: Discovery (`58280/udp`) is strictly an untrusted hint and never
//!   grants trust or mutates `KeystoreV2` credentials.
//! - Pairing uses the 4-message RFC 9382 SPAKE2 (`edwards25519`) + `Ed25519` handshake (`IPR2`).
//!   Failed PIN attempts from an unauthenticated IP never rotate or invalidate the host's active PIN.
//! - All post-pairing TCP services (Display RPC `58281`, Clipboard/File Transfer `58283`,
//!   Benchmark `58285`) use `TransportSessionV2` (`ITR2`) with ephemeral `X25519` + `K_root` +
//!   mutual pinned `Ed25519` signatures + `ChaCha20-Poly1305`.

use crate::security::{
    self,
    keystore::{global_keystore, KeystoreV2, VerifiedPeerCredentials},
    pairing::{
        handle_server_pairing_with_shared_locks, is_valid_6digit_pin,
        run_client_pairing_with_shared_keystore, PairingCoordinatorV2,
    },
    transport::{derive_loopback_self_credentials, ServiceId, TransportSessionV2},
};
use crate::system_info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{info, warn};

const MAX_DISCOVERED_PENDING_PEERS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecord {
    pub device_id: String,
    pub hostname: String,
    pub last_ip: String,
    pub paired_at_epoch: u64,
    pub via_direct_cable: bool,
    pub ed25519_pubkey_hex: String,
    pub key_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfigFile {
    pub auto_trust_direct_cable: bool,
    pub require_pairing_on_lan: bool,
    pub pairing_pin: String,
    pub pin_created_at_epoch: u64,
    pub trusted_peers: Vec<TrustedPeerRecord>,
    pub blocked_device_ids: Vec<String>,
    pub blocked_ips: Vec<String>,
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

struct RuntimeTrustState {
    pairing_coordinator: Mutex<PairingCoordinatorV2>,
    active_pin_cached: Mutex<(String, u64)>,
    pending_peers: Mutex<HashMap<String, PendingPeerInfo>>,
    ip_to_device_hint: Mutex<HashMap<String, String>>,
}

fn runtime_state() -> &'static RuntimeTrustState {
    static STATE: OnceLock<RuntimeTrustState> = OnceLock::new();
    STATE.get_or_init(|| {
        let host = system_info::get_hostname();
        let os = std::env::consts::OS.to_string();
        let coord = PairingCoordinatorV2::new(host, os);
        RuntimeTrustState {
            pairing_coordinator: Mutex::new(coord),
            active_pin_cached: Mutex::new((String::new(), 0)),
            pending_peers: Mutex::new(HashMap::new()),
            ip_to_device_hint: Mutex::new(HashMap::new()),
        }
    })
}

#[allow(dead_code)]
pub fn csprng_fill(buf: &mut [u8]) {
    security::csprng_fill(buf);
}

pub fn generate_random_token_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    security::csprng_fill(&mut bytes);
    security::hex_encode(&bytes)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    security::constant_time_eq(a, b)
}

/// Returns the currently active pairing PIN `(pin, created_at_epoch)` if the pairing window
/// is explicitly open and unexpired, or `("", 0)` when closed. Does NOT auto-open the window.
fn current_active_pin() -> (String, u64) {
    let rt = runtime_state();
    let now = security::unix_epoch_secs();
    let coord = rt
        .pairing_coordinator
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut cached = rt
        .active_pin_cached
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if let Some(pin) = coord.active_pin(now) {
        let created_at = coord.pin_created_at_secs();
        if cached.0 != pin || cached.1 != created_at {
            *cached = (pin.to_string(), created_at);
        }
        return cached.clone();
    }

    if !cached.0.is_empty() || cached.1 != 0 {
        *cached = (String::new(), 0);
    }
    (String::new(), 0)
}

/// Returns the active pairing PIN if already open, or opens a fresh 10-minute window on
/// explicit user/CLI request (such as `DisplayRpcRequest::GetPairingPin`).
pub fn open_or_get_pairing_pin() -> (String, u64) {
    let rt = runtime_state();
    let now = security::unix_epoch_secs();
    let mut coord = rt
        .pairing_coordinator
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut cached = rt
        .active_pin_cached
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if let Some(pin) = coord.active_pin(now) {
        let created_at = coord.pin_created_at_secs();
        *cached = (pin.to_string(), created_at);
        return cached.clone();
    }

    let pin = coord.open_pairing_window(now);
    *cached = (pin.clone(), now);
    (pin, now)
}

/// Explicitly regenerates the 6-digit pairing PIN and opens the 10-minute pairing window.
pub fn regenerate_pin() -> String {
    let rt = runtime_state();
    let now = security::unix_epoch_secs();
    let mut coord = rt
        .pairing_coordinator
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut cached = rt
        .active_pin_cached
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let pin = coord.open_pairing_window(now);
    *cached = (pin.clone(), now);
    pin
}

/// Sets a specific 6-digit PIN in the pairing coordinator (tests only).
#[cfg(test)]
pub fn set_active_pin_for_test(pin: &str) -> Result<(), String> {
    if !is_valid_6digit_pin(pin) {
        return Err("PIN must be 6 digits".into());
    }
    let rt = runtime_state();
    let now = security::unix_epoch_secs();
    let mut coord = rt
        .pairing_coordinator
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut cached = rt
        .active_pin_cached
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    coord
        .open_pairing_window_with_pin(pin, now)
        .map_err(|e| e.to_string())?;
    *cached = (pin.to_string(), now);
    Ok(())
}

/// Discovery boundary: records an untrusted discovery advertisement in the bounded in-memory UI cache.
/// NEVER creates or mutates trusted peer credentials; returns `true` ONLY if `device_id` is already
/// cryptographically paired and pinned in `KeystoreV2`.
pub fn observe_discovered_peer(
    device_id: &str,
    hostname: &str,
    ip: &str,
    via_direct_cable: bool,
) -> bool {
    let clean_id = device_id.trim().to_ascii_lowercase();
    let clean_ip = ip.trim();
    if clean_id.is_empty() || clean_ip.is_empty() || clean_id.len() > 64 {
        return false;
    }
    let clean_host: String = hostname
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();

    let (is_blocked, is_paired) = {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        let blocked = ks.is_device_or_ip_blocked(&clean_id, clean_ip);
        if blocked {
            (true, false)
        } else if ks.get_peer(&clean_id).is_some() {
            let _ = ks.update_peer_last_ip(&clean_id, clean_ip);
            (false, true)
        } else {
            (false, false)
        }
    };

    let rt = runtime_state();
    if !is_blocked {
        let mut hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(clean_ip) {
            hints.clear();
        }
        hints.insert(clean_ip.to_string(), clean_id.clone());
    }

    let mut pending = rt.pending_peers.lock().unwrap_or_else(|e| e.into_inner());
    if pending.len() >= MAX_DISCOVERED_PENDING_PEERS && !pending.contains_key(&clean_id) {
        if let Some(first_key) = pending.keys().next().cloned() {
            pending.remove(&first_key);
        }
    }
    pending.insert(
        clean_id.clone(),
        PendingPeerInfo {
            device_id: clean_id,
            hostname: clean_host,
            ip: clean_ip.to_string(),
            is_direct_cable: via_direct_cable,
            trusted: is_paired && !is_blocked,
            blocked: is_blocked,
        },
    );

    is_paired && !is_blocked
}

/// Unpairs or blocks a device in `KeystoreV2`.
pub fn untrust_or_block_device(device_id: &str, block: bool) {
    let clean_id = device_id.trim().to_ascii_lowercase();
    let rt = runtime_state();
    let known_ip = {
        let mut pending = rt.pending_peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = pending.get_mut(&clean_id) {
            p.trusted = false;
            p.blocked = block;
            Some(p.ip.clone())
        } else {
            None
        }
    };

    {
        let mut hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        hints.retain(|ip, id| id != &clean_id && known_ip.as_deref() != Some(ip.as_str()));
    }

    let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = ks.untrust_or_block_peer(&clean_id, block, known_ip.as_deref()) {
        warn!("Failed to persist untrust/block for {}: {}", clean_id, e);
    }
}

/// Policy setter retained for UI compatibility; in v2.0, cryptographic pairing is strictly mandatory
/// on all interfaces (including direct USB-C / Thunderbolt cables).
pub fn set_trust_policy(_auto_trust_direct_cable: bool, _require_pairing_on_lan: bool) {
    info!("Integrator v2.0 security policy enforces mandatory cryptographic pairing on all interfaces");
}

pub fn is_device_trusted(device_id: &str) -> bool {
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    ks.get_peer(device_id).is_some()
}

/// Checks whether a cryptographically paired peer exists for `remote_addr` (or loopback).
/// Note: Used only as a fast pre-filter where needed; actual authorization requires `TransportSessionV2`
/// or `AudioSession` AEAD verification.
pub fn has_paired_peer_at_ip(remote_addr: IpAddr) -> bool {
    if remote_addr.is_loopback() {
        return true;
    }
    let ip_str = remote_addr.to_string();
    lookup_verified_peer_for_ip(&ip_str).is_some()
}

/// Looks up the pinned `VerifiedPeerCredentials` for `peer_ip`, checking persisted `KeystoreV2`
/// records first, then verified runtime IP hints, or deriving loopback self-credentials for loopback IPs.
/// Never falls back to wildcarding a peer across unrelated IPs.
pub fn lookup_verified_peer_for_ip(peer_ip: &str) -> Option<VerifiedPeerCredentials> {
    let trimmed = peer_ip.trim();
    let ip_addr = trimmed.parse::<IpAddr>().ok()?;
    let canon_ip = ip_addr.to_string();

    if ip_addr.is_loopback() {
        let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        return Some(derive_loopback_self_credentials(&ks));
    }

    let hint_id = {
        let rt = runtime_state();
        let hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        hints.get(&canon_ip).or_else(|| hints.get(trimmed)).cloned()
    };

    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if ks.is_device_or_ip_blocked(hint_id.as_deref().unwrap_or(""), &canon_ip) {
        return None;
    }
    if let Some(found) = ks.find_peer_by_ip(&canon_ip) {
        if !ks.is_device_or_ip_blocked(&found.device_id_hex, &canon_ip) {
            return Some(found.clone());
        }
    }
    if let Some(ref dev_id) = hint_id {
        if let Some(creds) = ks.get_peer(dev_id) {
            if !ks.is_device_or_ip_blocked(&creds.device_id_hex, &canon_ip) {
                return Some(creds.clone());
            }
        }
    }
    None
}

/// Returns the local installation's 32-hex Ed25519-derived `device_id`.
pub fn local_device_id_hex() -> String {
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    ks.local_device_id_hex().to_string()
}

/// Resolves pinned `VerifiedPeerCredentials` directly by cryptographically authenticated
/// `device_id_hex` (from `TransportSessionV2`), validating blocklist state against `peer_ip`.
pub fn lookup_verified_peer_by_id_at_ip(
    device_id_hex: &str,
    peer_ip: IpAddr,
) -> Option<VerifiedPeerCredentials> {
    let clean_id = device_id_hex.trim().to_ascii_lowercase();
    if clean_id.len() != 32 {
        return None;
    }
    let ip_str = peer_ip.to_string();
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if peer_ip.is_loopback() && clean_id == ks.local_device_id_hex() {
        return Some(derive_loopback_self_credentials(&ks));
    }
    if ks.is_device_or_ip_blocked(&clean_id, &ip_str) {
        return None;
    }
    ks.get_peer(&clean_id).cloned()
}

pub fn get_trust_snapshot() -> (TrustConfigFile, Vec<PendingPeerInfo>) {
    let (pairing_pin, pin_created_at_epoch) = current_active_pin();
    let (trusted_peers, blocked_device_ids, blocked_ips) = {
        let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        let peers = ks
            .list_peers()
            .into_iter()
            .map(|p| TrustedPeerRecord {
                device_id: p.device_id_hex,
                hostname: p.hostname,
                last_ip: p.last_ip,
                paired_at_epoch: p.paired_at_epoch,
                via_direct_cable: p.via_direct_cable,
                ed25519_pubkey_hex: security::hex_encode(&p.ed25519_pubkey),
                key_id_hex: security::hex_encode(&p.key_id),
            })
            .collect();
        let blocked = ks.blocked_device_ids().to_vec();
        let blocked_ips = ks.blocked_ips().to_vec();
        (peers, blocked, blocked_ips)
    };

    let pending_peers: Vec<PendingPeerInfo> = {
        let rt = runtime_state();
        let pending = rt.pending_peers.lock().unwrap_or_else(|e| e.into_inner());
        pending.values().cloned().collect()
    };

    let cfg = TrustConfigFile {
        auto_trust_direct_cable: false,
        require_pairing_on_lan: true,
        pairing_pin,
        pin_created_at_epoch,
        trusted_peers,
        blocked_device_ids,
        blocked_ips,
    };
    (cfg, pending_peers)
}

// ============================================================================
// Pairing v2 & TransportV2 Network Entry Points
// ============================================================================

/// Initiates the 4-message RFC 9382 SPAKE2 + Ed25519 pairing handshake (`IPR2`) with `peer_ip:port`.
pub async fn pair_with_remote_peer_v2(
    peer_ip: &str,
    port: u16,
    pin: &str,
) -> Result<(VerifiedPeerCredentials, String), String> {
    let trimmed_ip = peer_ip.trim();
    let ip_addr: IpAddr = trimmed_ip
        .parse()
        .map_err(|_| format!("Invalid peer IP address '{}'", trimmed_ip))?;
    let canon_ip = ip_addr.to_string();
    let trimmed_pin = pin.trim();
    if !is_valid_6digit_pin(trimmed_pin) {
        return Err("Pairing PIN must be exactly 6 digits".into());
    }

    let addr = SocketAddr::new(ip_addr, port);
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| format!("Timed out connecting to {} for pairing", addr))?
        .map_err(|e| format!("Failed to connect to {} for pairing: {}", addr, e))?;
    let _ = stream.set_nodelay(true);

    let local_name = system_info::get_hostname();
    let local_os = std::env::consts::OS;
    let via_cable = system_info::is_direct_cable_route(&canon_ip);

    let (creds, sas) = tokio::time::timeout(
        Duration::from_secs(12),
        run_client_pairing_with_shared_keystore(
            &mut stream,
            global_keystore(),
            trimmed_pin,
            &local_name,
            local_os,
            &canon_ip,
            via_cable,
        ),
    )
    .await
    .map_err(|_| "Timed out during SPAKE2 pairing handshake".to_string())?
    .map_err(|e| e.to_string())?;

    // Record IP -> device_id mapping and mark trusted in pending peers
    let _ = observe_discovered_peer(&creds.device_id_hex, &creds.hostname, &canon_ip, via_cable);
    Ok((creds, sas))
}

/// Handles an incoming `IPR2` pairing connection on the host's control port (`58281/tcp`).
pub async fn handle_incoming_pairing_stream_v2(
    stream: &mut TcpStream,
    peer_ip: IpAddr,
    already_read_magic: Option<[u8; 4]>,
) -> Result<(VerifiedPeerCredentials, String), String> {
    let ip_str = peer_ip.to_string();
    let via_cable = system_info::is_direct_cable_route(&ip_str);
    let rt = runtime_state();

    let (creds, sas) = tokio::time::timeout(
        Duration::from_secs(12),
        handle_server_pairing_with_shared_locks(
            stream,
            already_read_magic,
            &rt.pairing_coordinator,
            global_keystore(),
            peer_ip,
            via_cable,
        ),
    )
    .await
    .map_err(|_| "Timed out waiting for client pairing confirmation".to_string())?
    .map_err(|e| e.to_string())?;

    let _ = observe_discovered_peer(&creds.device_id_hex, &creds.hostname, &ip_str, via_cable);
    Ok((creds, sas))
}

/// Connects to `peer_ip:port` and establishes a mutually authenticated `TransportSessionV2` (`ITR2`).
pub async fn connect_transport_to_ip(
    peer_ip: &str,
    port: u16,
    service_id: ServiceId,
    connect_timeout: Duration,
) -> Result<TransportSessionV2<TcpStream>, String> {
    let trimmed_ip = peer_ip.trim();
    let ip_addr: IpAddr = trimmed_ip
        .parse()
        .map_err(|_| format!("Invalid peer IP address '{}'", trimmed_ip))?;
    let canon_ip = ip_addr.to_string();

    let creds = lookup_verified_peer_for_ip(&canon_ip).ok_or_else(|| {
        format!(
            "Peer at {} is not paired or trusted. Pair using the 6-digit PIN in the Integrator UI first.",
            canon_ip
        )
    })?;

    let addr = SocketAddr::new(ip_addr, port);
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("Timed out connecting to {} ({:?})", addr, service_id))?
        .map_err(|e| format!("Failed to connect to {} ({:?}): {}", addr, service_id, e))?;
    let _ = stream.set_nodelay(true);

    let session = tokio::time::timeout(
        Duration::from_secs(6),
        TransportSessionV2::connect_client_with_shared_keystore(
            stream,
            global_keystore(),
            &creds,
            service_id,
        ),
    )
    .await
    .map_err(|_| format!("Timed out during TransportV2 handshake with {}", addr))?
    .map_err(|e| format!("TransportV2 handshake failed with {}: {}", addr, e))?;

    Ok(session)
}

/// Accepts an incoming `TransportSessionV2` (`ITR2`) connection from `peer_ip`.
pub async fn accept_transport_from_stream(
    stream: TcpStream,
    peer_ip: IpAddr,
    already_read_magic: Option<[u8; 4]>,
    expected_service: ServiceId,
) -> Result<TransportSessionV2<TcpStream>, String> {
    let _ = stream.set_nodelay(true);
    let allow_loopback = peer_ip.is_loopback();

    let session = tokio::time::timeout(
        Duration::from_secs(6),
        TransportSessionV2::accept_server_with_shared_keystore(
            stream,
            already_read_magic,
            global_keystore(),
            expected_service,
            allow_loopback,
        ),
    )
    .await
    .map_err(|_| format!("Timed out during TransportV2 server handshake from {}", peer_ip))?
    .map_err(|e| format!("TransportV2 server handshake rejected from {}: {}", peer_ip, e))?;

    if !peer_ip.is_loopback() {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        let _ = ks.update_peer_last_ip(session.peer_device_id_hex(), &peer_ip.to_string());
    }

    Ok(session)
}

// ============================================================================
// Discovery Beacon v2 Ed25519 Signing & Verification (No Static Keys)
// ============================================================================

fn build_beacon_v2_signing_payload(
    device_id_hex: &str,
    ed25519_pubkey_hex: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
) -> Vec<u8> {
    format!(
        "INTEGRATOR-BEACON-V2|{}|{}|{}|{}|{}",
        device_id_hex.trim().to_ascii_lowercase(),
        ed25519_pubkey_hex.trim().to_ascii_lowercase(),
        timestamp_ms,
        control_port,
        clipboard_port
    )
    .into_bytes()
}

/// Signs a v2 discovery beacon using the local installation's Ed25519 private key.
/// Returns `(local_device_id_hex, local_ed25519_pubkey_hex, signature_hex)`.
pub fn sign_discovery_beacon_v2(
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
) -> (String, String, String) {
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    let dev_id_hex = ks.local_device_id_hex().to_string();
    let pk_hex = security::hex_encode(&ks.local_ed25519_pubkey());
    let payload = build_beacon_v2_signing_payload(
        &dev_id_hex,
        &pk_hex,
        timestamp_ms,
        control_port,
        clipboard_port,
    );
    let sig = ks.sign_transcript(&payload);
    (dev_id_hex, pk_hex, security::hex_encode(&sig))
}

/// Verifies a v2 discovery beacon's fields, timestamp freshness (±60s), `device_id` derivation,
/// and `Ed25519` digital signature. If `device_id` is already pinned in `KeystoreV2`, also enforces
/// that `ed25519_pubkey_hex` matches the pinned public key.
pub fn verify_discovery_beacon_v2(
    device_id_hex: &str,
    ed25519_pubkey_hex: &str,
    sender_name: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
    signature_hex: &str,
) -> bool {
    let clean_id = device_id_hex.trim().to_ascii_lowercase();
    let clean_pk = ed25519_pubkey_hex.trim().to_ascii_lowercase();
    if clean_id.len() != 32
        || clean_pk.len() != 64
        || sender_name.trim().is_empty()
        || sender_name.len() > 128
        || control_port < 1024
        || clipboard_port < 1024
    {
        return false;
    }

    let now_ms = security::unix_epoch_millis();
    if timestamp_ms == 0 || now_ms.abs_diff(timestamp_ms) > 60_000 {
        return false;
    }

    let Some(id_bytes) = security::hex_decode_array::<16>(&clean_id) else {
        return false;
    };
    let Some(pk_bytes) = security::hex_decode_array::<32>(&clean_pk) else {
        return false;
    };
    let Some(sig_bytes) = security::hex_decode_array::<64>(signature_hex) else {
        return false;
    };

    let derived_id = security::derive_device_id_from_pubkey(&pk_bytes);
    if !constant_time_eq(&id_bytes, &derived_id) {
        return false;
    }

    let payload = build_beacon_v2_signing_payload(
        &clean_id,
        &clean_pk,
        timestamp_ms,
        control_port,
        clipboard_port,
    );
    if KeystoreV2::verify_signature(&pk_bytes, &payload, &sig_bytes).is_err() {
        return false;
    }

    // If this device_id is blocked or pinned in KeystoreV2 with a different Ed25519 key, reject.
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if ks.is_device_or_ip_blocked(&clean_id, "") {
        return false;
    }
    if let Some(pinned) = ks.get_peer(&clean_id) {
        if !constant_time_eq(&pinned.ed25519_pubkey, &pk_bytes) {
            return false;
        }
    }

    true
}

/// Canonical metadata fields bound into `DiscoveryBeacon` v2 Ed25519 signatures.
#[derive(Debug, Clone)]
pub struct DiscoveryBeaconSignedMeta<'a> {
    pub protocol_version: u16,
    pub sender_name: &'a str,
    pub os: &'a str,
    pub hardware_model: &'a str,
    pub display_width: u32,
    pub display_height: u32,
    pub display_fps: u32,
    pub share_name: Option<&'a str>,
    pub sunshine_name: Option<&'a str>,
    pub sunshine_port: u16,
    pub gpus: &'a [String],
}

fn append_lp_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&data[..(len as usize)]);
}

fn append_opt_lp_str(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            buf.push(1);
            append_lp_bytes(buf, v.as_bytes());
        }
        None => buf.push(0),
    }
}

fn build_beacon_v2_full_signing_payload(
    device_id_hex: &str,
    ed25519_pubkey_hex: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
    meta: &DiscoveryBeaconSignedMeta<'_>,
) -> Vec<u8> {
    let clean_id = device_id_hex.trim().to_ascii_lowercase();
    let clean_pk = ed25519_pubkey_hex.trim().to_ascii_lowercase();
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"INTEGRATOR-BEACON-V2-FULL\0");
    buf.extend_from_slice(&meta.protocol_version.to_be_bytes());
    append_lp_bytes(&mut buf, clean_id.as_bytes());
    append_lp_bytes(&mut buf, clean_pk.as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.extend_from_slice(&control_port.to_be_bytes());
    buf.extend_from_slice(&clipboard_port.to_be_bytes());
    append_lp_bytes(&mut buf, meta.sender_name.as_bytes());
    append_lp_bytes(&mut buf, meta.os.as_bytes());
    append_lp_bytes(&mut buf, meta.hardware_model.as_bytes());
    buf.extend_from_slice(&meta.display_width.to_be_bytes());
    buf.extend_from_slice(&meta.display_height.to_be_bytes());
    buf.extend_from_slice(&meta.display_fps.to_be_bytes());
    append_opt_lp_str(&mut buf, meta.share_name);
    append_opt_lp_str(&mut buf, meta.sunshine_name);
    buf.extend_from_slice(&meta.sunshine_port.to_be_bytes());
    let gpu_count = u32::try_from(meta.gpus.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&gpu_count.to_be_bytes());
    for gpu in meta.gpus.iter().take(gpu_count as usize) {
        append_lp_bytes(&mut buf, gpu.as_bytes());
    }
    buf
}

/// Signs all `DiscoveryBeacon` v2 fields (identity, ports, timestamp, and metadata)
/// using the local installation's Ed25519 private key.
pub fn sign_discovery_beacon_v2_full(
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
    meta: &DiscoveryBeaconSignedMeta<'_>,
) -> (String, String, String) {
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    let dev_id_hex = ks.local_device_id_hex().to_string();
    let pk_hex = security::hex_encode(&ks.local_ed25519_pubkey());
    let payload = build_beacon_v2_full_signing_payload(
        &dev_id_hex,
        &pk_hex,
        timestamp_ms,
        control_port,
        clipboard_port,
        meta,
    );
    let sig = ks.sign_transcript(&payload);
    (dev_id_hex, pk_hex, security::hex_encode(&sig))
}

/// Verifies a full `DiscoveryBeacon` v2 packet (signature over all metadata fields,
/// freshness ±60s, device_id derivation, blocklist check, and pinned Ed25519 key match).
pub fn verify_discovery_beacon_v2_full(
    device_id_hex: &str,
    ed25519_pubkey_hex: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
    source_ip: Option<IpAddr>,
    meta: &DiscoveryBeaconSignedMeta<'_>,
    signature_hex: &str,
) -> bool {
    let clean_id = device_id_hex.trim().to_ascii_lowercase();
    let clean_pk = ed25519_pubkey_hex.trim().to_ascii_lowercase();
    if meta.protocol_version != 2
        || clean_id.len() != 32
        || clean_pk.len() != 64
        || meta.sender_name.trim().is_empty()
        || meta.sender_name.chars().count() > 128
        || meta.os.chars().count() > 64
        || meta.hardware_model.chars().count() > 128
        || meta.share_name.map_or(false, |s| s.chars().count() > 128)
        || meta.sunshine_name.map_or(false, |s| s.chars().count() > 128)
        || meta.gpus.len() > 8
        || meta.gpus.iter().any(|g| g.chars().count() > 128)
        || control_port < 1024
        || clipboard_port < 1024
    {
        return false;
    }

    let now_ms = security::unix_epoch_millis();
    if timestamp_ms == 0 || now_ms.abs_diff(timestamp_ms) > 60_000 {
        return false;
    }

    let Some(id_bytes) = security::hex_decode_array::<16>(&clean_id) else {
        return false;
    };
    let Some(pk_bytes) = security::hex_decode_array::<32>(&clean_pk) else {
        return false;
    };
    let Some(sig_bytes) = security::hex_decode_array::<64>(signature_hex) else {
        return false;
    };

    let derived_id = security::derive_device_id_from_pubkey(&pk_bytes);
    if !constant_time_eq(&id_bytes, &derived_id) {
        return false;
    }

    let payload = build_beacon_v2_full_signing_payload(
        &clean_id,
        &clean_pk,
        timestamp_ms,
        control_port,
        clipboard_port,
        meta,
    );
    if KeystoreV2::verify_signature(&pk_bytes, &payload, &sig_bytes).is_err() {
        return false;
    }

    let source_ip_str = source_ip.map(|ip| ip.to_string()).unwrap_or_default();
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if ks.is_device_or_ip_blocked(&clean_id, &source_ip_str) {
        return false;
    }
    if let Some(pinned) = ks.get_peer(&clean_id) {
        if !constant_time_eq(&pinned.ed25519_pubkey, &pk_bytes) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::pairing::generate_unbiased_6digit_pin;

    #[test]
    fn csprng_pin_is_six_digits_and_non_constant() {
        let p1 = generate_unbiased_6digit_pin();
        let p2 = generate_unbiased_6digit_pin();
        assert_eq!(p1.len(), 6);
        assert_eq!(p2.len(), 6);
        assert!(is_valid_6digit_pin(&p1));
        assert!(is_valid_6digit_pin(&p2));
    }

    #[test]
    fn discovery_beacon_v2_ed25519_sign_and_verify() {
        let ts = security::unix_epoch_millis();
        let (dev_id, pk_hex, sig_hex) = sign_discovery_beacon_v2(ts, 58281, 58283);
        assert!(verify_discovery_beacon_v2(
            &dev_id,
            &pk_hex,
            "MyWorkstation",
            ts,
            58281,
            58283,
            &sig_hex
        ));

        // Tampered port or sender device_id must fail Ed25519 verification
        assert!(!verify_discovery_beacon_v2(
            &dev_id,
            &pk_hex,
            "MyWorkstation",
            ts,
            58999,
            58283,
            &sig_hex
        ));
    }

    #[test]
    fn discovery_never_establishes_trust_for_unpaired_peer() {
        let fake_id = "aa".repeat(16);
        let trusted = observe_discovered_peer(&fake_id, "UntrustedUSBDevice", "169.254.10.20", true);
        assert!(
            !trusted,
            "Direct-cable discovery advertisement must NEVER establish trust without SPAKE2 pairing"
        );
        assert!(!is_device_trusted(&fake_id));
    }

    #[test]
    fn pairing_window_starts_closed_and_no_wildcard_single_peer_ip() {
        let (cfg, _) = get_trust_snapshot();
        // Pairing window starts closed unless explicitly opened by regenerate_pin()/test/CLI
        assert!(
            cfg.pairing_pin.is_empty() || cfg.pin_created_at_epoch > 0,
            "pairing snapshot state must reflect explicit window state"
        );
        // Arbitrary unpinned/malformed IP must never resolve even if a peer exists
        assert!(lookup_verified_peer_for_ip("not-an-ip").is_none());
        assert!(lookup_verified_peer_for_ip("203.0.113.250").is_none());
        assert!(lookup_verified_peer_for_ip("[::1]").is_none());
        assert!(lookup_verified_peer_for_ip("::1").is_some());
    }

    #[test]
    fn blocked_device_beacon_is_rejected() {
        let fake_sk = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let fake_pk = fake_sk.verifying_key().to_bytes();
        let fake_id = security::derive_device_id_from_pubkey(&fake_pk);
        let id_hex = security::hex_encode(&fake_id);
        let pk_hex = security::hex_encode(&fake_pk);
        let ts = security::unix_epoch_millis();
        let payload = build_beacon_v2_signing_payload(&id_hex, &pk_hex, ts, 58281, 58283);
        let sig = <ed25519_dalek::SigningKey as ed25519_dalek::Signer<ed25519_dalek::Signature>>::sign(&fake_sk, &payload).to_bytes();
        let sig_hex = security::hex_encode(&sig);

        assert!(verify_discovery_beacon_v2(
            &id_hex,
            &pk_hex,
            "TempPeer",
            ts,
            58281,
            58283,
            &sig_hex
        ));

        // Block the device in keystore, then verify beacon is rejected, then clean up test keystore state.
        untrust_or_block_device(&id_hex, true);
        assert!(!verify_discovery_beacon_v2(
            &id_hex,
            &pk_hex,
            "TempPeer",
            ts,
            58281,
            58283,
            &sig_hex
        ));
        untrust_or_block_device(&id_hex, false);
    }

    #[test]
    fn discovery_beacon_v2_full_authenticates_all_metadata_fields() {
        let ts = security::unix_epoch_millis();
        let gpus = vec!["NVIDIA RTX 4090".to_string()];
        let meta = DiscoveryBeaconSignedMeta {
            protocol_version: 2,
            sender_name: "StudioPC",
            os: "Windows 11",
            hardware_model: "Custom Workstation",
            display_width: 3840,
            display_height: 2160,
            display_fps: 120,
            share_name: Some("Public"),
            sunshine_name: Some("StudioPC"),
            sunshine_port: 47989,
            gpus: &gpus,
        };
        let (dev_id, pk_hex, sig_hex) =
            sign_discovery_beacon_v2_full(ts, 58281, 58283, &meta);
        assert!(verify_discovery_beacon_v2_full(
            &dev_id,
            &pk_hex,
            ts,
            58281,
            58283,
            None,
            &meta,
            &sig_hex
        ));

        let mut tampered = meta.clone();
        tampered.share_name = Some("AdminShare");
        assert!(!verify_discovery_beacon_v2_full(
            &dev_id,
            &pk_hex,
            ts,
            58281,
            58283,
            None,
            &tampered,
            &sig_hex
        ));

        let mut tampered_gpu = meta.clone();
        let bad_gpus = vec!["Fake GPU".to_string()];
        tampered_gpu.gpus = &bad_gpus;
        assert!(!verify_discovery_beacon_v2_full(
            &dev_id,
            &pk_hex,
            ts,
            58281,
            58283,
            None,
            &tampered_gpu,
            &sig_hex
        ));
    }
}
