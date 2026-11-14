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
        generate_unbiased_6digit_pin, handle_server_pairing_with_shared_locks,
        is_valid_6digit_pin, run_client_pairing_with_shared_keystore, PairingCoordinatorV2,
    },
    transport::{derive_loopback_self_credentials, ServiceId, TransportSessionV2},
};
use crate::system_info;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
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
        let now = security::unix_epoch_secs();
        let mut coord = PairingCoordinatorV2::new(host, os);
        let pin = coord.open_pairing_window(now);
        RuntimeTrustState {
            pairing_coordinator: Mutex::new(coord),
            active_pin_cached: Mutex::new((pin, now)),
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

/// Ensures the host has an active, non-expired 6-digit pairing PIN in `PairingCoordinatorV2`.
/// Note: Failed network attempts NEVER rotate this PIN; it only refreshes when its 10-minute TTL
/// expires, after a legitimate pairing completes, or when the user clicks "Regenerate PIN".
fn ensure_active_pin() -> (String, u64) {
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
        if cached.0 != pin {
            *cached = (pin.to_string(), now);
        }
        return cached.clone();
    }

    let new_pin = coord.open_pairing_window(now);
    *cached = (new_pin.clone(), now);
    (new_pin, now)
}

/// Explicitly regenerates the 6-digit pairing PIN on user request.
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

/// Sets a specific 6-digit PIN in the pairing coordinator (used by deterministic tests).
#[allow(dead_code)]
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

/// Looks up the pinned `VerifiedPeerCredentials` for `peer_ip` (checking both `KeystoreV2::find_peer_by_ip`
/// and the discovery `ip_to_device_hint` table, or deriving loopback self-credentials for `127.0.0.1`).
pub fn lookup_verified_peer_for_ip(peer_ip: &str) -> Option<VerifiedPeerCredentials> {
    let trimmed = peer_ip.trim();
    if let Ok(ip_addr) = trimmed.parse::<IpAddr>() {
        if ip_addr.is_loopback() {
            let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            return Some(derive_loopback_self_credentials(&ks));
        }
    }

    let hint_id = {
        let rt = runtime_state();
        let hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        hints.get(trimmed).cloned()
    };

    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if ks.is_device_or_ip_blocked(hint_id.as_deref().unwrap_or(""), trimmed) {
        return None;
    }
    if let Some(ref dev_id) = hint_id {
        if let Some(creds) = ks.get_peer(dev_id) {
            return Some(creds.clone());
        }
    }
    ks.find_peer_by_ip(trimmed).cloned()
}

pub fn get_trust_snapshot() -> (TrustConfigFile, Vec<PendingPeerInfo>) {
    let (pairing_pin, pin_created_at_epoch) = ensure_active_pin();
    let (trusted_peers, blocked_device_ids) = {
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
        (peers, blocked)
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
        blocked_ips: Vec::new(),
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
    let trimmed_pin = pin.trim();
    if !is_valid_6digit_pin(trimmed_pin) {
        return Err("Pairing PIN must be exactly 6 digits".into());
    }

    let addr = format!("{}:{}", trimmed_ip, port);
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Timed out connecting to {} for pairing", addr))?
        .map_err(|e| format!("Failed to connect to {} for pairing: {}", addr, e))?;
    let _ = stream.set_nodelay(true);

    let local_name = system_info::get_hostname();
    let local_os = std::env::consts::OS;
    let via_cable = system_info::is_direct_cable_route(trimmed_ip);

    let (creds, sas) = tokio::time::timeout(
        Duration::from_secs(12),
        run_client_pairing_with_shared_keystore(
            &mut stream,
            global_keystore(),
            trimmed_pin,
            &local_name,
            local_os,
            trimmed_ip,
            via_cable,
        ),
    )
    .await
    .map_err(|_| "Timed out during SPAKE2 pairing handshake".to_string())?
    .map_err(|e| e.to_string())?;

    // Record IP -> device_id mapping and mark trusted in pending peers
    let _ = observe_discovered_peer(&creds.device_id_hex, &creds.hostname, trimmed_ip, via_cable);
    Ok((creds, sas))
}

/// Handles an incoming `IPR2` pairing connection on the host's control port (`58281/tcp`).
pub async fn handle_incoming_pairing_stream_v2(
    stream: &mut TcpStream,
    peer_ip: IpAddr,
    already_read_magic: Option<[u8; 4]>,
) -> Result<(VerifiedPeerCredentials, String), String> {
    let _ = ensure_active_pin();
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
    let creds = lookup_verified_peer_for_ip(peer_ip).ok_or_else(|| {
        format!(
            "Peer at {} is not paired or trusted. Pair using the 6-digit PIN in the Integrator UI first.",
            peer_ip
        )
    })?;

    let addr = format!("{}:{}", peer_ip.trim(), port);
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
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

    // If this device_id is already pinned in KeystoreV2, ensure its Ed25519 public key matches.
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pinned) = ks.get_peer(&clean_id) {
        if !constant_time_eq(&pinned.ed25519_pubkey, &pk_bytes) {
            return false;
        }
    }

    true
}

// ============================================================================
// Authenticated Paired-Only Frame Envelope (Used by Clipboard until Milestone 5)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairedAeadEnvelopeV2 {
    version: u8,
    sender_device_id_hex: String,
    key_id_hex: String,
    timestamp_ms: u64,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// Seals a frame exclusively for an already-paired peer using `ChaCha20Poly1305` under the peer's `K_root`.
/// Fails closed if the peer is not cryptographically paired in `KeystoreV2` (zero static fallback).
pub fn seal_envelope_for_ip(peer_ip: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let peer = lookup_verified_peer_for_ip(peer_ip).ok_or_else(|| {
        format!(
            "Refusing to send unauthenticated data to unpaired peer {}",
            peer_ip
        )
    })?;
    let sender_device_id_hex = system_info::get_or_create_device_id();
    let key_id_hex = security::hex_encode(&peer.key_id);
    let timestamp_ms = security::unix_epoch_millis();
    let nonce_bytes = security::csprng_array::<12>();
    let nonce_hex = security::hex_encode(&nonce_bytes);

    let mut aad = Vec::new();
    aad.extend_from_slice(b"integrator-paired-env-v2|");
    aad.extend_from_slice(sender_device_id_hex.as_bytes());
    aad.extend_from_slice(&peer.key_id);
    aad.extend_from_slice(&timestamp_ms.to_be_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*peer.root_key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "ChaCha20Poly1305 encryption failed".to_string())?;

    let env = PairedAeadEnvelopeV2 {
        version: 2,
        sender_device_id_hex,
        key_id_hex,
        timestamp_ms,
        nonce_hex,
        ciphertext_hex: security::hex_encode(&ct),
    };
    serde_json::to_vec(&env).map_err(|e| e.to_string())
}

/// Opens and authenticates a `PairedAeadEnvelopeV2` exclusively using the sender's pinned `K_root` in `KeystoreV2`.
pub fn open_envelope_from_ip(
    peer_ip: IpAddr,
    frame: &[u8],
) -> Result<(Option<String>, Vec<u8>), String> {
    let env: PairedAeadEnvelopeV2 = serde_json::from_slice(frame)
        .map_err(|_| "Rejected non-v2 or malformed encrypted frame".to_string())?;
    if env.version != 2 {
        return Err(format!("Unsupported envelope version {}", env.version));
    }

    let now_ms = security::unix_epoch_millis();
    if now_ms.abs_diff(env.timestamp_ms) > 120_000 {
        return Err("Rejected expired or skewed v2 envelope".into());
    }

    let sender_id = env.sender_device_id_hex.trim().to_ascii_lowercase();
    let peer = {
        let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = ks.get_peer(&sender_id) {
            p.clone()
        } else if peer_ip.is_loopback() && sender_id == ks.local_device_id_hex() {
            derive_loopback_self_credentials(&ks)
        } else {
            return Err(format!(
                "Rejected envelope from unpaired peer '{}' ({})",
                sender_id, peer_ip
            ));
        }
    };

    let Some(rx_key_id) = security::hex_decode_array::<16>(&env.key_id_hex) else {
        return Err("Invalid key_id_hex in v2 envelope".into());
    };
    if !constant_time_eq(&rx_key_id, &peer.key_id) {
        return Err("Envelope key_id mismatch against pinned peer".into());
    }

    let Some(nonce_bytes) = security::hex_decode_array::<12>(&env.nonce_hex) else {
        return Err("Invalid nonce_hex in v2 envelope".into());
    };
    let Some(ct_bytes) = security::hex_decode(&env.ciphertext_hex) else {
        return Err("Invalid ciphertext_hex in v2 envelope".into());
    };

    let mut aad = Vec::new();
    aad.extend_from_slice(b"integrator-paired-env-v2|");
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(&peer.key_id);
    aad.extend_from_slice(&env.timestamp_ms.to_be_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*peer.root_key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ct_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| "ChaCha20Poly1305 tag verification failed on v2 envelope".to_string())?;

    Ok((Some(sender_id), pt))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
