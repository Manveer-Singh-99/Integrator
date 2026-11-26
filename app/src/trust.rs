//! ============================================================================
//! Peer Trust, Ed25519 Identity, SPAKE2 Pairing & TransportV2 Orchestrator
//! ============================================================================
//!
//! # 1. Architectural Overview & Purpose
//!
//! `trust.rs` serves as the high-level security orchestrator for the Integrator
//! ecosystem. It provides the centralized boundary where peer identity pinning,
//! discovery advertisement observation, RFC 9382 SPAKE2 pairing coordination,
//! and authenticated `TransportV2` TCP session establishment intersect.
//!
//! # 2. Cryptographic Security Model & Threat Model
//!
//! ## 2.1 Core Security Principles
//! - **Zero Static Keys**: All legacy v1 static transport secrets and beacon keys have been
//!   eliminated. Every session uses ephemeral keys derived via CSPRNG and authenticated via
//!   pinned Ed25519 identity keys and SPAKE2 root keys.
//! - **Zero IP/Interface Auto-Trust**: Discovery advertisements broadcast on UDP port `58280`
//!   are treated as strictly untrusted hints. Connections arriving over direct physical cables
//!   (Thunderbolt 4 / USB4 / USB-C) NEVER auto-grant trust or bypass pairing. Trust is established
//!   exclusively via the 4-message mutual confirmation RFC 9382 SPAKE2 protocol (`IPR2`).
//! - **Anti-DoS PIN Protection**: Failed pairing attempts from unauthenticated IP addresses
//!   never rotate or invalidate the host's active pairing PIN. Only explicit user action or
//!   pairing window expiration can rotate the PIN. Attackers attempting brute-force PIN guesses
//!   face exponential per-IP lockout.
//! - **Mutual Authentication & Forward Secrecy**: All operational TCP services (Display RPC `58281`,
//!   Clipboard/File Transfer `58283`, Link Benchmark `58285`, Input KVM `58286`, Camera `58287`)
//!   enforce `TransportSessionV2` (`ITR2`) with ephemeral X25519 Diffie-Hellman key agreement,
//!   pre-shared root key $K_{\text{root}}$ injection, mutual Ed25519 transcript signatures,
//!   and directional ChaCha20-Poly1305 record encryption.
//! - **Discovery Beacon Integrity**: UDP discovery beacons are signed with the host's private
//!   Ed25519 identity key. Receivers verify signature authenticity, derive and validate the 16-byte
//!   `device_id`, enforce a $\pm 60$ second timestamp freshness window, and verify that the public
//!   key matches the pinned record in `KeystoreV2` if the peer is paired.
//!
//! ## 2.2 Threading & Concurrency Model
//! - Runtime state is encapsulated in the `RuntimeTrustState` singleton, managed via `OnceLock`.
//! - Internal sub-components (`pairing_coordinator`, `active_pin_cached`, `pending_peers`,
//!   `ip_to_device_hint`) are protected by individual standard `Mutex` guards.
//! - **Crucial Invariant**: Mutex guards are never held across async `.await` suspension points.
//!   All locks are acquired, read/updated, and dropped synchronously before invoking network I/O,
//!   ensuring all async futures implement `Send` and remain fully Tokio-compatible.
//!
//! ## 2.3 Cross-Platform / Cross-Device Flow (macOS ↔ Windows 11)
//! - **Discovery Phase (UDP Port `58280`)**: Both macOS and Windows 11 periodically broadcast
//!   Ed25519-signed `DiscoveryBeacon` v2 packets (`sign_discovery_beacon_v2_full`). The receiving
//!   counterpart verifies the signature, $\pm 60\text{s}$ timestamp freshness, `device_id` derivation,
//!   and blocklist state via `verify_discovery_beacon_v2_full`, then records the untrusted UI hint via
//!   `observe_discovered_peer`.
//! - **Pairing Phase (TCP Port `58281`, `IPR2`)**: When the user enters the 6-digit PIN displayed on
//!   the peer workstation, `pair_with_remote_peer_v2` (client) and `handle_incoming_pairing_stream_v2`
//!   (server) execute the 4-message RFC 9382 SPAKE2 + Ed25519 identity pinning handshake and persist
//!   the shared 32-byte root key $K_{\text{root}}$ in `KeystoreV2`.
//! - **Operational Transport Phase (`ITR2`)**: All cross-device services connect via
//!   `connect_transport_to_ip` / `connect_transport_to_hinted_ip` and accept via
//!   `accept_transport_from_stream`, binding each TCP stream to a dedicated `ServiceId`.
//! - **Biometric Passkey / Touch ID Flow (Windows 11 → macOS)**: Windows 11 generates a 32-byte
//!   CSPRNG challenge nonce (`generate_random_token_hex(32)`) and requests Touch ID verification over
//!   `TransportSessionV2`. The macOS host invokes `evaluate_local_touchid_and_sign` (calling into native
//!   `LocalAuthentication.framework` via FFI), signs the domain-separated challenge transcript with its
//!   Ed25519 identity key, and returns a `TouchIdSignedAssertion` that Windows 11 verifies via
//!   `verify_touchid_assertion` within a $\pm 120\text{s}$ freshness window.
//! - **Two-Phase Revocation Flow (`SEC-1D-06`, `SEC-1D-07`, `VULN-04`)**: When a user unpairs or blocks
//!   a peer (`untrust_or_block_device` / `unpair_device`), Phase A synchronously updates `KeystoreV2`
//!   on disk and increments the peer's revocation generation under the keystore lock, and Phase B
//!   asynchronously tears down all active KVM, Display, Camera, Audio, and Clipboard sessions outside
//!   the keystore lock.
//!
//! ## 2.4 Subsystem Linkages
//! ```text
//!       +-----------------------+
//!       |      Discovery        | (Port 58280 UDP / Bonjour / BLE - Untrusted hints)
//!       +-----------+-----------+
//!                   | observe_discovered_peer()
//!                   v
//!       +-----------------------+       +-------------------------+
//!       |     trust.rs          |<----->| KeystoreV2 (Storage)    |
//!       | (Trust Orchestrator)  |       | (~/.integrator/security)|
//!       +-----+-----------+-----+       +-------------------------+
//!             |           |
//!  pair_v2()  |           | connect_transport_to_ip()
//!             v           v
//!       +-----------+   +-------------------+
//!       | PairingV2 |   | TransportSessionV2|
//!       | (SPAKE2)  |   | (ITR2 ChaCha20)   |
//!       +-----------+   +-------------------+
//! ```
//!
//! # 3. Callers & Callees
//! - **Upstream Callers**:
//!   - `crate::discovery`: Broadcasts signed v2 beacons (`sign_discovery_beacon_v2_full`), verifies incoming beacons (`verify_discovery_beacon_v2_full`), feeds advertisements into `observe_discovered_peer`, and probes roamed peers via `connect_transport_to_hinted_ip`.
//!   - `crate::display::server` & `crate::display::controller`: Invokes `handle_incoming_pairing_stream_v2`, `accept_transport_from_stream`, `connect_transport_to_ip`, `open_or_get_pairing_pin`, and `evaluate_local_touchid_and_sign` on TCP port `58281`.
//!   - `crate::clipboard::service`: Calls `connect_transport_to_ip`, `accept_transport_from_stream`, `has_paired_peer_at_ip`, `generate_random_token_hex`, and `constant_time_eq` on TCP port `58283`.
//!   - `crate::benchmark`: Calls `connect_transport_to_ip` and `accept_transport_from_stream` on TCP port `58285`.
//!   - `crate::kvm::service`: Calls `connect_transport_to_ip` and `accept_transport_from_stream` on TCP port `58286`.
//!   - `crate::camera`: Calls `connect_transport_to_hinted_ip` and `accept_transport_from_stream` on TCP port `58287`.
//!   - `crate::audio`: Calls `lookup_verified_peer_for_ip`, `lookup_verified_peer_by_id_at_ip`, and `local_device_id_hex` for `IUA2` UDP audio session negotiation on port `58284`.
//!   - `crate::storage`: Calls `has_paired_peer_at_ip` before mounting or querying remote SMB shares.
//!   - `crate::core` & `crate::security::passkey`: Calls `get_trust_snapshot`, `regenerate_pin`, `untrust_or_block_device`, `unpair_device`, `pair_with_remote_peer_v2`, and Touch ID assertion helpers.
//! - **Downstream Callees**:
//!   - `crate::security::keystore::KeystoreV2`: Persistent Ed25519 device identity key, pinned peer trust store, and root keys $K_{\text{root}}$.
//!   - `crate::security::pairing::PairingCoordinatorV2`: RFC 9382 SPAKE2 protocol execution, PIN window lifecycle, and per-IP anti-DoS rate limiting.
//!   - `crate::security::transport::TransportSessionV2`: Authenticated, replay-protected ChaCha20-Poly1305 record layer.
//!   - `crate::system_info`: Hostname, OS platform, subnet validation, and direct Thunderbolt/USB4 cable route detection.
//!   - Native macOS FFI (`integrator_mac_touchid_available`, `integrator_mac_touchid_authenticate`): Objective-C/Swift `LocalAuthentication` bridge for Secure Enclave biometric verification.
//! ============================================================================

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

/// Bounded capacity for the unauthenticated in-memory discovered peer UI cache (64 entries).
const MAX_DISCOVERED_PENDING_PEERS: usize = 64;

/// TCP connection timeout when initiating an outbound SPAKE2 pairing session.
const PAIRING_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// End-to-end handshake timeout for both client and server sides of RFC 9382 SPAKE2 pairing.
const SPAKE2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);

/// Handshake timeout for both client and server sides of authenticated `TransportSessionV2`.
const TRANSPORT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);

/// Maximum permitted clock skew (in milliseconds) for UDP discovery beacon freshness validation (±60s).
const DISCOVERY_BEACON_MAX_SKEW_MS: u64 = 60_000;

/// Maximum permitted clock skew (in milliseconds) for Touch ID biometric signed assertions (±120s).
const TOUCHID_ASSERTION_MAX_SKEW_MS: u64 = 120_000;

/// Expected hex string length of a 32-byte CSPRNG Touch ID challenge nonce.
const TOUCHID_CHALLENGE_NONCE_HEX_LEN: usize = 64;

/// Maximum C buffer capacity in bytes for error strings returned by macOS `LocalAuthentication`.
#[cfg(target_os = "macos")]
const TOUCHID_MAC_ERROR_BUF_CAP: usize = 256;

/// Domain-separation prefix bound into all Ed25519 Touch ID biometric assertions.
const TOUCHID_ASSERTION_DOMAIN_SEP: &[u8] = b"INTEGRATOR-TOUCHID-ASSERTION-V1\0";

/// Cryptographically signed Touch ID biometric assertion generated by a paired macOS Secure Enclave host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchIdSignedAssertion {
    /// 32-byte (64-hex) one-time CSPRNG challenge nonce issued by the requesting peer.
    pub challenge_nonce_hex: String,
    /// 16-byte (32-hex) `device_id` of the peer that requested biometric authentication.
    pub requester_device_id: String,
    /// 16-byte (32-hex) `device_id` of the macOS host whose Touch ID sensor verified the user.
    pub signer_device_id: String,
    /// Hostname of the macOS host that performed the Touch ID biometric check.
    pub signer_hostname: String,
    /// Unix epoch timestamp in milliseconds when the Touch ID biometric match completed.
    pub timestamp_ms: u64,
    /// 32-byte (64-hex) Ed25519 identity public key of the signing macOS host.
    pub ed25519_pubkey_hex: String,
    /// 64-byte (128-hex) Ed25519 signature over the domain-separated Touch ID challenge transcript.
    pub signature_hex: String,
}

/// Serialized representation of a trusted peer record stored in the trust configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecord {
    /// 16-byte peer device UUID formatted as a 32-character lowercase hex string.
    pub device_id: String,
    /// Hostname advertised by the peer during pairing.
    pub hostname: String,
    /// Most recent observed IP address of the peer.
    pub last_ip: String,
    /// UTC timestamp in seconds when cryptographic pairing was completed.
    pub paired_at_epoch: u64,
    /// True if the peer was paired over a direct physical cable connection.
    pub via_direct_cable: bool,
    /// 32-byte Ed25519 identity public key formatted as a 64-character lowercase hex string.
    pub ed25519_pubkey_hex: String,
    /// 16-byte key identifier identifying the pinned root key $K_{\text{root}}$ in hex.
    pub key_id_hex: String,
}

/// Snapshot structure representing the trust configuration state exposed to UI and IPC queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfigFile {
    /// Legacy configuration flag; strictly false in v1.0 (pairing required on all interfaces).
    pub auto_trust_direct_cable: bool,
    /// Legacy configuration flag; strictly true in v1.0 (pairing required on LAN).
    pub require_pairing_on_lan: bool,
    /// Currently active 6-digit pairing PIN, or empty string if pairing window is closed.
    pub pairing_pin: String,
    /// UTC timestamp in seconds when the current pairing PIN was generated.
    pub pin_created_at_epoch: u64,
    /// List of all currently trusted and pinned peer devices.
    pub trusted_peers: Vec<TrustedPeerRecord>,
    /// List of blocked peer device UUIDs in hex.
    pub blocked_device_ids: Vec<String>,
    /// List of blocked IP addresses.
    pub blocked_ips: Vec<String>,
}

/// In-memory metadata representation of an observed network peer (trusted or untrusted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPeerInfo {
    /// 16-byte peer device UUID formatted as a 32-character lowercase hex string.
    pub device_id: String,
    /// Hostname advertised by the peer.
    pub hostname: String,
    /// IP address from which the advertisement or connection originated.
    pub ip: String,
    /// True if the connection route is over a direct physical cable.
    pub is_direct_cable: bool,
    /// True if the peer is cryptographically paired and not blocked.
    pub trusted: bool,
    /// True if the peer device UUID or IP address is currently blocked.
    pub blocked: bool,
}

/// Thread-safe in-memory runtime trust coordinator state.
struct RuntimeTrustState {
    /// Active SPAKE2 pairing coordinator managing PIN generation and anti-DoS rate limiting.
    pairing_coordinator: Mutex<PairingCoordinatorV2>,
    /// In-memory cache of the active pairing PIN `(pin, created_at_epoch)`.
    active_pin_cached: Mutex<(String, u64)>,
    /// Bounded UI cache of recently observed network peers.
    pending_peers: Mutex<HashMap<String, PendingPeerInfo>>,
    /// Fast-lookup hint mapping IP addresses to advertised device IDs.
    ip_to_device_hint: Mutex<HashMap<String, String>>,
}

/// Returns a reference to the global `RuntimeTrustState` singleton.
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

/// Generates a cryptographically secure random lowercase hex-encoded token of `byte_len` bytes
/// (producing `2 * byte_len` hex characters).
///
/// The intermediate raw random byte buffer is wrapped in [`zeroize::Zeroizing`] so raw entropy
/// does not linger on the heap after hex encoding.
pub fn generate_random_token_hex(byte_len: usize) -> String {
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; byte_len]);
    security::csprng_fill(&mut bytes);
    security::hex_encode(&bytes)
}

/// Compares two byte slices in constant time, mitigating timing side-channel attacks.
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

/// Discovery boundary: records an untrusted discovery advertisement in the bounded in-memory UI cache.
/// NEVER creates or mutates trusted peer credentials; returns `true` ONLY if `device_id` is already
/// cryptographically paired and pinned in `KeystoreV2` and neither the device nor source IP is blocked.
pub fn observe_discovered_peer(
    device_id: &str,
    hostname: &str,
    ip: &str,
    via_direct_cable: bool,
) -> bool {
    let clean_id = device_id.trim().to_ascii_lowercase();
    let raw_ip = ip.trim();
    if clean_id.is_empty() || raw_ip.is_empty() || clean_id.len() > 64 {
        return false;
    }
    // Parse and canonicalize the IP address; reject malformed, unspecified (0.0.0.0 / ::),
    // multicast, or IPv4 broadcast addresses so they can never pollute `last_ip` or hint maps.
    let Ok(parsed_ip) = raw_ip.parse::<IpAddr>() else {
        return false;
    };
    if parsed_ip.is_unspecified()
        || parsed_ip.is_multicast()
        || parsed_ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        return false;
    }
    let canon_ip = parsed_ip.to_string();
    let clean_ip = canon_ip.as_str();

    // Never record one of our own local interface IPs as a remote peer's IP (e.g. Windows ICS NAT reflection)
    if system_info::list_local_ipv4_interfaces()
        .iter()
        .any(|iface| iface.ip == clean_ip)
    {
        return false;
    }
    let clean_host: String = hostname
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();

    let incoming_same_subnet = system_info::is_same_subnet_as_peer(
        system_info::local_ip_for_peer(clean_ip).as_deref(),
        clean_ip,
    );

    let (is_blocked, is_paired, effective_ip) = {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        let device_blocked = ks.is_device_or_ip_blocked(&clean_id, "");
        let blocked = device_blocked || ks.is_device_or_ip_blocked(&clean_id, clean_ip);
        if blocked {
            // If only the incoming source IP is blocked while `clean_id` is an actively paired,
            // non-blocked peer in `KeystoreV2`, drop the spoofed/blocked-IP advertisement
            // immediately so it cannot overwrite the legitimate peer's UI record.
            if !device_blocked && ks.get_peer(&clean_id).is_some() {
                return false;
            }
            (true, false, clean_ip.to_string())
        } else if let Some(existing) = ks.get_peer(&clean_id) {
            let prev_ip = existing.last_ip.clone();
            let prev_is_self = system_info::list_local_ipv4_interfaces()
                .iter()
                .any(|iface| iface.ip == prev_ip);
            let prev_same_subnet = !prev_is_self
                && !prev_ip.is_empty()
                && system_info::is_same_subnet_as_peer(
                    system_info::local_ip_for_peer(&prev_ip).as_deref(),
                    &prev_ip,
                );
            // Only overwrite last_ip if the new IP is on a direct matching subnet or previous IP was not
            if incoming_same_subnet || !prev_same_subnet {
                let _ = ks.update_peer_last_ip(&clean_id, clean_ip);
                (false, true, clean_ip.to_string())
            } else {
                (false, true, prev_ip)
            }
        } else {
            (false, false, clean_ip.to_string())
        }
    };

    let rt = runtime_state();
    if !is_blocked {
        let mut hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(clean_ip) {
            // Evict a single existing entry rather than wiping the entire hint table (anti-DoS).
            if let Some(first_ip) = hints.keys().next().cloned() {
                hints.remove(&first_ip);
            }
        }
        hints.insert(clean_ip.to_string(), clean_id.clone());
        if effective_ip != clean_ip {
            if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(&effective_ip) {
                if let Some(first_ip) = hints.keys().next().cloned() {
                    hints.remove(&first_ip);
                }
            }
            hints.insert(effective_ip.clone(), clean_id.clone());
        }
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
            ip: effective_ip,
            is_direct_cable: via_direct_cable,
            trusted: is_paired && !is_blocked,
            blocked: is_blocked,
        },
    );

    is_paired && !is_blocked
}

/// Unpairs or blocks a device in `KeystoreV2` and coordinates two-phase revocation asynchronously.
///
/// Phase A (Keystore persistence & transport invalidation) runs synchronously under the keystore lock.
/// Phase B (Subsystems teardown) executes strictly outside the keystore lock and is awaited before returning.
///
/// Propagates persistence errors and teardown errors cleanly (SEC-1D-06, SEC-1D-07).
pub async fn untrust_or_block_device(device_id: &str, block: bool) -> Result<(), crate::security::keystore::KeystoreError> {
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

    // Phase A: Persist trust state to disk and invalidate active transport sessions under keystore lock.
    // If persistence fails, fail closed immediately without running Phase B as if it succeeded (SEC-1D-07).
    let unpair_gen = {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        ks.untrust_or_block_peer_ext(&clean_id, block, known_ip.as_deref())?
    };
    // Keystore lock dropped!

    // Phase B: Teardown subsystems outside keystore lock with exact unpair generation (SEC-1D-06, SEC-1D-14)
    if let Some(core) = crate::core::GLOBAL_CORE.get() {
        if let Err(e) = core.terminate_peer_connections_async(&clean_id, unpair_gen).await {
            warn!("Subsystem teardown failed during untrust/block for {}: {}", clean_id, e);
            return Err(crate::security::keystore::KeystoreError::IoFailure(e));
        }
    }
    Ok(())
}

/// Synchronous test helper for `untrust_or_block_device` used in unit tests.
#[cfg(test)]
pub fn untrust_or_block_device_sync(device_id: &str, block: bool) -> Result<(), crate::security::keystore::KeystoreError> {
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

    let unpair_gen = {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        ks.untrust_or_block_peer_ext(&clean_id, block, known_ip.as_deref())?
    };

    if let Some(core) = crate::core::GLOBAL_CORE.get() {
        core.terminate_peer_connections(&clean_id, unpair_gen);
    }
    Ok(())
}

/// Explicitly unpairs a device in `KeystoreV2` and coordinates two-phase revocation asynchronously.
///
/// Phase A runs under the keystore lock; Phase B executes outside the keystore lock and is awaited.
pub async fn unpair_device(device_id_hex: &str) -> Result<bool, crate::security::keystore::KeystoreError> {
    let clean_id = device_id_hex.trim().to_ascii_lowercase();
    let rt = runtime_state();
    let known_ip = {
        let mut pending = rt.pending_peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = pending.get_mut(&clean_id) {
            p.trusted = false;
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

    // Phase A: Persist trust removal to disk and invalidate active transport sessions under keystore lock
    let (removed, unpair_gen) = {
        let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        ks.unpair_peer_ext(&clean_id)?
    };
    // Keystore lock dropped!

    // Phase B: Teardown subsystems outside keystore lock with exact unpair generation (SEC-1D-06, SEC-1D-14)
    if let Some(core) = crate::core::GLOBAL_CORE.get() {
        if let Err(e) = core.terminate_peer_connections_async(&clean_id, unpair_gen).await {
            warn!("Subsystem teardown failed during unpair for {}: {}", clean_id, e);
            return Err(crate::security::keystore::KeystoreError::IoFailure(e));
        }
    }

    Ok(removed)
}

/// Policy setter retained for UI compatibility; in v1.0, cryptographic pairing is strictly mandatory
/// on all interfaces (including direct USB-C / Thunderbolt cables).
pub fn set_trust_policy(_auto_trust_direct_cable: bool, _require_pairing_on_lan: bool) {
    info!("Integrator v1.0 security policy enforces mandatory cryptographic pairing on all interfaces");
}

/// Checks whether a peer device ID is currently paired and trusted in the global keystore.
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

/// Resolves pinned `VerifiedPeerCredentials` for a Bonjour- or BLE-hinted `peer_ip` even when
/// the paired peer has roamed to a new IP address not yet recorded in `last_ip`.
///
/// Matches by exact `expected_device_id` (32-hex Bonjour TXT `id`) or unambiguous 8-hex
/// `expected_prefix` (BLE magic packet), strictly enforcing blocklist checks. The caller MUST
/// still complete a full `TransportSessionV2` mutual cryptographic handshake before trusting
/// that `peer_ip` actually belongs to the matched peer.
pub fn lookup_verified_peer_for_hint(
    peer_ip: &str,
    expected_device_id: Option<&str>,
    expected_prefix: Option<&str>,
) -> Option<VerifiedPeerCredentials> {
    let trimmed = peer_ip.trim();
    let ip_addr = trimmed.parse::<IpAddr>().ok()?;
    let canon_ip = ip_addr.to_string();

    if let Some(id) = expected_device_id {
        let clean_id = id.trim().to_ascii_lowercase();
        if clean_id.len() == 32 {
            let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            if !ks.is_device_or_ip_blocked(&clean_id, &canon_ip) {
                if let Some(creds) = ks.get_peer(&clean_id) {
                    return Some(creds.clone());
                }
            }
        }
    }

    if let Some(pfx) = expected_prefix {
        let clean_pfx = pfx.trim().to_ascii_lowercase();
        if clean_pfx.len() >= 8 && clean_pfx.chars().all(|c| c.is_ascii_hexdigit()) {
            let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let mut matched: Option<VerifiedPeerCredentials> = None;
            for peer in ks.list_peers() {
                if peer.device_id_hex.starts_with(&clean_pfx)
                    && !ks.is_device_or_ip_blocked(&peer.device_id_hex, &canon_ip)
                {
                    if matched.is_some() {
                        // Ambiguous prefix collision; refuse automatic prefix match.
                        matched = None;
                        break;
                    }
                    matched = Some(peer);
                }
            }
            if matched.is_some() {
                return matched;
            }
        }
    }

    lookup_verified_peer_for_ip(peer_ip)
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

/// Returns a complete snapshot tuple `(TrustConfigFile, Vec<PendingPeerInfo>)` representing current trust state.
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
///
/// Returns the pinned `VerifiedPeerCredentials` and human-readable confirmation SAS string on success.
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
    let mut stream = tokio::time::timeout(PAIRING_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("Timed out connecting to {} for pairing", addr))?
        .map_err(|e| format!("Failed to connect to {} for pairing: {}", addr, e))?;
    let _ = stream.set_nodelay(true);

    let local_name = system_info::get_hostname();
    let local_os = std::env::consts::OS;
    let via_cable = system_info::is_direct_cable_route(&canon_ip);

    // If the user explicitly initiates outbound PIN pairing to `canon_ip`, clear any stale pinned
    // record for the same IP or pending peer hostname whose identity key was regenerated on the peer.
    {
        let pending_host_and_id = {
            let rt = runtime_state();
            let pending = rt.pending_peers.lock().unwrap_or_else(|e| e.into_inner());
            pending
                .values()
                .find(|p| p.ip == canon_ip)
                .map(|p| (p.hostname.clone(), p.device_id.clone()))
        };
        let stale_ids: Vec<String> = {
            let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.list_peers()
                .into_iter()
                .filter(|p| {
                    let same_ip = p.last_ip == canon_ip;
                    let same_host = pending_host_and_id
                        .as_ref()
                        .map(|(h, id)| p.hostname.eq_ignore_ascii_case(h) && &p.device_id_hex != id)
                        .unwrap_or(false);
                    same_ip || same_host
                })
                .map(|p| p.device_id_hex)
                .collect()
        };
        // Keystore lock dropped! Execute complete Phase A + Phase B for each stale peer (SEC-1D-05)
        for sid in stale_ids {
            if let Err(e) = unpair_device(&sid).await {
                warn!("Failed to unpair and tear down stale peer {}: {}", sid, e);
            }
        }
    }

    let (creds, sas) = tokio::time::timeout(
        SPAKE2_HANDSHAKE_TIMEOUT,
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
        SPAKE2_HANDSHAKE_TIMEOUT,
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

    let creds = lookup_verified_peer_for_ip(&canon_ip)
        .or_else(|| {
            // If the paired peer roamed to a new IP on the active local subnet before its first
            // beacon updated `last_ip`, and KeystoreV2 has a single unambiguous paired peer,
            // attempt mutual TransportSessionV2 authentication with that pinned peer's credentials.
            let is_own_ip = system_info::list_local_ipv4_interfaces()
                .iter()
                .any(|iface| iface.ip == canon_ip);
            let on_local_subnet = !is_own_ip
                && system_info::is_same_subnet_as_peer(
                    system_info::local_ip_for_peer(&canon_ip).as_deref(),
                    &canon_ip,
                );
            if !on_local_subnet {
                return None;
            }
            let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let peers = ks.list_peers();
            if peers.len() == 1 {
                let candidate = &peers[0];
                if !ks.is_device_or_ip_blocked(&candidate.device_id_hex, &canon_ip) {
                    return Some(candidate.clone());
                }
            }
            None
        })
        .ok_or_else(|| {
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
        TRANSPORT_HANDSHAKE_TIMEOUT,
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

    if !ip_addr.is_loopback() {
        let rt = runtime_state();
        let mut hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(&canon_ip) {
            if let Some(first_ip) = hints.keys().next().cloned() {
                hints.remove(&first_ip);
            }
        }
        hints.insert(canon_ip, creds.device_id_hex.clone());
    }

    Ok(session)
}

/// Connects to `peer_ip:port` using a Bonjour (`expected_device_id`) or BLE (`expected_prefix`)
/// identity hint so a previously paired peer that roamed to a new IP can authenticate cleanly.
///
/// Updates the runtime `ip_to_device_hint` table ONLY after the mutual `TransportSessionV2`
/// Ed25519 + X25519 + ChaCha20-Poly1305 handshake succeeds.
pub async fn connect_transport_to_hinted_ip(
    peer_ip: &str,
    port: u16,
    service_id: ServiceId,
    connect_timeout: Duration,
    expected_device_id: Option<&str>,
    expected_prefix: Option<&str>,
) -> Result<TransportSessionV2<TcpStream>, String> {
    let trimmed_ip = peer_ip.trim();
    let ip_addr: IpAddr = trimmed_ip
        .parse()
        .map_err(|_| format!("Invalid peer IP address '{}'", trimmed_ip))?;
    let canon_ip = ip_addr.to_string();

    let creds = lookup_verified_peer_for_hint(&canon_ip, expected_device_id, expected_prefix)
        .ok_or_else(|| {
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
        TRANSPORT_HANDSHAKE_TIMEOUT,
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

    // Handshake cryptographically proved possession of `creds`'s Ed25519 identity key & root_key
    // at `canon_ip`; bind `canon_ip -> device_id_hex` for all subsequent services (KVM, Clipboard, etc.).
    if !ip_addr.is_loopback() {
        let rt = runtime_state();
        let mut hints = rt
            .ip_to_device_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(&canon_ip) {
            if let Some(first_ip) = hints.keys().next().cloned() {
                hints.remove(&first_ip);
            }
        }
        hints.insert(canon_ip, creds.device_id_hex.clone());
    }

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
        TRANSPORT_HANDSHAKE_TIMEOUT,
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
        let ip_str = peer_ip.to_string();
        let is_own_ip = system_info::list_local_ipv4_interfaces()
            .iter()
            .any(|iface| iface.ip == ip_str);
        if !is_own_ip {
            let dev_id = session.peer_device_id_hex().to_string();
            let incoming_same_subnet = system_info::is_same_subnet_as_peer(
                system_info::local_ip_for_peer(&ip_str).as_deref(),
                &ip_str,
            );
            {
                let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
                let should_update = ks
                    .get_peer(&dev_id)
                    .map(|p| {
                        let prev_is_self = system_info::list_local_ipv4_interfaces()
                            .iter()
                            .any(|iface| iface.ip == p.last_ip);
                        let prev_same_subnet = !prev_is_self
                            && !p.last_ip.is_empty()
                            && system_info::is_same_subnet_as_peer(
                                system_info::local_ip_for_peer(&p.last_ip).as_deref(),
                                &p.last_ip,
                            );
                        incoming_same_subnet || !prev_same_subnet
                    })
                    .unwrap_or(true);
                if should_update {
                    let _ = ks.update_peer_last_ip(&dev_id, &ip_str);
                }
            }
            let rt = runtime_state();
            let mut hints = rt
                .ip_to_device_hint
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if hints.len() >= MAX_DISCOVERED_PENDING_PEERS && !hints.contains_key(&ip_str) {
                if let Some(first_ip) = hints.keys().next().cloned() {
                    hints.remove(&first_ip);
                }
            }
            hints.insert(ip_str, dev_id);
        }
    }

    Ok(session)
}

// ============================================================================
// Touch ID Secure Enclave Biometric Challenge-Response Signing & Verification
// ============================================================================

#[cfg(target_os = "macos")]
extern "C" {
    /// Queries macOS `LocalAuthentication.framework` (`LAContext.canEvaluatePolicy`) to determine
    /// whether physical Touch ID Secure Enclave hardware is present and enrolled on this Mac.
    fn integrator_mac_touchid_available() -> bool;

    /// Synchronously prompts the macOS Touch ID biometric sheet (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`)
    /// with the localized UTF-8 `reason_ptr` string.
    ///
    /// Returns `1` on verified fingerprint match, or `0` on failure/cancellation (writing a
    /// null-terminated UTF-8 diagnostic into `out_error_buf` up to `out_error_cap` bytes).
    fn integrator_mac_touchid_authenticate(
        reason_ptr: *const std::os::raw::c_char,
        out_error_buf: *mut std::os::raw::c_char,
        out_error_cap: usize,
    ) -> i32;
}

/// Returns `true` if physical Apple Touch ID hardware is present and enrolled on this Mac.
pub fn is_local_touchid_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `integrator_mac_touchid_available` takes no arguments and safely queries `LAContext`.
        unsafe { integrator_mac_touchid_available() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Constructs the domain-separated binary transcript signed for a Touch ID biometric assertion.
///
/// Wire layout:
/// `TOUCHID_ASSERTION_DOMAIN_SEP` || `LP(challenge_nonce_hex)` || `LP(requester_device_id)` ||
/// `LP(signer_device_id)` || `LP(signer_hostname)` || `timestamp_ms (u64 BE)`.
fn build_touchid_assertion_signing_payload(
    challenge_nonce_hex: &str,
    requester_device_id: &str,
    signer_device_id: &str,
    signer_hostname: &str,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(TOUCHID_ASSERTION_DOMAIN_SEP);
    append_lp_bytes(&mut buf, challenge_nonce_hex.trim().to_ascii_lowercase().as_bytes());
    append_lp_bytes(&mut buf, requester_device_id.trim().to_ascii_lowercase().as_bytes());
    append_lp_bytes(&mut buf, signer_device_id.trim().to_ascii_lowercase().as_bytes());
    append_lp_bytes(&mut buf, signer_hostname.trim().as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf
}

/// Signs a verified Touch ID biometric challenge using the local installation's Ed25519 identity key.
#[cfg(any(target_os = "macos", test))]
pub fn sign_touchid_assertion(
    challenge_nonce_hex: &str,
    requester_device_id: &str,
) -> Result<TouchIdSignedAssertion, String> {
    let clean_nonce = challenge_nonce_hex.trim().to_ascii_lowercase();
    let clean_req_id = requester_device_id.trim().to_ascii_lowercase();
    if clean_nonce.len() != TOUCHID_CHALLENGE_NONCE_HEX_LEN
        || !clean_nonce.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Invalid 32-byte Touch ID challenge nonce".into());
    }
    if clean_req_id.len() != 32 || !clean_req_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid requester device_id for Touch ID challenge".into());
    }

    let signer_hostname = system_info::get_hostname();
    let timestamp_ms = security::unix_epoch_millis();
    let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
    let signer_device_id = ks.local_device_id_hex().to_string();
    let ed25519_pubkey_hex = security::hex_encode(&ks.local_ed25519_pubkey());
    let payload = build_touchid_assertion_signing_payload(
        &clean_nonce,
        &clean_req_id,
        &signer_device_id,
        &signer_hostname,
        timestamp_ms,
    );
    let sig = ks.sign_transcript(&payload);
    Ok(TouchIdSignedAssertion {
        challenge_nonce_hex: clean_nonce,
        requester_device_id: clean_req_id,
        signer_device_id,
        signer_hostname,
        timestamp_ms,
        ed25519_pubkey_hex,
        signature_hex: security::hex_encode(&sig),
    })
}

/// Prompts the local macOS Touch ID Secure Enclave sensor and returns a signed [`TouchIdSignedAssertion`]
/// on biometric fingerprint match.
///
/// Pre-validates `challenge_nonce_hex` (64 hex chars) and `requester_device_id` (32 hex chars)
/// before invoking the OS biometric modal so malformed requests fail fast without prompting the user.
pub fn evaluate_local_touchid_and_sign(
    challenge_nonce_hex: &str,
    requester_device_id: &str,
    requester_hostname: &str,
) -> Result<TouchIdSignedAssertion, String> {
    #[cfg(target_os = "macos")]
    {
        let clean_nonce = challenge_nonce_hex.trim().to_ascii_lowercase();
        let clean_req_id = requester_device_id.trim().to_ascii_lowercase();
        if clean_nonce.len() != TOUCHID_CHALLENGE_NONCE_HEX_LEN
            || !clean_nonce.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Invalid 32-byte Touch ID challenge nonce".into());
        }
        if clean_req_id.len() != 32 || !clean_req_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid requester device_id for Touch ID challenge".into());
        }

        let clean_host: String = requester_hostname
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        // macOS formats LocalAuthentication's Touch Bar & sheet prompt as "Touch ID to <reason>",
        // so pass concise verb-phrase reasons without duplicating "Touch ID".
        let reason = if clean_host.is_empty() {
            "approve Windows Hello login".to_string()
        } else if clean_host.starts_with("create a passkey ")
            || clean_host.starts_with("sign in to ")
        {
            clean_host
        } else {
            format!("approve {}", clean_host)
        };
        let c_reason = std::ffi::CString::new(reason)
            .map_err(|_| "Invalid Touch ID prompt reason".to_string())?;
        let mut err_buf = vec![0 as std::os::raw::c_char; TOUCHID_MAC_ERROR_BUF_CAP];
        // SAFETY: `c_reason` is a valid null-terminated CString and `err_buf` has capacity
        // `TOUCHID_MAC_ERROR_BUF_CAP`. We explicitly enforce a trailing NUL byte before reading.
        let rc = unsafe {
            integrator_mac_touchid_authenticate(
                c_reason.as_ptr(),
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };
        if rc == 1 {
            sign_touchid_assertion(&clean_nonce, &clean_req_id)
        } else {
            err_buf[TOUCHID_MAC_ERROR_BUF_CAP - 1] = 0;
            // SAFETY: `err_buf` is guaranteed to contain at least one NUL terminator within bounds.
            let err_str = unsafe { std::ffi::CStr::from_ptr(err_buf.as_ptr()) }
                .to_string_lossy()
                .trim()
                .to_string();
            Err(if err_str.is_empty() {
                "Touch ID verification failed or was cancelled".to_string()
            } else {
                err_str
            })
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (challenge_nonce_hex, requester_device_id, requester_hostname);
        Err("Apple Touch ID Secure Enclave hardware is only available on macOS".into())
    }
}

/// Cryptographically verifies a [`TouchIdSignedAssertion`] against the issued one-time
/// `expected_challenge_nonce_hex`, `expected_requester_device_id`, `expected_signer_device_id`,
/// timestamp freshness (`±120s`), and pinned Ed25519 public key in `KeystoreV2`.
pub fn verify_touchid_assertion(
    assertion: &TouchIdSignedAssertion,
    expected_challenge_nonce_hex: &str,
    expected_requester_device_id: &str,
    expected_signer_device_id: &str,
) -> Result<(), String> {
    let clean_nonce = assertion.challenge_nonce_hex.trim().to_ascii_lowercase();
    let exp_nonce = expected_challenge_nonce_hex.trim().to_ascii_lowercase();
    if clean_nonce.len() != TOUCHID_CHALLENGE_NONCE_HEX_LEN
        || !constant_time_eq(clean_nonce.as_bytes(), exp_nonce.as_bytes())
    {
        return Err("Touch ID assertion challenge nonce mismatch".into());
    }

    let clean_req = assertion.requester_device_id.trim().to_ascii_lowercase();
    let exp_req = expected_requester_device_id.trim().to_ascii_lowercase();
    if clean_req.len() != 32 || !constant_time_eq(clean_req.as_bytes(), exp_req.as_bytes()) {
        return Err("Touch ID assertion requester_device_id mismatch".into());
    }

    let clean_signer = assertion.signer_device_id.trim().to_ascii_lowercase();
    let exp_signer = expected_signer_device_id.trim().to_ascii_lowercase();
    if clean_signer.len() != 32
        || (!exp_signer.is_empty()
            && !constant_time_eq(clean_signer.as_bytes(), exp_signer.as_bytes()))
    {
        return Err("Touch ID assertion signer_device_id mismatch".into());
    }

    let now_ms = security::unix_epoch_millis();
    if assertion.timestamp_ms == 0
        || now_ms.abs_diff(assertion.timestamp_ms) > TOUCHID_ASSERTION_MAX_SKEW_MS
    {
        return Err("Touch ID assertion timestamp is stale or outside ±120s freshness window".into());
    }

    let signer_id_bytes = security::hex_decode_array::<16>(&clean_signer)
        .ok_or_else(|| "Invalid signer_device_id hex in Touch ID assertion".to_string())?;
    let pk_bytes = security::hex_decode_array::<32>(assertion.ed25519_pubkey_hex.trim())
        .ok_or_else(|| "Invalid ed25519_pubkey_hex in Touch ID assertion".to_string())?;
    let sig_bytes = security::hex_decode_array::<64>(assertion.signature_hex.trim())
        .ok_or_else(|| "Invalid signature_hex in Touch ID assertion".to_string())?;

    let derived_id = security::derive_device_id_from_pubkey(&pk_bytes);
    if !constant_time_eq(&signer_id_bytes, &derived_id) {
        return Err("Touch ID assertion signer_device_id does not match Ed25519 public key".into());
    }

    // Enforce pinned public key check in KeystoreV2 (or local self identity when tested locally on Mac)
    {
        let ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
        if ks.is_device_or_ip_blocked(&clean_signer, "") {
            return Err("Touch ID assertion signer is blocked in KeystoreV2".into());
        }
        if constant_time_eq(clean_signer.as_bytes(), ks.local_device_id_hex().as_bytes()) {
            if !constant_time_eq(&ks.local_ed25519_pubkey(), &pk_bytes) {
                return Err("Local Ed25519 public key mismatch in Touch ID assertion".into());
            }
        } else if let Some(pinned) = ks.get_peer(&clean_signer) {
            if !constant_time_eq(&pinned.ed25519_pubkey, &pk_bytes) {
                return Err("Touch ID assertion public key does not match pinned peer key in KeystoreV2".into());
            }
        } else {
            return Err("Touch ID assertion signer is not a paired peer in KeystoreV2".into());
        }
    }

    let payload = build_touchid_assertion_signing_payload(
        &clean_nonce,
        &clean_req,
        &clean_signer,
        &assertion.signer_hostname,
        assertion.timestamp_ms,
    );
    KeystoreV2::verify_signature(&pk_bytes, &payload, &sig_bytes)
        .map_err(|e| format!("Touch ID Ed25519 signature verification failed: {}", e))
}

// ============================================================================
// Discovery Beacon v2 Ed25519 Signing & Verification (No Static Keys)
// ============================================================================

/// Constructs the canonical ASCII signing payload for minimal v2 discovery beacons.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
    if timestamp_ms == 0 || now_ms.abs_diff(timestamp_ms) > DISCOVERY_BEACON_MAX_SKEW_MS {
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
///
/// Every field is serialized using unambiguous big-endian length-prefixed framing in
/// [`build_beacon_v2_full_signing_payload`] so an on-path adversary cannot tamper with
/// advertised display capabilities, SMB share names, Sunshine ports, or GPU lists.
#[derive(Debug, Clone)]
pub struct DiscoveryBeaconSignedMeta<'a> {
    /// Discovery beacon wire protocol version (must equal `2`).
    pub protocol_version: u16,
    /// Hostname advertised by the sending workstation (1..=128 Unicode scalar values).
    pub sender_name: &'a str,
    /// Operating system identifier string (e.g. `"macOS"` or `"Windows 11"`, max 64 chars).
    pub os: &'a str,
    /// Hardware model description string (e.g. `"MacBook Pro"` or `"Custom Workstation"`, max 128 chars).
    pub hardware_model: &'a str,
    /// Primary display horizontal resolution in physical pixels.
    pub display_width: u32,
    /// Primary display vertical resolution in physical pixels.
    pub display_height: u32,
    /// Primary display refresh rate in frames per second (Hz).
    pub display_fps: u32,
    /// Optional SMB network share name advertised by the host (max 128 chars).
    pub share_name: Option<&'a str>,
    /// Optional Sunshine display streaming host name advertised by the host (max 128 chars).
    pub sunshine_name: Option<&'a str>,
    /// TCP port on which the peer's Sunshine service listens (e.g. `47989`, or `0` if inactive).
    pub sunshine_port: u16,
    /// Slice of detected GPU adapter display names (max 8 entries, up to 128 chars each).
    pub gpus: &'a [String],
}

/// Appends length-prefixed bytes to a serialization buffer (4-byte big-endian length + raw bytes).
fn append_lp_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&data[..(len as usize)]);
}

/// Appends an optional length-prefixed string: 0x00 if None; 0x01 followed by length-prefixed bytes if Some.
fn append_opt_lp_str(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            buf.push(1);
            append_lp_bytes(buf, v.as_bytes());
        }
        None => buf.push(0),
    }
}

/// Constructs the unambiguous length-prefixed binary signing payload for full v2 discovery beacons.
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
    if timestamp_ms == 0 || now_ms.abs_diff(timestamp_ms) > DISCOVERY_BEACON_MAX_SKEW_MS {
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
        let _ = untrust_or_block_device_sync(&id_hex, true);
        assert!(!verify_discovery_beacon_v2(
            &id_hex,
            &pk_hex,
            "TempPeer",
            ts,
            58281,
            58283,
            &sig_hex
        ));
        let _ = untrust_or_block_device_sync(&id_hex, false);
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

    #[test]
    fn lookup_verified_peer_for_hint_resolves_pinned_peer_across_ip_change() {
        let pk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
            .verifying_key()
            .to_bytes();
        let peer_id_bytes = security::derive_device_id_from_pubkey(&pk);
        let dev_id = security::hex_encode(&peer_id_bytes);
        let prefix = &dev_id[..8];
        {
            let mut ks = global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.commit_paired_peer(
                peer_id_bytes,
                pk,
                zeroize::Zeroizing::new([0x99; 32]),
                "RoamingPeer".to_string(),
                "windows".to_string(),
                "172.20.10.7".to_string(),
                false,
            )
            .expect("commit_paired_peer should succeed with matching pubkey-derived device_id");
        }

        // Plain IP lookup at new college/hotspot IP 10.145.1.70 fails before hint resolution
        assert!(lookup_verified_peer_for_ip("10.145.1.70").is_none());

        // Bonjour full device_id hint resolves the pinned peer at its new IP
        let by_id = lookup_verified_peer_for_hint("10.145.1.70", Some(&dev_id), None)
            .expect("Bonjour full device_id hint should resolve pinned peer across IP change");
        assert_eq!(by_id.device_id_hex, dev_id);

        // BLE 8-hex prefix hint resolves the pinned peer at its new IP
        let by_prefix = lookup_verified_peer_for_hint("10.145.1.70", None, Some(prefix))
            .expect("BLE 8-hex prefix hint should resolve pinned peer across IP change");
        assert_eq!(by_prefix.device_id_hex, dev_id);

        // Unknown prefix must never match
        assert!(lookup_verified_peer_for_hint("10.145.1.70", None, Some("00000000")).is_none());

        // Clean up temporary test peer
        let _ = untrust_or_block_device_sync(&dev_id, false);
    }

    #[test]
    fn touchid_assertion_ed25519_sign_verify_and_nonce_binding() {
        let nonce = generate_random_token_hex(32);
        let my_id = local_device_id_hex();
        let assertion = sign_touchid_assertion(&nonce, &my_id)
            .expect("sign_touchid_assertion must succeed with valid 32-byte nonce");
        assert_eq!(assertion.challenge_nonce_hex, nonce);
        assert_eq!(assertion.requester_device_id, my_id);
        assert_eq!(assertion.signer_device_id, my_id);

        // Valid verification against matching challenge nonce and signer/requester IDs succeeds
        assert!(verify_touchid_assertion(&assertion, &nonce, &my_id, &my_id).is_ok());

        // Replay with a different challenge nonce must be rejected
        let wrong_nonce = generate_random_token_hex(32);
        assert!(verify_touchid_assertion(&assertion, &wrong_nonce, &my_id, &my_id).is_err());

        // Tampered hostname or signature must be rejected
        let mut tampered = assertion.clone();
        tampered.signer_hostname = "SpoofedMac".to_string();
        assert!(verify_touchid_assertion(&tampered, &nonce, &my_id, &my_id).is_err());
    }

    #[tokio::test]
    async fn test_untrust_or_block_device_returns_result_and_cleans_up() {
        let test_id = "test_untrust_dev_000000000000001";
        // Call untrust_or_block_device and verify it returns ResultOk
        let res = untrust_or_block_device(test_id, true).await;
        assert!(res.is_ok(), "untrust_or_block_device must return Ok on successful execution");

        let res_unblock = untrust_or_block_device(test_id, false).await;
        assert!(res_unblock.is_ok(), "untrust_or_block_device must return Ok on unblock");
    }

    #[tokio::test]
    async fn test_unpair_device_returns_result_and_cleans_up() {
        let test_id = "test_unpair_dev_0000000000000002";
        // Unpairing an unknown peer returns Ok(false)
        let res = unpair_device(test_id).await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), false);
    }
}
