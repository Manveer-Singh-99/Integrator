//! Peer trust, cryptographic identity, rate-limited PIN pairing, and authenticated
//! transport envelope (`~/.usbc_clipboard_cache/trusted_peers.json`).
//!
//! Security model:
//! - PINs, session IDs, nonces, and installation keys are generated via the OS CSPRNG
//!   (`getrandom`), using rejection sampling for unbiased 6-digit PINs.
//! - Pairing enforces a 10-minute PIN TTL, per-IP and global attempt rate limits,
//!   and a 15-minute lockout + automatic PIN rotation after 5 failed attempts.
//! - Successful pairing derives a 256-bit per-peer shared secret used to encrypt
//!   and authenticate control RPC and clipboard frames with RFC 8439 ChaCha20 +
//!   RFC 2104 HMAC-SHA256 (Encrypt-then-MAC) and nonce/timestamp replay protection.
//! - Configuration loading fails closed on corrupt files (preserving a backup rather
//!   than resetting to permissive defaults), and `auto_trust_direct_cable` defaults
//!   to `false` (explicit user opt-in convenience policy).

use crate::system_info;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

const PIN_TTL_SECS: u64 = 600; // 10 minutes
const ATTEMPT_WINDOW_SECS: u64 = 300; // 5 minutes
const MAX_FAILED_ATTEMPTS_PER_IP: u32 = 5;
const MAX_FAILED_ATTEMPTS_GLOBAL: u32 = 10;
const LOCKOUT_DURATION_SECS: u64 = 900; // 15 minutes
const ENVELOPE_REPLAY_WINDOW_MS: u64 = 120_000; // ±2 minutes
const MAX_REPLAY_NONCES: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecord {
    pub device_id: String,
    pub hostname: String,
    pub last_ip: String,
    pub paired_at_epoch: u64,
    pub via_direct_cable: bool,
    #[serde(default)]
    pub shared_secret_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfigFile {
    #[serde(default)]
    pub auto_trust_direct_cable: bool,
    #[serde(default = "default_true")]
    pub require_pairing_on_lan: bool,
    pub pairing_pin: String,
    #[serde(default)]
    pub pin_created_at_epoch: u64,
    #[serde(default)]
    pub local_identity_secret: String,
    #[serde(default)]
    pub trusted_peers: Vec<TrustedPeerRecord>,
    #[serde(default)]
    pub blocked_device_ids: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for TrustConfigFile {
    fn default() -> Self {
        Self {
            // Fail closed by default: direct-cable auto-trust is an opt-in convenience mode.
            auto_trust_direct_cable: false,
            require_pairing_on_lan: true,
            pairing_pin: generate_pin(),
            pin_created_at_epoch: epoch_secs(),
            local_identity_secret: generate_random_token_hex(32),
            trusted_peers: Vec::new(),
            blocked_device_ids: Vec::new(),
            blocked_ips: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PinAttemptRecord {
    failures: u32,
    window_start_epoch: u64,
    locked_until_epoch: u64,
}

struct TrustState {
    config: TrustConfigFile,
    /// Maps active peer IP -> observed remote device_id from discovery/authenticated RPC.
    ip_to_device: HashMap<String, String>,
    /// Tracks LAN peers seen via discovery that await user approval.
    pending_peers: HashMap<String, PendingPeerInfo>,
    /// Per-IP PIN verification throttling & lockout state.
    pin_attempts_by_ip: HashMap<String, PinAttemptRecord>,
    /// Global PIN verification throttling & lockout state.
    global_pin_attempts: PinAttemptRecord,
    /// Bounded replay cache of recently accepted envelope nonces.
    seen_nonces: VecDeque<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnvelope {
    pub version: u8,
    pub sender_device_id: String,
    pub timestamp_ms: u64,
    pub nonce_hex: String,
    pub key_mode: String, // "paired" or "transport"
    pub ciphertext_b64: String,
    pub mac_hex: String,
}

/// Fills `buf` using the operating system CSPRNG (`getrandom`).
pub fn csprng_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG (getrandom) failed to produce entropy");
}

/// Generates `byte_len` cryptographically random bytes encoded as lowercase hex.
pub fn generate_random_token_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    csprng_fill(&mut bytes);
    to_hex(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Constant-time byte comparison to prevent timing side channels on PINs and MACs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Standard RFC 2104 HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_LEN: usize = 64;
    let mut k_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = Sha256::digest(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let final_digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&final_digest);
    out
}

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        let off = i * 4;
        state[4 + i] = u32::from_le_bytes([key[off], key[off + 1], key[off + 2], key[off + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        let off = i * 4;
        state[13 + i] =
            u32::from_le_bytes([nonce[off], nonce[off + 1], nonce[off + 2], nonce[off + 3]]);
    }

    let mut working = state;
    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]).to_le_bytes();
        let off = i * 4;
        out[off..off + 4].copy_from_slice(&word);
    }
    out
}

/// Standard RFC 8439 ChaCha20 stream cipher XOR.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], initial_counter: u32, data: &mut [u8]) {
    let mut counter = initial_counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Generates an unbiased 6-digit PIN (`100000`..=`999999`) using OS CSPRNG rejection sampling.
fn generate_pin() -> String {
    const RANGE: u32 = 900_000;
    const MAX_UNBIASED: u32 = u32::MAX - (u32::MAX % RANGE);
    loop {
        let mut buf = [0u8; 4];
        csprng_fill(&mut buf);
        let candidate = u32::from_le_bytes(buf);
        if candidate < MAX_UNBIASED {
            let pin = 100_000 + (candidate % RANGE);
            return format!("{:06}", pin);
        }
    }
}

fn is_valid_pin_format(pin: &str) -> bool {
    pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit())
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn config_path() -> std::path::PathBuf {
    system_info::app_data_dir().join("trusted_peers.json")
}

fn load_from_disk() -> TrustConfigFile {
    let p = config_path();
    if p.exists() {
        match std::fs::read_to_string(&p) {
            Ok(txt) => match serde_json::from_str::<TrustConfigFile>(&txt) {
                Ok(mut cfg) => {
                    let mut mutated = false;
                    if !is_valid_pin_format(&cfg.pairing_pin)
                        || cfg.pin_created_at_epoch == 0
                        || epoch_secs().saturating_sub(cfg.pin_created_at_epoch) > PIN_TTL_SECS
                    {
                        cfg.pairing_pin = generate_pin();
                        cfg.pin_created_at_epoch = epoch_secs();
                        mutated = true;
                    }
                    if cfg.local_identity_secret.len() < 64 {
                        cfg.local_identity_secret = generate_random_token_hex(32);
                        mutated = true;
                    }
                    if mutated {
                        let _ = save_to_disk(&cfg);
                    }
                    return cfg;
                }
                Err(e) => {
                    let backup = p.with_extension(format!("json.corrupt.{}", epoch_secs()));
                    let _ = std::fs::copy(&p, &backup);
                    error!(
                        "Corrupt trust configuration at {} ({}); backed up to {} and failing closed",
                        p.display(),
                        e,
                        backup.display()
                    );
                    return TrustConfigFile {
                        auto_trust_direct_cable: false,
                        require_pairing_on_lan: true,
                        pairing_pin: generate_pin(),
                        pin_created_at_epoch: epoch_secs(),
                        local_identity_secret: generate_random_token_hex(32),
                        trusted_peers: Vec::new(),
                        blocked_device_ids: Vec::new(),
                        blocked_ips: Vec::new(),
                    };
                }
            },
            Err(e) => {
                error!(
                    "Unreadable trust configuration at {} ({}); failing closed in memory",
                    p.display(),
                    e
                );
                return TrustConfigFile {
                    auto_trust_direct_cable: false,
                    require_pairing_on_lan: true,
                    pairing_pin: generate_pin(),
                    pin_created_at_epoch: epoch_secs(),
                    local_identity_secret: generate_random_token_hex(32),
                    trusted_peers: Vec::new(),
                    blocked_device_ids: Vec::new(),
                    blocked_ips: Vec::new(),
                };
            }
        }
    }

    let cfg = TrustConfigFile::default();
    if let Err(e) = save_to_disk(&cfg) {
        warn!("Initial trust config persistence warning: {}", e);
    }
    cfg
}

fn save_to_disk(cfg: &TrustConfigFile) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create trust config directory: {}", e))?;
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("Failed to serialize trust config: {}", e))?;
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write temporary trust config {}: {}", tmp_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&tmp_path, &path).map_err(|e| {
        format!(
            "Failed to atomically commit trust config to {}: {}",
            path.display(),
            e
        )
    })
}

fn state() -> &'static Mutex<TrustState> {
    static TRUST: OnceLock<Mutex<TrustState>> = OnceLock::new();
    TRUST.get_or_init(|| {
        let config = load_from_disk();
        let mut ip_to_device = HashMap::new();
        for rec in &config.trusted_peers {
            if !rec.last_ip.is_empty() && !rec.device_id.is_empty() {
                ip_to_device.insert(rec.last_ip.clone(), rec.device_id.clone());
            }
        }
        Mutex::new(TrustState {
            config,
            ip_to_device,
            pending_peers: HashMap::new(),
            pin_attempts_by_ip: HashMap::new(),
            global_pin_attempts: PinAttemptRecord::default(),
            seen_nonces: VecDeque::new(),
        })
    })
}

fn ensure_fresh_pin_locked(guard: &mut TrustState) {
    let now = epoch_secs();
    if !is_valid_pin_format(&guard.config.pairing_pin)
        || guard.config.pin_created_at_epoch == 0
        || now.saturating_sub(guard.config.pin_created_at_epoch) > PIN_TTL_SECS
    {
        guard.config.pairing_pin = generate_pin();
        guard.config.pin_created_at_epoch = now;
        if let Err(e) = save_to_disk(&guard.config) {
            warn!("Failed to persist refreshed PIN: {}", e);
        }
    }
}

/// Record a discovered peer beacon and apply direct-cable auto-trust only if the user
/// explicitly enabled `auto_trust_direct_cable` and the device is not blocked.
pub fn observe_discovered_peer(
    device_id: &str,
    hostname: &str,
    ip: &str,
    via_direct_cable: bool,
) -> bool {
    let clean_id = device_id.trim();
    let clean_ip = ip.trim();
    if clean_id.is_empty() || clean_ip.is_empty() || clean_id.len() > 128 {
        return false;
    }
    let clean_host: String = hostname.trim().chars().take(128).collect();

    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());

    let blocked = guard
        .config
        .blocked_device_ids
        .iter()
        .any(|id| id == clean_id)
        || guard.config.blocked_ips.iter().any(|bip| bip == clean_ip);
    if blocked {
        guard.ip_to_device.insert(clean_ip.to_string(), clean_id.to_string());
        guard.pending_peers.insert(
            clean_id.to_string(),
            PendingPeerInfo {
                device_id: clean_id.to_string(),
                hostname: clean_host,
                ip: clean_ip.to_string(),
                is_direct_cable: via_direct_cable,
                trusted: false,
                blocked: true,
            },
        );
        return false;
    }

    // Do not let an unauthenticated beacon overwrite the IP mapping of an already-paired peer
    // that has a cryptographic shared secret unless it is from the same known IP.
    let existing_paired_with_secret = guard
        .config
        .trusted_peers
        .iter()
        .find(|p| p.device_id == clean_id)
        .map(|p| (!p.shared_secret_hex.is_empty(), p.last_ip.clone()));

    if let Some((has_secret, ref paired_ip)) = existing_paired_with_secret {
        if !has_secret || paired_ip == clean_ip || paired_ip.is_empty() {
            guard.ip_to_device.insert(clean_ip.to_string(), clean_id.to_string());
        }
    } else {
        guard.ip_to_device.insert(clean_ip.to_string(), clean_id.to_string());
    }

    let already_trusted = if let Some(rec) = guard
        .config
        .trusted_peers
        .iter_mut()
        .find(|p| p.device_id == clean_id)
    {
        if (rec.shared_secret_hex.is_empty() || rec.last_ip == clean_ip)
            && (rec.last_ip != clean_ip || rec.hostname != clean_host)
        {
            rec.last_ip = clean_ip.to_string();
            rec.hostname = clean_host.clone();
            if let Err(e) = save_to_disk(&guard.config) {
                warn!("Failed to persist updated peer metadata: {}", e);
            }
        }
        true
    } else {
        false
    };

    let auto_trusted =
        !already_trusted && guard.config.auto_trust_direct_cable && via_direct_cable;

    if auto_trusted {
        info!(
            "🔌 Auto-trusted direct-cable peer '{}' ({}) at {} per user convenience policy",
            clean_host, clean_id, clean_ip
        );
        guard.config.trusted_peers.push(TrustedPeerRecord {
            device_id: clean_id.to_string(),
            hostname: clean_host.clone(),
            last_ip: clean_ip.to_string(),
            paired_at_epoch: epoch_secs(),
            via_direct_cable: true,
            shared_secret_hex: String::new(),
        });
        if let Err(e) = save_to_disk(&guard.config) {
            warn!("Failed to persist auto-trusted peer: {}", e);
        }
    }

    let trusted = already_trusted || auto_trusted || !guard.config.require_pairing_on_lan;
    guard.pending_peers.insert(
        clean_id.to_string(),
        PendingPeerInfo {
            device_id: clean_id.to_string(),
            hostname: clean_host,
            ip: clean_ip.to_string(),
            is_direct_cable: via_direct_cable,
            trusted,
            blocked: false,
        },
    );
    trusted
}

pub fn trust_device(device_id: &str, hostname: &str, ip: &str, via_direct_cable: bool) {
    trust_device_with_secret(device_id, hostname, ip, via_direct_cable, None);
}

pub fn trust_device_with_secret(
    device_id: &str,
    hostname: &str,
    ip: &str,
    via_direct_cable: bool,
    shared_secret_hex: Option<String>,
) {
    let clean_id = device_id.trim();
    let clean_ip = ip.trim();
    if clean_id.is_empty() {
        return;
    }
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.config.blocked_device_ids.retain(|id| id != clean_id);
    if !clean_ip.is_empty() {
        guard.config.blocked_ips.retain(|bip| bip != clean_ip);
    }

    if let Some(rec) = guard
        .config
        .trusted_peers
        .iter_mut()
        .find(|p| p.device_id == clean_id)
    {
        rec.hostname = hostname.trim().to_string();
        if !clean_ip.is_empty() {
            rec.last_ip = clean_ip.to_string();
        }
        rec.via_direct_cable = via_direct_cable;
        if let Some(sec) = shared_secret_hex {
            if !sec.is_empty() {
                rec.shared_secret_hex = sec;
            }
        }
    } else {
        guard.config.trusted_peers.push(TrustedPeerRecord {
            device_id: clean_id.to_string(),
            hostname: hostname.trim().to_string(),
            last_ip: clean_ip.to_string(),
            paired_at_epoch: epoch_secs(),
            via_direct_cable,
            shared_secret_hex: shared_secret_hex.unwrap_or_default(),
        });
    }
    if !clean_ip.is_empty() {
        guard
            .ip_to_device
            .insert(clean_ip.to_string(), clean_id.to_string());
    }
    if let Some(p) = guard.pending_peers.get_mut(clean_id) {
        p.trusted = true;
        p.blocked = false;
    }
    if let Err(e) = save_to_disk(&guard.config) {
        warn!("Failed to persist trusted device {}: {}", clean_id, e);
    }
}

/// Computes the client pairing request HMAC proof bound to the PIN and client nonce/token.
pub fn compute_pairing_request_mac(
    pin: &str,
    device_id: &str,
    hostname: &str,
    client_nonce: &str,
    client_token: &str,
) -> String {
    let msg = format!(
        "INTEGRATOR-PAIR-REQ-V1|{}|{}|{}|{}",
        device_id.trim(),
        hostname.trim(),
        client_nonce.trim(),
        client_token.trim()
    );
    to_hex(&hmac_sha256(pin.trim().as_bytes(), msg.as_bytes()))
}

/// Derives the 256-bit shared session secret from a successful PIN-authenticated pairing exchange.
pub fn derive_pairing_shared_secret(
    pin: &str,
    client_token: &str,
    server_token: &str,
    client_nonce: &str,
) -> String {
    let context = format!(
        "INTEGRATOR-SHARED-SECRET-V1|{}|{}|{}",
        client_token.trim(),
        server_token.trim(),
        client_nonce.trim()
    );
    to_hex(&hmac_sha256(pin.trim().as_bytes(), context.as_bytes()))
}

/// Verifies a pairing request with rate limiting, lockout, PIN expiry, and constant-time comparison.
/// Returns `Ok(server_token_hex)` on success or `Err(reason)` on failure.
pub fn verify_pin_and_establish_session(
    device_id: &str,
    hostname: &str,
    ip: &str,
    pin: &str,
    client_nonce: &str,
    client_token: &str,
    client_mac: &str,
) -> Result<String, String> {
    let clean_id = device_id.trim();
    let clean_ip = ip.trim();
    let clean_pin = pin.trim();
    if clean_id.is_empty() || clean_ip.is_empty() {
        return Err("Missing device_id or peer IP address".into());
    }

    let now = epoch_secs();
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());

    if guard.config.blocked_device_ids.iter().any(|id| id == clean_id)
        || guard.config.blocked_ips.iter().any(|bip| bip == clean_ip)
    {
        return Err("This device is blocked on this host.".into());
    }

    // 1. Check global lockout
    if guard.global_pin_attempts.locked_until_epoch > now {
        let wait = guard.global_pin_attempts.locked_until_epoch - now;
        return Err(format!(
            "Pairing is temporarily locked due to too many failed PIN attempts. Try again in {}s.",
            wait
        ));
    }

    // 2. Check per-IP lockout
    if let Some(ip_rec) = guard.pin_attempts_by_ip.get(clean_ip) {
        if ip_rec.locked_until_epoch > now {
            let wait = ip_rec.locked_until_epoch - now;
            return Err(format!(
                "Too many failed PIN attempts from {}. Locked out for {}s.",
                clean_ip, wait
            ));
        }
    }

    // 3. Check PIN TTL expiry (10 minutes)
    if guard.config.pin_created_at_epoch == 0
        || now.saturating_sub(guard.config.pin_created_at_epoch) > PIN_TTL_SECS
    {
        guard.config.pairing_pin = generate_pin();
        guard.config.pin_created_at_epoch = now;
        let _ = save_to_disk(&guard.config);
        return Err(
            "The host pairing PIN expired and has been rotated. Check the new 6-digit PIN in the Integrator UI."
                .into(),
        );
    }

    // 4. Constant-time PIN verification (+ optional HMAC proof verification if supplied)
    let expected_pin = guard.config.pairing_pin.clone();
    let pin_ok = is_valid_pin_format(clean_pin)
        && constant_time_eq(expected_pin.as_bytes(), clean_pin.as_bytes());

    let mac_ok = if !client_mac.trim().is_empty() && !client_nonce.trim().is_empty() {
        let expected_mac = compute_pairing_request_mac(
            &expected_pin,
            clean_id,
            hostname,
            client_nonce,
            client_token,
        );
        constant_time_eq(expected_mac.as_bytes(), client_mac.trim().as_bytes())
    } else {
        true
    };

    if !pin_ok || !mac_ok {
        // Record failure for global & per-IP rate limiters
        if now.saturating_sub(guard.global_pin_attempts.window_start_epoch) > ATTEMPT_WINDOW_SECS {
            guard.global_pin_attempts.failures = 0;
            guard.global_pin_attempts.window_start_epoch = now;
        }
        guard.global_pin_attempts.failures += 1;
        let global_failures = guard.global_pin_attempts.failures;

        let ip_failures = {
            let ip_entry = guard
                .pin_attempts_by_ip
                .entry(clean_ip.to_string())
                .or_insert(PinAttemptRecord {
                    failures: 0,
                    window_start_epoch: now,
                    locked_until_epoch: 0,
                });
            if now.saturating_sub(ip_entry.window_start_epoch) > ATTEMPT_WINDOW_SECS {
                ip_entry.failures = 0;
                ip_entry.window_start_epoch = now;
            }
            ip_entry.failures += 1;
            if ip_entry.failures >= MAX_FAILED_ATTEMPTS_PER_IP
                || global_failures >= MAX_FAILED_ATTEMPTS_GLOBAL
            {
                ip_entry.locked_until_epoch = now + LOCKOUT_DURATION_SECS;
            }
            ip_entry.failures
        };

        if ip_failures >= MAX_FAILED_ATTEMPTS_PER_IP
            || global_failures >= MAX_FAILED_ATTEMPTS_GLOBAL
        {
            if global_failures >= MAX_FAILED_ATTEMPTS_GLOBAL {
                guard.global_pin_attempts.locked_until_epoch = now + LOCKOUT_DURATION_SECS;
            }
            // Rotate the PIN immediately upon lockout so prior guesses are useless
            guard.config.pairing_pin = generate_pin();
            guard.config.pin_created_at_epoch = now;
            let _ = save_to_disk(&guard.config);
            warn!(
                "🚨 Pairing lockout triggered for {} after {} failed attempts; PIN rotated",
                clean_ip, ip_failures
            );
            return Err(format!(
                "Too many failed PIN attempts ({}). Pairing locked for 15 minutes and PIN rotated.",
                ip_failures
            ));
        }

        let remaining = MAX_FAILED_ATTEMPTS_PER_IP.saturating_sub(ip_failures);
        return Err(format!(
            "Invalid pairing PIN ({} attempt(s) remaining before lockout).",
            remaining
        ));
    }

    // 5. Success! Clear failure counters, derive 256-bit shared secret, and rotate one-time PIN
    guard.pin_attempts_by_ip.remove(clean_ip);
    guard.global_pin_attempts.failures = 0;

    let server_token = generate_random_token_hex(32);
    let shared_secret = if !client_token.trim().is_empty() && !client_nonce.trim().is_empty() {
        derive_pairing_shared_secret(&expected_pin, client_token, &server_token, client_nonce)
    } else {
        generate_random_token_hex(32)
    };

    // Rotate one-time PIN after successful pairing
    guard.config.pairing_pin = generate_pin();
    guard.config.pin_created_at_epoch = now;
    drop(guard);

    let cable = system_info::is_direct_cable_route(clean_ip);
    trust_device_with_secret(clean_id, hostname, clean_ip, cable, Some(shared_secret));

    Ok(server_token)
}

#[allow(dead_code)]
pub fn verify_pin_and_trust(device_id: &str, hostname: &str, ip: &str, pin: &str) -> bool {
    verify_pin_and_establish_session(device_id, hostname, ip, pin, "", "", "").is_ok()
}

pub fn untrust_or_block_device(device_id: &str, block: bool) {
    let clean_id = device_id.trim();
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    let mut removed_ips = Vec::new();
    guard.config.trusted_peers.retain(|p| {
        if p.device_id == clean_id {
            if !p.last_ip.is_empty() {
                removed_ips.push(p.last_ip.clone());
            }
            false
        } else {
            true
        }
    });
    if block {
        if !guard.config.blocked_device_ids.iter().any(|id| id == clean_id) {
            guard.config.blocked_device_ids.push(clean_id.to_string());
        }
        for rip in &removed_ips {
            if !guard.config.blocked_ips.iter().any(|bip| bip == rip) {
                guard.config.blocked_ips.push(rip.clone());
            }
        }
    }
    let pending_ip = if let Some(p) = guard.pending_peers.get_mut(clean_id) {
        p.trusted = false;
        p.blocked = block;
        Some(p.ip.clone())
    } else {
        None
    };
    if let Some(pip) = pending_ip {
        if block && !pip.is_empty() && !guard.config.blocked_ips.iter().any(|bip| bip == &pip) {
            guard.config.blocked_ips.push(pip);
        }
    }
    if let Err(e) = save_to_disk(&guard.config) {
        warn!("Failed to persist untrust/block state for {}: {}", clean_id, e);
    }
}

pub fn set_trust_policy(auto_trust_direct_cable: bool, require_pairing_on_lan: bool) {
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.config.auto_trust_direct_cable = auto_trust_direct_cable;
    guard.config.require_pairing_on_lan = require_pairing_on_lan;
    if let Err(e) = save_to_disk(&guard.config) {
        warn!("Failed to persist updated trust policy: {}", e);
    }
}

pub fn regenerate_pin() -> String {
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.config.pairing_pin = generate_pin();
    guard.config.pin_created_at_epoch = epoch_secs();
    guard.pin_attempts_by_ip.clear();
    guard.global_pin_attempts = PinAttemptRecord::default();
    if let Err(e) = save_to_disk(&guard.config) {
        warn!("Failed to persist regenerated PIN: {}", e);
    }
    guard.config.pairing_pin.clone()
}

pub fn get_trust_snapshot() -> (TrustConfigFile, Vec<PendingPeerInfo>) {
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    ensure_fresh_pin_locked(&mut guard);
    let peers: Vec<PendingPeerInfo> = guard.pending_peers.values().cloned().collect();
    (guard.config.clone(), peers)
}

/// Check whether an incoming connection from `remote_addr` is authorized.
pub fn is_remote_addr_authorized(remote_addr: IpAddr) -> bool {
    if remote_addr.is_loopback() {
        return true;
    }
    let ip_str = remote_addr.to_string();
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());

    // 1. Always reject blocked IPs or blocked device IDs first
    if guard.config.blocked_ips.iter().any(|bip| bip == &ip_str) {
        return false;
    }
    if let Some(dev_id) = guard.ip_to_device.get(&ip_str) {
        if guard.config.blocked_device_ids.iter().any(|id| id == dev_id) {
            return false;
        }
        if guard.config.trusted_peers.iter().any(|p| &p.device_id == dev_id) {
            return true;
        }
    }

    // Check persisted trusted_peers by last_ip if no beacon has been seen yet in this session
    if let Some(rec) = guard.config.trusted_peers.iter().find(|p| p.last_ip == ip_str) {
        if guard
            .config
            .blocked_device_ids
            .iter()
            .any(|id| id == &rec.device_id)
        {
            return false;
        }
        return true;
    }

    if !guard.config.require_pairing_on_lan {
        return true;
    }

    let auto_cable = guard.config.auto_trust_direct_cable;
    drop(guard);

    if auto_cable {
        return system_info::is_direct_cable_route(&ip_str);
    }
    false
}

pub fn is_device_trusted(device_id: &str) -> bool {
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());
    if guard.config.blocked_device_ids.iter().any(|id| id == device_id) {
        return false;
    }
    guard
        .config
        .trusted_peers
        .iter()
        .any(|p| p.device_id == device_id)
}

fn derive_transport_keys(secret: &[u8], sender_device_id: &str) -> ([u8; 32], [u8; 32]) {
    let enc_key = hmac_sha256(
        secret,
        format!("INTEGRATOR-ENC-KEY-V1|{}", sender_device_id).as_bytes(),
    );
    let mac_key = hmac_sha256(
        secret,
        format!("INTEGRATOR-MAC-KEY-V1|{}", sender_device_id).as_bytes(),
    );
    (enc_key, mac_key)
}

fn lookup_peer_shared_secret_by_ip(peer_ip: &str) -> Option<Vec<u8>> {
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dev_id) = guard.ip_to_device.get(peer_ip) {
        if let Some(rec) = guard.config.trusted_peers.iter().find(|p| &p.device_id == dev_id) {
            if !rec.shared_secret_hex.is_empty() {
                return from_hex(&rec.shared_secret_hex);
            }
        }
    }
    if let Some(rec) = guard.config.trusted_peers.iter().find(|p| p.last_ip == peer_ip) {
        if !rec.shared_secret_hex.is_empty() {
            return from_hex(&rec.shared_secret_hex);
        }
    }
    None
}

fn lookup_peer_shared_secret_by_id(device_id: &str, peer_ip: &str) -> Option<Vec<u8>> {
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(rec) = guard
        .config
        .trusted_peers
        .iter()
        .find(|p| p.device_id == device_id)
    {
        if !rec.shared_secret_hex.is_empty() {
            return from_hex(&rec.shared_secret_hex);
        }
    }
    if let Some(rec) = guard.config.trusted_peers.iter().find(|p| p.last_ip == peer_ip) {
        if !rec.shared_secret_hex.is_empty() {
            return from_hex(&rec.shared_secret_hex);
        }
    }
    None
}

fn compute_envelope_mac(
    mac_key: &[u8; 32],
    version: u8,
    sender_device_id: &str,
    timestamp_ms: u64,
    nonce_hex: &str,
    key_mode: &str,
    ciphertext_b64: &str,
) -> String {
    let aad = format!(
        "INTEGRATOR-ENVELOPE-V{}|{}|{}|{}|{}|{}",
        version, sender_device_id, timestamp_ms, nonce_hex, key_mode, ciphertext_b64
    );
    to_hex(&hmac_sha256(mac_key, aad.as_bytes()))
}

/// Encrypts and authenticates an outgoing frame for `peer_ip` using RFC 8439 ChaCha20 + HMAC-SHA256.
pub fn seal_envelope_for_ip(peer_ip: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let sender_device_id = system_info::get_or_create_device_id();
    let timestamp_ms = epoch_millis();
    let mut nonce = [0u8; 12];
    csprng_fill(&mut nonce);
    let nonce_hex = to_hex(&nonce);

    let (key_mode, raw_secret) = if let Some(sec) = lookup_peer_shared_secret_by_ip(peer_ip) {
        ("paired".to_string(), sec)
    } else {
        (
            "transport".to_string(),
            b"INTEGRATOR-TRANSPORT-CHANNEL-KEY-V1".to_vec(),
        )
    };

    let (enc_key, mac_key) = derive_transport_keys(&raw_secret, &sender_device_id);
    let mut buf = plaintext.to_vec();
    chacha20_xor(&enc_key, &nonce, 1, &mut buf);
    let ciphertext_b64 = BASE64.encode(&buf);
    let mac_hex = compute_envelope_mac(
        &mac_key,
        1,
        &sender_device_id,
        timestamp_ms,
        &nonce_hex,
        &key_mode,
        &ciphertext_b64,
    );

    let env = SecureEnvelope {
        version: 1,
        sender_device_id,
        timestamp_ms,
        nonce_hex,
        key_mode,
        ciphertext_b64,
        mac_hex,
    };
    serde_json::to_vec(&env).map_err(|e| format!("Failed to serialize secure envelope: {}", e))
}

/// Verifies and decrypts an incoming frame from `peer_ip`.
/// Returns `(Option<authenticated_device_id>, plaintext_bytes)`.
pub fn open_envelope_from_ip(
    peer_ip: IpAddr,
    frame: &[u8],
) -> Result<(Option<String>, Vec<u8>), String> {
    if let Ok(env) = serde_json::from_slice::<SecureEnvelope>(frame) {
        if env.version != 1 {
            return Err(format!("Unsupported secure envelope version {}", env.version));
        }
        let sender_id = env.sender_device_id.trim();
        if sender_id.is_empty() || sender_id.len() > 128 {
            return Err("Invalid sender_device_id in secure envelope".into());
        }

        let now_ms = epoch_millis();
        let skew = now_ms.abs_diff(env.timestamp_ms);
        if skew > ENVELOPE_REPLAY_WINDOW_MS {
            return Err(format!(
                "Rejected expired or skewed envelope from {} (skew={}ms)",
                peer_ip, skew
            ));
        }

        let nonce_vec = from_hex(&env.nonce_hex)
            .filter(|v| v.len() == 12)
            .ok_or_else(|| "Invalid 12-byte nonce in secure envelope".to_string())?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        let ip_str = peer_ip.to_string();
        let (raw_secret, is_paired_crypto) = if env.key_mode == "paired" {
            let sec = lookup_peer_shared_secret_by_id(sender_id, &ip_str).ok_or_else(|| {
                format!(
                    "Peer {} ({}) sent paired-key envelope, but no shared secret is registered",
                    sender_id, ip_str
                )
            })?;
            (sec, true)
        } else {
            // If we already have a paired shared secret on file for this device_id,
            // refuse unauthenticated "transport" key downgrades!
            if lookup_peer_shared_secret_by_id(sender_id, &ip_str).is_some() {
                return Err(format!(
                    "Rejected transport-mode downgrade for cryptographically paired peer {}",
                    sender_id
                ));
            }
            (b"INTEGRATOR-TRANSPORT-CHANNEL-KEY-V1".to_vec(), false)
        };

        let (enc_key, mac_key) = derive_transport_keys(&raw_secret, sender_id);
        let expected_mac = compute_envelope_mac(
            &mac_key,
            env.version,
            sender_id,
            env.timestamp_ms,
            &env.nonce_hex,
            &env.key_mode,
            &env.ciphertext_b64,
        );

        if !constant_time_eq(expected_mac.as_bytes(), env.mac_hex.as_bytes()) {
            return Err(format!(
                "Envelope HMAC verification failed from {} ({})",
                sender_id, ip_str
            ));
        }

        // Replay check and device-to-IP binding under state lock
        {
            let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
            if guard
                .config
                .blocked_device_ids
                .iter()
                .any(|id| id == sender_id)
                || guard.config.blocked_ips.iter().any(|bip| bip == &ip_str)
            {
                return Err(format!("Rejected envelope from blocked peer {}", sender_id));
            }
            let nonce_key = format!("{}:{}", sender_id, env.nonce_hex);
            if guard.seen_nonces.iter().any(|n| n == &nonce_key) {
                return Err(format!("Rejected replayed envelope nonce from {}", sender_id));
            }
            if guard.seen_nonces.len() >= MAX_REPLAY_NONCES {
                guard.seen_nonces.pop_front();
            }
            guard.seen_nonces.push_back(nonce_key);

            if is_paired_crypto {
                guard
                    .ip_to_device
                    .insert(ip_str.clone(), sender_id.to_string());
                if let Some(rec) = guard
                    .config
                    .trusted_peers
                    .iter_mut()
                    .find(|p| p.device_id == sender_id)
                {
                    if rec.last_ip != ip_str {
                        rec.last_ip = ip_str;
                        let _ = save_to_disk(&guard.config);
                    }
                }
            }
        }

        let mut buf = BASE64
            .decode(&env.ciphertext_b64)
            .map_err(|e| format!("Invalid ciphertext base64 in envelope: {}", e))?;
        chacha20_xor(&enc_key, &nonce, 1, &mut buf);

        let auth_dev = if is_paired_crypto {
            Some(sender_id.to_string())
        } else if is_device_trusted(sender_id) && is_remote_addr_authorized(peer_ip) {
            Some(sender_id.to_string())
        } else {
            None
        };
        return Ok((auth_dev, buf));
    }

    // Fallback for local loopback CLI calls (`127.0.0.1`)
    if peer_ip.is_loopback() {
        return Ok((Some("loopback".to_string()), frame.to_vec()));
    }

    Err("Rejected unencrypted/unauthenticated network frame".into())
}

/// Signs discovery beacon metadata so paired or same-version peers can verify beacon integrity.
pub fn sign_discovery_beacon(
    device_id: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
) -> String {
    let msg = format!(
        "INTEGRATOR-BEACON-V1|{}|{}|{}|{}",
        device_id.trim(),
        timestamp_ms,
        control_port,
        clipboard_port
    );
    to_hex(&hmac_sha256(b"INTEGRATOR-DISCOVERY-BEACON-V1", msg.as_bytes()))
}

/// Validates discovery beacon fields and freshness window (±60s) before acting on discovery data.
pub fn verify_discovery_beacon_fields(
    device_id: &str,
    sender_name: &str,
    timestamp_ms: u64,
    control_port: u16,
    clipboard_port: u16,
    beacon_mac: &str,
) -> bool {
    if device_id.trim().is_empty()
        || device_id.len() > 128
        || sender_name.trim().is_empty()
        || sender_name.len() > 128
        || control_port < 1024
        || clipboard_port < 1024
    {
        return false;
    }
    if timestamp_ms > 0 {
        let now_ms = epoch_millis();
        if now_ms.abs_diff(timestamp_ms) > 60_000 {
            return false;
        }
    }
    if !beacon_mac.is_empty() {
        let expected = sign_discovery_beacon(device_id, timestamp_ms, control_port, clipboard_port);
        if !constant_time_eq(expected.as_bytes(), beacon_mac.as_bytes()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csprng_pin_is_six_digits_and_non_constant() {
        let p1 = generate_pin();
        let p2 = generate_pin();
        assert_eq!(p1.len(), 6);
        assert_eq!(p2.len(), 6);
        assert!(is_valid_pin_format(&p1));
        assert!(is_valid_pin_format(&p2));
    }

    #[test]
    fn rfc8439_chacha20_and_hmac_envelope_roundtrip_and_tamper_rejection() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let msg = b"secret workstation payload";
        let sealed = seal_envelope_for_ip("127.0.0.1", msg).unwrap();
        let (_, opened) = open_envelope_from_ip(ip, &sealed).unwrap();
        assert_eq!(opened, msg);

        // Tamper with MAC inside envelope JSON
        let mut env: SecureEnvelope = serde_json::from_slice(&sealed).unwrap();
        env.mac_hex = "00".repeat(32);
        let tampered = serde_json::to_vec(&env).unwrap();
        let non_loopback: IpAddr = "192.0.2.55".parse().unwrap();
        assert!(open_envelope_from_ip(non_loopback, &tampered).is_err());
    }

    #[test]
    fn pin_rate_limit_locks_out_after_five_failures() {
        let test_ip = "198.51.100.77";
        {
            let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
            guard.pin_attempts_by_ip.remove(test_ip);
            guard.global_pin_attempts = PinAttemptRecord::default();
            guard.config.pin_created_at_epoch = epoch_secs();
        }
        for i in 1..=MAX_FAILED_ATTEMPTS_PER_IP {
            let res = verify_pin_and_establish_session(
                "dev-attacker",
                "attacker-host",
                test_ip,
                "000000",
                "",
                "",
                "",
            );
            assert!(res.is_err());
            if i == MAX_FAILED_ATTEMPTS_PER_IP {
                assert!(res.unwrap_err().contains("locked"));
            }
        }
        // Subsequent attempt even with current PIN must be rejected while locked out
        let current_pin = {
            let guard = state().lock().unwrap_or_else(|e| e.into_inner());
            guard.config.pairing_pin.clone()
        };
        let locked_res = verify_pin_and_establish_session(
            "dev-attacker",
            "attacker-host",
            test_ip,
            &current_pin,
            "",
            "",
            "",
        );
        assert!(locked_res.is_err());
    }
}
