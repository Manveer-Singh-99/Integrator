//! Staged RFC 9382 SPAKE2 + Ed25519 Pairing Protocol (`IPR2`, v2) & Anti-DoS Coordinator.
//!
//! Security properties:
//! 1. **4-Message Staged Mutual Confirmation (`PairInit` -> `PairServerShare` -> `PairClientConfirm` -> `PairServerComplete`)**:
//!    - Neither side commits trust or transitions to the negotiated `K_root` until the peer's
//!      SPAKE2 confirmation MAC (`F_A` / `F_B`) and `Ed25519` transcript signature (`sig_A` / `sig_B`)
//!      are cryptographically verified.
//!    - The responder (Server `B`) verifies `F_A` and `sig_A` *before* revealing `F_B`, `sig_B`,
//!      or `F_ack`, preventing unauthenticated attackers from using the server as a signing oracle.
//! 2. **Anti-DoS PIN Lifecycle (Zero Forced PIN Rotation on Failed Guesses)**:
//!    - Failed confirmation attempts from an attacker **never** rotate or invalidate the host's active PIN.
//!    - Per-IP rate limiting enforces at most 3 failed attempts per 60s window per IP, followed by
//!      exponential per-IP lockout (`60s`, `120s`, `240s`, `480s`, `960s`), while other IPs remain
//!      able to pair with the active PIN until its 10-minute TTL expires or a valid pairing completes.
//! 3. **Bounded Concurrency & Replay Resistance**:
//!    - Max 4 concurrent in-flight pairing sessions globally (`MAX_CONCURRENT_SESSIONS = 4`),
//!      max 1 active session per IP, 15-second session TTL, and 32-byte fresh CSPRNG nonces on both sides.
//! 4. **Identity-Key Pinning**:
//!    - Verifies `device_id == SHA256("integrator-device-id-v2" || ed25519_pubkey)[0..16]` and blocks
//!      unexpected key changes for any already-pinned peer until explicitly unpaired.

use crate::security::{
    constant_time_eq, csprng_array, hex_decode_array, hex_encode,
    keystore::{KeystoreError, KeystoreV2, VerifiedPeerCredentials},
    spake2_rfc9382::{compute_password_salt, Spake2Error, Spake2Role, Spake2State},
    unix_epoch_secs,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PAIRING_WIRE_MAGIC: [u8; 4] = *b"IPR2";
pub const PAIRING_PROTOCOL_VERSION: u16 = 2;
pub const PAIRING_HEADER_VERSION_BYTE: u8 = 0x02;
pub const MAX_PAIRING_FRAME_BYTES: usize = 4096;

pub const PIN_TTL_SECS: u64 = 600; // 10 minutes
pub const INFLIGHT_SESSION_TTL_SECS: u64 = 15; // 15 seconds per handshake
pub const MAX_CONCURRENT_PAIRING_SESSIONS: usize = 4;
pub const MAX_FAILED_ATTEMPTS_PER_IP: u32 = 3;
pub const IP_ATTEMPT_WINDOW_SECS: u64 = 60;
pub const BASE_IP_LOCKOUT_SECS: u64 = 60;
pub const MAX_IP_RATE_LIMIT_ENTRIES: usize = 1024;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_PLATFORM_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingMsgType {
    PairInit = 0x01,
    PairServerShare = 0x02,
    PairClientConfirm = 0x03,
    PairServerComplete = 0x04,
    PairError = 0xFF,
}

impl PairingMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(PairingMsgType::PairInit),
            0x02 => Some(PairingMsgType::PairServerShare),
            0x03 => Some(PairingMsgType::PairClientConfirm),
            0x04 => Some(PairingMsgType::PairServerComplete),
            0xFF => Some(PairingMsgType::PairError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairInitMsg {
    pub version: u16,
    pub client_device_id_hex: String,
    pub client_ed25519_pk_hex: String,
    pub client_nonce_hex: String,
    pub device_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairServerShareMsg {
    pub version: u16,
    pub pairing_session_id_hex: String,
    pub server_device_id_hex: String,
    pub server_ed25519_pk_hex: String,
    pub server_nonce_hex: String,
    pub spake2_share_b_hex: String,
    pub device_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairClientConfirmMsg {
    pub pairing_session_id_hex: String,
    pub spake2_share_a_hex: String,
    pub confirm_mac_a_hex: String,
    pub identity_sig_a_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairServerCompleteMsg {
    pub pairing_session_id_hex: String,
    pub confirm_mac_b_hex: String,
    pub identity_sig_b_hex: String,
    pub ack_mac_hex: String,
    pub key_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairErrorWireMsg {
    pub code: u8,
    pub retry_after_secs: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    UnsupportedVersion(u16),
    InvalidFrameMagic([u8; 4]),
    InvalidMessageType(u8),
    OversizedFrame(usize),
    MalformedMessage(String),
    PairingWindowClosed,
    PinExpired,
    InvalidPinFormat,
    IpRateLimited { retry_after_secs: u64 },
    TooManyConcurrentSessions,
    SessionNotFoundOrExpired,
    SessionIpMismatch,
    SpoofedDeviceId,
    IdentityKeyPinnedConflict(String),
    Spake2Failure(Spake2Error),
    SignatureVerificationFailed,
    AckMacVerificationFailed,
    KeystoreFailure(KeystoreError),
    IoFailure(String),
    RemotePeerRejected { code: u8, message: String },
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairingError::UnsupportedVersion(v) => {
                write!(f, "Unsupported pairing protocol version {} (expected 2)", v)
            }
            PairingError::InvalidFrameMagic(m) => {
                write!(f, "Invalid pairing frame magic {:?} (expected IPR2)", m)
            }
            PairingError::InvalidMessageType(t) => {
                write!(f, "Unexpected or unknown pairing message type 0x{:02x}", t)
            }
            PairingError::OversizedFrame(len) => write!(
                f,
                "Pairing frame length {} exceeds maximum {} bytes",
                len, MAX_PAIRING_FRAME_BYTES
            ),
            PairingError::MalformedMessage(msg) => write!(f, "Malformed pairing message: {}", msg),
            PairingError::PairingWindowClosed => {
                write!(f, "Host pairing mode is not currently active")
            }
            PairingError::PinExpired => write!(f, "Active pairing PIN has expired"),
            PairingError::InvalidPinFormat => {
                write!(f, "Pairing PIN must be exactly 6 ASCII digits")
            }
            PairingError::IpRateLimited { retry_after_secs } => write!(
                f,
                "Too many failed pairing attempts from this IP; retry after {}s",
                retry_after_secs
            ),
            PairingError::TooManyConcurrentSessions => {
                write!(f, "Maximum concurrent pairing handshakes reached; try again shortly")
            }
            PairingError::SessionNotFoundOrExpired => {
                write!(f, "Pairing session ID not found or expired")
            }
            PairingError::SessionIpMismatch => {
                write!(f, "Pairing session source IP does not match initiator IP")
            }
            PairingError::SpoofedDeviceId => {
                write!(f, "Peer device_id does not match its Ed25519 public key")
            }
            PairingError::IdentityKeyPinnedConflict(msg) => write!(f, "{}", msg),
            PairingError::Spake2Failure(e) => write!(f, "SPAKE2 verification failed: {}", e),
            PairingError::SignatureVerificationFailed => {
                write!(f, "Peer Ed25519 transcript signature verification failed")
            }
            PairingError::AckMacVerificationFailed => {
                write!(f, "Server completion acknowledgment MAC verification failed")
            }
            PairingError::KeystoreFailure(e) => write!(f, "Keystore error: {}", e),
            PairingError::IoFailure(e) => write!(f, "I/O error during pairing: {}", e),
            PairingError::RemotePeerRejected { code, message } => {
                write!(f, "Remote peer rejected pairing (code {}): {}", code, message)
            }
        }
    }
}

impl std::error::Error for PairingError {}

impl PairingError {
    pub fn to_wire_error(&self) -> PairErrorWireMsg {
        let (code, retry) = match self {
            PairingError::UnsupportedVersion(_) => (1, 0),
            PairingError::PairingWindowClosed | PairingError::PinExpired => (2, 0),
            PairingError::IpRateLimited { retry_after_secs } => (3, *retry_after_secs as u32),
            PairingError::TooManyConcurrentSessions => (4, 5),
            PairingError::SpoofedDeviceId | PairingError::IdentityKeyPinnedConflict(_) => (5, 0),
            PairingError::Spake2Failure(_)
            | PairingError::SignatureVerificationFailed
            | PairingError::AckMacVerificationFailed => (6, 0),
            _ => (99, 0),
        };
        PairErrorWireMsg {
            code,
            retry_after_secs: retry,
            message: self.to_string().chars().take(120).collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct IpRateLimitRecord {
    failures: u32,
    window_started_at: u64,
    locked_until: u64,
    consecutive_lockouts: u32,
    last_touched: u64,
}

struct InFlightServerSession {
    pairing_session_id: [u8; 16],
    source_ip: IpAddr,
    created_at_secs: u64,
    client_device_id: [u8; 16],
    client_ed25519_pk: [u8; 32],
    client_device_name: String,
    client_platform: String,
    spake2_state: Spake2State,
    aad_hash: [u8; 32],
}

/// Manages the host's active pairing PIN, per-IP rate limiting, and in-flight SPAKE2 sessions.
pub struct PairingCoordinatorV2 {
    active_pin: Option<String>,
    pin_created_at_secs: u64,
    pairing_window_open: bool,
    local_device_name: String,
    local_platform: String,
    inflight_sessions: HashMap<[u8; 16], InFlightServerSession>,
    ip_rate_limits: HashMap<IpAddr, IpRateLimitRecord>,
}

impl PairingCoordinatorV2 {
    pub fn new(local_device_name: String, local_platform: String) -> Self {
        Self {
            active_pin: None,
            pin_created_at_secs: 0,
            pairing_window_open: false,
            local_device_name,
            local_platform,
            inflight_sessions: HashMap::new(),
            ip_rate_limits: HashMap::new(),
        }
    }

    /// Generates an unbiased 6-digit PIN (`100000`..=`999999`) via rejection sampling and opens
    /// the pairing window for `PIN_TTL_SECS` (10 minutes).
    pub fn open_pairing_window(&mut self, now_secs: u64) -> String {
        let pin = generate_unbiased_6digit_pin();
        self.active_pin = Some(pin.clone());
        self.pin_created_at_secs = now_secs;
        self.pairing_window_open = true;
        self.inflight_sessions.clear();
        pin
    }

    /// Opens the pairing window with an explicit 6-digit PIN (used for deterministic testing or user-regenerated PIN).
    pub fn open_pairing_window_with_pin(
        &mut self,
        pin: &str,
        now_secs: u64,
    ) -> Result<(), PairingError> {
        if !is_valid_6digit_pin(pin) {
            return Err(PairingError::InvalidPinFormat);
        }
        self.active_pin = Some(pin.to_string());
        self.pin_created_at_secs = now_secs;
        self.pairing_window_open = true;
        self.inflight_sessions.clear();
        Ok(())
    }

    pub fn close_pairing_window(&mut self) {
        self.pairing_window_open = false;
        self.active_pin = None;
        self.inflight_sessions.clear();
    }

    pub fn active_pin(&self, now_secs: u64) -> Option<&str> {
        if !self.pairing_window_open {
            return None;
        }
        if now_secs.saturating_sub(self.pin_created_at_secs) > PIN_TTL_SECS {
            return None;
        }
        self.active_pin.as_deref()
    }

    fn check_ip_rate_limit(&mut self, ip: IpAddr, now_secs: u64) -> Result<(), PairingError> {
        if let Some(rec) = self.ip_rate_limits.get_mut(&ip) {
            rec.last_touched = now_secs;
            if rec.locked_until > now_secs {
                return Err(PairingError::IpRateLimited {
                    retry_after_secs: rec.locked_until - now_secs,
                });
            }
            if now_secs.saturating_sub(rec.window_started_at) > IP_ATTEMPT_WINDOW_SECS {
                rec.failures = 0;
                rec.window_started_at = now_secs;
            }
        }
        Ok(())
    }

    /// Records a failed authentication attempt for `ip` WITHOUT rotating or invalidating the host's active PIN.
    fn record_ip_failure(&mut self, ip: IpAddr, now_secs: u64) {
        if self.ip_rate_limits.len() >= MAX_IP_RATE_LIMIT_ENTRIES
            && !self.ip_rate_limits.contains_key(&ip)
        {
            // Evict the oldest entry to bound memory usage.
            if let Some((&oldest_ip, _)) = self
                .ip_rate_limits
                .iter()
                .min_by_key(|(_, r)| r.last_touched)
            {
                self.ip_rate_limits.remove(&oldest_ip);
            }
        }

        let entry = self
            .ip_rate_limits
            .entry(ip)
            .or_insert_with(|| IpRateLimitRecord {
                failures: 0,
                window_started_at: now_secs,
                locked_until: 0,
                consecutive_lockouts: 0,
                last_touched: now_secs,
            });

        entry.last_touched = now_secs;
        if now_secs.saturating_sub(entry.window_started_at) > IP_ATTEMPT_WINDOW_SECS {
            entry.failures = 0;
            entry.window_started_at = now_secs;
        }

        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= MAX_FAILED_ATTEMPTS_PER_IP {
            let exp = entry.consecutive_lockouts.min(4);
            let lockout_secs = BASE_IP_LOCKOUT_SECS.saturating_mul(1u64 << exp);
            entry.locked_until = now_secs.saturating_add(lockout_secs);
            entry.consecutive_lockouts = entry.consecutive_lockouts.saturating_add(1);
            entry.failures = 0;
        }
    }

    fn clear_ip_failures(&mut self, ip: IpAddr) {
        self.ip_rate_limits.remove(&ip);
    }

    fn prune_expired_sessions(&mut self, now_secs: u64) {
        self.inflight_sessions.retain(|_, s| {
            now_secs.saturating_sub(s.created_at_secs) <= INFLIGHT_SESSION_TTL_SECS
        });
    }

    /// Step 1 (Server `B`): Processes `PairInit` from `source_ip` and returns `PairServerShareMsg`.
    pub fn handle_pair_init(
        &mut self,
        keystore: &KeystoreV2,
        source_ip: IpAddr,
        init_msg: &PairInitMsg,
        now_secs: u64,
    ) -> Result<PairServerShareMsg, PairingError> {
        self.check_ip_rate_limit(source_ip, now_secs)?;
        self.prune_expired_sessions(now_secs);

        if init_msg.version != PAIRING_PROTOCOL_VERSION {
            return Err(PairingError::UnsupportedVersion(init_msg.version));
        }

        if !self.pairing_window_open {
            return Err(PairingError::PairingWindowClosed);
        }

        let pin = match &self.active_pin {
            Some(p) if now_secs.saturating_sub(self.pin_created_at_secs) <= PIN_TTL_SECS => {
                p.clone()
            }
            Some(_) => {
                self.pairing_window_open = false;
                self.active_pin = None;
                return Err(PairingError::PinExpired);
            }
            None => return Err(PairingError::PairingWindowClosed),
        };

        let client_device_id: [u8; 16] = hex_decode_array(&init_msg.client_device_id_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid client_device_id_hex".into()))?;
        let client_ed25519_pk: [u8; 32] = hex_decode_array(&init_msg.client_ed25519_pk_hex)
            .ok_or_else(|| {
                PairingError::MalformedMessage("invalid client_ed25519_pk_hex".into())
            })?;
        let client_nonce: [u8; 32] = hex_decode_array(&init_msg.client_nonce_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid client_nonce_hex".into()))?;

        let clean_name = sanitize_label(&init_msg.device_name, MAX_NAME_LEN);
        let clean_platform = sanitize_label(&init_msg.platform, MAX_PLATFORM_LEN);

        // Verify client_device_id derivation and identity-key pinning before allocating session state.
        keystore
            .check_peer_identity_pinning(&client_device_id, &client_ed25519_pk, &clean_name)
            .map_err(|e| match e {
                KeystoreError::SpoofedDeviceId { .. } => PairingError::SpoofedDeviceId,
                KeystoreError::PinnedIdentityKeyMismatch { .. } => {
                    PairingError::IdentityKeyPinnedConflict(e.to_string())
                }
                other => PairingError::KeystoreFailure(other),
            })?;

        // Enforce at most 1 active in-flight session per source IP, and at most MAX_CONCURRENT_PAIRING_SESSIONS globally.
        self.inflight_sessions
            .retain(|_, s| s.source_ip != source_ip);
        if self.inflight_sessions.len() >= MAX_CONCURRENT_PAIRING_SESSIONS {
            return Err(PairingError::TooManyConcurrentSessions);
        }

        let pairing_session_id = csprng_array::<16>();
        let server_nonce = csprng_array::<32>();
        let server_device_id = keystore.local_device_id();
        let server_ed25519_pk = keystore.local_ed25519_pubkey();

        let salt_pw = compute_password_salt(&client_device_id, &server_device_id);
        let id_a = build_spake2_identity_a(&client_device_id, &client_ed25519_pk, &client_nonce);
        let id_b = build_spake2_identity_b(
            &server_device_id,
            &server_ed25519_pk,
            &server_nonce,
            &pairing_session_id,
        );

        let (spake2_state, spake2_share_b) =
            Spake2State::start_b(pin.as_bytes(), &salt_pw, &id_a, &id_b)
                .map_err(PairingError::Spake2Failure)?;

        let share_msg = PairServerShareMsg {
            version: PAIRING_PROTOCOL_VERSION,
            pairing_session_id_hex: hex_encode(&pairing_session_id),
            server_device_id_hex: hex_encode(&server_device_id),
            server_ed25519_pk_hex: hex_encode(&server_ed25519_pk),
            server_nonce_hex: hex_encode(&server_nonce),
            spake2_share_b_hex: hex_encode(&spake2_share_b),
            device_name: self.local_device_name.clone(),
            platform: self.local_platform.clone(),
        };

        let aad_hash = compute_pairing_header_aad(init_msg, &share_msg);

        self.inflight_sessions.insert(
            pairing_session_id,
            InFlightServerSession {
                pairing_session_id,
                source_ip,
                created_at_secs: now_secs,
                client_device_id,
                client_ed25519_pk,
                client_device_name: clean_name,
                client_platform: clean_platform,
                spake2_state,
                aad_hash,
            },
        );

        Ok(share_msg)
    }

    /// Step 2 (Server `B`): Processes `PairClientConfirm`, verifies `F_A` and `sig_A` BEFORE
    /// committing trust or revealing `F_B`, `sig_B`, and `F_ack`.
    /// On failure, records a per-IP failure without rotating the active PIN.
    pub fn handle_pair_client_confirm(
        &mut self,
        keystore: &mut KeystoreV2,
        source_ip: IpAddr,
        confirm_msg: &PairClientConfirmMsg,
        via_direct_cable: bool,
        now_secs: u64,
    ) -> Result<(PairServerCompleteMsg, VerifiedPeerCredentials, String), PairingError> {
        self.check_ip_rate_limit(source_ip, now_secs)?;
        self.prune_expired_sessions(now_secs);

        let session_id: [u8; 16] = hex_decode_array(&confirm_msg.pairing_session_id_hex)
            .ok_or_else(|| {
                PairingError::MalformedMessage("invalid pairing_session_id_hex".into())
            })?;

        let session = match self.inflight_sessions.remove(&session_id) {
            Some(s) => s,
            None => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::SessionNotFoundOrExpired);
            }
        };

        if session.source_ip != source_ip {
            self.record_ip_failure(source_ip, now_secs);
            return Err(PairingError::SessionIpMismatch);
        }

        let spake2_share_a: [u8; 32] = match hex_decode_array(&confirm_msg.spake2_share_a_hex) {
            Some(arr) => arr,
            None => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::MalformedMessage(
                    "invalid spake2_share_a_hex".into(),
                ));
            }
        };
        let confirm_mac_a: [u8; 32] = match hex_decode_array(&confirm_msg.confirm_mac_a_hex) {
            Some(arr) => arr,
            None => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::MalformedMessage(
                    "invalid confirm_mac_a_hex".into(),
                ));
            }
        };
        let sig_a: [u8; 64] = match hex_decode_array(&confirm_msg.identity_sig_a_hex) {
            Some(arr) => arr,
            None => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::MalformedMessage(
                    "invalid identity_sig_a_hex".into(),
                ));
            }
        };

        // Finish SPAKE2 and verify Client's confirmation MAC F_A.
        let transcript_out = match session
            .spake2_state
            .finish(&spake2_share_a, &session.aad_hash)
        {
            Ok(out) => out,
            Err(e) => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::Spake2Failure(e));
            }
        };

        if let Err(e) =
            transcript_out.verify_peer_confirm_mac(Spake2Role::InitiatorA, &confirm_mac_a)
        {
            // Wrong PIN or tampered transcript: penalize ONLY this source IP, keeping the legitimate PIN active!
            self.record_ip_failure(source_ip, now_secs);
            return Err(PairingError::Spake2Failure(e));
        }

        // Verify Client's Ed25519 signature over the transcript digest and F_A.
        let sig_a_payload =
            build_client_signature_payload(&transcript_out.tt_sha256, &confirm_mac_a);
        if KeystoreV2::verify_signature(&session.client_ed25519_pk, &sig_a_payload, &sig_a).is_err()
        {
            self.record_ip_failure(source_ip, now_secs);
            return Err(PairingError::SignatureVerificationFailed);
        }

        // Client is now cryptographically authenticated (both PIN and Ed25519 identity).
        // Compute Server's Ed25519 signature sig_B and final application secrets.
        let sig_b_payload = build_server_signature_payload(
            &transcript_out.tt_sha256,
            &transcript_out.confirm_mac_b,
            &sig_a,
        );
        let sig_b = keystore.sign_transcript(&sig_b_payload);
        let app_secrets = transcript_out.derive_application_secrets(&sig_a, &sig_b);

        // Commit Peer A to the OS-backed keystore.
        let creds = keystore
            .commit_paired_peer(
                session.client_device_id,
                session.client_ed25519_pk,
                app_secrets.root_key.clone(),
                session.client_device_name,
                session.client_platform,
                source_ip.to_string(),
                via_direct_cable,
            )
            .map_err(PairingError::KeystoreFailure)?;

        // Consume the one-time pairing PIN ONLY upon successful authenticated completion!
        self.clear_ip_failures(source_ip);
        self.close_pairing_window();

        let complete_msg = PairServerCompleteMsg {
            pairing_session_id_hex: hex_encode(&session.pairing_session_id),
            confirm_mac_b_hex: hex_encode(&transcript_out.confirm_mac_b),
            identity_sig_b_hex: hex_encode(&sig_b),
            ack_mac_hex: hex_encode(&app_secrets.ack_mac),
            key_id_hex: hex_encode(&app_secrets.key_id),
        };

        Ok((complete_msg, creds, app_secrets.sas_code))
    }
}

/// Client-side (`Initiator A`) state machine for a single pairing handshake.
pub struct ClientPairingHandshakeV2 {
    pin: String,
    init_msg: PairInitMsg,
    client_device_id: [u8; 16],
    client_ed25519_pk: [u8; 32],
    client_nonce: [u8; 32],
}

pub struct ClientAwaitingServerComplete {
    pairing_session_id: [u8; 16],
    server_device_id: [u8; 16],
    server_ed25519_pk: [u8; 32],
    server_device_name: String,
    server_platform: String,
    sig_a: [u8; 64],
    transcript_out: crate::security::spake2_rfc9382::Spake2TranscriptOutput,
}

impl ClientPairingHandshakeV2 {
    /// Step 1 (Client `A`): Creates `PairInitMsg` to send to the host.
    pub fn initiate(
        keystore: &KeystoreV2,
        pin: &str,
        local_device_name: &str,
        local_platform: &str,
    ) -> Result<(Self, PairInitMsg), PairingError> {
        let trimmed_pin = pin.trim();
        if !is_valid_6digit_pin(trimmed_pin) {
            return Err(PairingError::InvalidPinFormat);
        }

        let client_device_id = keystore.local_device_id();
        let client_ed25519_pk = keystore.local_ed25519_pubkey();
        let client_nonce = csprng_array::<32>();

        let init_msg = PairInitMsg {
            version: PAIRING_PROTOCOL_VERSION,
            client_device_id_hex: hex_encode(&client_device_id),
            client_ed25519_pk_hex: hex_encode(&client_ed25519_pk),
            client_nonce_hex: hex_encode(&client_nonce),
            device_name: sanitize_label(local_device_name, MAX_NAME_LEN),
            platform: sanitize_label(local_platform, MAX_PLATFORM_LEN),
        };

        Ok((
            Self {
                pin: trimmed_pin.to_string(),
                init_msg: init_msg.clone(),
                client_device_id,
                client_ed25519_pk,
                client_nonce,
            },
            init_msg,
        ))
    }

    /// Step 2 (Client `A`): Processes `PairServerShareMsg`, validates server identity & pinning,
    /// computes SPAKE2 share `pA`, `F_A`, and `sig_A`, and returns `PairClientConfirmMsg`.
    pub fn process_server_share(
        self,
        keystore: &KeystoreV2,
        share_msg: &PairServerShareMsg,
    ) -> Result<(ClientAwaitingServerComplete, PairClientConfirmMsg), PairingError> {
        if share_msg.version != PAIRING_PROTOCOL_VERSION {
            return Err(PairingError::UnsupportedVersion(share_msg.version));
        }

        let pairing_session_id: [u8; 16] = hex_decode_array(&share_msg.pairing_session_id_hex)
            .ok_or_else(|| {
                PairingError::MalformedMessage("invalid pairing_session_id_hex".into())
            })?;
        let server_device_id: [u8; 16] = hex_decode_array(&share_msg.server_device_id_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid server_device_id_hex".into()))?;
        let server_ed25519_pk: [u8; 32] = hex_decode_array(&share_msg.server_ed25519_pk_hex)
            .ok_or_else(|| {
                PairingError::MalformedMessage("invalid server_ed25519_pk_hex".into())
            })?;
        let server_nonce: [u8; 32] = hex_decode_array(&share_msg.server_nonce_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid server_nonce_hex".into()))?;
        let spake2_share_b: [u8; 32] = hex_decode_array(&share_msg.spake2_share_b_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid spake2_share_b_hex".into()))?;

        let clean_server_name = sanitize_label(&share_msg.device_name, MAX_NAME_LEN);
        let clean_server_platform = sanitize_label(&share_msg.platform, MAX_PLATFORM_LEN);

        // Verify server_device_id matches server_ed25519_pk and check identity-key pinning table.
        keystore
            .check_peer_identity_pinning(
                &server_device_id,
                &server_ed25519_pk,
                &clean_server_name,
            )
            .map_err(|e| match e {
                KeystoreError::SpoofedDeviceId { .. } => PairingError::SpoofedDeviceId,
                KeystoreError::PinnedIdentityKeyMismatch { .. } => {
                    PairingError::IdentityKeyPinnedConflict(e.to_string())
                }
                other => PairingError::KeystoreFailure(other),
            })?;

        let salt_pw = compute_password_salt(&self.client_device_id, &server_device_id);
        let id_a = build_spake2_identity_a(
            &self.client_device_id,
            &self.client_ed25519_pk,
            &self.client_nonce,
        );
        let id_b = build_spake2_identity_b(
            &server_device_id,
            &server_ed25519_pk,
            &server_nonce,
            &pairing_session_id,
        );

        let (spake2_state, spake2_share_a) =
            Spake2State::start_a(self.pin.as_bytes(), &salt_pw, &id_a, &id_b)
                .map_err(PairingError::Spake2Failure)?;

        let aad_hash = compute_pairing_header_aad(&self.init_msg, share_msg);
        let transcript_out = spake2_state
            .finish(&spake2_share_b, &aad_hash)
            .map_err(PairingError::Spake2Failure)?;

        let sig_a_payload = build_client_signature_payload(
            &transcript_out.tt_sha256,
            &transcript_out.confirm_mac_a,
        );
        let sig_a = keystore.sign_transcript(&sig_a_payload);

        let confirm_msg = PairClientConfirmMsg {
            pairing_session_id_hex: hex_encode(&pairing_session_id),
            spake2_share_a_hex: hex_encode(&spake2_share_a),
            confirm_mac_a_hex: hex_encode(&transcript_out.confirm_mac_a),
            identity_sig_a_hex: hex_encode(&sig_a),
        };

        Ok((
            ClientAwaitingServerComplete {
                pairing_session_id,
                server_device_id,
                server_ed25519_pk,
                server_device_name: clean_server_name,
                server_platform: clean_server_platform,
                sig_a,
                transcript_out,
            },
            confirm_msg,
        ))
    }
}

impl ClientAwaitingServerComplete {
    /// Step 3 (Client `A`): Verifies `PairServerCompleteMsg` (`F_B`, `sig_B`, `F_ack`, and `key_id`)
    /// BEFORE committing the server's `K_root` to the local keystore.
    pub fn finalize_and_commit(
        self,
        keystore: &mut KeystoreV2,
        complete_msg: &PairServerCompleteMsg,
        server_ip: &str,
        via_direct_cable: bool,
    ) -> Result<(VerifiedPeerCredentials, String), PairingError> {
        let rx_session_id: [u8; 16] = hex_decode_array(&complete_msg.pairing_session_id_hex)
            .ok_or_else(|| {
                PairingError::MalformedMessage("invalid pairing_session_id_hex".into())
            })?;
        if !constant_time_eq(&rx_session_id, &self.pairing_session_id) {
            return Err(PairingError::SessionNotFoundOrExpired);
        }

        let confirm_mac_b: [u8; 32] = hex_decode_array(&complete_msg.confirm_mac_b_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid confirm_mac_b_hex".into()))?;
        let sig_b: [u8; 64] = hex_decode_array(&complete_msg.identity_sig_b_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid identity_sig_b_hex".into()))?;
        let ack_mac: [u8; 32] = hex_decode_array(&complete_msg.ack_mac_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid ack_mac_hex".into()))?;
        let key_id: [u8; 16] = hex_decode_array(&complete_msg.key_id_hex)
            .ok_or_else(|| PairingError::MalformedMessage("invalid key_id_hex".into()))?;

        // 1. Verify Server's SPAKE2 confirmation MAC F_B.
        self.transcript_out
            .verify_peer_confirm_mac(Spake2Role::ResponderB, &confirm_mac_b)
            .map_err(PairingError::Spake2Failure)?;

        // 2. Verify Server's Ed25519 signature sig_B over the transcript digest, F_B, and sig_A.
        let sig_b_payload = build_server_signature_payload(
            &self.transcript_out.tt_sha256,
            &confirm_mac_b,
            &self.sig_a,
        );
        KeystoreV2::verify_signature(&self.server_ed25519_pk, &sig_b_payload, &sig_b)
            .map_err(|_| PairingError::SignatureVerificationFailed)?;

        // 3. Derive K_root, K_ack, and verify F_ack and key_id in constant time.
        let app_secrets = self
            .transcript_out
            .derive_application_secrets(&self.sig_a, &sig_b);
        if !constant_time_eq(&app_secrets.ack_mac, &ack_mac) {
            return Err(PairingError::AckMacVerificationFailed);
        }
        if !constant_time_eq(&app_secrets.key_id, &key_id) {
            return Err(PairingError::AckMacVerificationFailed);
        }

        // 4. Commit Server B to local OS-backed keystore.
        let creds = keystore
            .commit_paired_peer(
                self.server_device_id,
                self.server_ed25519_pk,
                app_secrets.root_key.clone(),
                self.server_device_name,
                self.server_platform,
                server_ip.to_string(),
                via_direct_cable,
            )
            .map_err(PairingError::KeystoreFailure)?;

        Ok((creds, app_secrets.sas_code))
    }
}

// ============================================================================
// Wire Framing & Async Stream Handshake Runners
// ============================================================================

/// Writes a bounded `IPR2` frame (`[magic: 4B][ver: 1B][msg_type: 1B][len: u16 BE][payload]`).
pub async fn send_pairing_frame<W, T>(
    writer: &mut W,
    msg_type: PairingMsgType,
    payload_obj: &T,
) -> Result<(), PairingError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(payload_obj)
        .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;
    if json.len() > MAX_PAIRING_FRAME_BYTES {
        return Err(PairingError::OversizedFrame(json.len()));
    }

    let mut frame = Vec::with_capacity(8 + json.len());
    frame.extend_from_slice(&PAIRING_WIRE_MAGIC);
    frame.push(PAIRING_HEADER_VERSION_BYTE);
    frame.push(msg_type as u8);
    frame.extend_from_slice(&(json.len() as u16).to_be_bytes());
    frame.extend_from_slice(&json);

    writer
        .write_all(&frame)
        .await
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;
    Ok(())
}

/// Reads a bounded `IPR2` frame from `reader`, enforcing `MAX_PAIRING_FRAME_BYTES` before allocation.
pub async fn recv_pairing_frame<R>(
    reader: &mut R,
) -> Result<(PairingMsgType, Vec<u8>), PairingError>
where
    R: AsyncRead + Unpin,
{
    recv_pairing_frame_with_prefixed_magic(reader, None).await
}

/// Reads a bounded `IPR2` frame when the 4-byte magic has optionally already been read from `reader`.
pub async fn recv_pairing_frame_with_prefixed_magic<R>(
    reader: &mut R,
    already_read_magic: Option<[u8; 4]>,
) -> Result<(PairingMsgType, Vec<u8>), PairingError>
where
    R: AsyncRead + Unpin,
{
    let magic = match already_read_magic {
        Some(m) => m,
        None => {
            let mut m = [0u8; 4];
            reader
                .read_exact(&mut m)
                .await
                .map_err(|e| PairingError::IoFailure(e.to_string()))?;
            m
        }
    };
    if magic != PAIRING_WIRE_MAGIC {
        return Err(PairingError::InvalidFrameMagic(magic));
    }

    let mut rest_hdr = [0u8; 4];
    reader
        .read_exact(&mut rest_hdr)
        .await
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;

    if rest_hdr[0] != PAIRING_HEADER_VERSION_BYTE {
        return Err(PairingError::UnsupportedVersion(rest_hdr[0] as u16));
    }

    let msg_type =
        PairingMsgType::from_u8(rest_hdr[1]).ok_or(PairingError::InvalidMessageType(rest_hdr[1]))?;
    let payload_len = u16::from_be_bytes([rest_hdr[2], rest_hdr[3]]) as usize;
    if payload_len == 0 || payload_len > MAX_PAIRING_FRAME_BYTES {
        return Err(PairingError::OversizedFrame(payload_len));
    }

    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;

    Ok((msg_type, payload))
}

/// Executes the complete 4-message Client (`Initiator A`) pairing flow over an async stream.
pub async fn run_client_pairing_over_stream<S>(
    stream: &mut S,
    keystore: &mut KeystoreV2,
    pin: &str,
    local_device_name: &str,
    local_platform: &str,
    server_ip: &str,
    via_direct_cable: bool,
) -> Result<(VerifiedPeerCredentials, String), PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (hs, init_msg) =
        ClientPairingHandshakeV2::initiate(keystore, pin, local_device_name, local_platform)?;
    send_pairing_frame(stream, PairingMsgType::PairInit, &init_msg).await?;

    let (msg_type, payload) = recv_pairing_frame(stream).await?;
    if msg_type == PairingMsgType::PairError {
        let err_msg: PairErrorWireMsg = serde_json::from_slice(&payload)
            .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;
        return Err(PairingError::RemotePeerRejected {
            code: err_msg.code,
            message: err_msg.message,
        });
    }
    if msg_type != PairingMsgType::PairServerShare {
        return Err(PairingError::InvalidMessageType(msg_type as u8));
    }
    let share_msg: PairServerShareMsg = serde_json::from_slice(&payload)
        .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;

    let (awaiting, confirm_msg) = hs.process_server_share(keystore, &share_msg)?;
    send_pairing_frame(stream, PairingMsgType::PairClientConfirm, &confirm_msg).await?;

    let (msg_type_2, payload_2) = recv_pairing_frame(stream).await?;
    if msg_type_2 == PairingMsgType::PairError {
        let err_msg: PairErrorWireMsg = serde_json::from_slice(&payload_2)
            .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;
        return Err(PairingError::RemotePeerRejected {
            code: err_msg.code,
            message: err_msg.message,
        });
    }
    if msg_type_2 != PairingMsgType::PairServerComplete {
        return Err(PairingError::InvalidMessageType(msg_type_2 as u8));
    }
    let complete_msg: PairServerCompleteMsg = serde_json::from_slice(&payload_2)
        .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;

    awaiting.finalize_and_commit(keystore, &complete_msg, server_ip, via_direct_cable)
}

/// Executes the 4-message Client (`Initiator A`) pairing flow using a shared `&std::sync::Mutex<KeystoreV2>`,
/// never holding the mutex across `.await` points so the returned future is `Send`.
pub async fn run_client_pairing_with_shared_keystore<S>(
    stream: &mut S,
    keystore_mutex: &std::sync::Mutex<KeystoreV2>,
    pin: &str,
    local_device_name: &str,
    local_platform: &str,
    server_ip: &str,
    via_direct_cable: bool,
) -> Result<(VerifiedPeerCredentials, String), PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (hs, init_msg) = {
        let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        ClientPairingHandshakeV2::initiate(&ks, pin, local_device_name, local_platform)?
    };
    send_pairing_frame(stream, PairingMsgType::PairInit, &init_msg).await?;

    let (msg_type, payload) = recv_pairing_frame(stream).await?;
    if msg_type == PairingMsgType::PairError {
        let err_msg: PairErrorWireMsg = serde_json::from_slice(&payload)
            .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;
        return Err(PairingError::RemotePeerRejected {
            code: err_msg.code,
            message: err_msg.message,
        });
    }
    if msg_type != PairingMsgType::PairServerShare {
        return Err(PairingError::InvalidMessageType(msg_type as u8));
    }
    let share_msg: PairServerShareMsg = serde_json::from_slice(&payload)
        .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;

    let (awaiting, confirm_msg) = {
        let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        hs.process_server_share(&ks, &share_msg)?
    };
    send_pairing_frame(stream, PairingMsgType::PairClientConfirm, &confirm_msg).await?;

    let (msg_type_2, payload_2) = recv_pairing_frame(stream).await?;
    if msg_type_2 == PairingMsgType::PairError {
        let err_msg: PairErrorWireMsg = serde_json::from_slice(&payload_2)
            .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;
        return Err(PairingError::RemotePeerRejected {
            code: err_msg.code,
            message: err_msg.message,
        });
    }
    if msg_type_2 != PairingMsgType::PairServerComplete {
        return Err(PairingError::InvalidMessageType(msg_type_2 as u8));
    }
    let complete_msg: PairServerCompleteMsg = serde_json::from_slice(&payload_2)
        .map_err(|e| PairingError::MalformedMessage(e.to_string()))?;

    let mut ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
    awaiting.finalize_and_commit(&mut ks, &complete_msg, server_ip, via_direct_cable)
}

/// Executes the 4-message Server (`Responder B`) pairing flow using shared `&std::sync::Mutex` references,
/// never holding any mutex guard across `.await` points so the returned future is `Send`.
pub async fn handle_server_pairing_with_shared_locks<S>(
    stream: &mut S,
    already_read_magic: Option<[u8; 4]>,
    coordinator_mutex: &std::sync::Mutex<PairingCoordinatorV2>,
    keystore_mutex: &std::sync::Mutex<KeystoreV2>,
    source_ip: IpAddr,
    via_direct_cable: bool,
) -> Result<(VerifiedPeerCredentials, String), PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (msg_type, payload) =
        recv_pairing_frame_with_prefixed_magic(stream, already_read_magic).await?;
    if msg_type != PairingMsgType::PairInit {
        let err = PairingError::InvalidMessageType(msg_type as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let init_msg: PairInitMsg = match serde_json::from_slice(&payload) {
        Ok(m) => m,
        Err(e) => {
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs = unix_epoch_secs();
    let share_res = {
        let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut coord = coordinator_mutex.lock().unwrap_or_else(|e| e.into_inner());
        coord.handle_pair_init(&ks, source_ip, &init_msg, now_secs)
    };
    let share_msg = match share_res {
        Ok(s) => s,
        Err(err) => {
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    send_pairing_frame(stream, PairingMsgType::PairServerShare, &share_msg).await?;

    let (msg_type_2, payload_2) = recv_pairing_frame(stream).await?;
    if msg_type_2 != PairingMsgType::PairClientConfirm {
        let err = PairingError::InvalidMessageType(msg_type_2 as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let confirm_msg: PairClientConfirmMsg = match serde_json::from_slice(&payload_2) {
        Ok(m) => m,
        Err(e) => {
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs_2 = unix_epoch_secs();
    let confirm_res = {
        let mut ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut coord = coordinator_mutex.lock().unwrap_or_else(|e| e.into_inner());
        coord.handle_pair_client_confirm(
            &mut ks,
            source_ip,
            &confirm_msg,
            via_direct_cable,
            now_secs_2,
        )
    };
    match confirm_res {
        Ok((complete_msg, creds, sas)) => {
            send_pairing_frame(stream, PairingMsgType::PairServerComplete, &complete_msg).await?;
            Ok((creds, sas))
        }
        Err(err) => {
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            Err(err)
        }
    }
}

/// Executes the complete 4-message Server (`Responder B`) pairing flow over an async stream.
pub async fn handle_server_pairing_over_stream<S>(
    stream: &mut S,
    coordinator: &mut PairingCoordinatorV2,
    keystore: &mut KeystoreV2,
    source_ip: IpAddr,
    via_direct_cable: bool,
) -> Result<(VerifiedPeerCredentials, String), PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_server_pairing_with_prefixed_magic(
        stream,
        None,
        coordinator,
        keystore,
        source_ip,
        via_direct_cable,
    )
    .await
}

/// Executes the 4-message Server pairing flow when the 4-byte `IPR2` magic has optionally already been read.
pub async fn handle_server_pairing_with_prefixed_magic<S>(
    stream: &mut S,
    already_read_magic: Option<[u8; 4]>,
    coordinator: &mut PairingCoordinatorV2,
    keystore: &mut KeystoreV2,
    source_ip: IpAddr,
    via_direct_cable: bool,
) -> Result<(VerifiedPeerCredentials, String), PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (msg_type, payload) =
        recv_pairing_frame_with_prefixed_magic(stream, already_read_magic).await?;
    if msg_type != PairingMsgType::PairInit {
        let err = PairingError::InvalidMessageType(msg_type as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let init_msg: PairInitMsg = match serde_json::from_slice(&payload) {
        Ok(m) => m,
        Err(e) => {
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs = unix_epoch_secs();
    let share_msg = match coordinator.handle_pair_init(keystore, source_ip, &init_msg, now_secs) {
        Ok(s) => s,
        Err(err) => {
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    send_pairing_frame(stream, PairingMsgType::PairServerShare, &share_msg).await?;

    let (msg_type_2, payload_2) = recv_pairing_frame(stream).await?;
    if msg_type_2 != PairingMsgType::PairClientConfirm {
        let err = PairingError::InvalidMessageType(msg_type_2 as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let confirm_msg: PairClientConfirmMsg = match serde_json::from_slice(&payload_2) {
        Ok(m) => m,
        Err(e) => {
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs_2 = unix_epoch_secs();
    match coordinator.handle_pair_client_confirm(
        keystore,
        source_ip,
        &confirm_msg,
        via_direct_cable,
        now_secs_2,
    ) {
        Ok((complete_msg, creds, sas)) => {
            send_pairing_frame(stream, PairingMsgType::PairServerComplete, &complete_msg).await?;
            Ok((creds, sas))
        }
        Err(err) => {
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            Err(err)
        }
    }
}

// ============================================================================
// Transcript & Helper Functions
// ============================================================================

fn build_spake2_identity_a(
    client_device_id: &[u8; 16],
    client_ed25519_pk: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + 2 + 16 + 32 + 32);
    out.extend_from_slice(b"integrator-pair-v2-A");
    out.extend_from_slice(&PAIRING_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(client_device_id);
    out.extend_from_slice(client_ed25519_pk);
    out.extend_from_slice(client_nonce);
    out
}

fn build_spake2_identity_b(
    server_device_id: &[u8; 16],
    server_ed25519_pk: &[u8; 32],
    server_nonce: &[u8; 32],
    pairing_session_id: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + 2 + 16 + 32 + 32 + 16);
    out.extend_from_slice(b"integrator-pair-v2-B");
    out.extend_from_slice(&PAIRING_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(server_device_id);
    out.extend_from_slice(server_ed25519_pk);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(pairing_session_id);
    out
}

fn compute_pairing_header_aad(init_msg: &PairInitMsg, share_msg: &PairServerShareMsg) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-pair-header-aad-v2");
    hasher.update(init_msg.version.to_be_bytes());
    hasher.update(init_msg.client_device_id_hex.as_bytes());
    hasher.update(init_msg.client_ed25519_pk_hex.as_bytes());
    hasher.update(init_msg.client_nonce_hex.as_bytes());
    hasher.update(share_msg.version.to_be_bytes());
    hasher.update(share_msg.pairing_session_id_hex.as_bytes());
    hasher.update(share_msg.server_device_id_hex.as_bytes());
    hasher.update(share_msg.server_ed25519_pk_hex.as_bytes());
    hasher.update(share_msg.server_nonce_hex.as_bytes());
    hasher.update(share_msg.spake2_share_b_hex.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn build_client_signature_payload(tt_sha256: &[u8; 32], confirm_mac_a: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26 + 32 + 32);
    buf.extend_from_slice(b"integrator-pair-sig-A-v2");
    buf.extend_from_slice(tt_sha256);
    buf.extend_from_slice(confirm_mac_a);
    buf
}

fn build_server_signature_payload(
    tt_sha256: &[u8; 32],
    confirm_mac_b: &[u8; 32],
    sig_a: &[u8; 64],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26 + 32 + 32 + 64);
    buf.extend_from_slice(b"integrator-pair-sig-B-v2");
    buf.extend_from_slice(tt_sha256);
    buf.extend_from_slice(confirm_mac_b);
    buf.extend_from_slice(sig_a);
    buf
}

pub fn generate_unbiased_6digit_pin() -> String {
    const RANGE: u32 = 900_000;
    const MAX_UNBIASED: u32 = u32::MAX - (u32::MAX % RANGE);
    loop {
        let buf = csprng_array::<4>();
        let candidate = u32::from_le_bytes(buf);
        if candidate < MAX_UNBIASED {
            let pin = 100_000 + (candidate % RANGE);
            return format!("{:06}", pin);
        }
    }
}

pub fn is_valid_6digit_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit())
}

fn sanitize_label(input: &str, max_len: usize) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        "Unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keystore::FixedKekProvider;
    use std::net::{IpAddr, Ipv4Addr};

    fn temp_keystore(label: &str, seed: u8) -> (std::path::PathBuf, KeystoreV2) {
        let rnd = hex_encode(&csprng_array::<6>());
        let dir = std::env::temp_dir().join(format!(
            "integrator_pair_m2_{}_{}_{}",
            label,
            std::process::id(),
            rnd
        ));
        let provider = FixedKekProvider::new([seed; 32]);
        let ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
        (dir, ks)
    }

    #[tokio::test]
    async fn test_pairing_v2_e2e_stream_handshake_and_persistence() {
        let (dir_c, mut ks_client) = temp_keystore("e2e_c", 0x11);
        let (dir_s, mut ks_server) = temp_keystore("e2e_s", 0x22);

        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let pin = coordinator.open_pairing_window(unix_epoch_secs());

        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        let server_fut = handle_server_pairing_over_stream(
            &mut server_stream,
            &mut coordinator,
            &mut ks_server,
            client_ip,
            true,
        );
        let client_fut = run_client_pairing_over_stream(
            &mut client_stream,
            &mut ks_client,
            &pin,
            "MacBook-Pro",
            "macOS",
            "10.99.99.1",
            true,
        );

        let (server_res, client_res) = tokio::join!(server_fut, client_fut);
        let (server_peer_creds, sas_s) = server_res.expect("server pairing must succeed");
        let (client_peer_creds, sas_c) = client_res.expect("client pairing must succeed");

        assert_eq!(sas_s, sas_c);
        assert_eq!(*server_peer_creds.root_key, *client_peer_creds.root_key);
        assert_eq!(server_peer_creds.key_id, client_peer_creds.key_id);
        assert_eq!(server_peer_creds.device_id, ks_client.local_device_id());
        assert_eq!(client_peer_creds.device_id, ks_server.local_device_id());

        // One-time PIN must be consumed after successful completion
        assert!(coordinator.active_pin(unix_epoch_secs()).is_none());

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_pairing_wrong_pin_does_not_rotate_active_pin_and_locks_out_attacker_ip_only() {
        let (dir_att, ks_attacker) = temp_keystore("dos_att", 0x31);
        let (dir_legit, mut ks_legit) = temp_keystore("dos_legit", 0x32);
        let (dir_srv, mut ks_server) = temp_keystore("dos_srv", 0x33);

        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 1_700_000_000;
        coordinator
            .open_pairing_window_with_pin("847291", now)
            .unwrap();

        let attacker_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 250));
        let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        // Attacker makes 3 wrong PIN guesses
        for wrong_pin in ["000000", "111111", "222222"] {
            let (hs, init_msg) =
                ClientPairingHandshakeV2::initiate(&ks_attacker, wrong_pin, "Attacker", "Linux")
                    .unwrap();
            let share_msg = coordinator
                .handle_pair_init(&ks_server, attacker_ip, &init_msg, now)
                .unwrap();
            let (_, confirm_msg) = hs.process_server_share(&ks_attacker, &share_msg).unwrap();
            let res = coordinator.handle_pair_client_confirm(
                &mut ks_server,
                attacker_ip,
                &confirm_msg,
                false,
                now,
            );
            assert_eq!(
                res.unwrap_err(),
                PairingError::Spake2Failure(Spake2Error::ConfirmationMacMismatch)
            );
            // CRITICAL: Active PIN must NOT have been rotated or cleared!
            assert_eq!(coordinator.active_pin(now), Some("847291"));
        }

        // 4th attempt from attacker_ip must be rate-limited / locked out
        let (_, init_4) =
            ClientPairingHandshakeV2::initiate(&ks_attacker, "847291", "Attacker", "Linux")
                .unwrap();
        let res_4 = coordinator.handle_pair_init(&ks_server, attacker_ip, &init_4, now);
        assert!(matches!(res_4, Err(PairingError::IpRateLimited { .. })));

        // Meanwhile, legitimate peer on legit_ip with the original PIN "847291" succeeds!
        let (hs_legit, init_legit) =
            ClientPairingHandshakeV2::initiate(&ks_legit, "847291", "MacBook-Pro", "macOS")
                .unwrap();
        let share_legit = coordinator
            .handle_pair_init(&ks_server, legit_ip, &init_legit, now)
            .expect("legitimate peer IP must not be blocked by attacker IP lockout");
        let (awaiting, confirm_legit) = hs_legit
            .process_server_share(&ks_legit, &share_legit)
            .unwrap();
        let (complete_msg, srv_creds, _) = coordinator
            .handle_pair_client_confirm(&mut ks_server, legit_ip, &confirm_legit, true, now)
            .expect("legitimate peer confirmation must succeed");
        let (cli_creds, _) = awaiting
            .finalize_and_commit(&mut ks_legit, &complete_msg, "10.99.99.1", true)
            .expect("client finalize must succeed");

        assert_eq!(*srv_creds.root_key, *cli_creds.root_key);

        let _ = std::fs::remove_dir_all(&dir_att);
        let _ = std::fs::remove_dir_all(&dir_legit);
        let _ = std::fs::remove_dir_all(&dir_srv);
    }

    #[test]
    fn test_pairing_expired_pin_and_closed_window_rejected() {
        let (dir_c, ks_client) = temp_keystore("exp_c", 0x41);
        let (dir_s, ks_server) = temp_keystore("exp_s", 0x42);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        let (_, init_msg) =
            ClientPairingHandshakeV2::initiate(&ks_client, "123456", "Mac", "macOS").unwrap();

        // Closed window by default
        assert_eq!(
            coordinator.handle_pair_init(&ks_server, ip, &init_msg, 1000),
            Err(PairingError::PairingWindowClosed)
        );

        // Open at t=1000, test after PIN_TTL_SECS (600s) at t=1601
        coordinator.open_pairing_window_with_pin("123456", 1000).unwrap();
        assert_eq!(
            coordinator.handle_pair_init(&ks_server, ip, &init_msg, 1000 + PIN_TTL_SECS + 1),
            Err(PairingError::PinExpired)
        );

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_pairing_mitm_pubkey_substitution_and_signature_forgery_rejected() {
        let (dir_c, ks_client) = temp_keystore("mitm_c", 0x51);
        let (dir_m, ks_mitm) = temp_keystore("mitm_m", 0x52);
        let (dir_s, mut ks_server) = temp_keystore("mitm_s", 0x53);

        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 2_000_000;
        coordinator.open_pairing_window_with_pin("555555", now).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        let (hs_c, mut init_msg) =
            ClientPairingHandshakeV2::initiate(&ks_client, "555555", "Mac", "macOS").unwrap();

        // MITM substitutes its own Ed25519 public key and device_id in PairInit
        init_msg.client_ed25519_pk_hex = hex_encode(&ks_mitm.local_ed25519_pubkey());
        init_msg.client_device_id_hex = hex_encode(&ks_mitm.local_device_id());

        let share_msg = coordinator
            .handle_pair_init(&ks_server, ip, &init_msg, now)
            .unwrap();

        // Client computes confirmation using its real identity, unaware of MITM modification
        let (_, confirm_msg) = hs_c.process_server_share(&ks_client, &share_msg).unwrap();

        // Server rejects because transcript TT (which binds id_A including client_ed25519_pk) mismatches!
        let res =
            coordinator.handle_pair_client_confirm(&mut ks_server, ip, &confirm_msg, true, now);
        assert!(matches!(
            res,
            Err(PairingError::Spake2Failure(
                Spake2Error::ConfirmationMacMismatch
            ))
        ));
        assert!(ks_server.list_peers().is_empty());

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_m);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_pairing_replayed_confirm_and_session_expiry_rejected() {
        let (dir_c, ks_client) = temp_keystore("rep_c", 0x61);
        let (dir_s, mut ks_server) = temp_keystore("rep_s", 0x62);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 3_000_000;
        coordinator.open_pairing_window_with_pin("987654", now).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        let (hs_c, init_msg) =
            ClientPairingHandshakeV2::initiate(&ks_client, "987654", "Mac", "macOS").unwrap();
        let share_msg = coordinator
            .handle_pair_init(&ks_server, ip, &init_msg, now)
            .unwrap();
        let (_, confirm_msg) = hs_c.process_server_share(&ks_client, &share_msg).unwrap();

        // If confirm arrives after INFLIGHT_SESSION_TTL_SECS (15s), session is pruned and rejected
        let expired_res = coordinator.handle_pair_client_confirm(
            &mut ks_server,
            ip,
            &confirm_msg,
            true,
            now + INFLIGHT_SESSION_TTL_SECS + 1,
        );
        assert_eq!(expired_res.unwrap_err(), PairingError::SessionNotFoundOrExpired);

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_pairing_concurrent_attempts_isolation_and_capacity_limit() {
        let (dir_s, mut ks_server) = temp_keystore("conc_s", 0x70);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 4_000_000;
        coordinator.open_pairing_window_with_pin("314159", now).unwrap();

        let mut clients = Vec::new();
        for i in 1..=4u8 {
            let (dir_c, ks_c) = temp_keystore(&format!("conc_c{}", i), 0x70 + i);
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let (hs, init_msg) =
                ClientPairingHandshakeV2::initiate(&ks_c, "314159", &format!("Client{}", i), "macOS")
                    .unwrap();
            let share_msg = coordinator
                .handle_pair_init(&ks_server, ip, &init_msg, now)
                .expect("up to 4 concurrent sessions must be accepted");
            clients.push((dir_c, ks_c, ip, hs, share_msg));
        }

        // 5th concurrent session from a 5th IP must be rejected with TooManyConcurrentSessions
        let (dir_c5, ks_c5) = temp_keystore("conc_c5", 0x75);
        let ip5 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let (_, init5) =
            ClientPairingHandshakeV2::initiate(&ks_c5, "314159", "Client5", "macOS").unwrap();
        assert_eq!(
            coordinator.handle_pair_init(&ks_server, ip5, &init5, now),
            Err(PairingError::TooManyConcurrentSessions)
        );

        // Client 2 completes its handshake cleanly
        let (_, mut ks_c2, ip2, hs2, share2) = clients.remove(1);
        let (awaiting2, confirm2) = hs2.process_server_share(&ks_c2, &share2).unwrap();
        let (complete2, _, _) = coordinator
            .handle_pair_client_confirm(&mut ks_server, ip2, &confirm2, false, now)
            .expect("Client 2 confirm must succeed");
        awaiting2
            .finalize_and_commit(&mut ks_c2, &complete2, "10.0.0.100", false)
            .expect("Client 2 finalize must succeed");

        for (d, _, _, _, _) in clients {
            let _ = std::fs::remove_dir_all(&d);
        }
        let _ = std::fs::remove_dir_all(&dir_c5);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_pairing_disconnects_and_unsupported_version_rejected() {
        let (dir_c, ks_client) = temp_keystore("disc_c", 0x81);
        let (dir_s, mut ks_server) = temp_keystore("disc_s", 0x82);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = unix_epoch_secs();
        coordinator.open_pairing_window_with_pin("246810", now).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        // 1. Unsupported version in PairInitMsg
        let (_, mut bad_init) =
            ClientPairingHandshakeV2::initiate(&ks_client, "246810", "Mac", "macOS").unwrap();
        bad_init.version = 1;
        assert_eq!(
            coordinator.handle_pair_init(&ks_server, ip, &bad_init, now),
            Err(PairingError::UnsupportedVersion(1))
        );

        // 2. Client disconnects right after PairInit; Server must not commit trust and PIN remains valid
        let (mut c_stream, mut s_stream) = tokio::io::duplex(4096);
        let (_, init_ok) =
            ClientPairingHandshakeV2::initiate(&ks_client, "246810", "Mac", "macOS").unwrap();
        send_pairing_frame(&mut c_stream, PairingMsgType::PairInit, &init_ok)
            .await
            .unwrap();
        drop(c_stream); // simulate sudden client disconnect

        let srv_res = handle_server_pairing_over_stream(
            &mut s_stream,
            &mut coordinator,
            &mut ks_server,
            ip,
            true,
        )
        .await;
        assert!(srv_res.is_err());
        assert!(ks_server.list_peers().is_empty());
        assert_eq!(coordinator.active_pin(unix_epoch_secs()), Some("246810"));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_pairing_blocks_unexpected_identity_key_change_for_pinned_peer() {
        let (dir_c1, mut ks_c1) = temp_keystore("pin_c1", 0x91);
        let (dir_c2, ks_c2) = temp_keystore("pin_c2", 0x92);
        let (dir_s, mut ks_s) = temp_keystore("pin_s", 0x93);

        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 6_000_000;
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));

        // First pairing with Client 1 ("MacBook-Pro")
        coordinator.open_pairing_window_with_pin("135790", now).unwrap();
        let (hs1, init1) =
            ClientPairingHandshakeV2::initiate(&ks_c1, "135790", "MacBook-Pro", "macOS").unwrap();
        let share1 = coordinator.handle_pair_init(&ks_s, ip, &init1, now).unwrap();
        let (await1, confirm1) = hs1.process_server_share(&ks_c1, &share1).unwrap();
        let (comp1, _, _) = coordinator
            .handle_pair_client_confirm(&mut ks_s, ip, &confirm1, true, now)
            .unwrap();
        await1
            .finalize_and_commit(&mut ks_c1, &comp1, "10.99.99.1", true)
            .unwrap();

        // Now Client 2 (with a DIFFERENT Ed25519 keypair) claims to be "MacBook-Pro"
        coordinator.open_pairing_window_with_pin("135790", now + 10).unwrap();
        let (_, init2) =
            ClientPairingHandshakeV2::initiate(&ks_c2, "135790", "MacBook-Pro", "macOS").unwrap();
        let conflict = coordinator.handle_pair_init(&ks_s, ip, &init2, now + 10);
        assert!(matches!(
            conflict,
            Err(PairingError::IdentityKeyPinnedConflict(_))
        ));

        let _ = std::fs::remove_dir_all(&dir_c1);
        let _ = std::fs::remove_dir_all(&dir_c2);
        let _ = std::fs::remove_dir_all(&dir_s);
    }
}

