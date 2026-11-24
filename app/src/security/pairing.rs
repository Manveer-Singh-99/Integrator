//! # Staged RFC 9382 SPAKE2 + Ed25519 Pairing Protocol (`IPR2`, v2) & Anti-DoS Coordinator (`app/src/security/pairing.rs`)
//!
//! ## 1. Module Purpose & Architectural Scope
//! This module implements the mutual cryptographic pairing handshake (`IPR2`) that transitions two Integrator
//! devices (e.g. macOS MacBook and Windows 11 Desktop) from an unauthenticated discovery state to a mutually
//! trusted, cryptographically pinned state.
//!
//! Pairing accomplishes three foundational objectives:
//! 1. Authenticates both machines using a transient 6-digit numeric PIN without exposing the PIN to offline dictionary attacks.
//! 2. Mutually verifies each machine's long-term Ed25519 identity key and records device identifiers in `KeystoreV2`.
//! 3. Derives a high-entropy 256-bit pre-shared root key ($K_{\text{root}}$) used to secure all future TCP/UDP sessions.
//!
//! In addition to the protocol state machine, this module contains the host-side [`PairingCoordinatorV2`], which
//! enforces strict anti-DoS protections to prevent unauthorized PIN rotation, brute-force enumeration, or resource exhaustion.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `app/src/trust.rs`: Invokes [`PairingCoordinatorV2`], [`run_client_pairing_with_shared_keystore`], [`handle_server_pairing_with_shared_locks`], [`generate_unbiased_6digit_pin`], and [`is_valid_6digit_pin`] to orchestrate host PIN generation and client/server pairing workflows.
//!   - `app/src/display/controller.rs`: Peeks the 4-byte wire header on port 58281 against [`PAIRING_WIRE_MAGIC`] (`"IPR2"`) to route unauthenticated pairing connections to [`handle_server_pairing_with_shared_locks`] using `already_read_magic: Some(*b"IPR2")`.
//! - **Downstream Callees**:
//!   - `app/src/security/spake2_rfc9382.rs`: [`Spake2State`], [`compute_password_salt`], and [`Spake2Role`] for RFC 9382 Edwards25519 PAKE key exchange and transcript authentication.
//!   - `app/src/security/keystore.rs`: [`KeystoreV2`] for verifying peer identity-key pinning, generating Ed25519 transcript signatures, and atomically committing newly paired peers to OS-protected storage (`trusted_peers_v2.json`).
//!   - `app/src/core.rs` & `app/src/clipboard/mod.rs`: Clears prior clipboard revocation state (`clear_peer_revocation`), resets camera session consent (`revoke_peer_consent`), and terminates half-open connections on rollback (`terminate_peer_connections_async`).
//!   - `tokio::io::{AsyncReadExt, AsyncWriteExt}` & `tokio::time::timeout`: Bounded asynchronous network frame I/O with strict 10-second per-operation timeouts.
//! - **Cross-Platform / Cross-Device Flow (Mac ↔ Windows 11)**:
//!   - Executes identically whether macOS acts as Initiator (Client A) and Windows 11 acts as Responder (Server B), or vice versa.
//!   - Wire frames use an 8-byte header (`[magic: "IPR2"][ver: 0x02][msg_type: u8][payload_len: u16 BE]`) wrapping UTF-8 JSON payloads capped at [`MAX_PAIRING_FRAME_BYTES`] (4,096 bytes).
//!   - Propagates link topology metadata (`via_direct_cable` for Thunderbolt/USB4/direct Ethernet vs standard LAN) and sanitized device/platform labels into [`KeystoreV2`] on both machines.
//!
//! ### Protocol State Machine (4-Message Staged Mutual Confirmation)
//! ```text
//!    Initiator (Client A)                                 Responder (Server B)
//!    ====================                                 ====================
//!    1. Initiate:
//!       Sample client_nonce (32B)
//!       Assemble PairInitMsg
//!                 ---------------- PairInit (0x01) -------------->
//!                                                      2. Receive PairInit:
//!                                                         Verify rate limits & window open
//!                                                         Verify client Ed25519 key against pinned records
//!                                                         Sample server_nonce (32B), session_id (16B)
//!                                                         Start SPAKE2 B: compute pB = y*B + w*N
//!                 <------------ PairServerShare (0x02) -----------
//!    3. Process Server Share:
//!       Verify server Ed25519 key against pinned records
//!       Start SPAKE2 A: compute pA = x*B + w*M
//!       Finish SPAKE2 A: compute K, Ke, Ka, KcA, KcB, F_A, F_B
//!       Sign transcript: sig_A = Ed25519_Sign(tt_sha256 || F_A)
//!                 ----------- PairClientConfirm (0x03) ---------->
//!                                                      4. Process Client Confirm:
//!                                                         Finish SPAKE2 B: compute K, Ke, Ka, KcA, KcB
//!                                                         Verify F_A == expected in constant-time
//!                                                         Verify sig_A with client_ed25519_pk
//!                                                         (Client is now fully authenticated!)
//!                                                         Sign transcript: sig_B = Ed25519_Sign(tt_sha256 || F_B || sig_A)
//!                                                         Derive K_root, K_ack, F_ack, SAS
//!                                                         Commit Client A to KeystoreV2
//!                                                         Consume PIN & close pairing window
//!                 <----------- PairServerComplete (0x04) ---------
//!    5. Finalize:
//!       Verify F_B == expected in constant-time
//!       Verify sig_B with server_ed25519_pk
//!       Derive K_root, K_ack, F_ack, SAS
//!       Verify F_ack == expected, key_id == expected
//!       Commit Server B to KeystoreV2
//! ```
//!
//! ## 3. Security Properties & Threat Model
//! - **Oracle Attack Mitigation**: Server B verifies Client A's SPAKE2 confirmation tag $F_A$ and Ed25519 signature
//!   $sig_A$ *before* generating $sig_B$ or revealing $F_B$ or $F_{\text{ack}}$. An unauthenticated attacker cannot use
//!   Server B as a signing oracle.
//! - **Anti-DoS PIN Lifecycle (Zero Forced PIN Rotation on Failed Guesses)**:
//!   - Attackers submitting incorrect PINs or corrupt handshake frames **never** cause the host's active PIN to rotate,
//!     expire, or close.
//!   - Per-IP rate limiting allows at most 3 failed guesses per 60-second window per IP. Exceeding this triggers
//!     exponential per-IP lockout ($60s \cdot 2^k$, capped at $960s$), while legitimate peers on other IPs remain
//!     able to pair using the active PIN until its 10-minute TTL expires.
//! - **Bounded Concurrency & Memory Isolation**:
//!   - At most 4 concurrent pairing sessions globally (`MAX_CONCURRENT_PAIRING_SESSIONS = 4`).
//!   - At most 1 active session per source IP.
//!   - In-flight sessions expire after 15 seconds (`INFLIGHT_SESSION_TTL_SECS = 15`).
//! - **Identity-Key Pinning**:
//!   - Enforces `device_id == SHA256("integrator-device-id-v2" || ed25519_pubkey)[0..16]`.
//!   - Automatically blocks conflicting keys for previously paired device IDs or hostnames.
//! - **Unbiased Random PIN Generation**:
//!   - Generates 6-digit numeric PINs via CSPRNG rejection sampling over $[0, 4294000000)$ modulo $900,000 + 100,000$.
//!
//! ## 4. Threading & Concurrency Model
//! Handshake runner functions operate asynchronously over Tokio `AsyncRead + AsyncWrite` streams. Shared state
//! (`PairingCoordinatorV2`, `KeystoreV2`) is wrapped in `std::sync::Mutex`. Locks are acquired briefly in synchronous
//! scopes and dropped before `.await` points to ensure futures are `Send` across multi-threaded Tokio runtimes.

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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// 4-byte ASCII wire magic identifying Integrator Pairing v2 frames (`"IPR2"`).
pub const PAIRING_WIRE_MAGIC: [u8; 4] = *b"IPR2";

/// Pairing protocol version (`2`).
pub const PAIRING_PROTOCOL_VERSION: u16 = 2;

/// Header version byte (`0x02`).
pub const PAIRING_HEADER_VERSION_BYTE: u8 = 0x02;

/// Maximum permitted serialized pairing frame payload length (4096 bytes).
pub const MAX_PAIRING_FRAME_BYTES: usize = 4096;

/// Time-to-live for an active pairing PIN (10 minutes = 600 seconds).
pub const PIN_TTL_SECS: u64 = 600;

/// Maximum duration an in-flight pairing handshake may remain pending before expiration (15 seconds).
pub const INFLIGHT_SESSION_TTL_SECS: u64 = 15;

/// Maximum concurrent in-flight pairing handshakes across all remote IPs (4 sessions).
pub const MAX_CONCURRENT_PAIRING_SESSIONS: usize = 4;

/// Maximum failed confirmation attempts permitted per IP before triggering exponential lockout (3 attempts).
pub const MAX_FAILED_ATTEMPTS_PER_IP: u32 = 3;

/// Maximum `PairInit` handshakes an IP may initiate per 60-second window (12 attempts).
pub const MAX_PAIR_INIT_PER_IP_PER_WINDOW: u32 = 12;

/// Rolling rate-limiting window duration (60 seconds).
pub const IP_ATTEMPT_WINDOW_SECS: u64 = 60;

/// Base lockout duration on rate limit violation (60 seconds).
pub const BASE_IP_LOCKOUT_SECS: u64 = 60;

/// Maximum tracked remote IPs in the rate limit table (1024 entries).
pub const MAX_IP_RATE_LIMIT_ENTRIES: usize = 1024;

/// Network I/O timeout for sending or receiving individual pairing frames (10 seconds).
pub const PAIRING_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum length of sanitized device name strings (64 characters).
pub const MAX_NAME_LEN: usize = 64;

/// Maximum length of sanitized platform identifier strings (16 characters).
pub const MAX_PLATFORM_LEN: usize = 16;

/// Maximum character length of wire error descriptions transmitted in `PairErrorWireMsg` (120 chars).
const MAX_WIRE_ERROR_MESSAGE_LEN: usize = 120;

/// Maximum exponential backoff shift exponent for consecutive per-IP lockouts (`2^4 = 16x`, 960 seconds).
const MAX_LOCKOUT_BACKOFF_EXPONENT: u32 = 4;

/// Minimum numeric value for generated 6-digit pairing PINs (`100_000`..=`999_999`).
const MIN_PIN_VALUE: u32 = 100_000;

/// Fallback device or platform label when sanitized peer metadata is empty.
const DEFAULT_UNKNOWN_DEVICE_NAME: &str = "Unknown";

/// Wire message type discriminator byte for `IPR2` frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairingMsgType {
    /// Client initiates pairing handshake (`0x01`).
    PairInit = 0x01,
    /// Server responds with ephemeral share and session ID (`0x02`).
    PairServerShare = 0x02,
    /// Client sends SPAKE2 MAC and Ed25519 identity signature (`0x03`).
    PairClientConfirm = 0x03,
    /// Server sends completion acknowledgment MAC and signature (`0x04`).
    PairServerComplete = 0x04,
    /// Handshake error notice (`0xFF`).
    PairError = 0xFF,
}

impl PairingMsgType {
    /// Maps a raw `u8` wire byte to a [`PairingMsgType`] variant.
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

/// Message 1: Sent from Initiator (Client A) to Responder (Server B) to start pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairInitMsg {
    /// Pairing protocol version (must be 2).
    pub version: u16,
    /// 32-character lowercase hex canonical device ID of Client A.
    pub client_device_id_hex: String,
    /// 64-character lowercase hex compressed Ed25519 public key of Client A.
    pub client_ed25519_pk_hex: String,
    /// 64-character lowercase hex CSPRNG random nonce from Client A (32 bytes).
    pub client_nonce_hex: String,
    /// Friendly device name of Client A (sanitized, max 64 chars).
    pub device_name: String,
    /// Operating system platform of Client A (e.g. `"macOS"`, max 16 chars).
    pub platform: String,
}

/// Message 2: Sent from Responder (Server B) to Initiator (Client A) containing Server's share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairServerShareMsg {
    /// Pairing protocol version (must be 2).
    pub version: u16,
    /// 32-character lowercase hex random session identifier (16 bytes).
    pub pairing_session_id_hex: String,
    /// 32-character lowercase hex canonical device ID of Server B.
    pub server_device_id_hex: String,
    /// 64-character lowercase hex compressed Ed25519 public key of Server B.
    pub server_ed25519_pk_hex: String,
    /// 64-character lowercase hex CSPRNG random nonce from Server B (32 bytes).
    pub server_nonce_hex: String,
    /// 64-character lowercase hex SPAKE2 blinded share $pB$ (32 bytes).
    pub spake2_share_b_hex: String,
    /// Friendly device name of Server B (sanitized, max 64 chars).
    pub device_name: String,
    /// Operating system platform of Server B (e.g. `"Windows"`, max 16 chars).
    pub platform: String,
}

/// Message 3: Sent from Initiator (Client A) to Responder (Server B) containing confirmation authenticators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairClientConfirmMsg {
    /// 32-character lowercase hex matching session identifier.
    pub pairing_session_id_hex: String,
    /// 64-character lowercase hex SPAKE2 blinded share $pA$ (32 bytes).
    pub spake2_share_a_hex: String,
    /// 64-character lowercase hex confirmation MAC $F_A = \text{HMAC-SHA256}(K_{cA}, TT)$ (32 bytes).
    pub confirm_mac_a_hex: String,
    /// 128-character lowercase hex Ed25519 signature $sig_A$ over $tt\_sha256 \,\|\, F_A$ (64 bytes).
    pub identity_sig_a_hex: String,
}

/// Message 4: Sent from Responder (Server B) to Initiator (Client A) confirming pairing completion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairServerCompleteMsg {
    /// 32-character lowercase hex matching session identifier.
    pub pairing_session_id_hex: String,
    /// 64-character lowercase hex confirmation MAC $F_B = \text{HMAC-SHA256}(K_{cB}, TT)$ (32 bytes).
    pub confirm_mac_b_hex: String,
    /// 128-character lowercase hex Ed25519 signature $sig_B$ over $tt\_sha256 \,\|\, F_B \,\|\, sig_A$ (64 bytes).
    pub identity_sig_b_hex: String,
    /// 64-character lowercase hex completion acknowledgment MAC $F_{\text{ack}}$ (32 bytes).
    pub ack_mac_hex: String,
    /// 32-character lowercase hex derived key identifier for $K_{\text{root}}$ (16 bytes).
    pub key_id_hex: String,
}

/// Wire error message transmitted when a handshake is rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairErrorWireMsg {
    /// Numeric error code category.
    pub code: u8,
    /// Seconds the remote peer must wait before retrying (for rate limiting).
    pub retry_after_secs: u32,
    /// Human-readable error description (clamped to 120 chars).
    pub message: String,
}

/// Error scenarios occurring during pairing handshake execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// Peer presented an unsupported protocol version number (expected [`PAIRING_PROTOCOL_VERSION`] = `2`).
    UnsupportedVersion(u16),
    /// Wire frame header did not start with the 4-byte [`PAIRING_WIRE_MAGIC`] (`"IPR2"`).
    InvalidFrameMagic([u8; 4]),
    /// Wire frame header specified an unknown or out-of-sequence [`PairingMsgType`] discriminator byte.
    InvalidMessageType(u8),
    /// Serialized frame payload length was `0` or exceeded [`MAX_PAIRING_FRAME_BYTES`] (4,096 bytes).
    OversizedFrame(usize),
    /// JSON payload deserialization or fixed-length hex field decoding failed.
    MalformedMessage(String),
    /// Host pairing window is currently closed (`pairing_window_open == false` or no active PIN).
    PairingWindowClosed,
    /// Active host pairing PIN exceeded its [`PIN_TTL_SECS`] (600-second) validity window.
    PinExpired,
    /// User-supplied or configured PIN is not exactly 6 ASCII decimal digits (`0`..=`9`).
    InvalidPinFormat,
    /// Source IP address is temporarily locked out due to excessive failed attempts or `PairInit` floods.
    IpRateLimited {
        /// Remaining lockout duration in seconds before the remote IP may retry.
        retry_after_secs: u64,
    },
    /// Server already has [`MAX_CONCURRENT_PAIRING_SESSIONS`] (4) active in-flight sessions from other IPs.
    TooManyConcurrentSessions,
    /// Referenced 16-byte `pairing_session_id` does not exist or exceeded [`INFLIGHT_SESSION_TTL_SECS`] (15s).
    SessionNotFoundOrExpired,
    /// `PairClientConfirm` arrived from a different source IP than the `PairInit` that created the session.
    SessionIpMismatch,
    /// Peer's claimed 16-byte `device_id` does not match `SHA256("integrator-device-id-v2" || ed25519_pk)[0..16]`.
    SpoofedDeviceId,
    /// Peer's Ed25519 public key conflicts with an existing pinned record for the same device ID or hostname.
    IdentityKeyPinnedConflict(String),
    /// Underlying RFC 9382 SPAKE2 mathematical or confirmation MAC verification error.
    Spake2Failure(Spake2Error),
    /// Peer's Ed25519 signature (`sig_A` or `sig_B`) over the pairing transcript digest failed verification.
    SignatureVerificationFailed,
    /// Server's final completion acknowledgment tag (`F_ack`) or derived `key_id` failed constant-time verification.
    AckMacVerificationFailed,
    /// Underlying OS keystore verification or persistence failure.
    KeystoreFailure(KeystoreError),
    /// Asynchronous socket read, write, flush, or 10-second I/O timeout error.
    IoFailure(String),
    /// Counterpart machine aborted the handshake with an explicit [`PairErrorWireMsg`] frame.
    RemotePeerRejected {
        /// Numeric wire error category code (`1`..=`99`).
        code: u8,
        /// Sanitized error description from the remote peer.
        message: String,
    },
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
    /// Maps internal error variant to a structured wire error message for transmission.
    pub fn to_wire_error(&self) -> PairErrorWireMsg {
        let (code, retry) = match self {
            PairingError::UnsupportedVersion(_) => (1, 0),
            PairingError::PairingWindowClosed | PairingError::PinExpired => (2, 0),
            PairingError::IpRateLimited { retry_after_secs } => {
                // Clamp to u32::MAX to prevent silent integer truncation on wire serialization.
                (3, (*retry_after_secs).min(u32::MAX as u64) as u32)
            }
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
            message: self.to_string().chars().take(MAX_WIRE_ERROR_MESSAGE_LEN).collect(),
        }
    }
}

/// Rate-limiting record tracking authentication failures and init attempts for a single IP address.
#[derive(Debug, Clone)]
struct IpRateLimitRecord {
    /// Count of authentication or protocol failures recorded within the active 60-second failure window.
    failures: u32,
    /// Count of `PairInit` messages received within the active 60-second init window.
    init_attempts: u32,
    /// Unix timestamp (seconds) when the current 60-second failure counting window started.
    window_started_at: u64,
    /// Unix timestamp (seconds) when the current 60-second `PairInit` rate window started.
    init_window_started_at: u64,
    /// Unix timestamp (seconds) until which this IP is locked out (`0` or `<= now_secs` if unlocked).
    locked_until: u64,
    /// Number of consecutive lockouts triggered by this IP, used to compute exponential backoff ($60\text{s} \cdot 2^{\min(k, 4)}$).
    consecutive_lockouts: u32,
    /// Unix timestamp (seconds) when this record was last accessed, used for LRU eviction when the table is full.
    last_touched: u64,
}

/// In-flight handshake state retained by Server B between `PairInit` and `PairClientConfirm`.
struct InFlightServerSession {
    /// 16-byte random CSPRNG session identifier uniquely binding `PairServerShare` to `PairClientConfirm`.
    pairing_session_id: [u8; 16],
    /// Network IP address of Initiator (Client A) that sent `PairInit`; enforced on `PairClientConfirm`.
    source_ip: IpAddr,
    /// Unix timestamp (seconds) when this in-flight session was created (expires after [`INFLIGHT_SESSION_TTL_SECS`] = 15s).
    created_at_secs: u64,
    /// Verified 16-byte canonical device ID of Client A.
    client_device_id: [u8; 16],
    /// Verified 32-byte compressed Ed25519 public key of Client A.
    client_ed25519_pk: [u8; 32],
    /// Sanitized friendly display name of Client A (clamped to [`MAX_NAME_LEN`] = 64 chars).
    client_device_name: String,
    /// Sanitized operating system platform identifier of Client A (clamped to [`MAX_PLATFORM_LEN`] = 16 chars).
    client_platform: String,
    /// Ephemeral Responder B RFC 9382 SPAKE2 state machine awaiting Client A's public share $pA$.
    spake2_state: Spake2State,
    /// 32-byte SHA-256 digest of the `PairInitMsg` and `PairServerShareMsg` wire fields bound as HKDF AAD.
    aad_hash: [u8; 32],
}

/// Host-side pairing coordinator managing the active PIN, in-flight handshakes, and anti-DoS rate limiting.
pub struct PairingCoordinatorV2 {
    /// Currently active 6-digit numeric pairing PIN wrapped in [`Zeroizing`] memory, or `None` if closed.
    active_pin: Option<Zeroizing<String>>,
    /// Unix timestamp (seconds) when `active_pin` was generated (valid for [`PIN_TTL_SECS`] = 600s).
    pin_created_at_secs: u64,
    /// Whether the host pairing window is currently open to accept incoming `PairInit` requests.
    pairing_window_open: bool,
    /// Sanitized friendly display name of this host machine advertised in `PairServerShareMsg`.
    local_device_name: String,
    /// Sanitized platform label of this host machine (e.g. `"macOS"` or `"Windows"`) advertised in `PairServerShareMsg`.
    local_platform: String,
    /// Map of active in-flight sessions keyed by 16-byte `pairing_session_id` (capped at [`MAX_CONCURRENT_PAIRING_SESSIONS`] = 4).
    inflight_sessions: HashMap<[u8; 16], InFlightServerSession>,
    /// Per-IP rate-limiting and exponential lockout state table (capped at [`MAX_IP_RATE_LIMIT_ENTRIES`] = 1,024).
    ip_rate_limits: HashMap<IpAddr, IpRateLimitRecord>,
}

impl PairingCoordinatorV2 {
    /// Constructs a fresh coordinator with sanitized local device name and platform labels.
    pub fn new(local_device_name: String, local_platform: String) -> Self {
        Self {
            active_pin: None,
            pin_created_at_secs: 0,
            pairing_window_open: false,
            local_device_name: sanitize_label(&local_device_name, MAX_NAME_LEN),
            local_platform: sanitize_label(&local_platform, MAX_PLATFORM_LEN),
            inflight_sessions: HashMap::new(),
            ip_rate_limits: HashMap::new(),
        }
    }

    /// Generates an unbiased 6-digit numeric PIN (`100000`..=`999999`) and opens the 10-minute pairing window.
    ///
    /// Preserves existing `ip_rate_limits` across PIN regenerations so an already-locked-out attacker IP
    /// cannot bypass its exponential backoff window when the local user refreshes the PIN.
    pub fn open_pairing_window(&mut self, now_secs: u64) -> String {
        let pin = generate_unbiased_6digit_pin();
        self.active_pin = Some(Zeroizing::new(pin.clone()));
        self.pin_created_at_secs = now_secs;
        self.pairing_window_open = true;
        self.inflight_sessions.clear();
        pin
    }

    /// Opens the pairing window with an explicit 6-digit PIN (for testing or user specification).
    #[cfg(test)]
    pub fn open_pairing_window_with_pin(
        &mut self,
        pin: &str,
        now_secs: u64,
    ) -> Result<(), PairingError> {
        if !is_valid_6digit_pin(pin) {
            return Err(PairingError::InvalidPinFormat);
        }
        self.active_pin = Some(Zeroizing::new(pin.to_string()));
        self.pin_created_at_secs = now_secs;
        self.pairing_window_open = true;
        self.inflight_sessions.clear();
        Ok(())
    }

    /// Closes the pairing window, clearing the active PIN and aborting all in-flight handshakes.
    pub fn close_pairing_window(&mut self) {
        self.pairing_window_open = false;
        self.active_pin = None;
        self.inflight_sessions.clear();
    }

    /// Returns the Unix epoch timestamp (seconds) when the current PIN was generated.
    pub fn pin_created_at_secs(&self) -> u64 {
        self.pin_created_at_secs
    }

    /// Aborts any in-flight pairing session originating from `ip`.
    pub fn cancel_inflight_for_ip(&mut self, ip: IpAddr) {
        self.inflight_sessions.retain(|_, s| s.source_ip != ip);
    }

    /// Returns the active PIN string if the pairing window is open and within its 10-minute TTL.
    pub fn active_pin(&self, now_secs: u64) -> Option<&str> {
        if !self.pairing_window_open {
            return None;
        }
        if now_secs.saturating_sub(self.pin_created_at_secs) > PIN_TTL_SECS {
            return None;
        }
        self.active_pin.as_deref().map(|z| z.as_str())
    }

    /// Evicts an unlocked, oldest-touched rate-limit entry when the table exceeds `MAX_IP_RATE_LIMIT_ENTRIES`.
    fn evict_one_rate_limit_entry(&mut self, now_secs: u64) {
        // Prefer evicting unlocked entries so attacking IPs currently in lockout cannot be purged
        if let Some(&evict_ip) = self
            .ip_rate_limits
            .iter()
            .filter(|(_, r)| r.locked_until <= now_secs)
            .min_by_key(|(_, r)| r.last_touched)
            .map(|(k, _)| k)
            .or_else(|| {
                self.ip_rate_limits
                    .iter()
                    .min_by_key(|(_, r)| r.locked_until)
                    .map(|(k, _)| k)
            })
        {
            self.ip_rate_limits.remove(&evict_ip);
        }
    }

    /// Retrieves or inserts the rate-limiting record for `ip`.
    fn ensure_rate_limit_entry_mut(
        &mut self,
        ip: IpAddr,
        now_secs: u64,
    ) -> &mut IpRateLimitRecord {
        if self.ip_rate_limits.len() >= MAX_IP_RATE_LIMIT_ENTRIES
            && !self.ip_rate_limits.contains_key(&ip)
        {
            self.evict_one_rate_limit_entry(now_secs);
        }
        self.ip_rate_limits
            .entry(ip)
            .or_insert_with(|| IpRateLimitRecord {
                failures: 0,
                init_attempts: 0,
                window_started_at: now_secs,
                init_window_started_at: now_secs,
                locked_until: 0,
                consecutive_lockouts: 0,
                last_touched: now_secs,
            })
    }

    /// Checks whether `ip` is currently locked out due to excessive failed attempts.
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
            if now_secs.saturating_sub(rec.init_window_started_at) > IP_ATTEMPT_WINDOW_SECS {
                rec.init_attempts = 0;
                rec.init_window_started_at = now_secs;
            }
        }
        Ok(())
    }

    /// Enforces the sliding window limit on `PairInit` frequency for a given IP.
    fn check_and_record_pair_init(&mut self, ip: IpAddr, now_secs: u64) -> Result<(), PairingError> {
        let entry = self.ensure_rate_limit_entry_mut(ip, now_secs);
        entry.last_touched = now_secs;
        if now_secs.saturating_sub(entry.init_window_started_at) > IP_ATTEMPT_WINDOW_SECS {
            entry.init_attempts = 0;
            entry.init_window_started_at = now_secs;
        }
        entry.init_attempts = entry.init_attempts.saturating_add(1);
        if entry.init_attempts > MAX_PAIR_INIT_PER_IP_PER_WINDOW {
            let exp = entry.consecutive_lockouts.min(MAX_LOCKOUT_BACKOFF_EXPONENT);
            let lockout_secs = BASE_IP_LOCKOUT_SECS.saturating_mul(1u64 << exp);
            entry.locked_until = now_secs.saturating_add(lockout_secs);
            entry.consecutive_lockouts = entry.consecutive_lockouts.saturating_add(1);
            entry.init_attempts = 0;
            return Err(PairingError::IpRateLimited {
                retry_after_secs: lockout_secs,
            });
        }
        Ok(())
    }

    /// Records an authentication failure for `ip` WITHOUT invalidating or rotating the active PIN.
    pub(crate) fn record_ip_failure(&mut self, ip: IpAddr, now_secs: u64) {
        let entry = self.ensure_rate_limit_entry_mut(ip, now_secs);
        entry.last_touched = now_secs;
        if now_secs.saturating_sub(entry.window_started_at) > IP_ATTEMPT_WINDOW_SECS {
            entry.failures = 0;
            entry.window_started_at = now_secs;
        }

        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= MAX_FAILED_ATTEMPTS_PER_IP {
            let exp = entry.consecutive_lockouts.min(MAX_LOCKOUT_BACKOFF_EXPONENT);
            let lockout_secs = BASE_IP_LOCKOUT_SECS.saturating_mul(1u64 << exp);
            entry.locked_until = now_secs.saturating_add(lockout_secs);
            entry.consecutive_lockouts = entry.consecutive_lockouts.saturating_add(1);
            entry.failures = 0;
        }
    }

    /// Clears rate-limiting failure tracking for `ip` after successful authenticated pairing.
    fn clear_ip_failures(&mut self, ip: IpAddr) {
        self.ip_rate_limits.remove(&ip);
    }

    /// Prunes in-flight handshake sessions exceeding `INFLIGHT_SESSION_TTL_SECS` (15s),
    /// penalizing each expired session's source IP and returning the list of pruned IPs.
    fn prune_expired_sessions(&mut self, now_secs: u64) -> Vec<IpAddr> {
        let mut expired_ips = Vec::new();
        self.inflight_sessions.retain(|_, s| {
            if now_secs.saturating_sub(s.created_at_secs) > INFLIGHT_SESSION_TTL_SECS {
                expired_ips.push(s.source_ip);
                false
            } else {
                true
            }
        });
        for &ip in &expired_ips {
            self.record_ip_failure(ip, now_secs);
        }
        expired_ips
    }

    /// Step 1 (Server B): Processes incoming `PairInitMsg` and responds with `PairServerShareMsg`.
    pub fn handle_pair_init(
        &mut self,
        keystore: &KeystoreV2,
        source_ip: IpAddr,
        init_msg: &PairInitMsg,
        now_secs: u64,
    ) -> Result<PairServerShareMsg, PairingError> {
        let _ = self.prune_expired_sessions(now_secs);
        self.check_ip_rate_limit(source_ip, now_secs)?;

        if init_msg.version != PAIRING_PROTOCOL_VERSION {
            return Err(PairingError::UnsupportedVersion(init_msg.version));
        }

        if !self.pairing_window_open {
            return Err(PairingError::PairingWindowClosed);
        }

        let pin = match &self.active_pin {
            Some(p) if now_secs.saturating_sub(self.pin_created_at_secs) <= PIN_TTL_SECS => {
                Zeroizing::new(p.as_str().to_string())
            }
            Some(_) => {
                self.close_pairing_window();
                return Err(PairingError::PinExpired);
            }
            None => return Err(PairingError::PairingWindowClosed),
        };

        self.check_and_record_pair_init(source_ip, now_secs)?;

        let client_device_id: [u8; 16] = hex_decode_array(&init_msg.client_device_id_hex)
            .ok_or_else(|| {
                self.record_ip_failure(source_ip, now_secs);
                PairingError::MalformedMessage("invalid client_device_id_hex".into())
            })?;
        let client_ed25519_pk: [u8; 32] = hex_decode_array(&init_msg.client_ed25519_pk_hex)
            .ok_or_else(|| {
                self.record_ip_failure(source_ip, now_secs);
                PairingError::MalformedMessage("invalid client_ed25519_pk_hex".into())
            })?;
        let client_nonce: [u8; 32] = hex_decode_array(&init_msg.client_nonce_hex)
            .ok_or_else(|| {
                self.record_ip_failure(source_ip, now_secs);
                PairingError::MalformedMessage("invalid client_nonce_hex".into())
            })?;

        let clean_name = sanitize_label(&init_msg.device_name, MAX_NAME_LEN);
        let clean_platform = sanitize_label(&init_msg.platform, MAX_PLATFORM_LEN);

        // Verify client_device_id derivation and identity-key pinning before allocating session state.
        keystore
            .check_peer_identity_pinning(&client_device_id, &client_ed25519_pk, &clean_name)
            .map_err(|e| {
                self.record_ip_failure(source_ip, now_secs);
                match e {
                    KeystoreError::SpoofedDeviceId { .. } => PairingError::SpoofedDeviceId,
                    KeystoreError::PinnedIdentityKeyMismatch { .. } => {
                        PairingError::IdentityKeyPinnedConflict(e.to_string())
                    }
                    other => PairingError::KeystoreFailure(other),
                }
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

        let salt_pw = Zeroizing::new(compute_password_salt(&client_device_id, &server_device_id));
        let id_a = build_spake2_identity_a(&client_device_id, &client_ed25519_pk, &client_nonce);
        let id_b = build_spake2_identity_b(
            &server_device_id,
            &server_ed25519_pk,
            &server_nonce,
            &pairing_session_id,
        );

        let (spake2_state, spake2_share_b) =
            Spake2State::start_b(pin.as_bytes(), &*salt_pw, &id_a, &id_b)
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

    /// Step 2 (Server B): Processes `PairClientConfirmMsg`, verifying $F_A$ and $sig_A$ before revealing $F_B$ or $F_{\text{ack}}$.
    pub fn handle_pair_client_confirm(
        &mut self,
        keystore: &mut KeystoreV2,
        source_ip: IpAddr,
        confirm_msg: &PairClientConfirmMsg,
        via_direct_cable: bool,
        now_secs: u64,
    ) -> Result<(PairServerCompleteMsg, VerifiedPeerCredentials, String), PairingError> {
        self.check_ip_rate_limit(source_ip, now_secs)?;
        let expired_ips = self.prune_expired_sessions(now_secs);

        if !self.pairing_window_open || self.active_pin.is_none() {
            return Err(PairingError::PairingWindowClosed);
        }
        if now_secs.saturating_sub(self.pin_created_at_secs) > PIN_TTL_SECS {
            self.close_pairing_window();
            return Err(PairingError::PinExpired);
        }

        let session_id: [u8; 16] = hex_decode_array(&confirm_msg.pairing_session_id_hex)
            .ok_or_else(|| {
                if !expired_ips.contains(&source_ip) {
                    self.record_ip_failure(source_ip, now_secs);
                }
                PairingError::MalformedMessage("invalid pairing_session_id_hex".into())
            })?;

        match self.inflight_sessions.get(&session_id) {
            None => {
                // Avoid double-penalizing source_ip if prune_expired_sessions already recorded the expiration failure above.
                if !expired_ips.contains(&source_ip) {
                    self.record_ip_failure(source_ip, now_secs);
                }
                return Err(PairingError::SessionNotFoundOrExpired);
            }
            Some(s) if s.source_ip != source_ip => {
                self.record_ip_failure(source_ip, now_secs);
                return Err(PairingError::SessionIpMismatch);
            }
            Some(_) => {}
        }
        let session = self
            .inflight_sessions
            .remove(&session_id)
            .ok_or(PairingError::SessionNotFoundOrExpired)?;

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

/// Client-side (Initiator A) state machine managing an active pairing handshake.
pub struct ClientPairingHandshakeV2 {
    /// 6-digit numeric pairing PIN entered by the user, wrapped in [`Zeroizing`] memory.
    pin: Zeroizing<String>,
    /// Sent [`PairInitMsg`] retained for computing the header AAD digest in Step 2.
    init_msg: PairInitMsg,
    /// 16-byte canonical device identifier of this client machine.
    client_device_id: [u8; 16],
    /// 32-byte compressed Ed25519 identity public key of this client machine.
    client_ed25519_pk: [u8; 32],
    /// 32-byte CSPRNG random nonce generated for this handshake session.
    client_nonce: [u8; 32],
}

/// Intermediate client state awaiting final `PairServerCompleteMsg`.
pub struct ClientAwaitingServerComplete {
    /// 16-byte session identifier assigned by Server B in `PairServerShareMsg`.
    pairing_session_id: [u8; 16],
    /// Verified 16-byte canonical device identifier of Server B.
    server_device_id: [u8; 16],
    /// Verified 32-byte compressed Ed25519 identity public key of Server B.
    server_ed25519_pk: [u8; 32],
    /// Sanitized friendly display name of Server B (clamped to [`MAX_NAME_LEN`] = 64 chars).
    server_device_name: String,
    /// Sanitized operating system platform identifier of Server B (clamped to [`MAX_PLATFORM_LEN`] = 16 chars).
    server_platform: String,
    /// Client A's 64-byte Ed25519 signature over `tt_sha256 || F_A`, bound into Server B's signature and `K_root` derivation.
    sig_a: [u8; 64],
    /// Completed RFC 9382 SPAKE2 transcript output containing $K_e$, $F_B$, and `tt_sha256`.
    transcript_out: crate::security::spake2_rfc9382::Spake2TranscriptOutput,
}

impl ClientPairingHandshakeV2 {
    /// Step 1 (Client A): Creates `PairInitMsg` to transmit to Server B.
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
                pin: Zeroizing::new(trimmed_pin.to_string()),
                init_msg: init_msg.clone(),
                client_device_id,
                client_ed25519_pk,
                client_nonce,
            },
            init_msg,
        ))
    }

    /// Step 2 (Client A): Processes `PairServerShareMsg`, computes $pA$, $F_A$, and $sig_A$, and returns `PairClientConfirmMsg`.
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

        let salt_pw =
            Zeroizing::new(compute_password_salt(&self.client_device_id, &server_device_id));
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
            Spake2State::start_a(self.pin.as_bytes(), &*salt_pw, &id_a, &id_b)
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
    /// Step 3 (Client A): Verifies `PairServerCompleteMsg` and commits Server B to local keystore.
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

/// Writes a bounded `IPR2` frame: `[magic: 4B][ver: 1B][msg_type: 1B][len: u16 BE][payload]`.
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

    tokio::time::timeout(PAIRING_IO_TIMEOUT, writer.write_all(&frame))
        .await
        .map_err(|_| PairingError::IoFailure("pairing write timed out".into()))?
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;
    tokio::time::timeout(PAIRING_IO_TIMEOUT, writer.flush())
        .await
        .map_err(|_| PairingError::IoFailure("pairing flush timed out".into()))?
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

/// Reads a bounded `IPR2` frame when the 4-byte magic has optionally already been read.
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
            tokio::time::timeout(PAIRING_IO_TIMEOUT, reader.read_exact(&mut m))
                .await
                .map_err(|_| PairingError::IoFailure("pairing magic read timed out".into()))?
                .map_err(|e| PairingError::IoFailure(e.to_string()))?;
            m
        }
    };
    if magic != PAIRING_WIRE_MAGIC {
        return Err(PairingError::InvalidFrameMagic(magic));
    }

    let mut rest_hdr = [0u8; 4];
    tokio::time::timeout(PAIRING_IO_TIMEOUT, reader.read_exact(&mut rest_hdr))
        .await
        .map_err(|_| PairingError::IoFailure("pairing header read timed out".into()))?
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
    tokio::time::timeout(PAIRING_IO_TIMEOUT, reader.read_exact(&mut payload))
        .await
        .map_err(|_| PairingError::IoFailure("pairing payload read timed out".into()))?
        .map_err(|e| PairingError::IoFailure(e.to_string()))?;

    Ok((msg_type, payload))
}

/// Executes the complete 4-message Client (`Initiator A`) pairing flow over an async stream.
#[cfg(test)]
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

    let res = awaiting.finalize_and_commit(keystore, &complete_msg, server_ip, via_direct_cable);
    if let Ok((ref creds, _)) = res {
        if let Some(core) = crate::core::GLOBAL_CORE.get() {
            core.camera.revoke_peer_consent(&creds.device_id_hex);
            core.clipboard.clear_peer_revocation(&creds.device_id_hex);
        }
        if let Some(clip) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
            clip.clear_peer_revocation(&creds.device_id_hex);
        }
    }
    res
}

/// Executes the 4-message Client pairing flow using a shared `Mutex<KeystoreV2>` without holding locks across `.await`.
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

    let res = {
        let mut ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        awaiting.finalize_and_commit(&mut ks, &complete_msg, server_ip, via_direct_cable)
    };
    if let Ok((ref creds, _)) = res {
        if let Some(core) = crate::core::GLOBAL_CORE.get() {
            core.camera.revoke_peer_consent(&creds.device_id_hex);
            core.clipboard.clear_peer_revocation(&creds.device_id_hex);
        }
        if let Some(clip) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
            clip.clear_peer_revocation(&creds.device_id_hex);
        }
    }
    res
}

/// Executes the 4-message Server pairing flow using shared `Mutex` references without holding locks across `.await`.
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
    let (msg_type, payload) = match recv_pairing_frame_with_prefixed_magic(stream, already_read_magic).await {
        Ok(res) => res,
        Err(e) => {
            let mut coord = coordinator_mutex.lock().unwrap_or_else(|err| err.into_inner());
            coord.record_ip_failure(source_ip, unix_epoch_secs());
            return Err(e);
        }
    };
    if msg_type != PairingMsgType::PairInit {
        {
            let mut coord = coordinator_mutex.lock().unwrap_or_else(|e| e.into_inner());
            coord.record_ip_failure(source_ip, unix_epoch_secs());
        }
        let err = PairingError::InvalidMessageType(msg_type as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let init_msg: PairInitMsg = match serde_json::from_slice(&payload) {
        Ok(m) => m,
        Err(e) => {
            {
                let mut coord = coordinator_mutex.lock().unwrap_or_else(|err| err.into_inner());
                coord.record_ip_failure(source_ip, unix_epoch_secs());
            }
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

    if let Err(e) = send_pairing_frame(stream, PairingMsgType::PairServerShare, &share_msg).await {
        let mut coord = coordinator_mutex.lock().unwrap_or_else(|err| err.into_inner());
        coord.cancel_inflight_for_ip(source_ip);
        coord.record_ip_failure(source_ip, unix_epoch_secs());
        return Err(e);
    }

    let (msg_type_2, payload_2) = match recv_pairing_frame(stream).await {
        Ok(res) => res,
        Err(e) => {
            let mut coord = coordinator_mutex.lock().unwrap_or_else(|err| err.into_inner());
            coord.cancel_inflight_for_ip(source_ip);
            coord.record_ip_failure(source_ip, unix_epoch_secs());
            return Err(e);
        }
    };
    if msg_type_2 != PairingMsgType::PairClientConfirm {
        {
            let mut coord = coordinator_mutex.lock().unwrap_or_else(|e| e.into_inner());
            coord.cancel_inflight_for_ip(source_ip);
            coord.record_ip_failure(source_ip, unix_epoch_secs());
        }
        let err = PairingError::InvalidMessageType(msg_type_2 as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let confirm_msg: PairClientConfirmMsg = match serde_json::from_slice(&payload_2) {
        Ok(m) => m,
        Err(e) => {
            {
                let mut coord = coordinator_mutex.lock().unwrap_or_else(|err| err.into_inner());
                coord.cancel_inflight_for_ip(source_ip);
                coord.record_ip_failure(source_ip, unix_epoch_secs());
            }
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs_2 = unix_epoch_secs();
    let (was_already_paired, confirm_res) = {
        let mut ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let prior_ids: std::collections::HashSet<String> =
            ks.list_peers().into_iter().map(|p| p.device_id_hex).collect();
        let mut coord = coordinator_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let res = coord.handle_pair_client_confirm(
            &mut ks,
            source_ip,
            &confirm_msg,
            via_direct_cable,
            now_secs_2,
        );
        let existed = res
            .as_ref()
            .map(|(_, creds, _)| prior_ids.contains(&creds.device_id_hex))
            .unwrap_or(false);
        (existed, res)
    };
    match confirm_res {
        Ok((complete_msg, creds, sas)) => {
            if let Err(e) =
                send_pairing_frame(stream, PairingMsgType::PairServerComplete, &complete_msg).await
            {
                if !was_already_paired {
                    let unpair_gen = {
                        let mut ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
                        ks.unpair_peer_ext(&creds.device_id_hex).map(|(_, g)| g).unwrap_or(0)
                    };
                    if let Some(core) = crate::core::GLOBAL_CORE.get() {
                        let _ = core.terminate_peer_connections_async(&creds.device_id_hex, unpair_gen).await;
                    }
                }
                return Err(e);
            }
            if let Some(core) = crate::core::GLOBAL_CORE.get() {
                core.camera.revoke_peer_consent(&creds.device_id_hex);
                core.clipboard.clear_peer_revocation(&creds.device_id_hex);
            }
            if let Some(clip) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
                clip.clear_peer_revocation(&creds.device_id_hex);
            }
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
#[cfg(test)]
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
#[cfg(test)]
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
    let (msg_type, payload) = match recv_pairing_frame_with_prefixed_magic(stream, already_read_magic).await {
        Ok(res) => res,
        Err(e) => {
            coordinator.record_ip_failure(source_ip, unix_epoch_secs());
            return Err(e);
        }
    };
    if msg_type != PairingMsgType::PairInit {
        coordinator.record_ip_failure(source_ip, unix_epoch_secs());
        let err = PairingError::InvalidMessageType(msg_type as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let init_msg: PairInitMsg = match serde_json::from_slice(&payload) {
        Ok(m) => m,
        Err(e) => {
            coordinator.record_ip_failure(source_ip, unix_epoch_secs());
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

    if let Err(e) = send_pairing_frame(stream, PairingMsgType::PairServerShare, &share_msg).await {
        coordinator.cancel_inflight_for_ip(source_ip);
        coordinator.record_ip_failure(source_ip, unix_epoch_secs());
        return Err(e);
    }

    let (msg_type_2, payload_2) = match recv_pairing_frame(stream).await {
        Ok(res) => res,
        Err(e) => {
            coordinator.cancel_inflight_for_ip(source_ip);
            coordinator.record_ip_failure(source_ip, unix_epoch_secs());
            return Err(e);
        }
    };
    if msg_type_2 != PairingMsgType::PairClientConfirm {
        coordinator.cancel_inflight_for_ip(source_ip);
        coordinator.record_ip_failure(source_ip, unix_epoch_secs());
        let err = PairingError::InvalidMessageType(msg_type_2 as u8);
        let _ = send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
        return Err(err);
    }

    let confirm_msg: PairClientConfirmMsg = match serde_json::from_slice(&payload_2) {
        Ok(m) => m,
        Err(e) => {
            coordinator.cancel_inflight_for_ip(source_ip);
            coordinator.record_ip_failure(source_ip, unix_epoch_secs());
            let err = PairingError::MalformedMessage(e.to_string());
            let _ =
                send_pairing_frame(stream, PairingMsgType::PairError, &err.to_wire_error()).await;
            return Err(err);
        }
    };

    let now_secs_2 = unix_epoch_secs();
    let prior_ids: std::collections::HashSet<String> = keystore
        .list_peers()
        .into_iter()
        .map(|p| p.device_id_hex)
        .collect();
    match coordinator.handle_pair_client_confirm(
        keystore,
        source_ip,
        &confirm_msg,
        via_direct_cable,
        now_secs_2,
    ) {
        Ok((complete_msg, creds, sas)) => {
            let was_already_paired = prior_ids.contains(&creds.device_id_hex);
            if let Err(e) =
                send_pairing_frame(stream, PairingMsgType::PairServerComplete, &complete_msg).await
            {
                if !was_already_paired {
                    let unpair_gen = keystore.unpair_peer_ext(&creds.device_id_hex).map(|(_, g)| g).unwrap_or(0);
                    if let Some(core) = crate::core::GLOBAL_CORE.get() {
                        let _ = core.terminate_peer_connections_async(&creds.device_id_hex, unpair_gen).await;
                    }
                }
                return Err(e);
            }
            if let Some(core) = crate::core::GLOBAL_CORE.get() {
                core.camera.revoke_peer_consent(&creds.device_id_hex);
                core.clipboard.clear_peer_revocation(&creds.device_id_hex);
            }
            if let Some(clip) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
                clip.clear_peer_revocation(&creds.device_id_hex);
            }
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

/// Assembles the 102-byte Client A identity byte string for the SPAKE2 transcript:
/// `20B("integrator-pair-v2-A") || 2B(u16_be(ver)) || 16B(client_device_id) || 32B(client_ed25519_pk) || 32B(client_nonce)`.
fn build_spake2_identity_a(
    client_device_id: &[u8; 16],
    client_ed25519_pk: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + 2 + 16 + 32 + 32);
    out.extend_from_slice(b"integrator-pair-v2-A");
    out.extend_from_slice(&PAIRING_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(client_device_id);
    out.extend_from_slice(client_ed25519_pk);
    out.extend_from_slice(client_nonce);
    out
}

/// Assembles the 118-byte Server B identity byte string for the SPAKE2 transcript:
/// `20B("integrator-pair-v2-B") || 2B(u16_be(ver)) || 16B(server_device_id) || 32B(server_ed25519_pk) || 32B(server_nonce) || 16B(session_id)`.
fn build_spake2_identity_b(
    server_device_id: &[u8; 16],
    server_ed25519_pk: &[u8; 32],
    server_nonce: &[u8; 32],
    pairing_session_id: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + 2 + 16 + 32 + 32 + 16);
    out.extend_from_slice(b"integrator-pair-v2-B");
    out.extend_from_slice(&PAIRING_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(server_device_id);
    out.extend_from_slice(server_ed25519_pk);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(pairing_session_id);
    out
}

/// Computes SHA-256 hash of `PairInitMsg` and `PairServerShareMsg` fields bound as AAD into confirmation keys.
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

/// Assembles the 88-byte payload signed by Client A:
/// `24B("integrator-pair-sig-A-v2") || 32B(tt_sha256) || 32B(confirm_mac_a)`.
fn build_client_signature_payload(tt_sha256: &[u8; 32], confirm_mac_a: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 32 + 32);
    buf.extend_from_slice(b"integrator-pair-sig-A-v2");
    buf.extend_from_slice(tt_sha256);
    buf.extend_from_slice(confirm_mac_a);
    buf
}

/// Assembles the 152-byte payload signed by Server B:
/// `24B("integrator-pair-sig-B-v2") || 32B(tt_sha256) || 32B(confirm_mac_b) || 64B(sig_a)`.
fn build_server_signature_payload(
    tt_sha256: &[u8; 32],
    confirm_mac_b: &[u8; 32],
    sig_a: &[u8; 64],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 32 + 32 + 64);
    buf.extend_from_slice(b"integrator-pair-sig-B-v2");
    buf.extend_from_slice(tt_sha256);
    buf.extend_from_slice(confirm_mac_b);
    buf.extend_from_slice(sig_a);
    buf
}

/// Generates an unbiased 6-digit numeric PIN (`100000`..=`999999`) using CSPRNG rejection sampling.
///
/// Modulo reduction of uniform `u32` integers over a range that is not a power of 2 introduces slight bias.
/// Rejection sampling discards values $\ge 2^{32} - (2^{32} \bmod 900,000)$, guaranteeing mathematical
/// uniformity across all 900,000 valid PINs.
pub fn generate_unbiased_6digit_pin() -> String {
    const RANGE: u32 = 900_000;
    const MAX_UNBIASED: u32 = u32::MAX - (u32::MAX % RANGE);
    loop {
        let buf = csprng_array::<4>();
        let candidate = u32::from_le_bytes(buf);
        if candidate < MAX_UNBIASED {
            let pin = MIN_PIN_VALUE + (candidate % RANGE);
            return format!("{:06}", pin);
        }
    }
}

/// Checks whether `pin` is exactly 6 ASCII digits (`0`..=`9`).
pub fn is_valid_6digit_pin(pin: &str) -> bool {
    pin.len() == crate::config::PAIRING_PIN_LENGTH && pin.chars().all(|c| c.is_ascii_digit())
}

/// Identifies Unicode bidirectional control characters used in visual spoofing attacks.
fn is_bidi_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Sanitizes friendly device and platform strings, stripping control characters, bidi overrides, and clamping length.
fn sanitize_label(input: &str, max_len: usize) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_format_char(*c))
        .take(max_len)
        .collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        DEFAULT_UNKNOWN_DEVICE_NAME.to_string()
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

    #[test]
    fn test_pairing_spoofed_ip_confirm_does_not_evict_legit_inflight_session() {
        let (dir_c, mut ks_c) = temp_keystore("spoof_c", 0xA1);
        let (dir_s, mut ks_s) = temp_keystore("spoof_s", 0xA2);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = 7_000_000;
        coordinator.open_pairing_window_with_pin("654321", now).unwrap();

        let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 2));
        let attacker_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 200));

        let (hs, init_msg) =
            ClientPairingHandshakeV2::initiate(&ks_c, "654321", "Mac", "macOS").unwrap();
        let share_msg = coordinator
            .handle_pair_init(&ks_s, legit_ip, &init_msg, now)
            .unwrap();
        let (awaiting, confirm_msg) = hs.process_server_share(&ks_c, &share_msg).unwrap();

        // Off-path attacker tries to submit confirm from another IP -> must fail with SessionIpMismatch
        // AND must NOT remove the legitimate in-flight session.
        let spoof_res = coordinator.handle_pair_client_confirm(
            &mut ks_s,
            attacker_ip,
            &confirm_msg,
            false,
            now,
        );
        assert_eq!(spoof_res.unwrap_err(), PairingError::SessionIpMismatch);

        // Legitimate client can still complete the same session.
        let (complete_msg, srv_creds, _) = coordinator
            .handle_pair_client_confirm(&mut ks_s, legit_ip, &confirm_msg, true, now)
            .expect("legit session must remain intact after spoofed IP attempt");
        let (cli_creds, _) = awaiting
            .finalize_and_commit(&mut ks_c, &complete_msg, "10.99.99.1", true)
            .unwrap();
        assert_eq!(*srv_creds.root_key, *cli_creds.root_key);

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_pairing_malformed_init_and_early_drop_locks_out_ip() {
        let (dir_c, mut ks_c) = temp_keystore("malf_c", 0xB1);
        let (dir_s, mut ks_s) = temp_keystore("malf_s", 0xB2);
        let mut coordinator =
            PairingCoordinatorV2::new("HP-Omen".to_string(), "Windows".to_string());
        let now = unix_epoch_secs();
        coordinator.open_pairing_window_with_pin("777888", now).unwrap();

        let attacker_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 66));
        let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 77));

        // Attempt 1: Attacker sends malformed frame magic / message type
        let (mut c1, mut s1) = tokio::io::duplex(1024);
        c1.write_all(b"GARBAGE_BYTES").await.unwrap();
        drop(c1);
        let res1 = handle_server_pairing_over_stream(&mut s1, &mut coordinator, &mut ks_s, attacker_ip, false).await;
        assert!(res1.is_err());

        // Attempt 2: Attacker sends valid frame wrapper with malformed JSON body
        let (mut c2, mut s2) = tokio::io::duplex(1024);
        send_pairing_frame(&mut c2, PairingMsgType::PairInit, &"not a valid PairInitMsg").await.unwrap();
        drop(c2);
        let res2 = handle_server_pairing_over_stream(&mut s2, &mut coordinator, &mut ks_s, attacker_ip, false).await;
        assert!(res2.is_err());

        // Attempt 3: Attacker sends valid PairInitMsg then drops before sending PairClientConfirm
        let (mut c3, mut s3) = tokio::io::duplex(4096);
        let (_, init_ok) = ClientPairingHandshakeV2::initiate(&ks_c, "777888", "AttackerMac", "macOS").unwrap();
        send_pairing_frame(&mut c3, PairingMsgType::PairInit, &init_ok).await.unwrap();
        // Server will send PairServerShare; attacker immediately closes stream
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = c3.read(&mut buf).await;
            drop(c3);
        });
        let res3 = handle_server_pairing_over_stream(&mut s3, &mut coordinator, &mut ks_s, attacker_ip, false).await;
        assert!(res3.is_err());

        // Attempt 4: Attacker is now locked out (3 strikes)
        let (_hs4, init4) = ClientPairingHandshakeV2::initiate(&ks_c, "777888", "AttackerMac", "macOS").unwrap();
        let lockout = coordinator.handle_pair_init(&ks_s, attacker_ip, &init4, now);
        assert!(matches!(lockout, Err(PairingError::IpRateLimited { .. })));

        // But legitimate client from legit_ip can still pair cleanly with the active PIN!
        let (hs_legit, init_legit) = ClientPairingHandshakeV2::initiate(&ks_c, "777888", "LegitMac", "macOS").unwrap();
        let share_legit = coordinator.handle_pair_init(&ks_s, legit_ip, &init_legit, now).unwrap();
        let (await_legit, confirm_legit) = hs_legit.process_server_share(&ks_c, &share_legit).unwrap();
        let (comp_legit, _, _) = coordinator
            .handle_pair_client_confirm(&mut ks_s, legit_ip, &confirm_legit, false, now)
            .expect("legitimate peer must succeed even when attacker IP is locked out");
        assert!(await_legit.finalize_and_commit(&mut ks_c, &comp_legit, "10.99.99.1", false).is_ok());

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_pairing_server_complete_send_failure_rolls_back_and_cleans_up() {
        let (dir_c, ks_c) = temp_keystore("rb_c", 0xD1);
        let (dir_s, mut ks_s) = temp_keystore("rb_s", 0xD2);
        let mut coordinator =
            PairingCoordinatorV2::new("ServerPC".to_string(), "Windows".to_string());
        let client_ip: IpAddr = "10.88.88.5".parse().unwrap();
        let now = unix_epoch_secs();
        coordinator.open_pairing_window_with_pin("555666", now).unwrap();

        let (mut c_stream, mut s_stream) = tokio::io::duplex(4096);

        // Production path: run handle_server_pairing_over_stream on the server side
        let server_task = tokio::spawn(async move {
            let res = handle_server_pairing_over_stream(
                &mut s_stream,
                &mut coordinator,
                &mut ks_s,
                client_ip,
                false,
            )
            .await;
            (res, ks_s)
        });

        // Client side executes:
        // 1. Send PairInit
        let (hs_c, init_msg) = ClientPairingHandshakeV2::initiate(&ks_c, "555666", "ClientMac", "macOS").unwrap();
        send_pairing_frame(&mut c_stream, PairingMsgType::PairInit, &init_msg).await.unwrap();

        // 2. Recv PairServerShare
        let (msg_type, payload) = recv_pairing_frame(&mut c_stream).await.unwrap();
        assert_eq!(msg_type, PairingMsgType::PairServerShare);
        let share_msg: PairServerShareMsg = serde_json::from_slice(&payload).unwrap();

        // 3. Send PairClientConfirm
        let (_awaiting, confirm_msg) = hs_c.process_server_share(&ks_c, &share_msg).unwrap();
        send_pairing_frame(&mut c_stream, PairingMsgType::PairClientConfirm, &confirm_msg).await.unwrap();

        // 4. Immediately drop c_stream so server fails when sending PairServerComplete
        drop(c_stream);

        // Server task completes with error because PairServerComplete send failed
        let (server_res, ks_s) = server_task.await.unwrap();
        assert!(server_res.is_err(), "Server pairing must fail when complete frame cannot be delivered");

        // Verify rollback: peer must NOT remain pinned in keystore (automatically unpinned by handle_server_pairing_over_stream)
        assert_eq!(ks_s.list_peers().len(), 0, "Peer must be unpinned upon rollback in keystore");

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }
}
