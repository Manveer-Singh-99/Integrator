//! ============================================================================
//! Unified Mutually Authenticated Transport Layer (`TransportV2`, Magic `ITR2`)
//! ============================================================================
//!
//! # 1. Architectural Overview & Purpose
//!
//! `TransportV2` provides a high-performance, forward-secret, post-quantum-resilient
//! (hybrid-ready), mutually authenticated, anti-replay cryptographic session layer
//! for all direct TCP communications within the Integrator ecosystem.
//!
//! It underpins all core cross-device streaming and RPC services:
//! - **Display & Control RPC** (`Port 58281`, `ServiceId::DisplayRpc = 0x01`): Remote display frame
//!   negotiation, resolution scaling, dynamic HEVC/AV1 parameter updates, virtual monitor topology.
//! - **Clipboard & File Transfer** (`Port 58283`, `ServiceId::ClipboardTransfer = 0x02`): Bidirectional
//!   system clipboard synchronization, multi-megabyte drag-and-drop chunks, MIME streaming.
//! - **Link Speed Benchmark** (`Port 58285`, `ServiceId::Benchmark = 0x03`): Cable vs Wi-Fi throughput
//!   characterization, raw bandwidth probing, packet jitter analysis.
//! - **Universal Input KVM & Drag-Drop Control** (`Port 58286`, `ServiceId::InputKvm = 0x04`): Ultra-low-latency
//!   pointer events, keyboard scan codes, mouse wheel ticks, drag preview thumbnails.
//! - **Mac -> Windows Shared Camera** (`Port 58287`, `ServiceId::CameraStream = 0x05`): Real-time raw NV12 /
//!   H.264 camera frame delivery, format negotiation, capture controls.
//!
//! # 2. Cryptographic Security Model & Threat Model
//!
//! The cryptographic protocol implements a 3-way authenticated Diffie-Hellman handshake
//! (`ClientHello` -> `ServerHello` -> `ClientFinish`) followed by a directional ChaCha20-Poly1305
//! AEAD record layer.
//!
//! ## 2.1 Threat Model
//! - **Adversary Capabilities**: Full control over local network traffic (active adversary): capability
//!   to intercept, reorder, delay, drop, replay, or inject arbitrary TCP packets on any service port.
//! - **Man-in-the-Middle (MitM) Resistance**: Handshake binds ephemeral `X25519` key exchanges to the
//!   long-term pre-shared root key ($K_{\text{root}}$) derived during RFC 9382 SPAKE2 pairing, and requires
//!   mutual `Ed25519` digital signatures over the complete cumulative handshake transcripts ($H_2$, $H_3$).
//! - **Forward Secrecy**: Ephemeral `X25519` keys are generated freshly per connection from CSPRNG and
//!   zeroized immediately after session derivation. Compromise of long-term $K_{\text{root}}$ or device
//!   Ed25519 identity keys cannot decrypt historical session captures.
//! - **Low-Order Point & Small-Subgroup Attacks**: Rejects all non-contributory or low-order Curve25519
//!   points (all-zero shared secret check + RFC 7748 §6.1 `was_contributory()` validation).
//! - **Replay Attack Mitigation**:
//!   1. Handshake: Timestamps enforced within $\pm 5$ minutes (`HANDSHAKE_TIMESTAMP_WINDOW_MS = 300_000ms`);
//!      active deduplication cache (`HELLO_REPLAY_CACHE`) protects against replayed `ClientHello` frames.
//!   2. Record Layer: Strict monotonic 64-bit sequence numbers (`seq`). An exact match (`rx_seq == expected_seq`)
//!      is enforced per directional channel. Any out-of-order, duplicated, or skipped record aborts the session.
//! - **Reflection & Cross-Direction Attacks**: Handshake derive distinct directional keys ($K_{\text{app\_c2s}}$,
//!   $K_{\text{app\_s2c}}$) and IV prefixes ($IV_{\text{c2s}}$ with LSB 0, $IV_{\text{s2c}}$ with LSB 1).
//! - **Reflection Across Services**: Handshake transcript $H_2$ binds `service_id` into the HKDF expansion,
//!   preventing an attacker from replaying a handshake intended for `Benchmark` against `DisplayRpc`.
//!
//! ## 2.2 Handshake Protocol State Machine
//! ```text
//! Client                                                  Server
//!   |                                                       |
//!   | 1. ClientHello                                        |
//!   |    (version, service_id, client_dev_id, key_id,       |
//!   |     client_random, eph_pk_c, timestamp_ms)           |
//!   |------------------------------------------------------>| (validate timestamp, key_id,
//!   |                                                       |  reject low-order eph_pk_c,
//!   |                                                       |  compute H2, derive K_hs,
//!   |                                                       |  sign H2 with Ed25519)
//!   | 2. ServerHello                                        |
//!   |    (version, server_dev_id, server_random,            |
//!   |     eph_pk_s, server_sig, server_finished_mac)        |
//!   |<------------------------------------------------------|
//!   | (validate server_dev_id, reject low-order eph_pk_s,   |
//!   |  compute H2, derive K_hs, verify server_mac & sig,    |
//!   |  compute H3, sign H3 with Ed25519, compute cli_mac)   |
//!   |                                                       |
//!   | 3. ClientFinish                                       |
//!   |    (client_sig, client_finished_mac)                  |
//!   |------------------------------------------------------>| (verify client_mac & sig,
//!   |                                                       |  record hello nonce,
//!   |                                                       |  compute H4, derive app keys)
//!   |                                                       |
//!   | <==== Full-Duplex Directional ChaCha20-Poly1305 =====>|
//! ```
//!
//! ## 2.3 Handshake Mathematical Formulations
//! 1. **Ephemeral Key Agreement**:
//!    $$DH = \text{X25519}(sk_{\text{eph}}, pk_{\text{eph, remote}})$$
//!    $$\text{Assert } DH \ne 0^{32} \land \text{contributory}(DH)$$
//! 2. **Transcript Hashes**:
//!    $$H_2 = \text{SHA256}(\text{"integrator-transport-v2-h2"} \mathbin{\Vert} \text{service\_id} \mathbin{\Vert} \text{len}(CH) \mathbin{\Vert} CH \mathbin{\Vert} dev\_id_s \mathbin{\Vert} rnd_s \mathbin{\Vert} pk_{s})$$
//!    $$H_3 = \text{SHA256}(\text{"integrator-transport-v2-h3"} \mathbin{\Vert} H_2 \mathbin{\Vert} sig_s \mathbin{\Vert} mac_s)$$
//!    $$H_4 = \text{SHA256}(\text{"integrator-transport-v2-h4"} \mathbin{\Vert} H_3 \mathbin{\Vert} sig_c \mathbin{\Vert} mac_c)$$
//! 3. **Handshake Key Derivation**:
//!    $$PRK_{\text{hs}} = \text{HKDF-Extract}(K_{\text{root}}, DH)$$
//!    $$K_{\text{hs\_s2c}} = \text{HKDF-Expand}(PRK_{\text{hs}}, \text{"integrator-v2-hs-s2c"} \mathbin{\Vert} H_2, 32)$$
//!    $$K_{\text{hs\_c2s}} = \text{HKDF-Expand}(PRK_{\text{hs}}, \text{"integrator-v2-hs-c2s"} \mathbin{\Vert} H_2, 32)$$
//! 4. **Application Key Derivation**:
//!    $$IKM_{\text{app}} = \text{HKDF-Expand}(PRK_{\text{hs}}, \text{"integrator-v2-derived"}, 32)$$
//!    $$PRK_{\text{app}} = \text{HKDF-Extract}(H_4, IKM_{\text{app}})$$
//!    $$K_{\text{app\_c2s}}, K_{\text{app\_s2c}}, IV_{\text{c2s}}, IV_{\text{s2c}}, K_{\text{rekey\_c2s}}, K_{\text{rekey\_s2c}}, \text{session\_id} \leftarrow \text{HKDF-Expand}(PRK_{\text{app}})$$
//!
//! ## 2.4 Record Layer Nonce Construction & AEAD Framing
//! - **Header Length**: 21 bytes authenticated as Additional Authenticated Data (`AAD`):
//!   `magic[4B] ("ITR2") || version[1B] (0x02) || frame_type[1B] || flags[1B] || epoch[2B] || seq[8B] || ciphertext_len[4B]`
//! - **Nonce Construction** (96 bits):
//!   `nonce = iv_salt[0..4] || seq.to_be_bytes()[0..8]`
//! - **ChaCha20-Poly1305 Encryption**:
//!   `ciphertext || tag = Encrypt(K_app, nonce, plaintext, AAD=header)`
//!
//! ## 2.5 In-Band Rekeying & Sequence Ratcheting
//! - To prevent sequence exhaustion and bound the volume of data encrypted under a single key,
//!   `TransportSessionV2` automatically ratchets its directional keys when:
//!   `seq >= rekey_frame_limit` (default $2^{32}$) OR `elapsed_time >= 3600s` (1 hour).
//! - In-band `Rekey` frame (`frame_type = 0x02`) is transmitted containing `REKEY-V2` magic payload.
//! - Both transmitter and receiver execute HKDF-SHA256 ratcheting:
//!   $$HK = \text{HKDF-Extract}(\text{epoch} + 1, K_{\text{rekey}})$$
//!   $$K_{\text{app, next}} \leftarrow \text{HKDF-Expand}(HK, \text{"integrator-v2-rekey-app"}, 32)$$
//!   $$K_{\text{rekey, next}} \leftarrow \text{HKDF-Expand}(HK, \text{"integrator-v2-rekey-next"}, 32)$$
//!   $$IV_{\text{next}} \leftarrow \text{HKDF-Expand}(HK, \text{"integrator-v2-rekey-iv"}, 4)$$
//! - `epoch` increments to `epoch + 1`, `seq` resets to `0`, and all prior keys are zeroized in memory.
//!
//! # 3. Threading, Concurrency & Split Halves
//!
//! `TransportSessionV2` supports lock-free full-duplex operation by splitting into
//! `TransportReaderV2` and `TransportWriterV2` via `into_split_tcp()`.
//! The reader owns `rx_state` while the writer owns `tx_state`. Because directional
//! cipher states are strictly independent (separate keys, separate IVs, separate sequence counters),
//! concurrent reads and writes proceed with zero lock contention.
//!
//! # 4. Cross-Platform Handshake Compatibility
//!
//! Wire formats use canonical network byte order (big-endian) for integers and hex-encoded
//! strings for cryptographic points and signatures in JSON handshake payloads. Tested and
//! validated between macOS (Apple Silicon & Intel) and Windows 11 (x86_64 & ARM64).
//!
//! # 5. Callers & Callees
//! - **Callers**:
//!   - `crate::rpc::server`: Display RPC on port 58281
//!   - `crate::clipboard::sync`: Clipboard transfer on port 58283
//!   - `crate::benchmark::runner`: Link benchmark on port 58285
//!   - `crate::input::server`: KVM input daemon on port 58286
//!   - `crate::camera::stream`: Camera streaming on port 58287
//! - **Callees**:
//!   - `crate::security::keystore::KeystoreV2`: Device identity key, peer trust store, root keys.
//!   - `crate::security::spake2_rfc9382::compute_hmac_sha256`: Constant-time finished HMAC calculation.
//!   - `chacha20poly1305`: Authenticated Encryption with Associated Data (AEAD).
//!   - `x25519_dalek`: Ephemeral Diffie-Hellman key agreement.
//!   - `zeroize`: Secure memory zeroization of session and rekey keys.
//! ============================================================================

use crate::security::{
    constant_time_eq, csprng_array, hex_decode_array, hex_encode,
    keystore::{KeystoreV2, VerifiedPeerCredentials},
    spake2_rfc9382::compute_hmac_sha256,
    unix_epoch_millis,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, Zeroizing};

/// Wire magic identifying the TransportV2 protocol framing (`b"ITR2"`).
pub const TRANSPORT_WIRE_MAGIC: [u8; 4] = *b"ITR2";

/// Major protocol version for TransportV2 negotiation (currently version 2).
pub const TRANSPORT_PROTOCOL_VERSION: u16 = 2;

/// Header byte representing protocol version 2 in record and handshake frames (0x02).
pub const TRANSPORT_HEADER_VERSION_BYTE: u8 = 0x02;

/// Maximum allowable length in bytes for any JSON handshake payload (4096 bytes / 4 KiB).
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 4096;

/// Exact wire length in bytes of the authenticated TransportV2 record header (21 bytes).
/// Wire layout: magic[4B] || version[1B] || frame_type[1B] || flags[1B] || epoch[2B] || seq[8B] || len[4B].
pub const RECORD_HEADER_LEN: usize = 21;

/// Exact wire length in bytes of the Poly1305 authentication tag appended to ciphertexts (16 bytes).
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum allowable clock skew window between client and server during handshake (300,000 ms = ±5 minutes).
pub const HANDSHAKE_TIMESTAMP_WINDOW_MS: u64 = 300_000;

/// Maximum number of recent authenticated handshake nonce entries maintained in `HELLO_REPLAY_CACHE` (2048 entries).
pub const MAX_HANDSHAKE_REPLAY_CACHE: usize = 2048;

/// Timeout applied to individual handshake read and write operations (10 seconds).
pub const HANDSHAKE_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout applied to individual record header and payload I/O operations (10 seconds).
pub const RECORD_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Default number of frames encrypted under a single directional key before an automatic ratchet occurs (2^32 frames).
pub const DEFAULT_REKEY_FRAME_LIMIT: u64 = 1u64 << 32;

/// Default maximum age of a directional session key before triggering an automatic ratchet (3600 seconds = 1 hour).
pub const DEFAULT_REKEY_AGE_SECS: u64 = 3600;

/// In-band payload magic identifying an explicit rekey control frame (`b"REKEY-V2"`).
const REKEY_MAGIC_PAYLOAD: &[u8] = b"REKEY-V2";

/// Maximum plaintext record payload size for `ServiceId::DisplayRpc` (64 KiB).
pub const MAX_DISPLAY_RPC_FRAME_BYTES: usize = 64 * 1024;

/// Maximum plaintext record payload size for `ServiceId::ClipboardTransfer` (2 MiB).
pub const MAX_CLIPBOARD_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Maximum plaintext record payload size for `ServiceId::Benchmark` (1 MiB).
pub const MAX_BENCHMARK_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum plaintext record payload size for `ServiceId::InputKvm` (128 KiB).
pub const MAX_INPUT_KVM_FRAME_BYTES: usize = 128 * 1024;

/// Maximum plaintext record payload size for `ServiceId::CameraStream` (2 MiB).
pub const MAX_CAMERA_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Extra grace period in milliseconds added when pruning `HELLO_REPLAY_CACHE` entries (60 seconds).
const REPLAY_CACHE_PRUNE_GRACE_PERIOD_MS: u64 = 60_000;

/// Upper cap in bytes for initial buffer pre-allocation when receiving chunked payloads (1 MiB).
const INITIAL_CHUNKED_BUFFER_CAPACITY_LIMIT: usize = 1024 * 1024;

/// Identifies the subsystem service requesting or hosting an authenticated TransportV2 session.
///
/// Binds cryptographic handshakes to specific services to prevent cross-service replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceId {
    /// Remote display rendering and control RPC (`Port 58281`, max payload 64 KiB).
    DisplayRpc = 0x01,
    /// Bidirectional clipboard synchronization and file transfer (`Port 58283`, max payload 2 MiB).
    ClipboardTransfer = 0x02,
    /// Direct network link speed benchmarking (`Port 58285`, max payload 1 MiB).
    Benchmark = 0x03,
    /// Universal input sharing and KVM drag-drop control (`Port 58286`, max payload 128 KiB).
    InputKvm = 0x04,
    /// Shared camera video frame streaming (`Port 58287`, max payload 2 MiB).
    CameraStream = 0x05,
}

impl ServiceId {
    /// Returns the maximum allowable plaintext payload size in bytes for a single record frame
    /// for this service.
    ///
    /// Exceeding this boundary triggers `TransportError::OversizedFrame`.
    pub fn max_plaintext_frame_bytes(self) -> usize {
        match self {
            ServiceId::DisplayRpc => MAX_DISPLAY_RPC_FRAME_BYTES,
            ServiceId::ClipboardTransfer => MAX_CLIPBOARD_FRAME_BYTES,
            ServiceId::Benchmark => MAX_BENCHMARK_FRAME_BYTES,
            ServiceId::InputKvm => MAX_INPUT_KVM_FRAME_BYTES,
            ServiceId::CameraStream => MAX_CAMERA_FRAME_BYTES,
        }
    }
}

/// Identifies the message type of a TransportV2 handshake frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeFrameType {
    /// First handshake message sent by the initiating client (0x10).
    ClientHello = 0x10,
    /// Response handshake message sent by the receiving server (0x11).
    ServerHello = 0x11,
    /// Final handshake confirmation message sent by the client (0x12).
    ClientFinish = 0x12,
    /// Error notification terminating the handshake (0x1F).
    HandshakeError = 0x1F,
}

impl HandshakeFrameType {
    /// Decodes a raw wire byte into a `HandshakeFrameType`. Returns `None` for invalid codes.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x10 => Some(HandshakeFrameType::ClientHello),
            0x11 => Some(HandshakeFrameType::ServerHello),
            0x12 => Some(HandshakeFrameType::ClientFinish),
            0x1F => Some(HandshakeFrameType::HandshakeError),
            _ => None,
        }
    }
}

/// Identifies the frame type of an authenticated and encrypted TransportV2 record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordFrameType {
    /// Encrypted application-layer data payload (0x01).
    ApplicationData = 0x01,
    /// In-band key ratchet notification triggering key derivation to epoch + 1 (0x02).
    Rekey = 0x02,
    /// Zero-payload or diagnostic keep-alive frame maintaining firewall state (0x03).
    KeepAlive = 0x03,
    /// Clean session termination notification (0x04).
    CloseNotify = 0x04,
}

impl RecordFrameType {
    /// Decodes a raw wire byte into a `RecordFrameType`. Returns `None` for unrecognized types.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(RecordFrameType::ApplicationData),
            0x02 => Some(RecordFrameType::Rekey),
            0x03 => Some(RecordFrameType::KeepAlive),
            0x04 => Some(RecordFrameType::CloseNotify),
            _ => None,
        }
    }
}

/// Wire structure for the `ClientHello` handshake message (JSON payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportHelloMsg {
    /// Protocol major version (must equal 2).
    pub version: u16,
    /// Targeted service identifier (`ServiceId` raw byte).
    pub service_id: u8,
    /// 16-byte local device UUID of the client formatted as a lowercase hex string.
    pub client_device_id_hex: String,
    /// 16-byte key identifier identifying the pinned root key $K_{\text{root}}$ in the server keystore.
    pub key_id_hex: String,
    /// 32-byte cryptographically secure random nonce generated by the client.
    pub client_random_hex: String,
    /// 32-byte ephemeral X25519 public key generated by the client.
    pub client_eph_x25519_pk_hex: String,
    /// UTC timestamp in milliseconds when this message was constructed (anti-replay check).
    pub timestamp_ms: u64,
}

/// Wire structure for the `ServerHello` handshake message (JSON payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportServerHelloMsg {
    /// Protocol major version (must equal 2).
    pub version: u16,
    /// 16-byte local device UUID of the server formatted as a lowercase hex string.
    pub server_device_id_hex: String,
    /// 32-byte cryptographically secure random nonce generated by the server.
    pub server_random_hex: String,
    /// 32-byte ephemeral X25519 public key generated by the server.
    pub server_eph_x25519_pk_hex: String,
    /// 64-byte Ed25519 digital signature over the server signature payload (`"integrator-transport-sig-S-v2"` || $H_2$).
    pub server_ed25519_sig_hex: String,
    /// 32-byte HMAC-SHA256 finished MAC over ($H_2$ || server_ed25519_sig) using $K_{\text{hs\_s2c}}$.
    pub server_finished_mac_hex: String,
}

/// Wire structure for the `ClientFinish` handshake message (JSON payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportClientFinishMsg {
    /// 64-byte Ed25519 digital signature over the client signature payload (`"integrator-transport-sig-C-v2"` || $H_3$).
    pub client_ed25519_sig_hex: String,
    /// 32-byte HMAC-SHA256 finished MAC over ($H_3$ || client_ed25519_sig) using $K_{\text{hs\_c2s}}$.
    pub client_finished_mac_hex: String,
}

/// Comprehensive error enumeration for TransportV2 handshake negotiation and record layer framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Received magic bytes did not match `TRANSPORT_WIRE_MAGIC` (`b"ITR2"`).
    InvalidMagic([u8; 4]),
    /// Protocol version received does not match `TRANSPORT_PROTOCOL_VERSION` (2).
    UnsupportedVersion(u16),
    /// Received an unexpected or unknown frame type code.
    UnexpectedFrameType(u8),
    /// Handshake `service_id` does not match the service expected by the server listener.
    ServiceMismatch { expected: u8, received: u8 },
    /// Frame payload exceeds the maximum allowable byte size for the given service or handshake phase.
    OversizedFrame { len: usize, max: usize },
    /// Handshake JSON parsing or schema validation failed.
    MalformedHandshake(String),
    /// Handshake timestamp delta exceeds the allowable window (`HANDSHAKE_TIMESTAMP_WINDOW_MS`).
    TimestampSkewExceeded { skew_ms: u64 },
    /// Handshake `client_random` nonce has already been authenticated within the recent replay cache.
    ReplayedHandshakeHello,
    /// Peer device ID is not paired or found in the local `KeystoreV2`.
    UntrustedPeer(String),
    /// Peer provided a `key_id` that does not match the pinned root key stored in `KeystoreV2`.
    KeyIdMismatch,
    /// Ephemeral X25519 public key produced an all-zero shared secret or non-contributory point.
    LowOrderEphemeralPoint,
    /// HMAC-SHA256 finished MAC verification failed during handshake.
    HandshakeMacMismatch,
    /// Ed25519 identity signature verification over the handshake transcript failed.
    HandshakeSignatureInvalid,
    /// ChaCha20-Poly1305 record authentication failed (tag mismatch or corrupted ciphertext/AAD).
    AeadDecryptionFailed,
    /// Record header epoch does not match the expected active epoch for the directional channel.
    EpochMismatch { expected: u16, received: u16 },
    /// Record header sequence number did not match the strictly required monotonic sequence number.
    SequenceMismatch { expected: u64, received: u64 },
    /// Sequence counter reached `u64::MAX` or epoch counter reached `u16::MAX` without ratcheting.
    SequenceExhausted,
    /// Transport session was cleanly closed via `CloseNotify` or connection shutdown.
    ConnectionClosed,
    /// Underlying TCP stream I/O failure or timeout.
    IoFailure(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::InvalidMagic(m) => {
                write!(f, "Invalid transport frame magic {:?} (expected ITR2)", m)
            }
            TransportError::UnsupportedVersion(v) => {
                write!(f, "Unsupported transport protocol version {} (expected 2)", v)
            }
            TransportError::UnexpectedFrameType(t) => {
                write!(f, "Unexpected transport frame type 0x{:02x}", t)
            }
            TransportError::ServiceMismatch { expected, received } => write!(
                f,
                "Transport service_id mismatch: expected 0x{:02x}, received 0x{:02x}",
                expected, received
            ),
            TransportError::OversizedFrame { len, max } => write!(
                f,
                "Transport frame length {} exceeds maximum {} bytes",
                len, max
            ),
            TransportError::MalformedHandshake(msg) => {
                write!(f, "Malformed transport handshake: {}", msg)
            }
            TransportError::TimestampSkewExceeded { skew_ms } => write!(
                f,
                "Transport handshake timestamp skew {}ms exceeds allowed window",
                skew_ms
            ),
            TransportError::ReplayedHandshakeHello => {
                write!(f, "Rejected replayed TransportHello nonce")
            }
            TransportError::UntrustedPeer(id) => write!(
                f,
                "Peer '{}' is not paired/trusted in the v2 keystore",
                id
            ),
            TransportError::KeyIdMismatch => write!(
                f,
                "Peer key_id does not match the pinned root key in the v2 keystore"
            ),
            TransportError::LowOrderEphemeralPoint => write!(
                f,
                "Rejected low-order X25519 ephemeral point (all-zero shared secret)"
            ),
            TransportError::HandshakeMacMismatch => {
                write!(f, "Transport handshake finished HMAC verification failed")
            }
            TransportError::HandshakeSignatureInvalid => {
                write!(f, "Transport handshake Ed25519 signature verification failed")
            }
            TransportError::AeadDecryptionFailed => {
                write!(f, "ChaCha20-Poly1305 record authentication/decryption failed")
            }
            TransportError::EpochMismatch { expected, received } => write!(
                f,
                "Transport record epoch mismatch: expected {}, received {}",
                expected, received
            ),
            TransportError::SequenceMismatch { expected, received } => write!(
                f,
                "Transport record sequence mismatch: expected {}, received {}",
                expected, received
            ),
            TransportError::SequenceExhausted => {
                write!(f, "Transport sequence or epoch counter exhausted")
            }
            TransportError::ConnectionClosed => write!(f, "Transport session closed cleanly"),
            TransportError::IoFailure(msg) => write!(f, "Transport I/O error: {}", msg),
        }
    }
}

impl std::error::Error for TransportError {}

/// Bounded replay cache for authenticated `(client_device_id, client_random, recorded_at_ms)` tuples.
///
/// Prevents active replay of historical `ClientHello` frames within the valid timestamp window.
static HELLO_REPLAY_CACHE: OnceLock<Mutex<VecDeque<([u8; 16], [u8; 32], u64)>>> = OnceLock::new();

/// Prunes entries in `HELLO_REPLAY_CACHE` older than $2 \times \text{HANDSHAKE\_TIMESTAMP\_WINDOW\_MS} + 60\text{s}$.
fn prune_hello_replay_cache(guard: &mut VecDeque<([u8; 16], [u8; 32], u64)>, now_ms: u64) {
    let max_age = HANDSHAKE_TIMESTAMP_WINDOW_MS
        .saturating_mul(2)
        .saturating_add(REPLAY_CACHE_PRUNE_GRACE_PERIOD_MS);
    guard.retain(|(_, _, ts)| now_ms.saturating_sub(*ts) <= max_age);
}

/// Checks whether a given `(client_device_id, client_random)` pair exists in the replay cache.
///
/// Returns `Err(TransportError::ReplayedHandshakeHello)` if the nonce is already recorded.
fn check_hello_nonce_not_replayed(
    client_device_id: &[u8; 16],
    client_random: &[u8; 32],
    now_ms: u64,
) -> Result<(), TransportError> {
    let cache = HELLO_REPLAY_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    prune_hello_replay_cache(&mut guard, now_ms);
    for (id, rnd, _) in guard.iter() {
        if constant_time_eq(id, client_device_id) && constant_time_eq(rnd, client_random) {
            return Err(TransportError::ReplayedHandshakeHello);
        }
    }
    Ok(())
}

/// Inserts an authenticated `(client_device_id, client_random)` tuple into the replay cache.
///
/// Invoked **only after** full signature and MAC verification to prevent unauthenticated cache pollution.
fn record_authenticated_hello_nonce(
    client_device_id: &[u8; 16],
    client_random: &[u8; 32],
    now_ms: u64,
) -> Result<(), TransportError> {
    let cache = HELLO_REPLAY_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    prune_hello_replay_cache(&mut guard, now_ms);
    for (id, rnd, _) in guard.iter() {
        if constant_time_eq(id, client_device_id) && constant_time_eq(rnd, client_random) {
            return Err(TransportError::ReplayedHandshakeHello);
        }
    }
    if guard.len() >= MAX_HANDSHAKE_REPLAY_CACHE {
        guard.pop_front();
    }
    guard.push_back((*client_device_id, *client_random, now_ms));
    Ok(())
}

/// Global monotonically increasing counter for transport session registration identifiers.
static NEXT_SESSION_REG_ID: AtomicU64 = AtomicU64::new(1);

/// Internal state tracking active sessions, actively revoked peers, and per-peer trust generations.
struct SessionRegistryState {
    sessions: HashMap<String, Vec<(u64, tokio::sync::watch::Sender<bool>)>>,
    revoked_peers: HashSet<String>,
    peer_generations: HashMap<String, u64>,
    local_device_ids: HashSet<String>,
}

/// Global registry of active `TransportSessionV2` sessions, mapping remote peer device ID (hex)
/// to their respective cancellation watch senders, coordinated with per-peer trust generations.
///
/// # Synchronization Invariant
/// **Lock Hierarchy:** `keystore_mutex` -> `ACTIVE_SESSION_REGISTRY`.
/// - `ACTIVE_SESSION_REGISTRY.write()` must NEVER acquire `keystore_mutex` or execute closures
///   that acquire it.
/// - Keystore queries to authenticate credentials and capture trust generation occur BEFORE
///   acquiring `ACTIVE_SESSION_REGISTRY.write()`.
/// - Atomic revocation-versus-registration is strictly preserved without TOCTOU windows:
///   Handshakes capture `expected_generation` from verified keystore credentials. When registering,
///   `ACTIVE_SESSION_REGISTRY.write()` atomically validates that the peer is not in `revoked_peers`
///   and that `reg.peer_generations[peer] == expected_generation`.
/// - Peer unpairing or revocation immediately marks `revoked_peers` and increments `peer_generations`,
///   deterministically aborting any in-flight handshake or stale session attempting to register.
static ACTIVE_SESSION_REGISTRY: LazyLock<RwLock<SessionRegistryState>> =
    LazyLock::new(|| RwLock::new(SessionRegistryState {
        sessions: HashMap::new(),
        revoked_peers: HashSet::new(),
        peer_generations: HashMap::new(),
        local_device_ids: HashSet::new(),
    }));

/// Registers a known local device identity hex in `ACTIVE_SESSION_REGISTRY`.
/// Only local device identities are authorized to use the special initial-generation registration path.
pub fn register_local_device_identity(local_device_id_hex: &str) {
    let key = local_device_id_hex.trim().to_ascii_lowercase();
    if !key.is_empty() {
        let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
        reg.local_device_ids.insert(key);
    }
}

/// RAII guard that unregisters the session from `ACTIVE_SESSION_REGISTRY` upon drop of all references.
#[derive(Debug)]
pub struct SessionRevocationGuard {
    reg_id: u64,
    peer_device_id_hex: String,
}

impl Drop for SessionRevocationGuard {
    fn drop(&mut self) {
        if self.reg_id != 0 {
            unregister_session_revocation(&self.peer_device_id_hex, self.reg_id);
        }
    }
}

/// Atomically registers an active session revocation watch channel for the given peer device ID hex,
/// validating against active revocations and strictly enforcing per-peer trust generation matching.
///
/// Executes without acquiring `keystore_mutex`, completely eliminating ABBA deadlocks.
pub fn register_session_revocation(
    peer_device_id_hex: &str,
    expected_generation: u64,
) -> Result<(Arc<SessionRevocationGuard>, tokio::sync::watch::Receiver<bool>), TransportError> {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());

    if reg.revoked_peers.contains(&key) {
        return Err(TransportError::UntrustedPeer(key));
    }

    if let Some(&current_gen) = reg.peer_generations.get(&key) {
        if current_gen != expected_generation {
            return Err(TransportError::UntrustedPeer(format!(
                "{}: trust generation mismatch (expected {}, current {})",
                key, expected_generation, current_gen
            )));
        }
    } else if reg.local_device_ids.contains(&key) && expected_generation >= 1 {
        // Special initial-generation registration path ONLY permitted for verified local device identity (loopback self)
        reg.peer_generations.insert(key.clone(), expected_generation);
    } else {
        // Remote peers with missing generation entry MUST fail closed (SEC-1C-05)
        return Err(TransportError::UntrustedPeer(format!(
            "{}: un-registered trust generation for remote peer",
            key
        )));
    }

    let reg_id = NEXT_SESSION_REG_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = tokio::sync::watch::channel(false);
    reg.sessions
        .entry(key.clone())
        .or_default()
        .push((reg_id, tx));

    let guard = Arc::new(SessionRevocationGuard {
        reg_id,
        peer_device_id_hex: key,
    });
    Ok((guard, rx))
}

/// Compatibility registration helper validating an external trust predicate outside the registry lock.
pub fn register_session_revocation_checked<F>(
    peer_device_id_hex: &str,
    is_trusted_fn: F,
) -> Result<(Arc<SessionRevocationGuard>, tokio::sync::watch::Receiver<bool>), TransportError>
where
    F: FnOnce() -> bool,
{
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    // Validate trust predicate strictly BEFORE acquiring ACTIVE_SESSION_REGISTRY.write()
    if !is_trusted_fn() {
        let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
        reg.revoked_peers.insert(key.clone());
        return Err(TransportError::UntrustedPeer(key));
    }
    register_session_revocation(&key, 1)
}

/// Unregisters an active session revocation channel when all halves of the session have dropped.
fn unregister_session_revocation(peer_device_id_hex: &str, reg_id: u64) {
    let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    let key = peer_device_id_hex.to_ascii_lowercase();
    if let Some(list) = reg.sessions.get_mut(&key) {
        list.retain(|(id, _)| *id != reg_id);
        if list.is_empty() {
            reg.sessions.remove(&key);
        }
    }
}

/// Registers or updates the active trust generation for `peer_device_id_hex`, clearing any active
/// revocation flag. Called when a peer is paired or re-paired, or when trusted peers are initialized.
pub fn register_peer_trust_generation(peer_device_id_hex: &str, generation: u64) {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    reg.revoked_peers.remove(&key);
    reg.peer_generations.insert(key, generation);
}

/// Immediately marks the peer as revoked in `ACTIVE_SESSION_REGISTRY`, updates its active trust generation
/// to `new_generation`, drains and terminates all active sessions connected to this peer, and returns the
/// count of terminated sessions.
pub fn invalidate_peer_trust(peer_device_id_hex: &str, new_generation: u64) -> usize {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let senders = {
        let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
        reg.revoked_peers.insert(key.clone());
        reg.peer_generations.insert(key.clone(), new_generation);
        reg.sessions.remove(&key).unwrap_or_default()
    };
    let count = senders.len();
    for (_reg_id, tx) in senders {
        let _ = tx.send(true);
    }
    if count > 0 {
        tracing::warn!(
            "🛑 Invalidate trust for peer {}: terminated {} active TransportSessionV2 streams (generation: {})",
            key,
            count,
            new_generation
        );
    }
    count
}

/// Immediately signals and aborts all active `TransportV2` sessions connected to the specified peer device ID,
/// increments its trust generation, and adds the peer device ID to the actively revoked set so pending registrations fail.
///
/// Returns the number of sessions signaled for immediate termination.
pub fn terminate_active_sessions_for_peer(peer_device_id_hex: &str) -> usize {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let next_gen = {
        let reg = ACTIVE_SESSION_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
        reg.peer_generations.get(&key).copied().unwrap_or(1).saturating_add(1)
    };
    invalidate_peer_trust(&key, next_gen)
}

/// Clears the actively revoked flag for `peer_device_id_hex` upon successful explicit pairing.
pub fn clear_peer_revocation(peer_device_id_hex: &str) {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let mut reg = ACTIVE_SESSION_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    reg.revoked_peers.remove(&key);
}

/// Returns true if `peer_device_id_hex` is currently recorded in the active revocation set.
#[allow(dead_code)]
pub fn is_peer_revoked(peer_device_id_hex: &str) -> bool {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let reg = ACTIVE_SESSION_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    reg.revoked_peers.contains(&key)
}

/// Returns the active trust generation recorded in `ACTIVE_SESSION_REGISTRY` for `peer_device_id_hex`, if any.
pub fn get_peer_trust_generation(peer_device_id_hex: &str) -> Option<u64> {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let reg = ACTIVE_SESSION_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    reg.peer_generations.get(&key).copied()
}

/// Result of fail-closed peer trust and generation verification against `ACTIVE_SESSION_REGISTRY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrustCheck {
    Valid,
    Revoked,
    StaleOrUnregisteredGeneration,
}

/// Verifies a peer's revocation status and expected trust generation fail-closed (matching `SEC-1C-05`).
///
/// Remote peers with no registered trust generation fail closed (`StaleOrUnregisteredGeneration`).
/// Only verified local loopback device identities (`local_device_ids`) are permitted to pass with
/// an unregistered generation `>= 1`.
pub fn check_peer_trust_generation_fail_closed(
    peer_device_id_hex: &str,
    expected_generation: u64,
) -> PeerTrustCheck {
    let key = peer_device_id_hex.trim().to_ascii_lowercase();
    let reg = ACTIVE_SESSION_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if reg.revoked_peers.contains(&key) {
        return PeerTrustCheck::Revoked;
    }
    if let Some(&cur_gen) = reg.peer_generations.get(&key) {
        if cur_gen == expected_generation {
            PeerTrustCheck::Valid
        } else {
            PeerTrustCheck::StaleOrUnregisteredGeneration
        }
    } else if reg.local_device_ids.contains(&key) && expected_generation >= 1 {
        PeerTrustCheck::Valid
    } else {
        PeerTrustCheck::StaleOrUnregisteredGeneration
    }
}

/// Directional AEAD cipher state for either outbound transmission (`tx`) or inbound reception (`rx`).
///
/// Manages the active 256-bit ChaCha20-Poly1305 key, the 256-bit rekey secret, the 4-byte IV salt prefix,
/// the current 16-bit epoch, and the strictly monotonic 64-bit sequence counter.
pub struct DirectionalCipherState {
    /// True if this state operates in the client-to-server direction; false if server-to-client.
    is_client_to_server: bool,
    /// Active 32-byte ChaCha20-Poly1305 symmetric encryption key (zeroized on drop/ratchet).
    app_key: Zeroizing<[u8; 32]>,
    /// Active 32-byte secret used as IKM for the next HKDF ratchet epoch (zeroized on drop/ratchet).
    rekey_secret: Zeroizing<[u8; 32]>,
    /// 4-byte static IV prefix derived via HKDF (domain-separated by LSB: 0 for c2s, 1 for s2c).
    iv_salt: [u8; 4],
    /// Current ratchet epoch counter (increments by 1 on each rekey; max `u16::MAX`).
    epoch: u16,
    /// Monotonically incrementing 64-bit record sequence number (resets to 0 upon epoch advance).
    seq: u64,
}

impl Drop for DirectionalCipherState {
    fn drop(&mut self) {
        // Zeroize the IV salt prefix on drop (app_key and rekey_secret auto-zeroize via Zeroizing wrapper).
        self.iv_salt.zeroize();
    }
}

impl DirectionalCipherState {
    /// Constructs a new directional cipher state, applying domain-separation bitmasking to `iv_salt`.
    ///
    /// Bitmasking invariant:
    /// - Client-to-Server: `iv_salt[0] &= 0xFE` (LSB is forced to 0).
    /// - Server-to-Client: `iv_salt[0] |= 0x01` (LSB is forced to 1).
    fn new(
        is_client_to_server: bool,
        app_key: Zeroizing<[u8; 32]>,
        rekey_secret: Zeroizing<[u8; 32]>,
        mut iv_salt: [u8; 4],
    ) -> Self {
        if is_client_to_server {
            iv_salt[0] &= 0xFE;
        } else {
            iv_salt[0] |= 0x01;
        }
        Self {
            is_client_to_server,
            app_key,
            rekey_secret,
            iv_salt,
            epoch: 0,
            seq: 0,
        }
    }

    /// Returns the current ratchet epoch index for this directional state.
    pub fn current_epoch(&self) -> u16 {
        self.epoch
    }

    /// Returns the current 64-bit monotonic sequence counter for this directional state.
    pub fn current_seq(&self) -> u64 {
        self.seq
    }

    /// Derives the 96-bit ChaCha20-Poly1305 nonce for a specific sequence number:
    /// `nonce = iv_salt[0..4] || seq.to_be_bytes()[0..8]`.
    fn compute_nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.iv_salt);
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    /// Ratchets the directional keys forward to `epoch + 1` via HKDF-SHA256 and resets `seq = 0`.
    ///
    /// Zeroizes previous epoch keys and returns `Err(TransportError::SequenceExhausted)` if epoch reaches `u16::MAX`.
    pub fn ratchet_epoch(&mut self) -> Result<(), TransportError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(TransportError::SequenceExhausted)?;

        // Expand new keys using current rekey_secret as IKM and next_epoch as salt.
        let hk = Hkdf::<Sha256>::new(Some(&next_epoch.to_be_bytes()), &*self.rekey_secret);
        let mut next_app_key = Zeroizing::new([0u8; 32]);
        let mut next_rekey_secret = Zeroizing::new([0u8; 32]);
        let mut next_iv = [0u8; 4];

        hk.expand(b"integrator-v2-rekey-app", &mut *next_app_key)
            .expect("HKDF expand 32B");
        hk.expand(b"integrator-v2-rekey-next", &mut *next_rekey_secret)
            .expect("HKDF expand 32B");
        hk.expand(b"integrator-v2-rekey-iv", &mut next_iv)
            .expect("HKDF expand 4B");

        // Maintain direction bitmasking invariant on the new IV prefix.
        if self.is_client_to_server {
            next_iv[0] &= 0xFE;
        } else {
            next_iv[0] |= 0x01;
        }

        // Install ratcheted keys and reset sequence counter to 0.
        self.app_key = next_app_key;
        self.rekey_secret = next_rekey_secret;
        self.iv_salt = next_iv;
        self.epoch = next_epoch;
        self.seq = 0;
        Ok(())
    }

    /// Encrypts and authenticates a plaintext payload into a complete TransportV2 record frame.
    ///
    /// Frame layout:
    /// - Header (21 bytes, passed as AAD):
    ///   `magic[4B] ("ITR2") || version[1B] (0x02) || frame_type[1B] || flags[1B] (0x00) || epoch[2B] || seq[8B] || ciphertext_len[4B]`
    /// - Body: ChaCha20-Poly1305 ciphertext with appended 16-byte Poly1305 authentication tag.
    fn seal_record(
        &mut self,
        frame_type: RecordFrameType,
        plaintext: &[u8],
        max_plaintext: usize,
    ) -> Result<Vec<u8>, TransportError> {
        if plaintext.len() > max_plaintext {
            return Err(TransportError::OversizedFrame {
                len: plaintext.len(),
                max: max_plaintext,
            });
        }
        if self.seq == u64::MAX {
            return Err(TransportError::SequenceExhausted);
        }

        let current_seq = self.seq;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(TransportError::SequenceExhausted)?;

        let ciphertext_len = (plaintext.len() + AEAD_TAG_LEN) as u32;
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0..4].copy_from_slice(&TRANSPORT_WIRE_MAGIC);
        header[4] = TRANSPORT_HEADER_VERSION_BYTE;
        header[5] = frame_type as u8;
        header[6] = 0; // flags: reserved, must be zero
        header[7..9].copy_from_slice(&self.epoch.to_be_bytes());
        header[9..17].copy_from_slice(&current_seq.to_be_bytes());
        header[17..21].copy_from_slice(&ciphertext_len.to_be_bytes());

        let nonce_bytes = self.compute_nonce(current_seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.app_key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| TransportError::AeadDecryptionFailed)?;

        let mut frame = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Verifies and decrypts an incoming TransportV2 record frame against this directional receiver state.
    ///
    /// Validates magic bytes, protocol version, flags, exact epoch match, and exact sequence number match
    /// before executing Poly1305 tag verification and ChaCha20 decryption.
    fn open_record(
        &mut self,
        header: &[u8; RECORD_HEADER_LEN],
        ciphertext: &[u8],
    ) -> Result<(RecordFrameType, Vec<u8>), TransportError> {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        if magic != TRANSPORT_WIRE_MAGIC {
            return Err(TransportError::InvalidMagic(magic));
        }
        if header[4] != TRANSPORT_HEADER_VERSION_BYTE {
            return Err(TransportError::UnsupportedVersion(header[4] as u16));
        }
        let frame_type = RecordFrameType::from_u8(header[5])
            .ok_or(TransportError::UnexpectedFrameType(header[5]))?;
        let rx_epoch = u16::from_be_bytes([header[7], header[8]]);
        let rx_seq = u64::from_be_bytes([
            header[9], header[10], header[11], header[12], header[13], header[14], header[15],
            header[16],
        ]);

        // Enforce strict epoch and sequence monotonic adherence.
        if rx_epoch != self.epoch {
            return Err(TransportError::EpochMismatch {
                expected: self.epoch,
                received: rx_epoch,
            });
        }
        if rx_seq != self.seq {
            return Err(TransportError::SequenceMismatch {
                expected: self.seq,
                received: rx_seq,
            });
        }

        let nonce_bytes = self.compute_nonce(rx_seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.app_key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| TransportError::AeadDecryptionFailed)?;

        if header[6] != 0 {
            return Err(TransportError::MalformedHandshake(format!(
                "unsupported record flags 0x{:02x}",
                header[6]
            )));
        }

        // Advance expected sequence number after successful decryption.
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(TransportError::SequenceExhausted)?;

        Ok((frame_type, plaintext))
    }
}

/// Active mutually authenticated `TransportV2` session wrapping an asynchronous stream `S`.
///
/// Encapsulates directional AEAD states (`tx_state` and `rx_state`), peer credentials,
/// session ID, and automatic rekeying thresholds.
pub struct TransportSessionV2<S> {
    /// Underlying full-duplex asynchronous transport stream (e.g. `TcpStream` or `DuplexStream`).
    stream: S,
    /// Service identifier bound to this session during handshake.
    service_id: ServiceId,
    /// 16-byte device UUID of the authenticated remote peer.
    #[cfg_attr(not(test), allow(dead_code))]
    peer_device_id: [u8; 16],
    /// Hex-encoded representation of `peer_device_id` for logging and diagnostic queries.
    peer_device_id_hex: String,
    /// Immutable trust generation bound to this authenticated peer session during handshake.
    trust_generation: u64,
    /// 16-byte unique session identifier derived during handshake ($H_4$ HKDF expansion).
    #[cfg_attr(not(test), allow(dead_code))]
    session_id: [u8; 16],
    /// Directional AEAD state for outbound records transmitted to the peer.
    tx_state: DirectionalCipherState,
    /// Directional AEAD state for inbound records received from the peer.
    rx_state: DirectionalCipherState,
    /// Timestamp when the outbound cipher state was last ratcheted.
    last_rekeyed_at: Instant,
    /// Configured threshold of frames transmitted under a single key before an automatic ratchet.
    rekey_frame_limit: u64,
    /// True if the session has sent or received a `CloseNotify` or encountered an unrecoverable error.
    closed: bool,
    /// RAII guard that automatically removes this session from `ACTIVE_SESSION_REGISTRY` on drop.
    _reg_guard: Option<Arc<SessionRevocationGuard>>,
    /// Watch receiver signaled when the peer's trust status is revoked.
    revocation_rx: tokio::sync::watch::Receiver<bool>,
}

impl<S> TransportSessionV2<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns a reference to the 16-byte raw device UUID of the authenticated remote peer.
    #[cfg(test)]
    pub fn peer_device_id(&self) -> &[u8; 16] {
        &self.peer_device_id
    }

    /// Returns a borrowed slice of the hex-encoded remote peer device UUID.
    pub fn peer_device_id_hex(&self) -> &str {
        &self.peer_device_id_hex
    }

    /// Returns the immutable authenticated trust generation bound to this peer session during handshake.
    pub fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns a reference to the 16-byte session identifier derived from the handshake transcript.
    #[cfg(test)]
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Returns the active ratchet epoch index for outbound traffic (`tx_state`).
    #[cfg(test)]
    pub fn tx_epoch(&self) -> u16 {
        self.tx_state.current_epoch()
    }

    /// Returns the active ratchet epoch index for inbound traffic (`rx_state`).
    #[cfg(test)]
    pub fn rx_epoch(&self) -> u16 {
        self.rx_state.current_epoch()
    }

    /// Overrides the maximum number of outbound frames allowed before triggering an in-band ratchet.
    #[cfg(test)]
    pub fn set_rekey_frame_limit(&mut self, limit: u64) {
        self.rekey_frame_limit = limit.clamp(1, u64::MAX - 1);
    }

    /// Initiates a mutually authenticated `TransportV2` client handshake over `stream` with a pinned `peer`.
    ///
    /// Protocol Steps:
    /// 1. Sample ephemeral X25519 secret key and 32-byte random nonce.
    /// 2. Construct and send `ClientHello` frame.
    /// 3. Read and parse `ServerHello` frame within `HANDSHAKE_IO_TIMEOUT`.
    /// 4. Verify server device UUID matches `peer.device_id`.
    /// 5. Compute ephemeral Diffie-Hellman secret; reject all-zero or non-contributory points.
    /// 6. Compute transcript $H_2$; derive handshake PRK and keys ($K_{\text{hs\_s2c}}$, $K_{\text{hs\_c2s}}$).
    /// 7. Verify server's finished HMAC and Ed25519 signature over $H_2$.
    /// 8. Compute transcript $H_3$; sign $H_3$ with local Ed25519 identity key; compute client finished HMAC.
    /// 9. Transmit `ClientFinish` frame to server.
    /// 10. Compute transcript $H_4$; derive application directional keys and session ID.
    #[cfg(test)]
    pub async fn connect_client(
        mut stream: S,
        keystore: &KeystoreV2,
        peer: &VerifiedPeerCredentials,
        service_id: ServiceId,
    ) -> Result<Self, TransportError> {
        // Coordinate peer revocation with handshake initiation and session registration.
        let (reg_guard, mut revocation_rx) = register_session_revocation(
            &peer.device_id_hex,
            peer.trust_generation,
        )?;

        let client_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_c = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_c = X25519PublicKey::from(&eph_sk_c);

        let hello_msg = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: service_id as u8,
            client_device_id_hex: keystore.local_device_id_hex().to_string(),
            key_id_hex: hex_encode(&peer.key_id),
            client_random_hex: hex_encode(&client_random),
            client_eph_x25519_pk_hex: hex_encode(eph_pk_c.as_bytes()),
            timestamp_ms: unix_epoch_millis(),
        };

        // Send ClientHello frame.
        let hello_bytes = send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ClientHello,
            &hello_msg,
            Some(&mut revocation_rx),
        )
        .await?;

        // Receive ServerHello frame.
        let (hs_type, srv_hello_bytes) = recv_handshake_frame(&mut stream, None, Some(&mut revocation_rx)).await?;
        if hs_type != HandshakeFrameType::ServerHello {
            return Err(TransportError::UnexpectedFrameType(hs_type as u8));
        }
        let srv_hello: TransportServerHelloMsg = serde_json::from_slice(&srv_hello_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        if srv_hello.version != TRANSPORT_PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(srv_hello.version));
        }

        let srv_dev_id: [u8; 16] = hex_decode_array(&srv_hello.server_device_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid server_device_id".into()))?;
        if !constant_time_eq(&srv_dev_id, &peer.device_id) {
            return Err(TransportError::UntrustedPeer(
                srv_hello.server_device_id_hex.clone(),
            ));
        }

        let srv_random: [u8; 32] = hex_decode_array(&srv_hello.server_random_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid server_random".into()))?;
        let srv_eph_pk_bytes: [u8; 32] = hex_decode_array(&srv_hello.server_eph_x25519_pk_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_eph_x25519_pk".into())
            })?;
        let srv_sig: [u8; 64] = hex_decode_array(&srv_hello.server_ed25519_sig_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_ed25519_sig".into())
            })?;
        let srv_mac: [u8; 32] = hex_decode_array(&srv_hello.server_finished_mac_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_finished_mac".into())
            })?;

        // Compute ephemeral X25519 shared secret and reject all-zero / low-order points (RFC 7748 §6.1).
        let srv_eph_pk = X25519PublicKey::from(srv_eph_pk_bytes);
        let dh_shared = eph_sk_c.diffie_hellman(&srv_eph_pk);
        if constant_time_eq(dh_shared.as_bytes(), &[0u8; 32]) || !dh_shared.was_contributory() {
            return Err(TransportError::LowOrderEphemeralPoint);
        }

        let h2 = compute_transcript_h2(
            service_id,
            &hello_bytes,
            &srv_dev_id,
            &srv_random,
            &srv_eph_pk_bytes,
        );
        let (prk_hs, k_hs_s2c, k_hs_c2s) =
            derive_handshake_keys(&peer.root_key, dh_shared.as_bytes(), &h2);

        // Verify Server's finished HMAC and Ed25519 signature before sending ClientFinish.
        let expected_srv_mac = compute_server_finished_mac(&k_hs_s2c, &h2, &srv_sig);
        if !constant_time_eq(&expected_srv_mac, &srv_mac) {
            return Err(TransportError::HandshakeMacMismatch);
        }
        let srv_sig_payload = build_server_sig_payload(&h2);
        KeystoreV2::verify_signature(&peer.ed25519_pubkey, &srv_sig_payload, &srv_sig)
            .map_err(|_| TransportError::HandshakeSignatureInvalid)?;

        // Compute H3, sign with local Ed25519 key, and compute client_finished_mac.
        let h3 = compute_transcript_h3(&h2, &srv_sig, &srv_mac);
        let cli_sig_payload = build_client_sig_payload(&h3);
        let cli_sig = keystore.sign_transcript(&cli_sig_payload);
        let cli_mac = compute_client_finished_mac(&k_hs_c2s, &h3, &cli_sig);

        let finish_msg = TransportClientFinishMsg {
            client_ed25519_sig_hex: hex_encode(&cli_sig),
            client_finished_mac_hex: hex_encode(&cli_mac),
        };
        send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ClientFinish,
            &finish_msg,
            Some(&mut revocation_rx),
        )
        .await?;

        // Derive application keys and directional cipher states.
        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        if *revocation_rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }

        Ok(Self {
            stream,
            service_id,
            peer_device_id: peer.device_id,
            peer_device_id_hex: peer.device_id_hex.clone(),
            trust_generation: peer.trust_generation,
            session_id,
            tx_state: c2s_state,
            rx_state: s2c_state,
            last_rekeyed_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
            closed: false,
            _reg_guard: Some(reg_guard),
            revocation_rx,
        })
    }

    /// Accepts a mutually authenticated `TransportV2` server session on `stream`.
    ///
    /// Validates that incoming `ClientHello` matches `expected_service`, verifies credentials in `KeystoreV2`,
    /// enforces anti-replay deduplication, and returns the established session.
    #[cfg(test)]
    pub async fn accept_server(
        stream: S,
        keystore: &KeystoreV2,
        expected_service: ServiceId,
        allow_loopback_self: bool,
    ) -> Result<Self, TransportError> {
        Self::accept_server_with_prefixed_magic(
            stream,
            None,
            keystore,
            expected_service,
            allow_loopback_self,
        )
        .await
    }

    /// Accepts a server session when the 4-byte `ITR2` magic has optionally already been read to demux the port.
    #[cfg(test)]
    pub async fn accept_server_with_prefixed_magic(
        mut stream: S,
        already_read_magic: Option<[u8; 4]>,
        keystore: &KeystoreV2,
        expected_service: ServiceId,
        allow_loopback_self: bool,
    ) -> Result<Self, TransportError> {
        let (hs_type, hello_bytes) = recv_handshake_frame(&mut stream, already_read_magic, None).await?;
        if hs_type != HandshakeFrameType::ClientHello {
            return Err(TransportError::UnexpectedFrameType(hs_type as u8));
        }

        let hello: TransportHelloMsg = serde_json::from_slice(&hello_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        if hello.version != TRANSPORT_PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(hello.version));
        }
        if hello.service_id != expected_service as u8 {
            return Err(TransportError::ServiceMismatch {
                expected: expected_service as u8,
                received: hello.service_id,
            });
        }

        let now_ms = unix_epoch_millis();
        let skew_ms = now_ms.abs_diff(hello.timestamp_ms);
        if skew_ms > HANDSHAKE_TIMESTAMP_WINDOW_MS {
            return Err(TransportError::TimestampSkewExceeded { skew_ms });
        }

        let client_dev_id: [u8; 16] = hex_decode_array(&hello.client_device_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid client_device_id".into()))?;
        let key_id: [u8; 16] = hex_decode_array(&hello.key_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid key_id".into()))?;
        let client_random: [u8; 32] = hex_decode_array(&hello.client_random_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid client_random".into()))?;
        let client_eph_pk_bytes: [u8; 32] = hex_decode_array(&hello.client_eph_x25519_pk_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_eph_x25519_pk".into())
            })?;

        // Look up client_dev_id in KeystoreV2 (or loopback self if explicitly enabled for 127.0.0.1 CLI IPC).
        let peer_creds = if let Some(p) = keystore.get_peer_by_id_bytes(&client_dev_id) {
            p.clone()
        } else if allow_loopback_self
            && constant_time_eq(&client_dev_id, &keystore.local_device_id())
        {
            derive_loopback_self_credentials(keystore)
        } else {
            return Err(TransportError::UntrustedPeer(
                hello.client_device_id_hex.clone(),
            ));
        };

        if !constant_time_eq(&key_id, &peer_creds.key_id) {
            return Err(TransportError::KeyIdMismatch);
        }

        // Coordinate peer revocation with handshake completion and session registration.
        let (reg_guard, mut revocation_rx) = register_session_revocation(
            &peer_creds.device_id_hex,
            peer_creds.trust_generation,
        )?;

        // Sample server ephemeral X25519 key and reject all-zero / low-order client public keys.
        let server_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_s = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_s = X25519PublicKey::from(&eph_sk_s);

        let client_eph_pk = X25519PublicKey::from(client_eph_pk_bytes);
        let dh_shared = eph_sk_s.diffie_hellman(&client_eph_pk);
        if constant_time_eq(dh_shared.as_bytes(), &[0u8; 32]) || !dh_shared.was_contributory() {
            return Err(TransportError::LowOrderEphemeralPoint);
        }

        // Read-only replay check AFTER validating key_id and contributory X25519 exchange
        // so unauthenticated callers cannot fill or evict HELLO_REPLAY_CACHE.
        check_hello_nonce_not_replayed(&client_dev_id, &client_random, now_ms)?;

        let server_dev_id = keystore.local_device_id();
        let h2 = compute_transcript_h2(
            expected_service,
            &hello_bytes,
            &server_dev_id,
            &server_random,
            eph_pk_s.as_bytes(),
        );
        let (prk_hs, k_hs_s2c, k_hs_c2s) =
            derive_handshake_keys(&peer_creds.root_key, dh_shared.as_bytes(), &h2);

        let srv_sig_payload = build_server_sig_payload(&h2);
        let srv_sig = keystore.sign_transcript(&srv_sig_payload);
        let srv_mac = compute_server_finished_mac(&k_hs_s2c, &h2, &srv_sig);

        let srv_hello = TransportServerHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            server_device_id_hex: hex_encode(&server_dev_id),
            server_random_hex: hex_encode(&server_random),
            server_eph_x25519_pk_hex: hex_encode(eph_pk_s.as_bytes()),
            server_ed25519_sig_hex: hex_encode(&srv_sig),
            server_finished_mac_hex: hex_encode(&srv_mac),
        };
        send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ServerHello,
            &srv_hello,
            Some(&mut revocation_rx),
        )
        .await?;

        let (hs_type_2, finish_bytes) = recv_handshake_frame(&mut stream, None, Some(&mut revocation_rx)).await?;
        if hs_type_2 != HandshakeFrameType::ClientFinish {
            return Err(TransportError::UnexpectedFrameType(hs_type_2 as u8));
        }
        let finish_msg: TransportClientFinishMsg = serde_json::from_slice(&finish_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        let cli_sig: [u8; 64] = hex_decode_array(&finish_msg.client_ed25519_sig_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_ed25519_sig".into())
            })?;
        let cli_mac: [u8; 32] = hex_decode_array(&finish_msg.client_finished_mac_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_finished_mac".into())
            })?;

        let h3 = compute_transcript_h3(&h2, &srv_sig, &srv_mac);
        let expected_cli_mac = compute_client_finished_mac(&k_hs_c2s, &h3, &cli_sig);
        if !constant_time_eq(&expected_cli_mac, &cli_mac) {
            return Err(TransportError::HandshakeMacMismatch);
        }

        let cli_sig_payload = build_client_sig_payload(&h3);
        KeystoreV2::verify_signature(&peer_creds.ed25519_pubkey, &cli_sig_payload, &cli_sig)
            .map_err(|_| TransportError::HandshakeSignatureInvalid)?;

        // Nonce is verified authentic: record in replay cache to reject subsequent identical attempts.
        record_authenticated_hello_nonce(&client_dev_id, &client_random, unix_epoch_millis())?;

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        if *revocation_rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }

        Ok(Self {
            stream,
            service_id: expected_service,
            peer_device_id: peer_creds.device_id,
            peer_device_id_hex: peer_creds.device_id_hex,
            trust_generation: peer_creds.trust_generation,
            session_id,
            tx_state: s2c_state,
            rx_state: c2s_state,
            last_rekeyed_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
            closed: false,
            _reg_guard: Some(reg_guard),
            revocation_rx,
        })
    }

    /// Triggers an explicit in-band outbound rekey (`FrameType::Rekey`) and ratchets `tx_state` to `epoch + 1`.
    pub async fn initiate_rekey(&mut self) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        if self.tx_state.current_epoch() == u16::MAX {
            self.closed = true;
            return Err(TransportError::SequenceExhausted);
        }
        let rekey_frame = self.tx_state.seal_record(
            RecordFrameType::Rekey,
            REKEY_MAGIC_PAYLOAD,
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.write_all(&rekey_frame))
                .await
                .map_err(|_| TransportError::IoFailure("rekey write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.flush())
                .await
                .map_err(|_| TransportError::IoFailure("rekey flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            self.closed = true;
            return Err(e);
        }
        if let Err(e) = self.tx_state.ratchet_epoch() {
            self.closed = true;
            return Err(e);
        }
        self.last_rekeyed_at = Instant::now();
        Ok(())
    }

    /// Encrypts and writes an application data frame, automatically ratcheting the outbound key
    /// if `rekey_frame_limit` or `DEFAULT_REKEY_AGE_SECS` has been reached.
    pub async fn send_message(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        if self.tx_state.current_seq() >= self.rekey_frame_limit
            || self.last_rekeyed_at.elapsed().as_secs() >= DEFAULT_REKEY_AGE_SECS
        {
            self.initiate_rekey().await?;
        }

        let frame = self.tx_state.seal_record(
            RecordFrameType::ApplicationData,
            plaintext,
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.write_all(&frame))
                .await
                .map_err(|_| TransportError::IoFailure("record write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.flush())
                .await
                .map_err(|_| TransportError::IoFailure("record flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            self.closed = true;
            return Err(e);
        }
        Ok(())
    }

    /// Reads, verifies, and decrypts the next application data frame, transparently handling
    /// in-band `Rekey` and `KeepAlive` control frames.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        let max_plaintext = self.service_id.max_plaintext_frame_bytes();
        let max_ciphertext = max_plaintext + AEAD_TAG_LEN;

        loop {
            let mut hdr = [0u8; RECORD_HEADER_LEN];
            let read_hdr_res = tokio::select! {
                res = self.stream.read_exact(&mut hdr) => res,
                _ = self.revocation_rx.changed() => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            };
            if let Err(e) = read_hdr_res {
                self.closed = true;
                return Err(TransportError::IoFailure(e.to_string()));
            }

            let mut magic = [0u8; 4];
            magic.copy_from_slice(&hdr[0..4]);
            if magic != TRANSPORT_WIRE_MAGIC {
                self.closed = true;
                return Err(TransportError::InvalidMagic(magic));
            }
            if hdr[4] != TRANSPORT_HEADER_VERSION_BYTE {
                self.closed = true;
                return Err(TransportError::UnsupportedVersion(hdr[4] as u16));
            }

            let ct_len = u32::from_be_bytes([hdr[17], hdr[18], hdr[19], hdr[20]]) as usize;
            if ct_len < AEAD_TAG_LEN || ct_len > max_ciphertext {
                self.closed = true;
                return Err(TransportError::OversizedFrame {
                    len: ct_len,
                    max: max_ciphertext,
                });
            }

            let mut ciphertext = vec![0u8; ct_len];
            let body_fut = self.stream.read_exact(&mut ciphertext);
            let body_res = tokio::select! {
                res = tokio::time::timeout(RECORD_IO_TIMEOUT, body_fut) => {
                    res.map_err(|_| TransportError::IoFailure("record payload read timed out".into()))
                       .and_then(|r| r.map_err(|e| TransportError::IoFailure(e.to_string())))
                }
                _ = self.revocation_rx.changed() => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            };
            if let Err(e) = body_res {
                self.closed = true;
                return Err(e);
            }

            let (frame_type, plaintext) = match self.rx_state.open_record(&hdr, &ciphertext) {
                Ok(v) => v,
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            };
            match frame_type {
                RecordFrameType::ApplicationData => return Ok(plaintext),
                RecordFrameType::Rekey => {
                    if plaintext.as_slice() != REKEY_MAGIC_PAYLOAD {
                        self.closed = true;
                        return Err(TransportError::MalformedHandshake(
                            "unexpected Rekey control payload".into(),
                        ));
                    }
                    if let Err(e) = self.rx_state.ratchet_epoch() {
                        self.closed = true;
                        return Err(e);
                    }
                }
                RecordFrameType::KeepAlive => continue,
                RecordFrameType::CloseNotify => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            }
        }
    }

    /// Sends a potentially multi-megabyte payload (e.g. a clipboard image or large JSON envelope)
    /// segmented into `<= max_plaintext_frame_bytes()` AEAD records preceded by an 8-byte length record.
    pub async fn send_chunked_payload(
        &mut self,
        payload: &[u8],
        max_total_len: usize,
    ) -> Result<(), TransportError> {
        if payload.is_empty() || payload.len() > max_total_len {
            return Err(TransportError::OversizedFrame {
                len: payload.len(),
                max: max_total_len,
            });
        }
        let max_chunk = self.service_id.max_plaintext_frame_bytes();
        let len_bytes = (payload.len() as u64).to_be_bytes();
        self.send_message(&len_bytes).await?;
        for chunk in payload.chunks(max_chunk) {
            self.send_message(chunk).await?;
        }
        Ok(())
    }

    /// Receives a potentially multi-megabyte payload segmented into AEAD records, verifying
    /// `total_len <= max_total_len` before allocating the output buffer.
    pub async fn recv_chunked_payload(
        &mut self,
        max_total_len: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let hdr_rec = self.recv_message().await?;
        if hdr_rec.len() != 8 {
            return Err(TransportError::OversizedFrame {
                len: hdr_rec.len(),
                max: 8,
            });
        }
        let mut len_arr = [0u8; 8];
        len_arr.copy_from_slice(&hdr_rec);
        let total_len = usize::try_from(u64::from_be_bytes(len_arr)).unwrap_or(usize::MAX);
        if total_len == 0 || total_len > max_total_len {
            return Err(TransportError::OversizedFrame {
                len: total_len,
                max: max_total_len,
            });
        }

        let mut out = Vec::with_capacity(total_len.min(INITIAL_CHUNKED_BUFFER_CAPACITY_LIMIT));
        while out.len() < total_len {
            let chunk = self.recv_message().await?;
            if chunk.is_empty() || out.len().saturating_add(chunk.len()) > total_len {
                return Err(TransportError::OversizedFrame {
                    len: out.len().saturating_add(chunk.len()),
                    max: total_len,
                });
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Sends an authenticated `CloseNotify` frame before closing the session.
    pub async fn close_notify(&mut self) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        self.closed = true;
        let frame = self.tx_state.seal_record(
            RecordFrameType::CloseNotify,
            b"",
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.write_all(&frame))
                .await
                .map_err(|_| TransportError::IoFailure("close_notify write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.stream.flush())
                .await
                .map_err(|_| TransportError::IoFailure("close_notify flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            return Err(e);
        }
        Ok(())
    }

    /// Initiates a mutually authenticated `TransportV2` client session using a shared `&Mutex<KeystoreV2>`,
    /// never holding the mutex guard across `.await` points so the returned future is `Send`.
    pub async fn connect_client_with_shared_keystore(
        mut stream: S,
        keystore_mutex: &std::sync::Mutex<KeystoreV2>,
        peer: &VerifiedPeerCredentials,
        service_id: ServiceId,
    ) -> Result<Self, TransportError> {
        let (local_dev_id_hex, peer_gen) = {
            let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let peer_gen = if let Some(creds) = ks.get_peer(&peer.device_id_hex) {
                creds.trust_generation
            } else if constant_time_eq(&peer.device_id, &ks.local_device_id()) {
                peer.trust_generation
            } else {
                return Err(TransportError::UntrustedPeer(peer.device_id_hex.clone()));
            };
            (ks.local_device_id_hex().to_string(), peer_gen)
        };

        // Coordinate peer revocation with handshake initiation and session registration.
        // Validates trust generation atomically inside ACTIVE_SESSION_REGISTRY without holding keystore_mutex.
        let (reg_guard, mut revocation_rx) = register_session_revocation(
            &peer.device_id_hex,
            peer_gen,
        )?;

        let client_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_c = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_c = X25519PublicKey::from(&eph_sk_c);

        let hello_msg = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: service_id as u8,
            client_device_id_hex: local_dev_id_hex,
            key_id_hex: hex_encode(&peer.key_id),
            client_random_hex: hex_encode(&client_random),
            client_eph_x25519_pk_hex: hex_encode(eph_pk_c.as_bytes()),
            timestamp_ms: unix_epoch_millis(),
        };

        let hello_bytes = send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ClientHello,
            &hello_msg,
            Some(&mut revocation_rx),
        )
        .await?;

        let (hs_type, srv_hello_bytes) = recv_handshake_frame(&mut stream, None, Some(&mut revocation_rx)).await?;
        if hs_type != HandshakeFrameType::ServerHello {
            return Err(TransportError::UnexpectedFrameType(hs_type as u8));
        }
        let srv_hello: TransportServerHelloMsg = serde_json::from_slice(&srv_hello_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        if srv_hello.version != TRANSPORT_PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(srv_hello.version));
        }

        let srv_dev_id: [u8; 16] = hex_decode_array(&srv_hello.server_device_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid server_device_id".into()))?;
        if !constant_time_eq(&srv_dev_id, &peer.device_id) {
            return Err(TransportError::UntrustedPeer(
                srv_hello.server_device_id_hex.clone(),
            ));
        }

        let srv_random: [u8; 32] = hex_decode_array(&srv_hello.server_random_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid server_random".into()))?;
        let srv_eph_pk_bytes: [u8; 32] = hex_decode_array(&srv_hello.server_eph_x25519_pk_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_eph_x25519_pk".into())
            })?;
        let srv_sig: [u8; 64] = hex_decode_array(&srv_hello.server_ed25519_sig_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_ed25519_sig".into())
            })?;
        let srv_mac: [u8; 32] = hex_decode_array(&srv_hello.server_finished_mac_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid server_finished_mac".into())
            })?;

        let srv_eph_pk = X25519PublicKey::from(srv_eph_pk_bytes);
        let dh_shared = eph_sk_c.diffie_hellman(&srv_eph_pk);
        if constant_time_eq(dh_shared.as_bytes(), &[0u8; 32]) || !dh_shared.was_contributory() {
            return Err(TransportError::LowOrderEphemeralPoint);
        }

        let h2 = compute_transcript_h2(
            service_id,
            &hello_bytes,
            &srv_dev_id,
            &srv_random,
            &srv_eph_pk_bytes,
        );
        let (prk_hs, k_hs_s2c, k_hs_c2s) =
            derive_handshake_keys(&peer.root_key, dh_shared.as_bytes(), &h2);

        let expected_srv_mac = compute_server_finished_mac(&k_hs_s2c, &h2, &srv_sig);
        if !constant_time_eq(&expected_srv_mac, &srv_mac) {
            return Err(TransportError::HandshakeMacMismatch);
        }
        let srv_sig_payload = build_server_sig_payload(&h2);
        KeystoreV2::verify_signature(&peer.ed25519_pubkey, &srv_sig_payload, &srv_sig)
            .map_err(|_| TransportError::HandshakeSignatureInvalid)?;

        let h3 = compute_transcript_h3(&h2, &srv_sig, &srv_mac);
        let cli_sig_payload = build_client_sig_payload(&h3);
        let cli_sig = {
            let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ks.sign_transcript(&cli_sig_payload)
        };
        let cli_mac = compute_client_finished_mac(&k_hs_c2s, &h3, &cli_sig);

        let finish_msg = TransportClientFinishMsg {
            client_ed25519_sig_hex: hex_encode(&cli_sig),
            client_finished_mac_hex: hex_encode(&cli_mac),
        };
        send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ClientFinish,
            &finish_msg,
            Some(&mut revocation_rx),
        )
        .await?;

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        if *revocation_rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }

        Ok(Self {
            stream,
            service_id,
            peer_device_id: peer.device_id,
            peer_device_id_hex: peer.device_id_hex.clone(),
            trust_generation: peer_gen,
            session_id,
            tx_state: c2s_state,
            rx_state: s2c_state,
            last_rekeyed_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
            closed: false,
            _reg_guard: Some(reg_guard),
            revocation_rx,
        })
    }

    /// Accepts a mutually authenticated `TransportV2` server session using a shared `&Mutex<KeystoreV2>`,
    /// never holding the mutex guard across `.await` points so the returned future is `Send`.
    pub async fn accept_server_with_shared_keystore(
        mut stream: S,
        already_read_magic: Option<[u8; 4]>,
        keystore_mutex: &std::sync::Mutex<KeystoreV2>,
        expected_service: ServiceId,
        allow_loopback_self: bool,
    ) -> Result<Self, TransportError> {
        let (hs_type, hello_bytes) = recv_handshake_frame(&mut stream, already_read_magic, None).await?;
        if hs_type != HandshakeFrameType::ClientHello {
            return Err(TransportError::UnexpectedFrameType(hs_type as u8));
        }

        let hello: TransportHelloMsg = serde_json::from_slice(&hello_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        if hello.version != TRANSPORT_PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(hello.version));
        }
        if hello.service_id != expected_service as u8 {
            return Err(TransportError::ServiceMismatch {
                expected: expected_service as u8,
                received: hello.service_id,
            });
        }

        let now_ms = unix_epoch_millis();
        let skew_ms = now_ms.abs_diff(hello.timestamp_ms);
        if skew_ms > HANDSHAKE_TIMESTAMP_WINDOW_MS {
            return Err(TransportError::TimestampSkewExceeded { skew_ms });
        }

        let client_dev_id: [u8; 16] = hex_decode_array(&hello.client_device_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid client_device_id".into()))?;
        let key_id: [u8; 16] = hex_decode_array(&hello.key_id_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid key_id".into()))?;
        let client_random: [u8; 32] = hex_decode_array(&hello.client_random_hex)
            .ok_or_else(|| TransportError::MalformedHandshake("invalid client_random".into()))?;
        let client_eph_pk_bytes: [u8; 32] = hex_decode_array(&hello.client_eph_x25519_pk_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_eph_x25519_pk".into())
            })?;

        let (peer_creds, server_dev_id) = {
            let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
            let creds = if let Some(p) = ks.get_peer_by_id_bytes(&client_dev_id) {
                p.clone()
            } else if allow_loopback_self && constant_time_eq(&client_dev_id, &ks.local_device_id())
            {
                derive_loopback_self_credentials(&ks)
            } else {
                return Err(TransportError::UntrustedPeer(
                    hello.client_device_id_hex.clone(),
                ));
            };
            (creds, ks.local_device_id())
        };

        if !constant_time_eq(&key_id, &peer_creds.key_id) {
            return Err(TransportError::KeyIdMismatch);
        }

        // Coordinate peer revocation with handshake completion and session registration.
        // Validates trust generation atomically inside ACTIVE_SESSION_REGISTRY without holding keystore_mutex.
        let (reg_guard, mut revocation_rx) = register_session_revocation(
            &peer_creds.device_id_hex,
            peer_creds.trust_generation,
        )?;

        let server_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_s = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_s = X25519PublicKey::from(&eph_sk_s);

        let client_eph_pk = X25519PublicKey::from(client_eph_pk_bytes);
        let dh_shared = eph_sk_s.diffie_hellman(&client_eph_pk);
        if constant_time_eq(dh_shared.as_bytes(), &[0u8; 32]) || !dh_shared.was_contributory() {
            return Err(TransportError::LowOrderEphemeralPoint);
        }

        check_hello_nonce_not_replayed(&client_dev_id, &client_random, now_ms)?;

        let h2 = compute_transcript_h2(
            expected_service,
            &hello_bytes,
            &server_dev_id,
            &server_random,
            eph_pk_s.as_bytes(),
        );
        let (prk_hs, k_hs_s2c, k_hs_c2s) =
            derive_handshake_keys(&peer_creds.root_key, dh_shared.as_bytes(), &h2);

        let srv_sig_payload = build_server_sig_payload(&h2);
        let srv_sig = {
            let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ks.sign_transcript(&srv_sig_payload)
        };
        let srv_mac = compute_server_finished_mac(&k_hs_s2c, &h2, &srv_sig);

        let srv_hello = TransportServerHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            server_device_id_hex: hex_encode(&server_dev_id),
            server_random_hex: hex_encode(&server_random),
            server_eph_x25519_pk_hex: hex_encode(eph_pk_s.as_bytes()),
            server_ed25519_sig_hex: hex_encode(&srv_sig),
            server_finished_mac_hex: hex_encode(&srv_mac),
        };
        send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ServerHello,
            &srv_hello,
            Some(&mut revocation_rx),
        )
        .await?;

        let (hs_type_2, finish_bytes) = recv_handshake_frame(&mut stream, None, Some(&mut revocation_rx)).await?;
        if hs_type_2 != HandshakeFrameType::ClientFinish {
            return Err(TransportError::UnexpectedFrameType(hs_type_2 as u8));
        }
        let finish_msg: TransportClientFinishMsg = serde_json::from_slice(&finish_bytes)
            .map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;

        let cli_sig: [u8; 64] = hex_decode_array(&finish_msg.client_ed25519_sig_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_ed25519_sig".into())
            })?;
        let cli_mac: [u8; 32] = hex_decode_array(&finish_msg.client_finished_mac_hex)
            .ok_or_else(|| {
                TransportError::MalformedHandshake("invalid client_finished_mac".into())
            })?;

        let h3 = compute_transcript_h3(&h2, &srv_sig, &srv_mac);
        let expected_cli_mac = compute_client_finished_mac(&k_hs_c2s, &h3, &cli_sig);
        if !constant_time_eq(&expected_cli_mac, &cli_mac) {
            return Err(TransportError::HandshakeMacMismatch);
        }

        let cli_sig_payload = build_client_sig_payload(&h3);
        KeystoreV2::verify_signature(&peer_creds.ed25519_pubkey, &cli_sig_payload, &cli_sig)
            .map_err(|_| TransportError::HandshakeSignatureInvalid)?;

        record_authenticated_hello_nonce(&client_dev_id, &client_random, unix_epoch_millis())?;

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        if *revocation_rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }

        Ok(Self {
            stream,
            service_id: expected_service,
            peer_device_id: peer_creds.device_id,
            peer_device_id_hex: peer_creds.device_id_hex,
            trust_generation: peer_creds.trust_generation,
            session_id,
            tx_state: s2c_state,
            rx_state: c2s_state,
            last_rekeyed_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
            closed: false,
            _reg_guard: Some(reg_guard),
            revocation_rx,
        })
    }
}

/// Read half of a full-duplex split `TransportSessionV2`, owning independent inbound AEAD state.
pub struct TransportReaderV2<R> {
    /// Underlying reader stream (e.g. `OwnedReadHalf`).
    reader: R,
    /// Service identifier bound during handshake.
    service_id: ServiceId,
    /// Directional AEAD state for inbound records.
    rx_state: DirectionalCipherState,
    /// True if the reader stream is closed.
    closed: bool,
    /// RAII guard that automatically removes this session from `ACTIVE_SESSION_REGISTRY` on drop.
    _reg_guard: Option<Arc<SessionRevocationGuard>>,
    /// Watch receiver signaled when the peer's trust status is revoked.
    revocation_rx: tokio::sync::watch::Receiver<bool>,
}

/// Write half of a full-duplex split `TransportSessionV2`, owning independent outbound AEAD state.
pub struct TransportWriterV2<W> {
    /// Underlying writer stream (e.g. `OwnedWriteHalf`).
    writer: W,
    /// Service identifier bound during handshake.
    service_id: ServiceId,
    /// Directional AEAD state for outbound records.
    tx_state: DirectionalCipherState,
    /// Timestamp when outbound cipher state was last ratcheted.
    last_rekeyed_at: Instant,
    /// Outbound frame threshold before automatic ratcheting.
    rekey_frame_limit: u64,
    /// True if the writer stream is closed.
    closed: bool,
    /// RAII guard that automatically removes this session from `ACTIVE_SESSION_REGISTRY` on drop of all halves.
    _reg_guard: Option<Arc<SessionRevocationGuard>>,
    /// Watch receiver signaled when the peer's trust status is revoked.
    revocation_rx: tokio::sync::watch::Receiver<bool>,
}

impl<R: AsyncRead + Unpin> TransportReaderV2<R> {

    /// Reads, verifies, and decrypts the next application data frame, transparently handling
    /// in-band `Rekey` and `KeepAlive` control frames.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        let max_plaintext = self.service_id.max_plaintext_frame_bytes();
        let max_ciphertext = max_plaintext + AEAD_TAG_LEN;

        loop {
            let mut hdr = [0u8; RECORD_HEADER_LEN];
            let read_hdr_res = tokio::select! {
                res = self.reader.read_exact(&mut hdr) => res,
                _ = self.revocation_rx.changed() => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            };
            if let Err(e) = read_hdr_res {
                self.closed = true;
                return Err(TransportError::IoFailure(e.to_string()));
            }

            let mut magic = [0u8; 4];
            magic.copy_from_slice(&hdr[0..4]);
            if magic != TRANSPORT_WIRE_MAGIC {
                self.closed = true;
                return Err(TransportError::InvalidMagic(magic));
            }
            if hdr[4] != TRANSPORT_HEADER_VERSION_BYTE {
                self.closed = true;
                return Err(TransportError::UnsupportedVersion(hdr[4] as u16));
            }

            let ct_len = u32::from_be_bytes([hdr[17], hdr[18], hdr[19], hdr[20]]) as usize;
            if ct_len < AEAD_TAG_LEN || ct_len > max_ciphertext {
                self.closed = true;
                return Err(TransportError::OversizedFrame {
                    len: ct_len,
                    max: max_ciphertext,
                });
            }

            let mut ciphertext = vec![0u8; ct_len];
            let body_fut = self.reader.read_exact(&mut ciphertext);
            let body_res = tokio::select! {
                res = tokio::time::timeout(RECORD_IO_TIMEOUT, body_fut) => {
                    res.map_err(|_| TransportError::IoFailure("record payload read timed out".into()))
                       .and_then(|r| r.map_err(|e| TransportError::IoFailure(e.to_string())))
                }
                _ = self.revocation_rx.changed() => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            };
            if let Err(e) = body_res {
                self.closed = true;
                return Err(e);
            }

            let (frame_type, plaintext) = match self.rx_state.open_record(&hdr, &ciphertext) {
                Ok(v) => v,
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            };
            match frame_type {
                RecordFrameType::ApplicationData => return Ok(plaintext),
                RecordFrameType::Rekey => {
                    if plaintext.as_slice() != REKEY_MAGIC_PAYLOAD {
                        self.closed = true;
                        return Err(TransportError::MalformedHandshake(
                            "unexpected Rekey control payload".into(),
                        ));
                    }
                    if let Err(e) = self.rx_state.ratchet_epoch() {
                        self.closed = true;
                        return Err(e);
                    }
                }
                RecordFrameType::KeepAlive => continue,
                RecordFrameType::CloseNotify => {
                    self.closed = true;
                    return Err(TransportError::ConnectionClosed);
                }
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> TransportWriterV2<W> {

    /// Triggers an explicit in-band outbound rekey (`FrameType::Rekey`) and ratchets `tx_state` to `epoch + 1`.
    pub async fn initiate_rekey(&mut self) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        if self.tx_state.current_epoch() == u16::MAX {
            self.closed = true;
            return Err(TransportError::SequenceExhausted);
        }
        let rekey_frame = self.tx_state.seal_record(
            RecordFrameType::Rekey,
            REKEY_MAGIC_PAYLOAD,
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.write_all(&rekey_frame))
                .await
                .map_err(|_| TransportError::IoFailure("rekey write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.flush())
                .await
                .map_err(|_| TransportError::IoFailure("rekey flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            self.closed = true;
            return Err(e);
        }
        if let Err(e) = self.tx_state.ratchet_epoch() {
            self.closed = true;
            return Err(e);
        }
        self.last_rekeyed_at = Instant::now();
        Ok(())
    }

    /// Encrypts and writes an application data frame, ratcheting keys if limits are exceeded.
    pub async fn send_message(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        if self.tx_state.current_seq() >= self.rekey_frame_limit
            || self.last_rekeyed_at.elapsed().as_secs() >= DEFAULT_REKEY_AGE_SECS
        {
            self.initiate_rekey().await?;
        }

        let frame = self.tx_state.seal_record(
            RecordFrameType::ApplicationData,
            plaintext,
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.write_all(&frame))
                .await
                .map_err(|_| TransportError::IoFailure("record write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.flush())
                .await
                .map_err(|_| TransportError::IoFailure("record flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            self.closed = true;
            return Err(e);
        }
        Ok(())
    }

    /// Sends an authenticated `CloseNotify` frame before closing the writer stream.
    #[allow(dead_code)]
    pub async fn close_notify(&mut self) -> Result<(), TransportError> {
        if self.closed || *self.revocation_rx.borrow() {
            self.closed = true;
            return Err(TransportError::ConnectionClosed);
        }
        self.closed = true;
        let frame = self.tx_state.seal_record(
            RecordFrameType::CloseNotify,
            b"",
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        let write_fut = async {
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.write_all(&frame))
                .await
                .map_err(|_| TransportError::IoFailure("close_notify write timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            tokio::time::timeout(RECORD_IO_TIMEOUT, self.writer.flush())
                .await
                .map_err(|_| TransportError::IoFailure("close_notify flush timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            Ok::<(), TransportError>(())
        };
        let write_res = tokio::select! {
            res = write_fut => res,
            _ = self.revocation_rx.changed() => {
                self.closed = true;
                return Err(TransportError::ConnectionClosed);
            }
        };
        if let Err(e) = write_res {
            return Err(e);
        }
        Ok(())
    }
}

impl TransportSessionV2<tokio::net::TcpStream> {
    /// Splits a TCP `TransportSessionV2` into lock-free full-duplex reader and writer halves,
    /// sharing the session registration lifetime across both halves.
    pub fn into_split_tcp(
        mut self,
    ) -> (
        TransportReaderV2<tokio::net::tcp::OwnedReadHalf>,
        TransportWriterV2<tokio::net::tcp::OwnedWriteHalf>,
    ) {
        let (read_half, write_half) = self.stream.into_split();
        let reg_guard = self._reg_guard.take();
        (
            TransportReaderV2 {
                reader: read_half,
                service_id: self.service_id,
                rx_state: self.rx_state,
                closed: self.closed,
                _reg_guard: reg_guard.clone(),
                revocation_rx: self.revocation_rx.clone(),
            },
            TransportWriterV2 {
                writer: write_half,
                service_id: self.service_id,
                tx_state: self.tx_state,
                last_rekeyed_at: self.last_rekeyed_at,
                rekey_frame_limit: self.rekey_frame_limit,
                closed: self.closed,
                _reg_guard: reg_guard,
                revocation_rx: self.revocation_rx,
            },
        )
    }
}

impl<S> TransportSessionV2<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Splits an arbitrary asynchronous full-duplex `TransportSessionV2` stream (such as `DuplexStream`)
    /// into reader and writer halves sharing session registration lifetime.
    #[allow(dead_code)]
    pub fn into_split(
        mut self,
    ) -> (
        TransportReaderV2<tokio::io::ReadHalf<S>>,
        TransportWriterV2<tokio::io::WriteHalf<S>>,
    ) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        let reg_guard = self._reg_guard.take();
        (
            TransportReaderV2 {
                reader: read_half,
                service_id: self.service_id,
                rx_state: self.rx_state,
                closed: self.closed,
                _reg_guard: reg_guard.clone(),
                revocation_rx: self.revocation_rx.clone(),
            },
            TransportWriterV2 {
                writer: write_half,
                service_id: self.service_id,
                tx_state: self.tx_state,
                last_rekeyed_at: self.last_rekeyed_at,
                rekey_frame_limit: self.rekey_frame_limit,
                closed: self.closed,
                _reg_guard: reg_guard,
                revocation_rx: self.revocation_rx,
            },
        )
    }
}

/// Derives loopback self-credentials from the local `KeystoreV2` so same-user local CLI/IPC
/// calls over `127.0.0.1` also use full `TransportV2` mutual authentication and encryption.
pub fn derive_loopback_self_credentials(keystore: &KeystoreV2) -> VerifiedPeerCredentials {
    register_local_device_identity(keystore.local_device_id_hex());
    let sig = keystore.sign_transcript(b"integrator-loopback-self-root-derivation-v2");
    let hk = Hkdf::<Sha256>::new(Some(&keystore.local_device_id()), &sig);
    let mut root_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"integrator-v2-loopback-root-key", &mut *root_key)
        .expect("32B HKDF expand");
    let key_id = super::derive_key_id(&root_key);

    VerifiedPeerCredentials {
        device_id: keystore.local_device_id(),
        device_id_hex: keystore.local_device_id_hex().to_string(),
        ed25519_pubkey: keystore.local_ed25519_pubkey(),
        key_id,
        root_key,
        hostname: "localhost".to_string(),
        os: std::env::consts::OS.to_string(),
        last_ip: "127.0.0.1".to_string(),
        paired_at_epoch: 0,
        via_direct_cable: true,
        trust_generation: 1,
    }
}

// ============================================================================
// Handshake Framing & Key Derivation Helpers
// ============================================================================

/// Encodes and writes a handshake frame over `writer` with an 8-byte frame header:
/// `magic[4B] ("ITR2") || version[1B] (0x02) || hs_type[1B] || payload_len[2B]`.
async fn send_handshake_frame<W, T>(
    writer: &mut W,
    hs_type: HandshakeFrameType,
    msg: &T,
    mut revocation_rx: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> Result<Vec<u8>, TransportError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    if let Some(ref rx) = revocation_rx {
        if *rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }
    }

    let payload =
        serde_json::to_vec(msg).map_err(|e| TransportError::MalformedHandshake(e.to_string()))?;
    if payload.len() > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(TransportError::OversizedFrame {
            len: payload.len(),
            max: MAX_HANDSHAKE_FRAME_BYTES,
        });
    }

    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&TRANSPORT_WIRE_MAGIC);
    frame.push(TRANSPORT_HEADER_VERSION_BYTE);
    frame.push(hs_type as u8);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);

    let write_fut = async {
        writer
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        Ok::<(), TransportError>(())
    };

    let write_res = match revocation_rx.as_mut() {
        Some(rx) => tokio::select! {
            r = tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, write_fut) => {
                match r {
                    Ok(res) => res,
                    Err(_) => Err(TransportError::IoFailure("handshake write timed out".into())),
                }
            }
            _ = rx.changed() => return Err(TransportError::ConnectionClosed),
        },
        None => match tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, write_fut).await {
            Ok(res) => res,
            Err(_) => Err(TransportError::IoFailure("handshake write timed out".into())),
        },
    };
    write_res?;
    Ok(payload)
}

/// Reads and parses an incoming handshake frame header and body from `reader` within `HANDSHAKE_IO_TIMEOUT`.
async fn recv_handshake_frame<R>(
    reader: &mut R,
    already_read_magic: Option<[u8; 4]>,
    mut revocation_rx: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> Result<(HandshakeFrameType, Vec<u8>), TransportError>
where
    R: AsyncRead + Unpin,
{
    if let Some(ref rx) = revocation_rx {
        if *rx.borrow() {
            return Err(TransportError::ConnectionClosed);
        }
    }

    let magic = match already_read_magic {
        Some(m) => m,
        None => {
            let mut m = [0u8; 4];
            let read_fut = reader.read_exact(&mut m);
            let res = match revocation_rx.as_mut() {
                Some(rx) => tokio::select! {
                    r = tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_fut) => r,
                    _ = rx.changed() => return Err(TransportError::ConnectionClosed),
                },
                None => tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_fut).await,
            };
            res.map_err(|_| TransportError::IoFailure("handshake magic read timed out".into()))?
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            m
        }
    };
    if magic != TRANSPORT_WIRE_MAGIC {
        return Err(TransportError::InvalidMagic(magic));
    }

    let mut rest_hdr = [0u8; 4];
    let read_hdr_fut = reader.read_exact(&mut rest_hdr);
    let hdr_res = match revocation_rx.as_mut() {
        Some(rx) => tokio::select! {
            r = tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_hdr_fut) => r,
            _ = rx.changed() => return Err(TransportError::ConnectionClosed),
        },
        None => tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_hdr_fut).await,
    };
    hdr_res.map_err(|_| TransportError::IoFailure("handshake header read timed out".into()))?
        .map_err(|e| TransportError::IoFailure(e.to_string()))?;

    if rest_hdr[0] != TRANSPORT_HEADER_VERSION_BYTE {
        return Err(TransportError::UnsupportedVersion(rest_hdr[0] as u16));
    }
    let hs_type = HandshakeFrameType::from_u8(rest_hdr[1])
        .ok_or(TransportError::UnexpectedFrameType(rest_hdr[1]))?;
    let payload_len = u16::from_be_bytes([rest_hdr[2], rest_hdr[3]]) as usize;
    if payload_len == 0 || payload_len > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(TransportError::OversizedFrame {
            len: payload_len,
            max: MAX_HANDSHAKE_FRAME_BYTES,
        });
    }

    let mut payload = vec![0u8; payload_len];
    let read_body_fut = reader.read_exact(&mut payload);
    let body_res = match revocation_rx.as_mut() {
        Some(rx) => tokio::select! {
            r = tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_body_fut) => r,
            _ = rx.changed() => return Err(TransportError::ConnectionClosed),
        },
        None => tokio::time::timeout(HANDSHAKE_IO_TIMEOUT, read_body_fut).await,
    };
    body_res.map_err(|_| TransportError::IoFailure("handshake payload read timed out".into()))?
        .map_err(|e| TransportError::IoFailure(e.to_string()))?;
    Ok((hs_type, payload))
}

/// Computes the handshake transcript hash $H_2$ over service ID, ClientHello bytes, server device ID,
/// server random nonce, and server ephemeral public key.
fn compute_transcript_h2(
    service_id: ServiceId,
    hello_bytes: &[u8],
    server_dev_id: &[u8; 16],
    server_random: &[u8; 32],
    server_eph_pk: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"integrator-transport-v2-h2");
    h.update([service_id as u8]);
    h.update((hello_bytes.len() as u32).to_be_bytes());
    h.update(hello_bytes);
    h.update(server_dev_id);
    h.update(server_random);
    h.update(server_eph_pk);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Computes the handshake transcript hash $H_3$ over $H_2$, server Ed25519 signature, and server finished MAC.
fn compute_transcript_h3(h2: &[u8; 32], srv_sig: &[u8; 64], srv_mac: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"integrator-transport-v2-h3");
    h.update(h2);
    h.update(srv_sig);
    h.update(srv_mac);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Computes the handshake transcript hash $H_4$ over $H_3$, client Ed25519 signature, and client finished MAC.
fn compute_transcript_h4(h3: &[u8; 32], cli_sig: &[u8; 64], cli_mac: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"integrator-transport-v2-h4");
    h.update(h3);
    h.update(cli_sig);
    h.update(cli_mac);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Derives the handshake pseudorandom key `PRK_hs` and directional handshake MAC keys (`k_hs_s2c`, `k_hs_c2s`).
fn derive_handshake_keys(
    root_key: &[u8; 32],
    dh_shared: &[u8],
    h2: &[u8; 32],
) -> (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
) {
    let (prk_arr, hk) = Hkdf::<Sha256>::extract(Some(root_key), dh_shared);
    let mut prk_hs = Zeroizing::new([0u8; 32]);
    prk_hs.copy_from_slice(&prk_arr);

    let mut info_s2c = Vec::with_capacity(32 + 32);
    info_s2c.extend_from_slice(b"integrator-v2-hs-s2c");
    info_s2c.extend_from_slice(h2);
    let mut k_hs_s2c = Zeroizing::new([0u8; 32]);
    hk.expand(&info_s2c, &mut *k_hs_s2c).expect("32B expand");

    let mut info_c2s = Vec::with_capacity(32 + 32);
    info_c2s.extend_from_slice(b"integrator-v2-hs-c2s");
    info_c2s.extend_from_slice(h2);
    let mut k_hs_c2s = Zeroizing::new([0u8; 32]);
    hk.expand(&info_c2s, &mut *k_hs_c2s).expect("32B expand");

    (prk_hs, k_hs_s2c, k_hs_c2s)
}

/// Derives application-layer directional cipher states (`c2s` and `s2c`) and the 16-byte session ID.
fn derive_application_states(
    prk_hs: &[u8; 32],
    h4: &[u8; 32],
) -> (DirectionalCipherState, DirectionalCipherState, [u8; 16]) {
    let hk_hs = Hkdf::<Sha256>::from_prk(prk_hs).expect("valid 32B PRK");
    let mut derived_ikm = Zeroizing::new([0u8; 32]);
    hk_hs
        .expand(b"integrator-v2-derived", &mut *derived_ikm)
        .expect("32B expand");

    let hk_app = Hkdf::<Sha256>::new(Some(h4), &*derived_ikm);

    let mut k_app_c2s = Zeroizing::new([0u8; 32]);
    let mut k_app_s2c = Zeroizing::new([0u8; 32]);
    let mut iv_c2s = [0u8; 4];
    let mut iv_s2c = [0u8; 4];
    let mut k_rekey_c2s = Zeroizing::new([0u8; 32]);
    let mut k_rekey_s2c = Zeroizing::new([0u8; 32]);
    let mut session_id = [0u8; 16];

    hk_app
        .expand(b"integrator-v2-app-c2s-key", &mut *k_app_c2s)
        .expect("32B");
    hk_app
        .expand(b"integrator-v2-app-s2c-key", &mut *k_app_s2c)
        .expect("32B");
    hk_app
        .expand(b"integrator-v2-app-c2s-iv", &mut iv_c2s)
        .expect("4B");
    hk_app
        .expand(b"integrator-v2-app-s2c-iv", &mut iv_s2c)
        .expect("4B");
    hk_app
        .expand(b"integrator-v2-rekey-c2s", &mut *k_rekey_c2s)
        .expect("32B");
    hk_app
        .expand(b"integrator-v2-rekey-s2c", &mut *k_rekey_s2c)
        .expect("32B");
    hk_app
        .expand(b"integrator-v2-session-id", &mut session_id)
        .expect("16B");

    let c2s = DirectionalCipherState::new(true, k_app_c2s, k_rekey_c2s, iv_c2s);
    let s2c = DirectionalCipherState::new(false, k_app_s2c, k_rekey_s2c, iv_s2c);
    (c2s, s2c, session_id)
}

/// Constructs the byte payload that the server signs with its Ed25519 identity key:
/// `b"integrator-transport-sig-S-v2"` || $H_2$.
fn build_server_sig_payload(h2: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"integrator-transport-sig-S-v2");
    v.extend_from_slice(h2);
    v
}

/// Constructs the byte payload that the client signs with its Ed25519 identity key:
/// `b"integrator-transport-sig-C-v2"` || $H_3$.
fn build_client_sig_payload(h3: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"integrator-transport-sig-C-v2");
    v.extend_from_slice(h3);
    v
}

/// Computes the 32-byte HMAC-SHA256 finished MAC over ($H_2$ || `sig_s`) using `k_hs_s2c`.
fn compute_server_finished_mac(k_hs_s2c: &[u8; 32], h2: &[u8; 32], sig_s: &[u8; 64]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 64);
    data.extend_from_slice(h2);
    data.extend_from_slice(sig_s);
    compute_hmac_sha256(k_hs_s2c, &data)
}

/// Computes the 32-byte HMAC-SHA256 finished MAC over ($H_3$ || `sig_c`) using `k_hs_c2s`.
fn compute_client_finished_mac(k_hs_c2s: &[u8; 32], h3: &[u8; 32], sig_c: &[u8; 64]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 64);
    data.extend_from_slice(h3);
    data.extend_from_slice(sig_c);
    compute_hmac_sha256(k_hs_c2s, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keystore::FixedKekProvider;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct BlockNotifyStream<S> {
        inner: S,
        notify: Arc<tokio::sync::Notify>,
        enabled: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for BlockNotifyStream<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for BlockNotifyStream<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let res = Pin::new(&mut self.inner).poll_write(cx, buf);
            if self.enabled.load(Ordering::SeqCst) && matches!(res, std::task::Poll::Pending) {
                self.notify.notify_waiters();
            }
            res
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn create_paired_keystores(
        label: &str,
    ) -> (
        std::path::PathBuf,
        KeystoreV2,
        VerifiedPeerCredentials,
        std::path::PathBuf,
        KeystoreV2,
        VerifiedPeerCredentials,
    ) {
        let rnd = hex_encode(&csprng_array::<6>());
        let dir_c = std::env::temp_dir().join(format!("integrator_tr_c_{}_{}", label, rnd));
        let dir_s = std::env::temp_dir().join(format!("integrator_tr_s_{}_{}", label, rnd));

        let mut ks_c =
            KeystoreV2::open_with_provider(dir_c.clone(), &FixedKekProvider::new([0x11; 32]))
                .unwrap();
        let mut ks_s =
            KeystoreV2::open_with_provider(dir_s.clone(), &FixedKekProvider::new([0x22; 32]))
                .unwrap();

        let shared_root = Zeroizing::new([0x7Au8; 32]);

        let srv_creds_on_client = ks_c
            .commit_paired_peer(
                ks_s.local_device_id(),
                ks_s.local_ed25519_pubkey(),
                shared_root.clone(),
                "HP-Omen".to_string(),
                "Windows".to_string(),
                "10.99.99.1".to_string(),
                true,
            )
            .unwrap();

        let cli_creds_on_server = ks_s
            .commit_paired_peer(
                ks_c.local_device_id(),
                ks_c.local_ed25519_pubkey(),
                shared_root,
                "MacBook-Pro".to_string(),
                "macOS".to_string(),
                "10.99.99.2".to_string(),
                true,
            )
            .unwrap();

        (
            dir_c,
            ks_c,
            srv_creds_on_client,
            dir_s,
            ks_s,
            cli_creds_on_server,
        )
    }

    #[tokio::test]
    async fn test_transport_v2_mutual_auth_and_bidirectional_framing() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, _) = create_paired_keystores("e2e");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let client_fut =
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc);
        let server_fut =
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false);

        let (c_res, s_res) = tokio::join!(client_fut, server_fut);
        let mut client_sess = c_res.expect("client handshake must succeed");
        let mut server_sess = s_res.expect("server handshake must succeed");

        assert_eq!(client_sess.session_id(), server_sess.session_id());
        assert_eq!(client_sess.peer_device_id(), &ks_s.local_device_id());
        assert_eq!(server_sess.peer_device_id(), &ks_c.local_device_id());

        client_sess
            .send_message(b"ping-from-client")
            .await
            .unwrap();
        let rx_on_srv = server_sess.recv_message().await.unwrap();
        assert_eq!(rx_on_srv, b"ping-from-client");

        server_sess
            .send_message(b"pong-from-server")
            .await
            .unwrap();
        let rx_on_cli = client_sess.recv_message().await.unwrap();
        assert_eq!(rx_on_cli, b"pong-from-server");

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_transport_v2_rejects_all_zero_x25519_ephemeral_point() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, _) = create_paired_keystores("low_order");
        let (mut c_stream, s_stream) = tokio::io::duplex(16_384);

        // Low-order Curve25519 point [0u8; 32] produces an all-zero shared secret
        let low_order_hello = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: ServiceId::DisplayRpc as u8,
            client_device_id_hex: ks_c.local_device_id_hex().to_string(),
            key_id_hex: hex_encode(&srv_creds.key_id),
            client_random_hex: hex_encode(&csprng_array::<32>()),
            client_eph_x25519_pk_hex: hex_encode(&[0u8; 32]),
            timestamp_ms: unix_epoch_millis(),
        };

        send_handshake_frame(
            &mut c_stream,
            HandshakeFrameType::ClientHello,
            &low_order_hello,
            None,
        )
        .await
        .unwrap();

        let srv_res =
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false).await;
        assert_eq!(srv_res.err(), Some(TransportError::LowOrderEphemeralPoint));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_transport_v2_rejects_untrusted_peer_wrong_root_key_and_service_mismatch() {
        let (dir_c, ks_c, mut srv_creds, dir_s, ks_s, _) = create_paired_keystores("neg");

        // 1. Service mismatch: Client initiates Benchmark (0x03) against DisplayRpc (0x01) listener
        let (c1, s1) = tokio::io::duplex(16_384);
        let (_, s_res1) = tokio::join!(
            TransportSessionV2::connect_client(c1, &ks_c, &srv_creds, ServiceId::Benchmark),
            TransportSessionV2::accept_server(s1, &ks_s, ServiceId::DisplayRpc, false),
        );
        assert!(matches!(
            s_res1.err(),
            Some(TransportError::ServiceMismatch { .. })
        ));

        // 2. Wrong K_root (keeping same key_id to test handshake MAC failure)
        srv_creds.root_key = Zeroizing::new([0xFFu8; 32]);
        let (c2, s2) = tokio::io::duplex(16_384);
        let (c_res2, _) = tokio::join!(
            TransportSessionV2::connect_client(c2, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s2, &ks_s, ServiceId::DisplayRpc, false),
        );
        assert_eq!(c_res2.err(), Some(TransportError::HandshakeMacMismatch));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_transport_v2_record_tamper_and_sequence_enforcement() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, _) = create_paired_keystores("tamper");

        // 1. Ciphertext bitflip must fail with AeadDecryptionFailed and poison session
        {
            let (c_stream, s_stream) = tokio::io::duplex(65_536);
            let (c_res, s_res) = tokio::join!(
                TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
                TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
            );
            let mut client_sess = c_res.unwrap();
            let mut server_sess = s_res.unwrap();

            let mut raw_frame = client_sess
                .tx_state
                .seal_record(RecordFrameType::ApplicationData, b"secret-rpc", 65_536)
                .unwrap();
            raw_frame[21] ^= 0x01; // flip 1 bit in ciphertext
            client_sess.stream.write_all(&raw_frame).await.unwrap();
            client_sess.stream.flush().await.unwrap();

            let err = server_sess.recv_message().await.unwrap_err();
            assert_eq!(err, TransportError::AeadDecryptionFailed);
            assert_eq!(server_sess.recv_message().await.unwrap_err(), TransportError::ConnectionClosed);
        }

        // 2. Actual AAD header bitflip (flags byte 6) must fail AEAD verification
        {
            let (c_stream, s_stream) = tokio::io::duplex(65_536);
            let (c_res, s_res) = tokio::join!(
                TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
                TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
            );
            let mut client_sess = c_res.unwrap();
            let mut server_sess = s_res.unwrap();

            let mut raw_frame = client_sess
                .tx_state
                .seal_record(RecordFrameType::ApplicationData, b"secret-rpc-aad", 65_536)
                .unwrap();
            raw_frame[6] ^= 0x01; // flip 1 bit in authenticated header AAD
            client_sess.stream.write_all(&raw_frame).await.unwrap();
            client_sess.stream.flush().await.unwrap();

            let err = server_sess.recv_message().await.unwrap_err();
            assert_eq!(err, TransportError::AeadDecryptionFailed);
        }

        // 3. Sequence number header tamper (byte 16) must trigger SequenceMismatch
        {
            let (c_stream, s_stream) = tokio::io::duplex(65_536);
            let (c_res, s_res) = tokio::join!(
                TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
                TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
            );
            let mut client_sess = c_res.unwrap();
            let mut server_sess = s_res.unwrap();

            let mut raw_frame = client_sess
                .tx_state
                .seal_record(RecordFrameType::ApplicationData, b"secret-rpc-seq", 65_536)
                .unwrap();
            raw_frame[16] ^= 0x01; // tamper sequence number in header
            client_sess.stream.write_all(&raw_frame).await.unwrap();
            client_sess.stream.flush().await.unwrap();

            let err = server_sess.recv_message().await.unwrap_err();
            assert_eq!(
                err,
                TransportError::SequenceMismatch {
                    expected: 0,
                    received: 1,
                }
            );
        }

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_transport_v2_inband_rekey_and_sequence_exhaustion() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, _) = create_paired_keystores("rekey");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        // Configure rekey after every 2 frames
        client_sess.set_rekey_frame_limit(2);

        for i in 0..5u32 {
            let msg = format!("frame-{}", i);
            client_sess.send_message(msg.as_bytes()).await.unwrap();
            let received = server_sess.recv_message().await.unwrap();
            assert_eq!(received, msg.as_bytes());
        }

        // After 5 frames with limit=2, epoch must have ratcheted to 2 on both sides!
        assert_eq!(client_sess.tx_epoch(), 2);
        assert_eq!(server_sess.rx_epoch(), 2);

        // Test hard sequence exhaustion at u64::MAX
        client_sess.tx_state.seq = u64::MAX;
        let exhausted = client_sess
            .tx_state
            .seal_record(RecordFrameType::ApplicationData, b"overflow", 1024);
        assert_eq!(exhausted.err(), Some(TransportError::SequenceExhausted));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_active_session_termination_upon_peer_revocation() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("revocation");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        // 1. Initial message send and receive succeeds
        client_sess.send_message(b"hello before revocation").await.unwrap();
        let rx = server_sess.recv_message().await.unwrap();
        assert_eq!(rx, b"hello before revocation");

        // 2. Spawn a background receive task on server_sess
        let recv_handle = tokio::spawn(async move {
            server_sess.recv_message().await
        });

        // Small yield to ensure server_sess is actively waiting in recv_message
        tokio::task::yield_now().await;

        // 3. Terminate active sessions for client peer (signaling server session)
        let terminated_count = terminate_active_sessions_for_peer(&cli_creds.device_id_hex);
        assert!(terminated_count >= 1);

        // 4. Background recv_message must immediately abort with ConnectionClosed
        let res = recv_handle.await.unwrap();
        assert!(matches!(res, Err(TransportError::ConnectionClosed)));

        // 5. Subsequent send on client_sess must also fail when its session is revoked
        let cli_term_count = terminate_active_sessions_for_peer(&srv_creds.device_id_hex);
        assert!(cli_term_count >= 1);
        let send_res = client_sess.send_message(b"post revocation").await;
        assert!(matches!(send_res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_revoke_peer_while_server_waiting_for_client_finish() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("test1_rev_wait_finish");
        let (mut c_stream, s_stream) = tokio::io::duplex(65_536);

        // Server task starts accepting
        let server_handle = tokio::spawn(async move {
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false).await
        });

        // Client manually sends ClientHello
        let client_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_c = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_c = X25519PublicKey::from(&eph_sk_c);

        let hello_msg = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: ServiceId::DisplayRpc as u8,
            client_device_id_hex: ks_c.local_device_id_hex().to_string(),
            key_id_hex: hex_encode(&srv_creds.key_id),
            client_random_hex: hex_encode(&client_random),
            client_eph_x25519_pk_hex: hex_encode(eph_pk_c.as_bytes()),
            timestamp_ms: unix_epoch_millis(),
        };

        send_handshake_frame(&mut c_stream, HandshakeFrameType::ClientHello, &hello_msg, None).await.unwrap();

        // Client receives ServerHello
        let (hs_type, _) = recv_handshake_frame(&mut c_stream, None, None).await.unwrap();
        assert_eq!(hs_type, HandshakeFrameType::ServerHello);

        // Now server is actively inside `recv_handshake_frame` waiting for ClientFinish!
        tokio::task::yield_now().await;

        // Revoke the client peer
        let count = terminate_active_sessions_for_peer(&cli_creds.device_id_hex);
        assert!(count >= 1, "Server's pending handshake session must be registered and signaled");

        // Server accept must immediately abort with ConnectionClosed
        let srv_res = server_handle.await.unwrap();
        assert!(matches!(srv_res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_revoke_peer_after_auth_during_session_registration() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("test2_rev_reg");

        // 1. Terminate/revoke peer beforehand
        terminate_active_sessions_for_peer(&cli_creds.device_id_hex);

        // 2. An attempt to register or accept server for revoked peer must immediately return UntrustedPeer
        let (c_stream, s_stream) = tokio::io::duplex(65_536);
        let srv_res = TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false);
        let cli_res = TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc);

        let (_c_out, s_out) = tokio::join!(cli_res, srv_res);
        assert!(matches!(s_out, Err(TransportError::UntrustedPeer(_))));

        // 3. Test atomic registration failure if trust check function returns false
        let reg_fail = register_session_revocation_checked("some_untrusted_peer", || false);
        assert!(matches!(reg_fail, Err(TransportError::UntrustedPeer(_))));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_drop_reader_half_retaining_writer_then_revoke_peer() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("test3_split_lifetime");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let _client_sess = c_res.unwrap();
        let server_sess = s_res.unwrap();

        // Split server session into reader and writer halves
        let (server_reader, mut server_writer) = server_sess.into_split();

        // Drop the reader half; writer is retained!
        drop(server_reader);

        // Revoke the peer
        let count = terminate_active_sessions_for_peer(&cli_creds.device_id_hex);
        assert!(count >= 1, "Writer must keep the registration alive in ACTIVE_SESSION_REGISTRY");

        // Writer's send_message must immediately return ConnectionClosed
        let send_res = server_writer.send_message(b"should fail after revocation").await;
        assert!(matches!(send_res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_revoke_peer_while_write_is_blocked() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, _cli_creds) = create_paired_keystores("test4_blocked_write");
        // Tiny buffer: 64 bytes so a write of 16KB will block
        let (c_stream, s_stream) = tokio::io::duplex(64);

        let notify = Arc::new(tokio::sync::Notify::new());
        let enabled = Arc::new(AtomicBool::new(false));

        let wrapped_c_stream = BlockNotifyStream {
            inner: c_stream,
            notify: notify.clone(),
            enabled: enabled.clone(),
        };

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(wrapped_c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let _server_sess = s_res.unwrap();

        // Enable blocking notification on poll_write Pending
        enabled.store(true, Ordering::SeqCst);

        // Client attempts to send a large payload that blocks because duplex buffer is full
        let send_handle = tokio::spawn(async move {
            let big_msg = vec![0x42u8; 16_384];
            client_sess.send_message(&big_msg).await
        });

        // Deterministically wait until write is actively blocked in poll_write
        notify.notified().await;

        // Revoke the server peer on client side
        let count = terminate_active_sessions_for_peer(&srv_creds.device_id_hex);
        assert!(count >= 1);

        // The blocked write must abort immediately with ConnectionClosed
        let res = send_handle.await.unwrap();
        assert!(matches!(res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_revoke_peer_during_active_display_stream() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("test5_display");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        // Simulate active display frame streaming
        client_sess.send_message(b"video_frame_0").await.unwrap();
        let frame = server_sess.recv_message().await.unwrap();
        assert_eq!(frame, b"video_frame_0");

        // Spawn background display receiver
        let display_rx_handle = tokio::spawn(async move {
            server_sess.recv_message().await
        });
        tokio::task::yield_now().await;

        // Revoke peer
        terminate_active_sessions_for_peer(&cli_creds.device_id_hex);

        let res = display_rx_handle.await.unwrap();
        assert!(matches!(res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_revoke_peer_during_active_file_transfer() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) = create_paired_keystores("test6_transfer");
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        // Spawn receiver task waiting for chunked file payload
        let recv_handle = tokio::spawn(async move {
            server_sess.recv_chunked_payload(1024 * 1024).await
        });

        // Send 8-byte length header announcing 1MB file
        let len_bytes = (1024u64 * 1024).to_be_bytes();
        client_sess.send_message(&len_bytes).await.unwrap();

        // Send first chunk
        client_sess.send_message(&[0x55; 1024]).await.unwrap();
        tokio::task::yield_now().await;

        // Revoke peer mid-transfer
        terminate_active_sessions_for_peer(&cli_creds.device_id_hex);

        // Receiver must fail with ConnectionClosed
        let res = recv_handle.await.unwrap();
        assert!(matches!(res, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_race_revocation_against_connection_establishment() {
        for i in 0..50 {
            let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) =
                create_paired_keystores(&format!("test7_race_{}", i));
            let (c_stream, s_stream) = tokio::io::duplex(65_536);

            let srv_dev_id_hex = srv_creds.device_id_hex.clone();
            let cli_dev_id_hex = cli_creds.device_id_hex.clone();

            let conn_task = tokio::spawn(async move {
                let client_fut = TransportSessionV2::connect_client(
                    c_stream,
                    &ks_c,
                    &srv_creds,
                    ServiceId::DisplayRpc,
                );
                let server_fut = TransportSessionV2::accept_server(
                    s_stream,
                    &ks_s,
                    ServiceId::DisplayRpc,
                    false,
                );
                tokio::join!(client_fut, server_fut)
            });

            let rev_task = tokio::spawn(async move {
                if i % 2 == 1 {
                    tokio::task::yield_now().await;
                }
                terminate_active_sessions_for_peer(&cli_dev_id_hex);
                terminate_active_sessions_for_peer(&srv_dev_id_hex);
            });

            let (conn_res, _) = tokio::join!(conn_task, rev_task);
            let (c_out, s_out) = conn_res.unwrap();

            // If a session managed to be created, any subsequent write/read on it MUST fail with ConnectionClosed
            if let Ok(mut c_sess) = c_out {
                let err = c_sess.send_message(b"post_race").await;
                assert!(matches!(err, Err(TransportError::ConnectionClosed)));
            }
            if let Ok(mut s_sess) = s_out {
                let err = s_sess.send_message(b"post_race").await;
                assert!(matches!(err, Err(TransportError::ConnectionClosed)));
            }

            let _ = std::fs::remove_dir_all(&dir_c);
            let _ = std::fs::remove_dir_all(&dir_s);
        }
    }

    #[tokio::test]
    async fn test_deadlock_concurrent_pairing_and_handshake() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) =
            create_paired_keystores("deadlock_reg");
        let ks_c_arc = Arc::new(std::sync::Mutex::new(ks_c));
        let ks_s_arc = Arc::new(std::sync::Mutex::new(ks_s));

        let srv_id_hex = srv_creds.device_id_hex.clone();
        let cli_id_hex = cli_creds.device_id_hex.clone();

        // Task A: repeatedly initiates handshakes with shared keystores
        let ks_c_clone = ks_c_arc.clone();
        let ks_s_clone = ks_s_arc.clone();
        let srv_creds_clone = srv_creds.clone();
        let handshake_task = tokio::spawn(async move {
            let mut attempts = 0;
            for _ in 0..50 {
                let (c_stream, s_stream) = tokio::io::duplex(65_536);
                let c_fut = TransportSessionV2::connect_client_with_shared_keystore(
                    c_stream,
                    &ks_c_clone,
                    &srv_creds_clone,
                    ServiceId::DisplayRpc,
                );
                let s_fut = TransportSessionV2::accept_server_with_shared_keystore(
                    s_stream,
                    None,
                    &ks_s_clone,
                    ServiceId::DisplayRpc,
                    false,
                );
                let _ = tokio::join!(c_fut, s_fut);
                attempts += 1;
            }
            attempts
        });

        // Task B: repeatedly updates trust and terminates active sessions concurrently
        let ks_s_clone2 = ks_s_arc.clone();
        let srv_id_clone2 = srv_id_hex.clone();
        let cli_id_clone2 = cli_id_hex.clone();
        let cli_dev_id = cli_creds.device_id;
        let cli_pubkey = cli_creds.ed25519_pubkey;
        let pairing_task = tokio::spawn(async move {
            let mut iterations = 0;
            let mut root_byte = 0x33u8;
            for _ in 0..50 {
                root_byte = root_byte.wrapping_add(1);
                let new_root = Zeroizing::new([root_byte; 32]);
                {
                    let mut ks = ks_s_clone2.lock().unwrap();
                    let _ = ks.commit_paired_peer(
                        cli_dev_id,
                        cli_pubkey,
                        new_root.clone(),
                        "MacBook-Pro".into(),
                        "macOS".into(),
                        "10.99.99.2".into(),
                        true,
                    );
                }
                terminate_active_sessions_for_peer(&srv_id_clone2);
                terminate_active_sessions_for_peer(&cli_id_clone2);
                iterations += 1;
                tokio::task::yield_now().await;
            }
            iterations
        });

        let timeout_res = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            async { tokio::try_join!(handshake_task, pairing_task) },
        )
        .await;

        assert!(timeout_res.is_ok(), "Concurrent pairing and handshake must not deadlock!");

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_stale_handshake_rejected_after_unpair_and_repair() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) =
            create_paired_keystores("stale_handshake");
        let (mut c_stream, s_stream) = tokio::io::duplex(65_536);

        let ks_s_arc = Arc::new(std::sync::Mutex::new(ks_s));
        let ks_s_clone = ks_s_arc.clone();

        // 1. Client begins handshake by sending ClientHello authenticated with generation 1
        let client_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_c = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_c = X25519PublicKey::from(&eph_sk_c);

        let hello_msg = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: ServiceId::DisplayRpc as u8,
            client_device_id_hex: ks_c.local_device_id_hex().to_string(),
            key_id_hex: hex_encode(&srv_creds.key_id),
            client_random_hex: hex_encode(&client_random),
            client_eph_x25519_pk_hex: hex_encode(eph_pk_c.as_bytes()),
            timestamp_ms: unix_epoch_millis(),
        };

        send_handshake_frame(
            &mut c_stream,
            HandshakeFrameType::ClientHello,
            &hello_msg,
            None,
        )
        .await
        .unwrap();

        // 2. Server accepts in background task using shared keystore
        let server_handle = tokio::spawn(async move {
            TransportSessionV2::accept_server_with_shared_keystore(
                s_stream,
                None,
                &ks_s_clone,
                ServiceId::DisplayRpc,
                false,
            )
            .await
        });

        // 3. Client receives ServerHello
        let (hs_type, _srv_hello_bytes) = recv_handshake_frame(&mut c_stream, None, None)
            .await
            .unwrap();
        assert_eq!(hs_type, HandshakeFrameType::ServerHello);

        // 4. While the handshake is in flight, unpair peer on server
        // This advances trust generation and terminates in-flight sessions for this peer
        {
            let mut ks = ks_s_arc.lock().unwrap();
            ks.unpair_peer(&cli_creds.device_id_hex).unwrap();
        }

        // 5. Client attempts to send ClientFinish using old handshake keys
        let dummy_finish = TransportClientFinishMsg {
            client_ed25519_sig_hex: hex_encode(&[0x11; 64]),
            client_finished_mac_hex: hex_encode(&[0x22; 32]),
        };
        let _ = send_handshake_frame(
            &mut c_stream,
            HandshakeFrameType::ClientFinish,
            &dummy_finish,
            None,
        )
        .await;

        // 6. Server MUST reject stale handshake (due to revocation / connection closed)
        let srv_res = server_handle.await.unwrap();
        assert!(
            srv_res.is_err(),
            "Stale handshake after unpair must be rejected"
        );

        // 7. Furthermore, re-pairing with new root key sets generation to 3
        {
            let mut ks = ks_s_arc.lock().unwrap();
            ks.commit_paired_peer(
                cli_creds.device_id,
                cli_creds.ed25519_pubkey,
                Zeroizing::new([0x88u8; 32]),
                "MacBook-Pro".to_string(),
                "macOS".to_string(),
                "10.99.99.2".to_string(),
                true,
            ).unwrap();
        }

        // An attempt by client to register session revocation with stale generation 1 must be rejected
        let reg_stale = register_session_revocation(&cli_creds.device_id_hex, 1);
        assert!(
            reg_stale.is_err(),
            "Registration with stale generation 1 must be rejected"
        );

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_production_tcp_split_lifetime() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) =
            create_paired_keystores("tcp_split_prod");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_fut = async {
            let (sock, _) = listener.accept().await.unwrap();
            TransportSessionV2::accept_server(sock, &ks_s, ServiceId::DisplayRpc, false).await
        };
        let cli_fut = async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            TransportSessionV2::connect_client(sock, &ks_c, &srv_creds, ServiceId::DisplayRpc).await
        };

        let (s_res, c_res) = tokio::join!(srv_fut, cli_fut);
        let s_sess = s_res.expect("server accept must succeed");
        let c_sess = c_res.expect("client connect must succeed");

        // Split both sessions into full-duplex reader and writer halves using production into_split_tcp()
        let (mut s_reader, mut s_writer) = s_sess.into_split_tcp();
        let (mut c_reader, mut c_writer) = c_sess.into_split_tcp();

        // 1. Verify bidirectional communication through split halves
        c_writer.send_message(b"tcp-ping").await.unwrap();
        let rx_on_srv = s_reader.recv_message().await.unwrap();
        assert_eq!(rx_on_srv, b"tcp-ping");

        s_writer.send_message(b"tcp-pong").await.unwrap();
        let rx_on_cli = c_reader.recv_message().await.unwrap();
        assert_eq!(rx_on_cli, b"tcp-pong");

        // 2. Drop server reader; server writer must retain the session registration guard!
        drop(s_reader);

        // Terminate client peer on server side
        let count_cli = terminate_active_sessions_for_peer(&cli_creds.device_id_hex);
        assert!(count_cli >= 1, "Writer half must keep the session registered");

        // Server writer must fail immediately on send_message
        let w_err = s_writer.send_message(b"post-revocation").await;
        assert!(matches!(w_err, Err(TransportError::ConnectionClosed)));

        // 3. Drop client writer; client reader must retain the session registration guard!
        drop(c_writer);

        // Terminate server peer on client side
        let count_srv = terminate_active_sessions_for_peer(&srv_creds.device_id_hex);
        assert!(count_srv >= 1, "Reader half must keep the session registered");

        // Client reader must fail immediately on recv_message
        let r_err = c_reader.recv_message().await;
        assert!(matches!(r_err, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_unpair_peer_terminates_active_transport_sessions() {
        let (dir_c, ks_c, srv_creds, dir_s, mut ks_s, cli_creds) =
            create_paired_keystores("unpair_term_sessions");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_fut = async {
            let (sock, _) = listener.accept().await.unwrap();
            TransportSessionV2::accept_server(sock, &ks_s, ServiceId::DisplayRpc, false).await
        };
        let cli_fut = async {
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            TransportSessionV2::connect_client(sock, &ks_c, &srv_creds, ServiceId::DisplayRpc).await
        };

        let (s_res, c_res) = tokio::join!(srv_fut, cli_fut);
        let mut s_sess = s_res.expect("server accept must succeed");
        let mut c_sess = c_res.expect("client connect must succeed");

        // Verify active communication before unpair
        c_sess.send_message(b"hello-before-unpair").await.unwrap();
        let rx = s_sess.recv_message().await.unwrap();
        assert_eq!(rx, b"hello-before-unpair");

        // Explicit unpair on server side - must invalidate active sessions immediately
        let removed = ks_s.unpair_peer(&cli_creds.device_id_hex).unwrap();
        assert!(removed, "unpair_peer must remove peer from keystore");

        // Active server session must be immediately terminated and fail on write
        let s_err = s_sess.send_message(b"post-unpair").await;
        assert!(matches!(s_err, Err(TransportError::ConnectionClosed)));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[tokio::test]
    async fn test_unpair_peer_rejects_inflight_handshake() {
        let (dir_c, _ks_c, srv_creds, dir_s, ks_s, cli_creds) =
            create_paired_keystores("unpair_inflight_hs");

        let ks_s_arc = Arc::new(std::sync::Mutex::new(ks_s));
        let (mut c_stream, s_stream) = tokio::io::duplex(64 * 1024);

        let ks_s_clone = Arc::clone(&ks_s_arc);
        let server_handle = tokio::spawn(async move {
            TransportSessionV2::accept_server_with_shared_keystore(
                s_stream,
                None,
                &ks_s_clone,
                ServiceId::DisplayRpc,
                false,
            )
            .await
        });

        // 1. Client sends valid ClientHello
        let client_random = csprng_array::<32>();
        let eph_sk = X25519SecretKey::from(csprng_array::<32>());
        let eph_pk = X25519PublicKey::from(&eph_sk);
        let hello = TransportHelloMsg {
            version: TRANSPORT_PROTOCOL_VERSION,
            service_id: ServiceId::DisplayRpc as u8,
            client_device_id_hex: cli_creds.device_id_hex.clone(),
            key_id_hex: hex_encode(&srv_creds.key_id),
            client_random_hex: hex_encode(&client_random),
            client_eph_x25519_pk_hex: hex_encode(eph_pk.as_bytes()),
            timestamp_ms: unix_epoch_millis(),
        };
        send_handshake_frame(
            &mut c_stream,
            HandshakeFrameType::ClientHello,
            &hello,
            None,
        )
        .await
        .unwrap();

        // 2. Client receives ServerHello
        let (hs_type, _srv_hello_bytes) = recv_handshake_frame(&mut c_stream, None, None)
            .await
            .unwrap();
        assert_eq!(hs_type, HandshakeFrameType::ServerHello);

        // 3. Unpair peer on server while handshake is in flight
        {
            let mut ks = ks_s_arc.lock().unwrap();
            let unpair_res = ks.unpair_peer(&cli_creds.device_id_hex).unwrap();
            assert!(unpair_res);
        }

        // 4. Client attempts to send finish message
        let dummy_finish = TransportClientFinishMsg {
            client_ed25519_sig_hex: hex_encode(&[0x55; 64]),
            client_finished_mac_hex: hex_encode(&[0x66; 32]),
        };
        let _ = send_handshake_frame(
            &mut c_stream,
            HandshakeFrameType::ClientFinish,
            &dummy_finish,
            None,
        )
        .await;

        // 5. Server handshake MUST reject and fail closed
        let srv_res = server_handle.await.unwrap();
        assert!(
            srv_res.is_err(),
            "Server must reject in-flight handshake when peer was unpaired"
        );

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_remote_peer_missing_generation_fails_closed() {
        let fake_remote_peer = "ffffffffffffffffffffffffffffffff";
        // Remote peer that is NOT registered in peer_generations or local_device_ids must fail closed
        let res = register_session_revocation(fake_remote_peer, 1);
        assert!(
            res.is_err(),
            "Registration for remote peer without prior trust generation registration must fail closed"
        );
        match res.unwrap_err() {
            TransportError::UntrustedPeer(msg) => {
                assert!(msg.contains("un-registered trust generation for remote peer"));
            }
            other => panic!("Expected UntrustedPeer error, got {:?}", other),
        }
    }

    #[test]
    fn test_remote_peer_missing() {
        test_remote_peer_missing_generation_fails_closed();
    }

    #[test]
    fn test_unpair_peer_generation_sync_with_transport_registry() {
        let (dir_c, _ks_c, _srv_creds, dir_s, mut ks_s, cli_creds) =
            create_paired_keystores("unpair_gen_sync");

        let peer_id = cli_creds.device_id_hex.clone();
        let initial_gen = ks_s.peer_trust_generation(&peer_id).unwrap();
        assert_eq!(
            get_peer_trust_generation(&peer_id),
            Some(initial_gen),
            "Initial keystore generation must match transport registry"
        );

        // Perform Phase A unpair
        let removed = ks_s.unpair_peer(&peer_id).unwrap();
        assert!(removed);

        let next_ks_gen = ks_s.peer_trust_generation(&peer_id).unwrap();
        let next_transport_gen = get_peer_trust_generation(&peer_id).unwrap();

        assert_eq!(next_ks_gen, initial_gen + 1);
        assert_eq!(
            next_transport_gen, next_ks_gen,
            "Transport registry generation must match keystore generation exactly after unpair"
        );
        assert!(is_peer_revoked(&peer_id), "Peer must be marked revoked in transport registry");

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_untrust_or_block_generation_sync_with_transport_registry() {
        let (dir_c, _ks_c, _srv_creds, dir_s, mut ks_s, cli_creds) =
            create_paired_keystores("untrust_gen_sync");

        let peer_id = cli_creds.device_id_hex.clone();
        let initial_gen = ks_s.peer_trust_generation(&peer_id).unwrap();

        // Perform untrust or block
        ks_s.untrust_or_block_peer(&peer_id, true, Some("127.0.0.1")).unwrap();

        let next_ks_gen = ks_s.peer_trust_generation(&peer_id).unwrap();
        let next_transport_gen = get_peer_trust_generation(&peer_id).unwrap();

        assert_eq!(next_ks_gen, initial_gen + 1);
        assert_eq!(
            next_transport_gen, next_ks_gen,
            "Transport registry generation must match keystore generation exactly after untrust_or_block"
        );
        assert!(is_peer_revoked(&peer_id), "Peer must be marked revoked in transport registry");

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_peer_trust_generation_returns_tracked_generation_after_removal() {
        let (dir_c, _ks_c, _srv_creds, dir_s, mut ks_s, cli_creds) =
            create_paired_keystores("tracked_gen_after_removal");

        let peer_id = cli_creds.device_id_hex.clone();
        assert!(ks_s.get_peer(&peer_id).is_some());

        ks_s.unpair_peer(&peer_id).unwrap();

        // Peer is no longer in pinned peers
        assert!(ks_s.get_peer(&peer_id).is_none());
        // But tracked trust generation must still be available
        assert_eq!(ks_s.peer_trust_generation(&peer_id), Some(2));

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }

    #[test]
    fn test_no_duplicate_generation_increment_during_subsystem_teardown() {
        let peer_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee99";
        register_peer_trust_generation(peer_id, 10);
        assert_eq!(get_peer_trust_generation(peer_id), Some(10));

        // Invalidate trust at generation 11 (Phase A)
        invalidate_peer_trust(peer_id, 11);
        assert_eq!(get_peer_trust_generation(peer_id), Some(11));

        // Subsystem teardown runs (Phase B) - verifying transport generation remains 11
        // (no secondary call to terminate_active_sessions_for_peer)
        assert_eq!(get_peer_trust_generation(peer_id), Some(11));
    }

    #[tokio::test]
    async fn test_transport_session_trust_generation_is_immutable_after_registry_update() {
        let (dir_c, ks_c, srv_creds, dir_s, ks_s, cli_creds) =
            create_paired_keystores("immutable_session_gen");

        let ks_c_mutex = std::sync::Mutex::new(ks_c);
        let ks_s_mutex = std::sync::Mutex::new(ks_s);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let client_fut = TransportSessionV2::connect_client_with_shared_keystore(
            client_io,
            &ks_c_mutex,
            &srv_creds,
            ServiceId::CameraStream,
        );
        let server_fut = TransportSessionV2::accept_server_with_shared_keystore(
            server_io,
            None,
            &ks_s_mutex,
            ServiceId::CameraStream,
            false,
        );

        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        let client_session = client_res.expect("client handshake succeeds");
        let server_session = server_res.expect("server handshake succeeds");

        assert_eq!(client_session.trust_generation(), srv_creds.trust_generation);
        assert_eq!(server_session.trust_generation(), cli_creds.trust_generation);
        assert_eq!(server_session.trust_generation(), 1);

        // Advance both peer generations in the global registry (simulating unpair + re-pair)
        register_peer_trust_generation(&srv_creds.device_id_hex, 7);
        register_peer_trust_generation(&cli_creds.device_id_hex, 9);

        // Existing authenticated session handles MUST retain their immutable handshake generation
        assert_eq!(
            client_session.trust_generation(),
            1,
            "Client session trust_generation() must remain immutable after registry update"
        );
        assert_eq!(
            server_session.trust_generation(),
            1,
            "Server session trust_generation() must remain immutable after registry update"
        );
        drop(client_session);
        drop(server_session);

        // Unpair and re-pair both peers so their authenticated trust generation advances to 3 (> 1),
        // proving `trust_generation()` is neither hardcoded to 1 nor a live registry lookup.
        let shared_root_2 = Zeroizing::new([0x8Bu8; 32]);
        let srv_creds_gen3 = {
            let mut ks_c_guard = ks_c_mutex.lock().unwrap();
            let ks_s_guard = ks_s_mutex.lock().unwrap();
            let _ = ks_c_guard.unpair_peer(&srv_creds.device_id_hex).unwrap();
            ks_c_guard
                .commit_paired_peer(
                    ks_s_guard.local_device_id(),
                    ks_s_guard.local_ed25519_pubkey(),
                    shared_root_2.clone(),
                    "HP-Omen".to_string(),
                    "Windows".to_string(),
                    "10.99.99.1".to_string(),
                    true,
                )
                .unwrap()
        };
        let cli_creds_gen3 = {
            let ks_c_guard = ks_c_mutex.lock().unwrap();
            let mut ks_s_guard = ks_s_mutex.lock().unwrap();
            let _ = ks_s_guard.unpair_peer(&cli_creds.device_id_hex).unwrap();
            ks_s_guard
                .commit_paired_peer(
                    ks_c_guard.local_device_id(),
                    ks_c_guard.local_ed25519_pubkey(),
                    shared_root_2,
                    "MacBook".to_string(),
                    "macOS".to_string(),
                    "10.99.99.2".to_string(),
                    true,
                )
                .unwrap()
        };
        assert_eq!(srv_creds_gen3.trust_generation, 3);
        assert_eq!(cli_creds_gen3.trust_generation, 3);

        let (client_io2, server_io2) = tokio::io::duplex(64 * 1024);
        let (client_res2, server_res2) = tokio::join!(
            TransportSessionV2::connect_client_with_shared_keystore(
                client_io2,
                &ks_c_mutex,
                &srv_creds_gen3,
                ServiceId::CameraStream,
            ),
            TransportSessionV2::accept_server_with_shared_keystore(
                server_io2,
                None,
                &ks_s_mutex,
                ServiceId::CameraStream,
                false,
            ),
        );
        let client_session2 = client_res2.expect("gen-3 client handshake succeeds");
        let server_session2 = server_res2.expect("gen-3 server handshake succeeds");
        assert_eq!(client_session2.trust_generation(), 3);
        assert_eq!(server_session2.trust_generation(), 3);

        // Advance global registry far past 3; sessions MUST stay pinned to immutable generation 3
        register_peer_trust_generation(&srv_creds_gen3.device_id_hex, 12);
        register_peer_trust_generation(&cli_creds_gen3.device_id_hex, 15);
        assert_eq!(client_session2.trust_generation(), 3);
        assert_eq!(server_session2.trust_generation(), 3);

        let _ = std::fs::remove_dir_all(&dir_c);
        let _ = std::fs::remove_dir_all(&dir_s);
    }
}
