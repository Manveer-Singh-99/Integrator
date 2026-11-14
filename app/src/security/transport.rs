//! Unified Mutually Authenticated Transport Layer (`TransportV2`, Magic `ITR2`).
//!
//! Provides a single authenticated, forward-secret, replay-protected record layer for:
//! - Display & Control RPC (`Port 58281`, `ServiceId::DisplayRpc = 0x01`)
//! - Clipboard & File Transfer (`Port 58283`, `ServiceId::ClipboardTransfer = 0x02`)
//! - Link Speed Benchmark (`Port 58285`, `ServiceId::Benchmark = 0x03`)
//!
//! Cryptographic properties:
//! 1. **Mutual Authentication (`TransportHello` -> `TransportServerHello` -> `TransportClientFinish`)**:
//!    - Combines ephemeral `X25519` Diffie-Hellman (forward secrecy), the pre-shared `K_root`
//!      from RFC 9382 SPAKE2 pairing, and mutual `Ed25519` digital signatures over the complete
//!      handshake transcript (`H_2`, `H_3`).
//! 2. **All-Zero X25519 Shared-Secret Rejection**:
//!    - Explicitly checks `constant_time_eq(dh.as_bytes(), &[0u8; 32]) || !dh.was_contributory()`
//!      to reject all low-order Curve25519 points (RFC 7748 §6.1).
//! 3. **Directional ChaCha20-Poly1305 Record Layer**:
//!    - Independent keys (`K_app_c2s`, `K_app_s2c`) and LSB-separated 4-byte IV prefixes (`iv_c2s`, `iv_s2c`).
//!    - Deterministic 96-bit nonce: `iv_dir[0..4] || seq_be[0..8]`.
//!    - 21-byte frame header bound as `AAD`; strict monotonic sequence enforcement (`hdr.seq == rx_seq`).
//! 4. **Sequence Exhaustion & In-Band Rekeying**:
//!    - Supports in-band key ratcheting (`FrameType::Rekey = 0x02`) via HKDF-SHA256, resetting `seq = 0`
//!      at `epoch + 1` and zeroizing previous epoch keys.
//!    - Fails closed if `seq == u64::MAX` or `epoch == u16::MAX`.

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
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, Zeroizing};

pub const TRANSPORT_WIRE_MAGIC: [u8; 4] = *b"ITR2";
pub const TRANSPORT_PROTOCOL_VERSION: u16 = 2;
pub const TRANSPORT_HEADER_VERSION_BYTE: u8 = 0x02;
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 4096;
pub const RECORD_HEADER_LEN: usize = 21;
pub const AEAD_TAG_LEN: usize = 16;

pub const HANDSHAKE_TIMESTAMP_WINDOW_MS: u64 = 300_000; // ±5 minutes
pub const MAX_HANDSHAKE_REPLAY_CACHE: usize = 2048;
pub const DEFAULT_REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
pub const DEFAULT_REKEY_AGE_SECS: u64 = 3600; // 1 hour

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceId {
    DisplayRpc = 0x01,
    ClipboardTransfer = 0x02,
    Benchmark = 0x03,
}

impl ServiceId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(ServiceId::DisplayRpc),
            0x02 => Some(ServiceId::ClipboardTransfer),
            0x03 => Some(ServiceId::Benchmark),
            _ => None,
        }
    }

    pub fn max_plaintext_frame_bytes(self) -> usize {
        match self {
            ServiceId::DisplayRpc => 64 * 1024,            // 64 KiB
            ServiceId::ClipboardTransfer => 2 * 1024 * 1024, // 2 MiB (1 MiB chunk + metadata)
            ServiceId::Benchmark => 1024 * 1024,           // 1 MiB
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeFrameType {
    ClientHello = 0x10,
    ServerHello = 0x11,
    ClientFinish = 0x12,
    HandshakeError = 0x1F,
}

impl HandshakeFrameType {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordFrameType {
    ApplicationData = 0x01,
    Rekey = 0x02,
    KeepAlive = 0x03,
    CloseNotify = 0x04,
}

impl RecordFrameType {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportHelloMsg {
    pub version: u16,
    pub service_id: u8,
    pub client_device_id_hex: String,
    pub key_id_hex: String,
    pub client_random_hex: String,
    pub client_eph_x25519_pk_hex: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportServerHelloMsg {
    pub version: u16,
    pub server_device_id_hex: String,
    pub server_random_hex: String,
    pub server_eph_x25519_pk_hex: String,
    pub server_ed25519_sig_hex: String,
    pub server_finished_mac_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportClientFinishMsg {
    pub client_ed25519_sig_hex: String,
    pub client_finished_mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    UnexpectedFrameType(u8),
    ServiceMismatch { expected: u8, received: u8 },
    OversizedFrame { len: usize, max: usize },
    MalformedHandshake(String),
    TimestampSkewExceeded { skew_ms: u64 },
    ReplayedHandshakeHello,
    UntrustedPeer(String),
    KeyIdMismatch,
    LowOrderEphemeralPoint,
    HandshakeMacMismatch,
    HandshakeSignatureInvalid,
    AeadDecryptionFailed,
    EpochMismatch { expected: u16, received: u16 },
    SequenceMismatch { expected: u64, received: u64 },
    SequenceExhausted,
    ConnectionClosed,
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

/// Bounded replay cache for `(client_device_id, client_random)` in `TransportHello`.
static HELLO_REPLAY_CACHE: OnceLock<Mutex<VecDeque<([u8; 16], [u8; 32])>>> = OnceLock::new();

fn check_and_record_hello_nonce(
    client_device_id: &[u8; 16],
    client_random: &[u8; 32],
) -> Result<(), TransportError> {
    let cache = HELLO_REPLAY_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    for (id, rnd) in guard.iter() {
        if constant_time_eq(id, client_device_id) && constant_time_eq(rnd, client_random) {
            return Err(TransportError::ReplayedHandshakeHello);
        }
    }
    if guard.len() >= MAX_HANDSHAKE_REPLAY_CACHE {
        guard.pop_front();
    }
    guard.push_back((*client_device_id, *client_random));
    Ok(())
}

/// Directional AEAD state for either outbound (`tx`) or inbound (`rx`) traffic.
pub struct DirectionalCipherState {
    is_client_to_server: bool,
    app_key: Zeroizing<[u8; 32]>,
    rekey_secret: Zeroizing<[u8; 32]>,
    iv_salt: [u8; 4],
    epoch: u16,
    seq: u64,
}

impl Drop for DirectionalCipherState {
    fn drop(&mut self) {
        self.iv_salt.zeroize();
    }
}

impl DirectionalCipherState {
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

    pub fn current_epoch(&self) -> u16 {
        self.epoch
    }

    pub fn current_seq(&self) -> u64 {
        self.seq
    }

    fn compute_nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.iv_salt);
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    /// Ratchets the directional key to `epoch + 1` and resets `seq = 0`.
    pub fn ratchet_epoch(&mut self) -> Result<(), TransportError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(TransportError::SequenceExhausted)?;

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

        if self.is_client_to_server {
            next_iv[0] &= 0xFE;
        } else {
            next_iv[0] |= 0x01;
        }

        self.app_key = next_app_key;
        self.rekey_secret = next_rekey_secret;
        self.iv_salt = next_iv;
        self.epoch = next_epoch;
        self.seq = 0;
        Ok(())
    }

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
        header[6] = 0; // flags
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

        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(TransportError::SequenceExhausted)?;

        Ok((frame_type, plaintext))
    }
}

/// Active mutually authenticated `TransportV2` session wrapping an async stream `S`.
pub struct TransportSessionV2<S> {
    stream: S,
    service_id: ServiceId,
    peer_device_id: [u8; 16],
    peer_device_id_hex: String,
    peer_ed25519_pubkey: [u8; 32],
    session_id: [u8; 16],
    tx_state: DirectionalCipherState,
    rx_state: DirectionalCipherState,
    established_at: Instant,
    rekey_frame_limit: u64,
}

impl<S> TransportSessionV2<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn peer_device_id(&self) -> &[u8; 16] {
        &self.peer_device_id
    }

    pub fn peer_device_id_hex(&self) -> &str {
        &self.peer_device_id_hex
    }

    pub fn peer_ed25519_pubkey(&self) -> &[u8; 32] {
        &self.peer_ed25519_pubkey
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn tx_epoch(&self) -> u16 {
        self.tx_state.current_epoch()
    }

    pub fn rx_epoch(&self) -> u16 {
        self.rx_state.current_epoch()
    }

    pub fn set_rekey_frame_limit(&mut self, limit: u64) {
        self.rekey_frame_limit = limit.max(1);
    }

    /// Initiates a mutually authenticated `TransportV2` client session with a specific pinned `peer`.
    pub async fn connect_client(
        mut stream: S,
        keystore: &KeystoreV2,
        peer: &VerifiedPeerCredentials,
        service_id: ServiceId,
    ) -> Result<Self, TransportError> {
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

        let hello_bytes = send_handshake_frame(
            &mut stream,
            HandshakeFrameType::ClientHello,
            &hello_msg,
        )
        .await?;

        let (hs_type, srv_hello_bytes) = recv_handshake_frame(&mut stream, None).await?;
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

        // Compute ephemeral X25519 shared secret and reject all-zero / low-order points!
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
        send_handshake_frame(&mut stream, HandshakeFrameType::ClientFinish, &finish_msg).await?;

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        Ok(Self {
            stream,
            service_id,
            peer_device_id: peer.device_id,
            peer_device_id_hex: peer.device_id_hex.clone(),
            peer_ed25519_pubkey: peer.ed25519_pubkey,
            session_id,
            tx_state: c2s_state,
            rx_state: s2c_state,
            established_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
        })
    }

    /// Accepts a mutually authenticated `TransportV2` server session on `stream`.
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
    pub async fn accept_server_with_prefixed_magic(
        mut stream: S,
        already_read_magic: Option<[u8; 4]>,
        keystore: &KeystoreV2,
        expected_service: ServiceId,
        allow_loopback_self: bool,
    ) -> Result<Self, TransportError> {
        let (hs_type, hello_bytes) = recv_handshake_frame(&mut stream, already_read_magic).await?;
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

        // Check replay cache for (client_dev_id, client_random).
        check_and_record_hello_nonce(&client_dev_id, &client_random)?;

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
        send_handshake_frame(&mut stream, HandshakeFrameType::ServerHello, &srv_hello).await?;

        let (hs_type_2, finish_bytes) = recv_handshake_frame(&mut stream, None).await?;
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

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        Ok(Self {
            stream,
            service_id: expected_service,
            peer_device_id: peer_creds.device_id,
            peer_device_id_hex: peer_creds.device_id_hex,
            peer_ed25519_pubkey: peer_creds.ed25519_pubkey,
            session_id,
            tx_state: s2c_state,
            rx_state: c2s_state,
            established_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
        })
    }

    /// Triggers an explicit in-band outbound rekey (`FrameType::Rekey`) and ratchets `tx_state` to `epoch + 1`.
    pub async fn initiate_rekey(&mut self) -> Result<(), TransportError> {
        let rekey_frame = self.tx_state.seal_record(
            RecordFrameType::Rekey,
            b"REKEY-V2",
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        self.stream
            .write_all(&rekey_frame)
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        self.tx_state.ratchet_epoch()?;
        Ok(())
    }

    /// Encrypts and writes an application data frame, automatically ratcheting the outbound key
    /// if `rekey_frame_limit` or `DEFAULT_REKEY_AGE_SECS` has been reached.
    pub async fn send_message(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if self.tx_state.current_seq() >= self.rekey_frame_limit
            || (self.tx_state.current_epoch() == 0
                && self.established_at.elapsed().as_secs() >= DEFAULT_REKEY_AGE_SECS)
        {
            self.initiate_rekey().await?;
        }

        let frame = self.tx_state.seal_record(
            RecordFrameType::ApplicationData,
            plaintext,
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        Ok(())
    }

    /// Reads, verifies, and decrypts the next application data frame, transparently handling
    /// in-band `Rekey` and `KeepAlive` control frames.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError> {
        let max_plaintext = self.service_id.max_plaintext_frame_bytes();
        let max_ciphertext = max_plaintext + AEAD_TAG_LEN;

        loop {
            let mut hdr = [0u8; RECORD_HEADER_LEN];
            self.stream
                .read_exact(&mut hdr)
                .await
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;

            let mut magic = [0u8; 4];
            magic.copy_from_slice(&hdr[0..4]);
            if magic != TRANSPORT_WIRE_MAGIC {
                return Err(TransportError::InvalidMagic(magic));
            }
            if hdr[4] != TRANSPORT_HEADER_VERSION_BYTE {
                return Err(TransportError::UnsupportedVersion(hdr[4] as u16));
            }

            let ct_len = u32::from_be_bytes([hdr[17], hdr[18], hdr[19], hdr[20]]) as usize;
            if ct_len < AEAD_TAG_LEN || ct_len > max_ciphertext {
                return Err(TransportError::OversizedFrame {
                    len: ct_len,
                    max: max_ciphertext,
                });
            }

            let mut ciphertext = vec![0u8; ct_len];
            self.stream
                .read_exact(&mut ciphertext)
                .await
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;

            let (frame_type, plaintext) = self.rx_state.open_record(&hdr, &ciphertext)?;
            match frame_type {
                RecordFrameType::ApplicationData => return Ok(plaintext),
                RecordFrameType::Rekey => {
                    self.rx_state.ratchet_epoch()?;
                }
                RecordFrameType::KeepAlive => continue,
                RecordFrameType::CloseNotify => return Err(TransportError::ConnectionClosed),
            }
        }
    }

    /// Sends an authenticated `CloseNotify` frame before closing the session.
    pub async fn close_notify(&mut self) -> Result<(), TransportError> {
        let frame = self.tx_state.seal_record(
            RecordFrameType::CloseNotify,
            b"",
            self.service_id.max_plaintext_frame_bytes(),
        )?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| TransportError::IoFailure(e.to_string()))?;
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
        let local_dev_id_hex = {
            let ks = keystore_mutex.lock().unwrap_or_else(|e| e.into_inner());
            ks.local_device_id_hex().to_string()
        };

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
        )
        .await?;

        let (hs_type, srv_hello_bytes) = recv_handshake_frame(&mut stream, None).await?;
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
        send_handshake_frame(&mut stream, HandshakeFrameType::ClientFinish, &finish_msg).await?;

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        Ok(Self {
            stream,
            service_id,
            peer_device_id: peer.device_id,
            peer_device_id_hex: peer.device_id_hex.clone(),
            peer_ed25519_pubkey: peer.ed25519_pubkey,
            session_id,
            tx_state: c2s_state,
            rx_state: s2c_state,
            established_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
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
        let (hs_type, hello_bytes) = recv_handshake_frame(&mut stream, already_read_magic).await?;
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

        check_and_record_hello_nonce(&client_dev_id, &client_random)?;

        let server_random = csprng_array::<32>();
        let eph_sk_bytes = Zeroizing::new(csprng_array::<32>());
        let eph_sk_s = X25519SecretKey::from(*eph_sk_bytes);
        let eph_pk_s = X25519PublicKey::from(&eph_sk_s);

        let client_eph_pk = X25519PublicKey::from(client_eph_pk_bytes);
        let dh_shared = eph_sk_s.diffie_hellman(&client_eph_pk);
        if constant_time_eq(dh_shared.as_bytes(), &[0u8; 32]) || !dh_shared.was_contributory() {
            return Err(TransportError::LowOrderEphemeralPoint);
        }

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
        send_handshake_frame(&mut stream, HandshakeFrameType::ServerHello, &srv_hello).await?;

        let (hs_type_2, finish_bytes) = recv_handshake_frame(&mut stream, None).await?;
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

        let h4 = compute_transcript_h4(&h3, &cli_sig, &cli_mac);
        let (c2s_state, s2c_state, session_id) = derive_application_states(&prk_hs, &h4);

        Ok(Self {
            stream,
            service_id: expected_service,
            peer_device_id: peer_creds.device_id,
            peer_device_id_hex: peer_creds.device_id_hex,
            peer_ed25519_pubkey: peer_creds.ed25519_pubkey,
            session_id,
            tx_state: s2c_state,
            rx_state: c2s_state,
            established_at: Instant::now(),
            rekey_frame_limit: DEFAULT_REKEY_FRAME_LIMIT,
        })
    }
}

/// Derives loopback self-credentials from the local `KeystoreV2` so same-user local CLI/IPC
/// calls over `127.0.0.1` also use full `TransportV2` mutual authentication and encryption.
pub fn derive_loopback_self_credentials(keystore: &KeystoreV2) -> VerifiedPeerCredentials {
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
    }
}

// ============================================================================
// Handshake Framing & Key Derivation Helpers
// ============================================================================

async fn send_handshake_frame<W, T>(
    writer: &mut W,
    hs_type: HandshakeFrameType,
    msg: &T,
) -> Result<Vec<u8>, TransportError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
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

    writer
        .write_all(&frame)
        .await
        .map_err(|e| TransportError::IoFailure(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| TransportError::IoFailure(e.to_string()))?;
    Ok(payload)
}

async fn recv_handshake_frame<R>(
    reader: &mut R,
    already_read_magic: Option<[u8; 4]>,
) -> Result<(HandshakeFrameType, Vec<u8>), TransportError>
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
                .map_err(|e| TransportError::IoFailure(e.to_string()))?;
            m
        }
    };
    if magic != TRANSPORT_WIRE_MAGIC {
        return Err(TransportError::InvalidMagic(magic));
    }

    let mut rest_hdr = [0u8; 4];
    reader
        .read_exact(&mut rest_hdr)
        .await
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
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| TransportError::IoFailure(e.to_string()))?;
    Ok((hs_type, payload))
}

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

fn build_server_sig_payload(h2: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"integrator-transport-sig-S-v2");
    v.extend_from_slice(h2);
    v
}

fn build_client_sig_payload(h3: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"integrator-transport-sig-C-v2");
    v.extend_from_slice(h3);
    v
}

fn compute_server_finished_mac(k_hs_s2c: &[u8; 32], h2: &[u8; 32], sig_s: &[u8; 64]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 64);
    data.extend_from_slice(h2);
    data.extend_from_slice(sig_s);
    compute_hmac_sha256(k_hs_s2c, &data)
}

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
        let (c_stream, s_stream) = tokio::io::duplex(65_536);

        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(c_stream, &ks_c, &srv_creds, ServiceId::DisplayRpc),
            TransportSessionV2::accept_server(s_stream, &ks_s, ServiceId::DisplayRpc, false),
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        // Seal a valid record at seq=0, then tamper with 1 bit in the AAD header (sequence number)
        let mut raw_frame = client_sess
            .tx_state
            .seal_record(RecordFrameType::ApplicationData, b"secret-rpc", 65_536)
            .unwrap();
        raw_frame[21] ^= 0x01; // flip 1 bit in ciphertext
        client_sess.stream.write_all(&raw_frame).await.unwrap();
        client_sess.stream.flush().await.unwrap();

        let err = server_sess.recv_message().await.unwrap_err();
        assert_eq!(err, TransportError::AeadDecryptionFailed);

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
}
