//! Authenticated UDP Audio Sessions (`IUA2` on Port `58284`).
//!
//! Eliminates unauthenticated IP-based UDP audio filtering and replaces it with:
//! 1. Control-plane session negotiation over `TransportSessionV2` (`DisplayRpc` on port `58281`),
//!    binding a fresh `audio_session_id` (`[u8; 8]`), `K_audio` (`32B`), and `nonce_salt` (`4B`)
//!    to the peer's `K_root` and fresh `sender_nonce` / `receiver_nonce` entropy.
//! 2. Per-datagram `ChaCha20-Poly1305` authenticated encryption with a 32-byte `IUA2` header bound
//!    as AEAD `AAD` and a unique 96-bit nonce (`nonce_salt[4B] || pkt_seq.to_be_bytes()[8B]`).
//! 3. DTLS/WireGuard-style 64-packet sliding-window anti-replay protection (`ReplayWindow64`) that
//!    is updated **only** after Poly1305 tag verification succeeds, preventing window-poisoning DoS.
//! 4. Session lifecycle enforcement: 15-minute maximum session TTL (`900s`), 60-second idle timeout,
//!    and sequence-exhaustion cutoff (`2^48 - 1`).

use crate::security::{constant_time_eq, csprng_array, unix_epoch_secs};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 4-byte magic prefix for Integrator UDP Audio v2 datagrams (`"IUA2"`).
pub const AUDIO_UDP_WIRE_MAGIC: [u8; 4] = *b"IUA2";

/// Protocol version `2` for Integrator UDP Audio v2.
pub const AUDIO_UDP_PROTOCOL_VERSION: u16 = 2;

/// Fixed 32-byte `IUA2` datagram header size (authenticated as AEAD `AAD`).
pub const AUDIO_UDP_HEADER_LEN: usize = 32;

/// 16-byte Poly1305 authentication tag size.
pub const AUDIO_UDP_TAG_LEN: usize = 16;

/// Minimum encrypted PCM payload size (`1` byte).
pub const MIN_AUDIO_PAYLOAD_LEN: usize = 1;

/// Maximum encrypted PCM payload size (`4096` bytes, comfortably below 64 KiB and standard jumbo/MTU bounds).
pub const MAX_AUDIO_PAYLOAD_LEN: usize = 4096;

/// Minimum wire datagram size (`32B header + 1B payload + 16B tag = 49B`).
pub const MIN_AUDIO_DATAGRAM_LEN: usize =
    AUDIO_UDP_HEADER_LEN + MIN_AUDIO_PAYLOAD_LEN + AUDIO_UDP_TAG_LEN;

/// Maximum wire datagram size (`32B header + 4096B payload + 16B tag = 4144B`).
pub const MAX_AUDIO_DATAGRAM_LEN: usize =
    AUDIO_UDP_HEADER_LEN + MAX_AUDIO_PAYLOAD_LEN + AUDIO_UDP_TAG_LEN;

/// Maximum UDP audio session lifetime (`15 minutes = 900 seconds`).
pub const AUDIO_SESSION_TTL_SECS: u64 = 900;

/// Maximum UDP audio session idle timeout (`60 seconds`).
pub const AUDIO_SESSION_IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum active UDP audio sessions tracked concurrently.
pub const MAX_ACTIVE_AUDIO_SESSIONS: usize = 16;

/// Maximum packet sequence number (`2^48 - 1`) before requiring session rotation.
pub const MAX_AUDIO_PACKET_SEQ: u64 = (1u64 << 48) - 1;

/// Frame flag for standard PCM audio data.
pub const AUDIO_FLAG_PCM_FRAME: u16 = 0x0001;

/// Frame flag for authenticated keepalive datagrams.
pub const AUDIO_FLAG_KEEPALIVE: u16 = 0x0002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioUdpError {
    PacketBounds(usize),
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    InvalidFlags(u16),
    InvalidSequenceNumber(u64),
    PayloadLengthMismatch { header_len: usize, actual_len: usize },
    UnknownSession([u8; 8]),
    SessionExpired,
    PacketTooOld { pkt_seq: u64, highest_seq: u64 },
    DuplicatePacket(u64),
    AeadFailed,
    InvalidHandshakeParam(&'static str),
}

impl fmt::Display for AudioUdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketBounds(sz) => write!(f, "UDP audio datagram size {} out of bounds", sz),
            Self::InvalidMagic(m) => write!(f, "Invalid UDP audio magic {:02x?}", m),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported UDP audio version {}", v),
            Self::InvalidFlags(fl) => write!(f, "Invalid UDP audio flags 0x{:04x}", fl),
            Self::InvalidSequenceNumber(s) => write!(f, "Invalid UDP audio sequence number {}", s),
            Self::PayloadLengthMismatch {
                header_len,
                actual_len,
            } => write!(
                f,
                "UDP audio payload length mismatch (header {}, actual {})",
                header_len, actual_len
            ),
            Self::UnknownSession(id) => {
                write!(f, "Unknown UDP audio session {:02x?}", id)
            }
            Self::SessionExpired => write!(f, "UDP audio session expired"),
            Self::PacketTooOld {
                pkt_seq,
                highest_seq,
            } => write!(
                f,
                "UDP audio packet seq {} is older than 64-packet window (highest {})",
                pkt_seq, highest_seq
            ),
            Self::DuplicatePacket(seq) => {
                write!(f, "Duplicate/replayed UDP audio packet seq {}", seq)
            }
            Self::AeadFailed => write!(f, "UDP audio ChaCha20-Poly1305 authentication failed"),
            Self::InvalidHandshakeParam(msg) => write!(f, "Invalid audio session param: {}", msg),
        }
    }
}

impl std::error::Error for AudioUdpError {}

/// Wire representation of the 32-byte `IUA2` header (authenticated as AEAD `AAD`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioDatagramHeader {
    pub version: u16,
    pub flags: u16,
    pub session_id: [u8; 8],
    pub pkt_seq: u64,
    pub timestamp_us: u32,
    pub frame_samples: u16,
    pub payload_len: u16,
}

impl AudioDatagramHeader {
    pub fn to_bytes(&self) -> [u8; AUDIO_UDP_HEADER_LEN] {
        let mut out = [0u8; AUDIO_UDP_HEADER_LEN];
        out[0..4].copy_from_slice(&AUDIO_UDP_WIRE_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..16].copy_from_slice(&self.session_id);
        out[16..24].copy_from_slice(&self.pkt_seq.to_be_bytes());
        out[24..28].copy_from_slice(&self.timestamp_us.to_be_bytes());
        out[28..30].copy_from_slice(&self.frame_samples.to_be_bytes());
        out[30..32].copy_from_slice(&self.payload_len.to_be_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, AudioUdpError> {
        if buf.len() < AUDIO_UDP_HEADER_LEN {
            return Err(AudioUdpError::PacketBounds(buf.len()));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if !constant_time_eq(&magic, &AUDIO_UDP_WIRE_MAGIC) {
            return Err(AudioUdpError::InvalidMagic(magic));
        }
        let version = u16::from_be_bytes([buf[4], buf[5]]);
        if version != AUDIO_UDP_PROTOCOL_VERSION {
            return Err(AudioUdpError::UnsupportedVersion(version));
        }
        let flags = u16::from_be_bytes([buf[6], buf[7]]);
        if flags != AUDIO_FLAG_PCM_FRAME && flags != AUDIO_FLAG_KEEPALIVE {
            return Err(AudioUdpError::InvalidFlags(flags));
        }
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&buf[8..16]);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[16..24]);
        let pkt_seq = u64::from_be_bytes(seq_bytes);
        if pkt_seq == 0 || pkt_seq >= MAX_AUDIO_PACKET_SEQ {
            return Err(AudioUdpError::InvalidSequenceNumber(pkt_seq));
        }

        let timestamp_us = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let frame_samples = u16::from_be_bytes([buf[28], buf[29]]);
        let payload_len = u16::from_be_bytes([buf[30], buf[31]]);
        if !(MIN_AUDIO_PAYLOAD_LEN..=MAX_AUDIO_PAYLOAD_LEN).contains(&(payload_len as usize)) {
            return Err(AudioUdpError::PacketBounds(payload_len as usize));
        }

        Ok(Self {
            version,
            flags,
            session_id,
            pkt_seq,
            timestamp_us,
            frame_samples,
            payload_len,
        })
    }
}

/// 64-packet sliding-window anti-replay state (RFC 6479 / DTLS / WireGuard style).
///
/// `check_before_aead` performs a read-only check before decryption; `commit_after_aead`
/// mutates the window ONLY after Poly1305 tag verification succeeds.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow64 {
    highest_seq: u64,
    bitmap: u64,
}

impl ReplayWindow64 {
    pub fn new() -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
        }
    }

    pub fn highest_seq(&self) -> u64 {
        self.highest_seq
    }

    /// Pre-AEAD check: verifies `pkt_seq` is non-zero, below `MAX_AUDIO_PACKET_SEQ`,
    /// not older than `highest_seq - 63`, and not already marked in `bitmap`.
    pub fn check_before_aead(&self, pkt_seq: u64) -> Result<(), AudioUdpError> {
        if pkt_seq == 0 || pkt_seq >= MAX_AUDIO_PACKET_SEQ {
            return Err(AudioUdpError::InvalidSequenceNumber(pkt_seq));
        }
        if self.highest_seq == 0 {
            return Ok(());
        }
        if pkt_seq > self.highest_seq {
            return Ok(());
        }
        let offset = self.highest_seq - pkt_seq;
        if offset >= 64 {
            return Err(AudioUdpError::PacketTooOld {
                pkt_seq,
                highest_seq: self.highest_seq,
            });
        }
        if ((self.bitmap >> offset) & 1) == 1 {
            return Err(AudioUdpError::DuplicatePacket(pkt_seq));
        }
        Ok(())
    }

    /// Post-AEAD commit: marks `pkt_seq` as received and advances `highest_seq` if needed.
    pub fn commit_after_aead(&mut self, pkt_seq: u64) {
        if self.highest_seq == 0 {
            self.highest_seq = pkt_seq;
            self.bitmap = 1;
            return;
        }
        if pkt_seq > self.highest_seq {
            let shift = pkt_seq - self.highest_seq;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_seq = pkt_seq;
        } else {
            let offset = self.highest_seq - pkt_seq;
            if offset < 64 {
                self.bitmap |= 1u64 << offset;
            }
        }
    }
}

/// Derives `(k_audio, nonce_salt)` from `K_root`, `sender_nonce`, `receiver_nonce`, and `session_id`:
/// - `salt_audio = SHA256("INTEGRATOR-AUDIO-SALT-V2" || sender_nonce || receiver_nonce || session_id)`
/// - `prk = HKDF-Extract(salt_audio, K_root)`
/// - `k_audio = HKDF-Expand(prk, "integrator-udp-audio-key-v2", 32)`
/// - `nonce_salt = HKDF-Expand(prk, "integrator-udp-audio-iv-v2", 4)`
pub fn derive_audio_session_keys(
    k_root: &[u8; 32],
    sender_nonce: &[u8; 32],
    receiver_nonce: &[u8; 32],
    session_id: &[u8; 8],
) -> (Zeroizing<[u8; 32]>, [u8; 4]) {
    let mut hasher = Sha256::new();
    hasher.update(b"INTEGRATOR-AUDIO-SALT-V2");
    hasher.update(sender_nonce);
    hasher.update(receiver_nonce);
    hasher.update(session_id);
    let salt_audio = hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(&salt_audio), k_root);
    let mut k_audio = Zeroizing::new([0u8; 32]);
    let mut nonce_salt = [0u8; 4];
    hk.expand(b"integrator-udp-audio-key-v2", &mut *k_audio)
        .expect("HKDF expand 32B audio key");
    hk.expand(b"integrator-udp-audio-iv-v2", &mut nonce_salt)
        .expect("HKDF expand 4B audio iv");
    (k_audio, nonce_salt)
}

#[inline]
fn build_audio_aead_nonce(nonce_salt: &[u8; 4], pkt_seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(nonce_salt);
    nonce[4..12].copy_from_slice(&pkt_seq.to_be_bytes());
    nonce
}

/// Sender-side state for encrypting outbound `IUA2` UDP audio datagrams.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AudioSessionSender {
    pub session_id: [u8; 8],
    k_audio: [u8; 32],
    nonce_salt: [u8; 4],
    next_seq: u64,
    pub expires_at_secs: u64,
}

impl AudioSessionSender {
    pub fn new(
        session_id: [u8; 8],
        k_audio: [u8; 32],
        nonce_salt: [u8; 4],
        expires_at_secs: u64,
    ) -> Self {
        Self {
            session_id,
            k_audio,
            nonce_salt,
            next_seq: 1,
            expires_at_secs,
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Seals a PCM or keepalive audio payload into a complete `IUA2` wire datagram.
    pub fn seal_datagram(
        &mut self,
        flags: u16,
        timestamp_us: u32,
        frame_samples: u16,
        plaintext: &[u8],
        now_secs: u64,
    ) -> Result<Vec<u8>, AudioUdpError> {
        if now_secs >= self.expires_at_secs {
            return Err(AudioUdpError::SessionExpired);
        }
        if !(MIN_AUDIO_PAYLOAD_LEN..=MAX_AUDIO_PAYLOAD_LEN).contains(&plaintext.len()) {
            return Err(AudioUdpError::PacketBounds(plaintext.len()));
        }
        if self.next_seq == 0 || self.next_seq >= MAX_AUDIO_PACKET_SEQ {
            return Err(AudioUdpError::InvalidSequenceNumber(self.next_seq));
        }

        let pkt_seq = self.next_seq;
        self.next_seq += 1;

        let header = AudioDatagramHeader {
            version: AUDIO_UDP_PROTOCOL_VERSION,
            flags,
            session_id: self.session_id,
            pkt_seq,
            timestamp_us,
            frame_samples,
            payload_len: plaintext.len() as u16,
        };
        let header_bytes = header.to_bytes();
        let nonce_bytes = build_audio_aead_nonce(&self.nonce_salt, pkt_seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k_audio));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| AudioUdpError::AeadFailed)?;

        let mut datagram = Vec::with_capacity(AUDIO_UDP_HEADER_LEN + ciphertext.len());
        datagram.extend_from_slice(&header_bytes);
        datagram.extend_from_slice(&ciphertext);
        Ok(datagram)
    }
}

/// Receiver-side state for a single authenticated `IUA2` UDP audio session.
pub struct AudioSessionReceiver {
    pub session_id: [u8; 8],
    pub peer_device_id: [u8; 16],
    k_audio: Zeroizing<[u8; 32]>,
    nonce_salt: [u8; 4],
    pub sample_rate: u32,
    pub channels: u8,
    pub bit_depth: u8,
    pub created_at_secs: u64,
    pub expires_at_secs: u64,
    pub last_activity_secs: u64,
    pub replay_window: ReplayWindow64,
}

impl AudioSessionReceiver {
    pub fn new(
        session_id: [u8; 8],
        peer_device_id: [u8; 16],
        k_audio: Zeroizing<[u8; 32]>,
        nonce_salt: [u8; 4],
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
        now_secs: u64,
    ) -> Self {
        Self {
            session_id,
            peer_device_id,
            k_audio,
            nonce_salt,
            sample_rate,
            channels,
            bit_depth,
            created_at_secs: now_secs,
            expires_at_secs: now_secs.saturating_add(AUDIO_SESSION_TTL_SECS),
            last_activity_secs: now_secs,
            replay_window: ReplayWindow64::new(),
        }
    }

    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at_secs
            || now_secs.saturating_sub(self.last_activity_secs) > AUDIO_SESSION_IDLE_TIMEOUT_SECS
    }

    /// Verifies and decrypts an `IUA2` datagram against this session, updating the
    /// 64-packet replay window ONLY after Poly1305 tag verification succeeds.
    pub fn open_datagram(
        &mut self,
        datagram: &[u8],
        now_secs: u64,
    ) -> Result<(AudioDatagramHeader, Vec<u8>), AudioUdpError> {
        if !(MIN_AUDIO_DATAGRAM_LEN..=MAX_AUDIO_DATAGRAM_LEN).contains(&datagram.len()) {
            return Err(AudioUdpError::PacketBounds(datagram.len()));
        }
        if self.is_expired(now_secs) {
            return Err(AudioUdpError::SessionExpired);
        }

        let header = AudioDatagramHeader::from_bytes(&datagram[..AUDIO_UDP_HEADER_LEN])?;
        if !constant_time_eq(&header.session_id, &self.session_id) {
            return Err(AudioUdpError::UnknownSession(header.session_id));
        }

        let expected_total = AUDIO_UDP_HEADER_LEN + (header.payload_len as usize) + AUDIO_UDP_TAG_LEN;
        if datagram.len() != expected_total {
            return Err(AudioUdpError::PayloadLengthMismatch {
                header_len: header.payload_len as usize,
                actual_len: datagram.len().saturating_sub(AUDIO_UDP_HEADER_LEN + AUDIO_UDP_TAG_LEN),
            });
        }

        // Step 1: Pre-AEAD replay check (read-only)
        self.replay_window.check_before_aead(header.pkt_seq)?;

        // Step 2: AEAD decryption & Poly1305 tag verification
        let nonce_bytes = build_audio_aead_nonce(&self.nonce_salt, header.pkt_seq);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.k_audio));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &datagram[AUDIO_UDP_HEADER_LEN..],
                    aad: &datagram[..AUDIO_UDP_HEADER_LEN],
                },
            )
            .map_err(|_| AudioUdpError::AeadFailed)?;

        // Step 3: Commit sequence number to replay window ONLY after AEAD succeeds
        self.replay_window.commit_after_aead(header.pkt_seq);
        self.last_activity_secs = now_secs;

        Ok((header, plaintext))
    }
}

/// Wire parameters returned inside `DisplayRpcResponse` when negotiating a UDP audio session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiatedAudioSessionWire {
    pub session_id_hex: String,
    pub receiver_nonce_hex: String,
    pub expires_in_secs: u64,
}

/// Registry of active `AudioSessionReceiver` instances keyed by 8-byte `session_id`.
#[derive(Default)]
pub struct AudioSessionRegistry {
    sessions: HashMap<[u8; 8], AudioSessionReceiver>,
}

impl AudioSessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn prune_expired(&mut self, now_secs: u64) {
        self.sessions.retain(|_, s| !s.is_expired(now_secs));
    }

    /// Negotiates and registers a new `AudioSessionReceiver` for an authenticated peer.
    pub fn negotiate_receiver_session(
        &mut self,
        peer_device_id: [u8; 16],
        k_root: &[u8; 32],
        sender_nonce: &[u8; 32],
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
        now_secs: u64,
    ) -> Result<NegotiatedAudioSessionWire, AudioUdpError> {
        if !(8_000..=192_000).contains(&sample_rate) {
            return Err(AudioUdpError::InvalidHandshakeParam(
                "sample_rate must be 8000..=192000",
            ));
        }
        if !(1..=8).contains(&channels) {
            return Err(AudioUdpError::InvalidHandshakeParam("channels must be 1..=8"));
        }
        if !matches!(bit_depth, 16 | 24 | 32) {
            return Err(AudioUdpError::InvalidHandshakeParam(
                "bit_depth must be 16, 24, or 32",
            ));
        }

        self.prune_expired(now_secs);

        // Remove any prior session for the same peer_device_id if we are near capacity
        if self.sessions.len() >= MAX_ACTIVE_AUDIO_SESSIONS {
            self.sessions
                .retain(|_, s| s.peer_device_id != peer_device_id);
            if self.sessions.len() >= MAX_ACTIVE_AUDIO_SESSIONS {
                if let Some(oldest_id) = self
                    .sessions
                    .iter()
                    .min_by_key(|(_, s)| s.last_activity_secs)
                    .map(|(k, _)| *k)
                {
                    self.sessions.remove(&oldest_id);
                }
            }
        }

        let session_id = csprng_array::<8>();
        let receiver_nonce = csprng_array::<32>();
        let (k_audio, nonce_salt) =
            derive_audio_session_keys(k_root, sender_nonce, &receiver_nonce, &session_id);

        let receiver = AudioSessionReceiver::new(
            session_id,
            peer_device_id,
            k_audio,
            nonce_salt,
            sample_rate,
            channels,
            bit_depth,
            now_secs,
        );
        self.sessions.insert(session_id, receiver);

        Ok(NegotiatedAudioSessionWire {
            session_id_hex: crate::security::hex_encode(&session_id),
            receiver_nonce_hex: crate::security::hex_encode(&receiver_nonce),
            expires_in_secs: AUDIO_SESSION_TTL_SECS,
        })
    }

    /// Verifies and decrypts an incoming `IUA2` UDP datagram against the matching session.
    pub fn open_incoming_datagram(
        &mut self,
        datagram: &[u8],
        now_secs: u64,
    ) -> Result<([u8; 16], AudioDatagramHeader, Vec<u8>), AudioUdpError> {
        if !(MIN_AUDIO_DATAGRAM_LEN..=MAX_AUDIO_DATAGRAM_LEN).contains(&datagram.len()) {
            return Err(AudioUdpError::PacketBounds(datagram.len()));
        }
        let header = AudioDatagramHeader::from_bytes(&datagram[..AUDIO_UDP_HEADER_LEN])?;
        let Some(session) = self.sessions.get_mut(&header.session_id) else {
            return Err(AudioUdpError::UnknownSession(header.session_id));
        };
        if session.is_expired(now_secs) {
            let expired_id = header.session_id;
            self.sessions.remove(&expired_id);
            return Err(AudioUdpError::SessionExpired);
        }
        let peer_id = session.peer_device_id;
        let (hdr, plain) = session.open_datagram(datagram, now_secs)?;
        Ok((peer_id, hdr, plain))
    }

    pub fn active_session_count(&self) -> usize {
        let now = unix_epoch_secs();
        self.sessions.values().filter(|s| !s.is_expired(now)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_sender_and_registry() -> (AudioSessionSender, AudioSessionRegistry, u64) {
        let now = 1_750_000_000u64;
        let peer_id = [0x42u8; 16];
        let k_root = [0x77u8; 32];
        let sender_nonce = [0x11u8; 32];

        let mut registry = AudioSessionRegistry::new();
        let wire = registry
            .negotiate_receiver_session(peer_id, &k_root, &sender_nonce, 48_000, 2, 24, now)
            .expect("negotiate session");

        let session_id = crate::security::hex_decode_array::<8>(&wire.session_id_hex).unwrap();
        let receiver_nonce =
            crate::security::hex_decode_array::<32>(&wire.receiver_nonce_hex).unwrap();
        let (k_audio, nonce_salt) =
            derive_audio_session_keys(&k_root, &sender_nonce, &receiver_nonce, &session_id);

        let sender = AudioSessionSender::new(
            session_id,
            *k_audio,
            nonce_salt,
            now + wire.expires_in_secs,
        );
        (sender, registry, now)
    }

    #[test]
    fn test_audio_udp_iua2_roundtrip_and_aad_binding() {
        let (mut sender, mut registry, now) = setup_sender_and_registry();
        let pcm = vec![0x5Au8; 576]; // 2ms 48kHz 24-bit stereo frame

        let dgram = sender
            .seal_datagram(AUDIO_FLAG_PCM_FRAME, 2_000, 96, &pcm, now)
            .expect("seal datagram");
        assert_eq!(dgram.len(), AUDIO_UDP_HEADER_LEN + 576 + AUDIO_UDP_TAG_LEN);

        let (peer_id, hdr, decrypted) = registry
            .open_incoming_datagram(&dgram, now)
            .expect("open datagram");
        assert_eq!(peer_id, [0x42u8; 16]);
        assert_eq!(hdr.pkt_seq, 1);
        assert_eq!(hdr.frame_samples, 96);
        assert_eq!(decrypted, pcm);

        // Tamper with AAD header (frame_samples byte 29) -> AEAD must reject
        let dgram2 = sender
            .seal_datagram(AUDIO_FLAG_PCM_FRAME, 4_000, 96, &pcm, now)
            .unwrap();
        let mut tampered_aad = dgram2.clone();
        tampered_aad[29] ^= 0x01;
        assert_eq!(
            registry.open_incoming_datagram(&tampered_aad, now),
            Err(AudioUdpError::AeadFailed)
        );

        // Because tampered_aad failed AEAD, seq=2 was NOT committed to the replay window!
        // Delivering the genuine dgram2 now must succeed!
        let (_, hdr2, dec2) = registry
            .open_incoming_datagram(&dgram2, now)
            .expect("genuine packet after forged packet must succeed");
        assert_eq!(hdr2.pkt_seq, 2);
        assert_eq!(dec2, pcm);
    }

    #[test]
    fn test_audio_udp_replay_out_of_order_and_anti_window_poisoning() {
        let (mut sender, mut registry, now) = setup_sender_and_registry();
        let pcm = vec![0x33u8; 128];

        // Generate 80 sequential packets (seq 1..=80)
        let mut packets = Vec::new();
        for i in 1..=80u32 {
            packets.push(
                sender
                    .seal_datagram(AUDIO_FLAG_PCM_FRAME, i * 1000, 48, &pcm, now)
                    .unwrap(),
            );
        }

        // Deliver packet #10 first
        registry.open_incoming_datagram(&packets[9], now).unwrap();
        // Exact replay of packet #10 must be rejected as DuplicatePacket(10)
        assert_eq!(
            registry.open_incoming_datagram(&packets[9], now),
            Err(AudioUdpError::DuplicatePacket(10))
        );

        // Out-of-order delivery of packet #5 (within 64-packet window of 10) must succeed
        registry.open_incoming_datagram(&packets[4], now).unwrap();
        // Second delivery of packet #5 must fail as DuplicatePacket(5)
        assert_eq!(
            registry.open_incoming_datagram(&packets[4], now),
            Err(AudioUdpError::DuplicatePacket(5))
        );

        // Attacker attempts to poison the replay window by forging a packet with pkt_seq = 5000
        let mut forged_high_seq = packets[10].clone();
        forged_high_seq[16..24].copy_from_slice(&5000u64.to_be_bytes());
        assert_eq!(
            registry.open_incoming_datagram(&forged_high_seq, now),
            Err(AudioUdpError::AeadFailed)
        );

        // Verify replay window was NOT advanced to 5000: packet #11 must still be accepted!
        registry
            .open_incoming_datagram(&packets[10], now)
            .expect("forged high-seq packet must not poison replay window");

        // Now deliver packet #80 (highest_seq becomes 80; window covers 17..=80)
        registry.open_incoming_datagram(&packets[79], now).unwrap();

        // Packet #16 is now older than the 64-packet window (80 - 16 = 64) -> PacketTooOld
        assert_eq!(
            registry.open_incoming_datagram(&packets[15], now),
            Err(AudioUdpError::PacketTooOld {
                pkt_seq: 16,
                highest_seq: 80,
            })
        );

        // Packet #17 is at the exact tail edge of the window (80 - 17 = 63) -> must succeed!
        registry.open_incoming_datagram(&packets[16], now).unwrap();
    }

    #[test]
    fn test_audio_udp_session_expiry_and_unknown_session_rejected() {
        let (mut sender, mut registry, now) = setup_sender_and_registry();
        let pcm = vec![0xAAu8; 64];

        let dgram1 = sender
            .seal_datagram(AUDIO_FLAG_PCM_FRAME, 1000, 16, &pcm, now)
            .unwrap();

        // Unknown session_id must be rejected
        let mut wrong_sess = dgram1.clone();
        wrong_sess[8] ^= 0xFF;
        assert!(matches!(
            registry.open_incoming_datagram(&wrong_sess, now),
            Err(AudioUdpError::UnknownSession(_))
        ));

        // Advance clock past idle timeout (now + 61s) -> SessionExpired
        assert_eq!(
            registry.open_incoming_datagram(&dgram1, now + AUDIO_SESSION_IDLE_TIMEOUT_SECS + 1),
            Err(AudioUdpError::SessionExpired)
        );
    }
}
