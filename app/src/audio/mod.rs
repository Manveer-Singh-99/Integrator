//! # Authenticated UDP Audio Sink (`IUA2`) & Acoustic Chime Subsystem
//!
//! ## 1. Module Purpose & Scope
//! This module implements the experimental Authenticated UDP Audio Sink (`IUA2` protocol) on UDP port
//! `AUDIO_PORT = 58284` and local speaker test chime synthesis for the Integrator engine.
//!
//! ### Core Subsystem Responsibilities:
//! 1. **Cryptographic UDP Audio Protocol (`IUA2`)**:
//!    - Binds UDP port 58284 to receive low-latency audio datagrams without TCP head-of-line blocking.
//!    - Every session is negotiated out-of-band over mutually authenticated `TransportSessionV2`
//!      via `DisplayRpcRequest::NegotiateAudioSession`.
//!    - Derives a session-specific 256-bit AEAD key `K_audio`, an 8-byte `audio_session_id`, and a
//!      4-byte `nonce_salt` using HKDF-SHA256 seeded from the peer's root master key `K_root` and
//!      fresh CSPRNG nonces (`sender_nonce` and `receiver_nonce`).
//! 2. **AEAD Datagram Decryption & Replay Prevention**:
//!    - Each incoming datagram is authenticated and decrypted using `ChaCha20-Poly1305`.
//!    - The 32-byte canonical `IUA2` datagram header serves as Additional Authenticated Data (AAD).
//!    - The 96-bit nonce is constructed as `nonce_salt[4B] || pkt_seq[8B]`.
//!    - Replay attacks are defeated using an in-memory 64-packet sliding window bitmask (`ReplayWindow64`),
//!      updated strictly *after* AEAD authentication tag verification succeeds.
//! 3. **Local Acoustic Chime Synthesis**:
//!    - Synthesizes 24-bit 48kHz stereo uncompressed PCM WAV files to verify audio output drivers
//!      on both macOS (invoking `/usr/bin/afplay`) and Windows (invoking `powershell -c System.Media.SoundPlayer`).
//!    - Spawns background reaper threads (`reap_child`) to prevent zombie process accumulation.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                         Audio Subsystem & IUA2 Wire Protocol                           │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                     Peer Machine                              Local Machine
//!              ┌────────────────────────┐                ┌────────────────────────┐
//!              │  DisplayController     │                │   DisplayController    │
//!              │  (RPC Client)          │                │   (RPC Server)         │
//!              └───────────┬────────────┘                └───────────┬────────────┘
//!                          │                                         │
//!                          │ NegotiateAudioSession (TransportV2)     │
//!                          ├────────────────────────────────────────►│
//!                          │                                         │
//!                          │ NegotiatedAudioSessionWire (K_audio)    │
//!                          │◄────────────────────────────────────────┤
//!                          │                                         │
//!                          ▼                                         ▼
//!              ┌────────────────────────┐                ┌────────────────────────┐
//!              │   AudioSessionSender   │                │   AudioManager (Sink)  │
//!              │   - Seal Datagram      │                │   - UDP Port 58284     │
//!              │   - Increment Seq      │                │   - Anti-Replay Bitmask│
//!              └───────────┬────────────┘                │   - ChaCha20-Poly1305  │
//!                          │                             └───────────▲────────────┘
//!                          │ Authenticated IUA2 UDP                  │
//!                          └─────────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Spawns the background UDP sink task `AudioManager::start_udp_audio_sink()` and
//!   queries health status via `AudioManager::status()`.
//! - RPC Handlers (`DisplayRpcRequest::NegotiateAudioSession`): Call `AudioManager::handle_negotiate_session_for_peer()`.
//! - Settings UI: Invokes `AudioManager::play_test_chime()` to trigger audible speaker tests.
//!
//! ### Downstream Callees:
//! - `crate::security::audio_udp`: Core primitives (`AudioSessionRegistry`, `ReplayWindow64`, `AudioSessionSender`).
//! - `crate::trust`: Verified peer trust lookup.
//! - OS subprocesses: `/usr/bin/afplay` (macOS) and PowerShell (Windows).
//!
//! ## 3. Threading & Concurrency Model
//! - The UDP audio sink runs on a dedicated Tokio asynchronous task polling `tokio::net::UdpSocket`.
//! - Active audio session keys are guarded in memory by `AUDIO_SESSION_REGISTRY` (`Mutex<AudioSessionRegistry>`).
//! - Child process execution for acoustic chimes is isolated from the Tokio async worker pool.
//!
//! ## 4. Security & Safety Invariants
//! - **Zero Cleartext UDP**: Unauthenticated packets lacking a registered session ID or failing AEAD
//!   tag verification are discarded immediately.
//! - **Sliding Replay Window**: Duplicate sequence numbers or packets older than the 64-packet window
//!   are dropped to prevent packet injection or replay attacks.
//! - **Session Expiration**: Inactive audio sessions automatically expire after `MAX_NEGOTIATED_AUDIO_TTL_SECS = 600s`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use crate::display::controller::DisplayController;
use crate::display::protocol::DisplayRpcRequest;
use crate::security::audio_udp::{
    derive_audio_session_keys, AudioSessionRegistry, AudioSessionSender,
    NegotiatedAudioSessionWire, MAX_AUDIO_DATAGRAM_LEN, MIN_AUDIO_DATAGRAM_LEN,
};
use crate::{config, security, system_info, trust};

pub const AUDIO_PORT: u16 = config::AUDIO_PORT;

const LOG_RATE_LIMIT: Duration = Duration::from_secs(30);
const RECENT_PACKET_WINDOW_MS: u64 = 5_000;
#[allow(dead_code)]
const MAX_NEGOTIATED_AUDIO_TTL_SECS: u64 = 600;

static SINK_LISTENING: AtomicBool = AtomicBool::new(false);
static LAST_PACKET_EPOCH_MS: AtomicU64 = AtomicU64::new(0);
static PACKETS_DRAINED: AtomicU64 = AtomicU64::new(0);
static AUDIO_SESSION_REGISTRY: OnceLock<Mutex<AudioSessionRegistry>> = OnceLock::new();
static CHIME_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn global_audio_registry() -> &'static Mutex<AudioSessionRegistry> {
    AUDIO_SESSION_REGISTRY.get_or_init(|| Mutex::new(AudioSessionRegistry::new()))
}

fn chime_file_lock() -> &'static Mutex<()> {
    CHIME_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

/// Serde default helper providing the canonical UDP audio streaming port.
fn default_audio_port() -> u16 {
    AUDIO_PORT
}

/// Diagnostic runtime status snapshot for the experimental authenticated UDP audio sink.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioRoutingStatus {
    /// Human-readable description of the active UDP audio sink state and topology.
    pub topology: String,
    /// Measured audio pipeline latency in milliseconds.
    pub latency_ms: f32,
    /// Configured PCM sample rate in Hz.
    pub sample_rate: u32,
    /// Configured PCM sample bit depth.
    pub bit_depth: u8,
    /// Whether active OS audio playback routing is currently enabled.
    pub is_active: bool,
    /// UDP port bound by the authenticated `IUA2` audio sink (defaults to [`AUDIO_PORT`]).
    #[serde(default = "default_audio_port")]
    pub port: u16,
}

impl Default for AudioRoutingStatus {
    fn default() -> Self {
        Self {
            topology: "UDP Audio Sink (Experimental Preview - Offline)".to_string(),
            latency_ms: 0.0,
            sample_rate: config::DEFAULT_AUDIO_SAMPLE_RATE,
            bit_depth: config::DEFAULT_AUDIO_BIT_DEPTH,
            is_active: false,
            port: AUDIO_PORT,
        }
    }
}

struct SinkListeningGuard;

impl Drop for SinkListeningGuard {
    fn drop(&mut self) {
        SINK_LISTENING.store(false, Ordering::Release);
    }
}

fn rate_limit_allow(last_logged: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    match *last_logged {
        Some(prev) if now.duration_since(prev) < LOG_RATE_LIMIT => false,
        _ => {
            *last_logged = Some(now);
            true
        }
    }
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Spawns a background thread to reap a child process when it exits so we do
/// not accumulate zombie processes or leak OS process handles.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn reap_child(mut child: std::process::Child) {
    if let Ok( Some(_) ) = child.try_wait() {
        return;
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

pub struct AudioManager;

impl AudioManager {
    /// Returns the honest runtime status of the experimental UDP audio sink.
    ///
    /// `is_active` remains `false` because incoming preview packets are only
    /// validated and drained (full OS audio output playback is not yet active).
    #[allow(dead_code)]
    pub fn status() -> AudioRoutingStatus {
        if !SINK_LISTENING.load(Ordering::Acquire) {
            return AudioRoutingStatus::default();
        }

        let last_ms = LAST_PACKET_EPOCH_MS.load(Ordering::Acquire);
        let now_ms = epoch_millis();
        let recently_draining =
            last_ms > 0 && now_ms.saturating_sub(last_ms) <= RECENT_PACKET_WINDOW_MS;

        let topology = if recently_draining {
            "UDP Audio Sink (Experimental Preview - Draining Authenticated IUA2 Packets, No OS Playback)"
        } else {
            "UDP Audio Sink (Experimental Preview - Listening for Authenticated IUA2 Sessions, No OS Playback)"
        };

        AudioRoutingStatus {
            topology: topology.to_string(),
            latency_ms: 0.0,
            sample_rate: config::DEFAULT_AUDIO_SAMPLE_RATE,
            bit_depth: config::DEFAULT_AUDIO_BIT_DEPTH,
            is_active: false,
            port: AUDIO_PORT,
        }
    }

    #[allow(dead_code)]
    pub fn packets_drained() -> u64 {
        PACKETS_DRAINED.load(Ordering::Relaxed)
    }

    /// Resolves peer credentials directly by cryptographically authenticated `TransportSessionV2`
    /// `peer_device_id` when available, falling back to verified IP lookup only for local/test callers.
    pub fn handle_negotiate_session_for_peer(
        authenticated_peer_device_id: Option<&str>,
        caller_ip: IpAddr,
        sender_nonce_hex: &str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<NegotiatedAudioSessionWire, String> {
        let Some(sender_nonce) = security::hex_decode_array::<32>(sender_nonce_hex) else {
            return Err("Invalid 32-byte sender_nonce_hex".into());
        };
        if sender_nonce.iter().all(|&b| b == 0) {
            return Err("Rejected all-zero audio sender_nonce".into());
        }

        let peer_creds = match authenticated_peer_device_id {
            Some(peer_id) => trust::lookup_verified_peer_by_id_at_ip(peer_id, caller_ip)
                .ok_or_else(|| {
                    format!(
                        "No cryptographically paired non-blocked peer {} for {}",
                        peer_id, caller_ip
                    )
                })?,
            None => {
                let ip_str = caller_ip.to_string();
                trust::lookup_verified_peer_for_ip(&ip_str).ok_or_else(|| {
                    format!("No cryptographically paired peer found for {}", ip_str)
                })?
            }
        };

        let now = security::unix_epoch_secs();
        let res = {
            let mut reg = global_audio_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            reg.negotiate_receiver_session(
                peer_creds.device_id,
                peer_creds.trust_generation,
                &peer_creds.root_key,
                &sender_nonce,
                sample_rate,
                channels,
                bit_depth,
                now,
            )
        };
        res.map_err(|e| e.to_string())
    }

    /// Immediately and unconditionally evicts all active audio sessions associated with the given peer device ID hex.
    pub fn revoke_peer_audio_sessions(peer_device_id_hex: &str) -> usize {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let Some(peer_bytes) = security::hex_decode_array::<16>(&clean_id) else {
            return 0;
        };
        let mut reg = global_audio_registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.revoke_peer_sessions(&peer_bytes)
    }

    /// Negotiates an outbound `AudioSessionSender` with `peer_ip` over `TransportSessionV2` (`DisplayRpc`).
    #[allow(dead_code)]
    pub async fn negotiate_sender_session(
        peer_ip: &str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<AudioSessionSender> {
        let peer_creds = trust::lookup_verified_peer_for_ip(peer_ip)
            .ok_or_else(|| anyhow::anyhow!("Peer {} is not paired", peer_ip))?;
        let sender_nonce = security::csprng_array::<32>();
        let req = DisplayRpcRequest::NegotiateAudioSession {
            sender_nonce_hex: security::hex_encode(&sender_nonce),
            sample_rate,
            channels,
            bit_depth,
        };
        let resp = DisplayController::send_remote_rpc(peer_ip, &req).await?;
        if !resp.success {
            anyhow::bail!("Peer rejected audio session negotiation: {}", resp.message);
        }
        let wire = resp
            .audio_session
            .ok_or_else(|| anyhow::anyhow!("Peer response missing audio_session parameters"))?;
        if wire.expires_in_secs == 0 {
            anyhow::bail!("Peer returned zero audio session TTL");
        }
        if sample_rate == 0 || channels == 0 || bit_depth == 0 {
            anyhow::bail!("Invalid local audio stream parameters");
        }
        let session_id = security::hex_decode_array::<8>(&wire.session_id_hex)
            .ok_or_else(|| anyhow::anyhow!("Invalid session_id_hex from peer"))?;
        let receiver_nonce = security::hex_decode_array::<32>(&wire.receiver_nonce_hex)
            .ok_or_else(|| anyhow::anyhow!("Invalid receiver_nonce_hex from peer"))?;
        if receiver_nonce.iter().all(|&b| b == 0) {
            anyhow::bail!("Peer returned all-zero receiver_nonce");
        }

        let (k_audio, nonce_salt) = derive_audio_session_keys(
            &peer_creds.root_key,
            &sender_nonce,
            &receiver_nonce,
            &session_id,
        );
        let now = security::unix_epoch_secs();
        let bounded_ttl = wire.expires_in_secs.min(MAX_NEGOTIATED_AUDIO_TTL_SECS);
        Ok(AudioSessionSender::new(
            session_id,
            k_audio,
            nonce_salt,
            now.saturating_add(bounded_ttl),
        ))
    }

    /// Generates and plays a 24-bit 48kHz stereo test chime asynchronously off the Tokio pool.
    #[allow(dead_code)]
    pub async fn play_spatial_test_chime_async() -> Result<String> {
        tokio::task::spawn_blocking(Self::play_spatial_test_chime)
            .await
            .map_err(|e| anyhow::anyhow!("Audio chime task panicked: {}", e))?
    }

    /// Generates and plays a 24-bit 48kHz stereo test chime through the local
    /// host's default audio output.
    pub fn play_spatial_test_chime() -> Result<String> {
        let _guard = chime_file_lock().lock().unwrap_or_else(|e| e.into_inner());
        let data_dir = system_info::app_data_dir();
        std::fs::create_dir_all(&data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700));
        }
        let wav_path = data_dir.join("spatial_test_chime.wav");

        // Synthesize 24-bit 48kHz stereo WAV
        Self::synthesize_chime_wav(&wav_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&wav_path, std::fs::Permissions::from_mode(0o600));
        }

        // Play sound via native OS audio engine using qualified system binaries
        #[cfg(target_os = "macos")]
        {
            let child = Command::new(config::MACOS_AFPLAY_BIN)
                .arg(&wav_path)
                .spawn()
                .with_context(|| format!("Failed to spawn {}", config::MACOS_AFPLAY_BIN))?;

            reap_child(child);
            Ok("Played 24-bit 48kHz stereo chime via macOS audio output".to_string())
        }
        #[cfg(target_os = "windows")]
        {
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let path_str = wav_path.to_string_lossy().to_string();
            let ps_cmd = format!(
                "(New-Object Media.SoundPlayer '{}').PlaySync()",
                path_str.replace('\'', "''")
            );
            let ps_exe = crate::system_info::system32_exe(config::POWERSHELL_SYSTEM32_REL_PATH);
            let mut cmd = Command::new(ps_exe);
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            let child = cmd
                .spawn()
                .context("Failed to spawn PowerShell SoundPlayer")?;

            reap_child(child);
            Ok("Played 24-bit 48kHz stereo chime via Windows audio output".to_string())
        }
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            let _ = wav_path;
            Ok("Synthesized 24-bit 48kHz stereo chime (no native playback backend on this OS)"
                .to_string())
        }
    }

    /// Synthesizes a binaural / stereo 24-bit 48kHz WAV chime into the target file.
    fn synthesize_chime_wav(path: &Path) -> Result<()> {
        let sample_rate = 48000usize;
        let duration_secs = 1.2f32;
        let total_frames = (sample_rate as f32 * duration_secs) as usize;
        let num_channels = 2usize;
        let bytes_per_sample = 3usize; // 24-bit

        let raw_file = File::create(path)?;
        let mut file = BufWriter::with_capacity(64 * 1024, raw_file);

        // RIFF WAVE Header for 24-bit stereo 48000Hz PCM
        let block_align = (num_channels * bytes_per_sample) as u16;
        let byte_rate = (sample_rate as u32) * (block_align as u32);
        let data_chunk_size = (total_frames * num_channels * bytes_per_sample) as u32;
        let riff_chunk_size = 36 + data_chunk_size;

        // "RIFF"
        file.write_all(b"RIFF")?;
        file.write_all(&riff_chunk_size.to_le_bytes())?;
        file.write_all(b"WAVE")?;

        // "fmt " chunk
        file.write_all(b"fmt ")?;
        file.write_all(&16u32.to_le_bytes())?; // Subchunk1Size (16 for PCM)
        file.write_all(&1u16.to_le_bytes())?; // AudioFormat (1 = PCM)
        file.write_all(&(num_channels as u16).to_le_bytes())?;
        file.write_all(&(sample_rate as u32).to_le_bytes())?;
        file.write_all(&byte_rate.to_le_bytes())?;
        file.write_all(&block_align.to_le_bytes())?;
        file.write_all(&24u16.to_le_bytes())?; // BitsPerSample

        // "data" chunk
        file.write_all(b"data")?;
        file.write_all(&data_chunk_size.to_le_bytes())?;

        // Synthesize harmonic chime tones (C5 523.25 Hz, G5 783.99 Hz, C6 1046.50 Hz)
        let f1 = 523.25f32;
        let f2 = 783.99f32;
        let f3 = 1046.50f32;

        let two_pi = std::f32::consts::PI * 2.0;

        for i in 0..total_frames {
            let t = i as f32 / sample_rate as f32;

            // Envelope: 8ms linear attack, smooth exponential decay
            let attack = (t / 0.008).min(1.0);
            let decay = (-3.8 * t).exp();
            let env = attack * decay;

            let s1 = (two_pi * f1 * t).sin() * 0.45;
            let s2 = (two_pi * f2 * t).sin() * 0.35;
            let s3 = (two_pi * f3 * t).sin() * 0.15;
            let mono_sample = (s1 + s2 + s3) * env;

            let left_pan = 1.05f32;
            let right_pan = 0.95f32;

            let sample_l = (mono_sample * left_pan).clamp(-1.0, 1.0);
            let sample_r = (mono_sample * right_pan).clamp(-1.0, 1.0);

            // Convert to 24-bit signed PCM (-8388608 to 8388607)
            let val_l = (sample_l * 8388600.0) as i32;
            let val_r = (sample_r * 8388600.0) as i32;

            let b_l = val_l.to_le_bytes();
            let b_r = val_r.to_le_bytes();

            file.write_all(&b_l[0..3])?;
            file.write_all(&b_r[0..3])?;
        }

        file.flush()?;
        Ok(())
    }

    /// Starts the experimental authenticated UDP audio preview sink receiver on [`AUDIO_PORT`].
    ///
    /// Enforces per-datagram `IUA2` `ChaCha20-Poly1305` authentication, 64-packet sliding-window
    /// anti-replay protection, and session expiry while rate-limiting warnings so LAN floods
    /// cannot spam logs.
    pub async fn start_sink_server() -> Result<()> {
        if SINK_LISTENING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let guard = SinkListeningGuard;

        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", AUDIO_PORT)).await?;
        tracing::info!(
            "🔊 Experimental Authenticated UDP Audio Sink (IUA2 Preview) listening on port {} (AEAD + 64-pkt replay window; OS playback not active)",
            AUDIO_PORT
        );

        tokio::spawn(async move {
            let _guard = guard;
            // Allocate 1 byte beyond MAX_AUDIO_DATAGRAM_LEN so oversized datagrams
            // on Unix are detected via `size > MAX_AUDIO_DATAGRAM_LEN`.
            let mut buf = vec![0u8; MAX_AUDIO_DATAGRAM_LEN + 1];
            let mut last_unauth_log: Option<Instant> = None;
            let mut last_bounds_log: Option<Instant> = None;
            let mut last_err_log: Option<Instant> = None;

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, peer)) => {
                        if !(MIN_AUDIO_DATAGRAM_LEN..=MAX_AUDIO_DATAGRAM_LEN).contains(&size) {
                            if rate_limit_allow(&mut last_bounds_log) {
                                tracing::warn!(
                                    "⚠️ Dropped out-of-bounds UDP audio datagram ({} bytes, expected {}..={}) from {} (rate-limited {}s)",
                                    size,
                                    MIN_AUDIO_DATAGRAM_LEN,
                                    MAX_AUDIO_DATAGRAM_LEN,
                                    peer.ip(),
                                    LOG_RATE_LIMIT.as_secs()
                                );
                            }
                            continue;
                        }

                        let now_secs = security::unix_epoch_secs();
                        let verify_res = {
                            let mut reg = global_audio_registry()
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            reg.open_incoming_datagram(&buf[..size], now_secs)
                        };

                        match verify_res {
                            Ok((_peer_id, _hdr, _plaintext)) => {
                                PACKETS_DRAINED.fetch_add(1, Ordering::Relaxed);
                                LAST_PACKET_EPOCH_MS.store(epoch_millis(), Ordering::Relaxed);
                            }
                            Err(reason) => {
                                if rate_limit_allow(&mut last_unauth_log) {
                                    tracing::warn!(
                                        "🚫 Dropped unauthenticated/replayed IUA2 UDP audio packet from {} on port {}: {} (rate-limited {}s)",
                                        peer.ip(),
                                        AUDIO_PORT,
                                        reason,
                                        LOG_RATE_LIMIT.as_secs()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let raw = e.raw_os_error();
                        // Windows WSAEMSGSIZE (10040) / WSAECONNRESET (10054) can be triggered
                        // by single malformed/transient datagrams and must not stall the loop.
                        let is_datagram_err = matches!(raw, Some(10040 | 10054));
                        if rate_limit_allow(&mut last_err_log) {
                            tracing::warn!(
                                "Audio UDP receiver error on port {} (rate-limited {}s): {}",
                                AUDIO_PORT,
                                LOG_RATE_LIMIT.as_secs(),
                                e
                            );
                        }
                        if !is_datagram_err {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::audio_udp::AUDIO_FLAG_PCM_FRAME;

    #[test]
    fn default_status_is_honest_experimental_preview() {
        let status = AudioRoutingStatus::default();
        assert!(!status.is_active);
        assert_eq!(status.latency_ms, 0.0);
        assert_eq!(status.sample_rate, config::DEFAULT_AUDIO_SAMPLE_RATE);
        assert_eq!(status.bit_depth, config::DEFAULT_AUDIO_BIT_DEPTH);
        assert_eq!(status.port, AUDIO_PORT);
        assert_eq!(
            status.topology,
            "UDP Audio Sink (Experimental Preview - Offline)"
        );
    }

    #[test]
    fn audio_routing_status_serde_defaults_preserve_backward_compatibility() {
        let legacy_json = r#"{
            "topology": "UDP Audio Sink (Experimental Preview - Offline)",
            "latency_ms": 0.0,
            "sample_rate": 48000,
            "bit_depth": 24,
            "is_active": false
        }"#;
        let parsed: AudioRoutingStatus = serde_json::from_str(legacy_json)
            .expect("legacy AudioRoutingStatus JSON should deserialize");
        assert_eq!(parsed.port, AUDIO_PORT);

        let serialized =
            serde_json::to_string(&parsed).expect("AudioRoutingStatus should serialize");
        let roundtrip: AudioRoutingStatus =
            serde_json::from_str(&serialized).expect("AudioRoutingStatus should roundtrip");
        assert_eq!(roundtrip.port, AUDIO_PORT);
    }

    #[test]
    fn reject_all_zero_sender_nonce_and_authenticate_by_device_id() {
        let zeros = "00".repeat(32);
        assert!(AudioManager::handle_negotiate_session_for_peer(
            None,
            "127.0.0.1".parse().unwrap(),
            &zeros,
            48_000,
            2,
            24
        )
        .is_err());

        let nonce = security::hex_encode(&security::csprng_array::<32>());
        let local_id = trust::local_device_id_hex();
        let wire = AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            24,
        );
        assert!(wire.is_ok());

        // Unknown device_id must fail even on loopback
        assert!(AudioManager::handle_negotiate_session_for_peer(
            Some(&"ff".repeat(16)),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            24,
        )
        .is_err());
    }

    #[test]
    fn negotiate_and_verify_loopback_iua2_session() {
        let sender_nonce = security::csprng_array::<32>();
        let sender_nonce_hex = security::hex_encode(&sender_nonce);
        let wire = AudioManager::handle_negotiate_session_for_peer(
            None,
            "127.0.0.1".parse().unwrap(),
            &sender_nonce_hex,
            48_000,
            2,
            24,
        )
        .expect("negotiate loopback audio session");

        let creds = trust::lookup_verified_peer_for_ip("127.0.0.1").unwrap();
        let session_id = security::hex_decode_array::<8>(&wire.session_id_hex).unwrap();
        let receiver_nonce = security::hex_decode_array::<32>(&wire.receiver_nonce_hex).unwrap();
        let (k_audio, nonce_salt) = derive_audio_session_keys(
            &creds.root_key,
            &sender_nonce,
            &receiver_nonce,
            &session_id,
        );
        let now = security::unix_epoch_secs();
        let mut sender = AudioSessionSender::new(
            session_id,
            k_audio,
            nonce_salt,
            now + wire.expires_in_secs,
        );

        let dgram = sender
            .seal_datagram(AUDIO_FLAG_PCM_FRAME, 1000, 48, &[0x11u8; 288], now)
            .unwrap();
        let mut reg = global_audio_registry().lock().unwrap();
        let (peer_id, hdr, plain) = reg.open_incoming_datagram(&dgram, now).unwrap();
        assert_eq!(peer_id, creds.device_id);
        assert_eq!(hdr.pkt_seq, 1);
        assert_eq!(plain.len(), 288);
    }
}
