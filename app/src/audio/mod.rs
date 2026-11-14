//! Experimental UDP Audio Sink (Preview) and local speaker chime synthesis.
//!
//! Binds [`AUDIO_PORT`] as an experimental UDP audio preview sink that validates
//! sender authorization and datagram bounds before draining packets (full
//! WASAPI <-> CoreAudio duplex streaming is not yet implemented), and provides
//! local 24-bit 48kHz stereo WAV chime synthesis for speaker verification.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use crate::{config, system_info, trust};

pub const AUDIO_PORT: u16 = config::AUDIO_PORT;

/// Accepted UDP audio preview datagram bounds in bytes (1..=8192 covers
/// standard 5-20ms PCM frames without accepting empty or oversized packets).
const MIN_AUDIO_PACKET_BYTES: usize = 1;
const MAX_AUDIO_PACKET_BYTES: usize = 8192;

const AUTH_CACHE_TTL: Duration = Duration::from_secs(5);
const AUTH_CACHE_MAX_ENTRIES: usize = 64;
const UNKNOWN_AUTH_WINDOW: Duration = Duration::from_secs(5);
const MAX_UNKNOWN_AUTH_PROBES_PER_WINDOW: usize = 16;
const LOG_RATE_LIMIT: Duration = Duration::from_secs(30);
const RECENT_PACKET_WINDOW_MS: u64 = 5_000;

static SINK_LISTENING: AtomicBool = AtomicBool::new(false);
static LAST_PACKET_EPOCH_MS: AtomicU64 = AtomicU64::new(0);
static PACKETS_DRAINED: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioRoutingStatus {
    pub topology: String,
    pub latency_ms: f32,
    pub sample_rate: u32,
    pub bit_depth: u8,
    pub is_active: bool,
}

impl Default for AudioRoutingStatus {
    fn default() -> Self {
        Self {
            topology: "UDP Audio Sink (Experimental Preview - Offline)".to_string(),
            latency_ms: 0.0,
            sample_rate: 48_000,
            bit_depth: 24,
            is_active: false,
        }
    }
}

struct SinkListeningGuard;

impl Drop for SinkListeningGuard {
    fn drop(&mut self) {
        SINK_LISTENING.store(false, Ordering::Release);
    }
}

struct SenderAuthFilter {
    cache: HashMap<IpAddr, (bool, Instant)>,
    window_start: Instant,
    unknown_probes_in_window: usize,
    last_unauth_log: Option<Instant>,
    last_bounds_log: Option<Instant>,
}

impl SenderAuthFilter {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            window_start: Instant::now(),
            unknown_probes_in_window: 0,
            last_unauth_log: None,
            last_bounds_log: None,
        }
    }

    async fn is_authorized(&mut self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }

        let now = Instant::now();
        if let Some(&(allowed, cached_at)) = self.cache.get(&ip) {
            if now.duration_since(cached_at) < AUTH_CACHE_TTL {
                return allowed;
            }
        }

        if now.duration_since(self.window_start) >= UNKNOWN_AUTH_WINDOW {
            self.window_start = now;
            self.unknown_probes_in_window = 0;
        }

        if self.unknown_probes_in_window >= MAX_UNKNOWN_AUTH_PROBES_PER_WINDOW {
            return false;
        }
        self.unknown_probes_in_window += 1;

        let allowed = tokio::task::spawn_blocking(move || trust::is_remote_addr_authorized(ip))
            .await
            .unwrap_or(false);

        if self.cache.len() >= AUTH_CACHE_MAX_ENTRIES {
            self.cache
                .retain(|_, &mut (_, ts)| now.duration_since(ts) < AUTH_CACHE_TTL);
            if self.cache.len() >= AUTH_CACHE_MAX_ENTRIES {
                self.cache.clear();
            }
        }
        self.cache.insert(ip, (allowed, now));
        allowed
    }

    fn should_log_unauth(&mut self) -> bool {
        rate_limit_allow(&mut self.last_unauth_log)
    }

    fn should_log_bounds(&mut self) -> bool {
        rate_limit_allow(&mut self.last_bounds_log)
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn reap_child(mut child: std::process::Child) {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || {
            let _ = child.wait();
        });
    } else {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
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
            "UDP Audio Sink (Experimental Preview - Draining Packets, No OS Playback)"
        } else {
            "UDP Audio Sink (Experimental Preview - Listening, No OS Playback)"
        };

        AudioRoutingStatus {
            topology: topology.to_string(),
            latency_ms: 0.0,
            sample_rate: 48_000,
            bit_depth: 24,
            is_active: false,
        }
    }

    #[allow(dead_code)]
    pub fn packets_drained() -> u64 {
        PACKETS_DRAINED.load(Ordering::Relaxed)
    }

    /// Generates and plays a 24-bit 48kHz stereo test chime through the local
    /// host's default audio output.
    pub fn play_spatial_test_chime() -> Result<String> {
        let wav_path = system_info::app_data_dir().join("spatial_test_chime.wav");

        // Synthesize 24-bit 48kHz stereo WAV
        Self::synthesize_chime_wav(&wav_path)?;

        // Play sound via native OS audio engine
        #[cfg(target_os = "macos")]
        {
            let child = Command::new("afplay")
                .arg(&wav_path)
                .spawn()
                .context("Failed to spawn afplay")?;

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
            let mut cmd = Command::new("powershell.exe");
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

        let mut file = File::create(path)?;

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

    /// Starts the experimental UDP audio preview sink receiver on [`AUDIO_PORT`].
    ///
    /// Enforces peer trust via [`trust::is_remote_addr_authorized`] and checks
    /// datagram byte bounds while rate-limiting warnings so LAN floods cannot
    /// spam logs.
    pub async fn start_sink_server() -> Result<()> {
        if SINK_LISTENING.load(Ordering::Acquire) {
            return Ok(());
        }

        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", AUDIO_PORT)).await?;
        SINK_LISTENING.store(true, Ordering::Release);
        tracing::info!(
            "🔊 Experimental UDP Audio Sink (Preview) listening on port {} (packets validated & drained; OS playback not active)",
            AUDIO_PORT
        );

        tokio::spawn(async move {
            let _guard = SinkListeningGuard;
            // Allocate 1 byte beyond MAX_AUDIO_PACKET_BYTES so oversized datagrams
            // on Unix are detected via `size > MAX_AUDIO_PACKET_BYTES` rather than
            // silently passing at the exact boundary.
            let mut buf = vec![0u8; MAX_AUDIO_PACKET_BYTES + 1];
            let mut auth_filter = SenderAuthFilter::new();
            let mut last_err_log: Option<Instant> = None;

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, peer)) => {
                        if !auth_filter.is_authorized(peer.ip()).await {
                            if auth_filter.should_log_unauth() {
                                tracing::warn!(
                                    "🚫 Dropped unauthorized UDP audio packet from {} on port {} (rate-limited {}s)",
                                    peer.ip(),
                                    AUDIO_PORT,
                                    LOG_RATE_LIMIT.as_secs()
                                );
                            }
                            continue;
                        }

                        if !(MIN_AUDIO_PACKET_BYTES..=MAX_AUDIO_PACKET_BYTES).contains(&size) {
                            if auth_filter.should_log_bounds() {
                                tracing::warn!(
                                    "⚠️ Dropped out-of-bounds UDP audio packet ({} bytes, expected {}..={}) from {} (rate-limited {}s)",
                                    size,
                                    MIN_AUDIO_PACKET_BYTES,
                                    MAX_AUDIO_PACKET_BYTES,
                                    peer.ip(),
                                    LOG_RATE_LIMIT.as_secs()
                                );
                            }
                            continue;
                        }

                        // Experimental preview: packet authorized and within bounds; drained cleanly.
                        PACKETS_DRAINED.fetch_add(1, Ordering::Relaxed);
                        LAST_PACKET_EPOCH_MS.store(epoch_millis(), Ordering::Relaxed);
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

    #[test]
    fn default_status_is_honest_experimental_preview() {
        let status = AudioRoutingStatus::default();
        assert!(!status.is_active);
        assert_eq!(status.latency_ms, 0.0);
        assert_eq!(status.sample_rate, 48_000);
        assert_eq!(status.bit_depth, 24);
        assert_eq!(
            status.topology,
            "UDP Audio Sink (Experimental Preview - Offline)"
        );
    }

    #[tokio::test]
    async fn sender_auth_allows_loopback_and_rate_limits_logs() {
        let mut filter = SenderAuthFilter::new();
        assert!(filter.is_authorized("127.0.0.1".parse().unwrap()).await);
        assert!(filter.should_log_unauth());
        assert!(!filter.should_log_unauth());
        assert!(filter.should_log_bounds());
        assert!(!filter.should_log_bounds());
    }
}
