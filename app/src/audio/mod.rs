//! # Authenticated UDP Audio Sink (`IUA2`) & Dynamic Audio Routing Subsystem
//!
//! ## 1. Module Purpose & Scope
//! This module implements the Authenticated UDP Audio Sink (`IUA2` protocol) on UDP port
//! `AUDIO_PORT = 58284`, Windows 11 WASAPI loopback audio capture (`win_capture.cpp`),
//! macOS native C11 CoreAudio playback & lock-free SPSC (`audio_macos.c`), macOS HAL shared-memory
//! capture (`IntegratorAudioDriver.c`), and local speaker test chime synthesis for the Integrator engine.
//!
//! ### Hardened Batch 1G.8-r2 Concurrency, Lifecycle & Security Invariants:
//! - **Deadlock-Free Two-Phase Lifecycle (`NEW-01`, `AUD-1G7-07`)**: `AUDIO_LIFECYCLE_LOCK`
//!   is NEVER held across remote TCP RPC `.await` points. All remote calls run unlocked under
//!   a reserved `ROUTING_GENERATION` token and re-verify generation, `AUDIO_SHUTDOWN`,
//!   `AUDIO_ENABLED`, and fail-closed peer trust upon re-acquiring the lock.
//! - **Synchronized Playout State (`NEW-02`, `NEW-03`, `NEW-04`, `AUD-1G7-05/08`)**:
//!   `PLAYOUT_STATE_LOCK` atomically coordinates `PLAYOUT_ACTIVE`, CoreAudio start/stop,
//!   `JitterBuffer` push/reset, and `PLAYOUT_WORKER_HANDLE` swaps. `PlayoutWorkerGuard::drop`
//!   stops CoreAudio *before* clearing `PLAYOUT_ACTIVE`, eliminating the idle-timeout wedge.
//! - **Cross-Peer & Format Isolation (`NEW-02`, `NEW-06`, `AUD-1G7-10/15`)**:
//!   Inbound UDP frames are verified against `ACTIVE_CAPTURE_TARGET.peer_device_id` (preventing
//!   cross-peer speaker hijack), require canonical 48 kHz / 2ch / 16-bit / 240-sample framing,
//!   filter `AUDIO_FLAG_KEEPALIVE` before `JitterBuffer`, and enforce session ownership on both
//!   `StartAudioCapture` and `StopAudioCapture`.
//! - **Generation-Scoped Windows WASAPI Teardown (`NEW-05`, `NEW-1G8-03`)**:
//!   `integrator_win_audio_capture_start(gen)`, `integrator_win_audio_capture_stop_if_gen(gen)`,
//!   and `integrator_on_win_audio_capture_ended(gen, reason)` bind native capture strictly to
//!   its owning `ROUTING_GENERATION` so stale workers or drop threads can never disturb newer sessions.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `crate::core::IntegratorCore`: Starts the UDP sink server at daemon boot, updates mixer balance/mute
//!     (`AudioManager::set_mixer`), exposes telemetry via `AudioManager::status()`, triggers spatial test
//!     chimes (`play_spatial_test_chime`), and invokes `revoke_peer_audio_sessions()` on peer unpair/block.
//!   - `crate::display::controller::DisplayController`: Handles authenticated `DisplayRpcRequest`
//!     commands (`NegotiateAudioSession`, `StartAudioCapture`, `StopAudioCapture`, `StartAudioRouting`,
//!     `StopAudioRouting`, `GetAudioStatus`).
//!   - `crate::ffi`: Calls `AudioManager::shutdown_sync()` during host process teardown.
//! - **Downstream Callees**:
//!   - `crate::audio::jitter::JitterBuffer`: Bounded 64-slot ring jitter buffer with `session_order`
//!     isolation and `min_seq_floor` rewind protection.
//!   - `crate::security::audio_udp`: `AudioSessionRegistry` and `AudioSessionSender` providing
//!     HKDF-SHA256 session keys, ChaCha20-Poly1305 AEAD framing, and 64-packet replay windows.
//!   - `crate::security::transport`: `check_peer_trust_generation_fail_closed` for continuous revocation checks.
//!   - Native FFI (`audio_macos.c`, `win_capture.cpp`, macOS POSIX `shm_open` for `IntegratorAudioDriver`).
//! - **Cross-Platform / Cross-Device Flow**:
//!   - Windows 11 WASAPI loopback (or macOS HAL shared-memory virtual device) captures 5 ms 48 kHz
//!     stereo PCM16 frames, encrypts them as `IUA2` UDP datagrams over port `58284`, and streams to
//!     the paired peer's UDP sink -> `JitterBuffer` -> 5 ms playout timer -> `apply_mixer_gain_pcm16` ->
//!     CoreAudio C11 SPSC ring buffer.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Async Tasks**: `SINK_RECEIVER_TASK` (UDP 58284 decrypt/push loop), `PLAYOUT_WORKER_HANDLE`
//!   (5 ms `tokio::time::interval` playout pump), `SENDER_TASK` (AEAD sealing + UDP `send_to`), and
//!   `MAC_CAPTURE_TASK` (macOS SHM polling).
//! - **Real-Time OS Threads**: Windows WASAPI MMCSS capture thread calls `integrator_on_win_audio_captured`
//!   and uses `try_lock()` + bounded `try_send(16)` on `SENDER_CHANNEL` so real-time audio callbacks
//!   never block on mutexes or network I/O.
//! - **Lock Ordering Invariant**:
//!   1. `AUDIO_LIFECYCLE_LOCK` (async mutex, NEVER held across remote network RPC `.await`)
//!   2. `PLAYOUT_STATE_LOCK` (short sync mutex, NEVER held across `.await`)
//!   3. Leaf locks: `ACTIVE_CAPTURE_TARGET`, `JITTER_BUFFER`, `AUDIO_SESSION_REGISTRY`,
//!      `PLAYOUT_WORKER_HANDLE`, `SENDER_CHANNEL`, `SENDER_TASK`, `SINK_RECEIVER_TASK`, `MAC_CAPTURE_TASK`
//!   Waiters always acquire outer locks before leaf locks and never acquire `PLAYOUT_STATE_LOCK` while
//!   holding a leaf lock.
//!
//! ## 4. Security & Safety Invariants
//! - **Zero Unauthenticated Playout**: Every UDP datagram must pass ChaCha20-Poly1305 AEAD tag verification,
//!   anti-replay sliding window checks, and constant-time `ACTIVE_CAPTURE_TARGET.peer_device_id` matching.
//! - **Fail-Closed Trust & Feature Gates**: Both sender and receiver paths check `AUDIO_SHUTDOWN`,
//!   `AUDIO_ENABLED`, and `check_peer_trust_generation_fail_closed` before starting and continuously
//!   during active streaming.
//! - **Canonical Frame Enforcement**: Stage 1 accepts only 48,000 Hz, 2-channel, 16-bit PCM frames of
//!   240 samples/channel (960 bytes) or 1-byte `AUDIO_FLAG_SILENCE` frames.
//! - **Audio Mixer Safety**: `apply_mixer_gain_pcm16` guards against NaN/Inf balance inputs and clamps
//!   scaled samples strictly within `[i16::MIN, i16::MAX]` to prevent wraparound distortion.

pub mod jitter;

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
use tokio::sync::Notify;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use crate::display::controller::DisplayController;
use crate::display::protocol::DisplayRpcRequest;
use crate::security::audio_udp::{
    derive_audio_session_keys, AudioSessionRegistry, AudioSessionSender, AudioUdpError,
    NegotiatedAudioSessionWire, AUDIO_FLAG_KEEPALIVE, AUDIO_FLAG_PCM_FRAME, AUDIO_FLAG_SILENCE,
    AUDIO_FRAME_BYTES, AUDIO_FRAME_MS, AUDIO_FRAME_SAMPLES_PER_CH, AUDIO_SESSION_TTL_SECS,
    MAX_AUDIO_DATAGRAM_LEN, MIN_AUDIO_DATAGRAM_LEN,
};
use crate::security::keystore::VerifiedPeerCredentials;
use crate::security::transport::{check_peer_trust_generation_fail_closed, PeerTrustCheck};
use crate::{config, security, system_info, trust};

/// UDP port bound by the Authenticated UDP Audio Sink (`IUA2`) listener (`58284`).
pub const AUDIO_PORT: u16 = config::AUDIO_PORT;

/// Canonical PCM audio sample rate: 48,000 Hz.
pub const CANONICAL_SAMPLE_RATE: u32 = 48_000;
/// Canonical PCM audio channel count: 2 (Stereo).
pub const CANONICAL_CHANNELS: u8 = 2;
/// Canonical PCM audio bit depth: 16-bit signed integer.
pub const CANONICAL_BIT_DEPTH: u8 = 16;
/// Canonical audio frame duration in milliseconds: 5 ms.
pub const CANONICAL_FRAME_MS: u32 = AUDIO_FRAME_MS;
/// Canonical 5ms stereo 16-bit PCM frame byte size: 960 bytes.
pub const CANONICAL_FRAME_BYTES: usize = AUDIO_FRAME_BYTES;

/// Minimum interval between repeated warning/error log emissions per category (30 seconds).
const LOG_RATE_LIMIT: Duration = Duration::from_secs(30);
/// Idle window (ms) after the last received packet before the playout worker auto-stops (5,000 ms).
const RECENT_PACKET_WINDOW_MS: u64 = 5_000;
/// Minimum interval between CoreAudio HAL restart attempts after a start failure (500 ms).
const HAL_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Maximum permitted lifetime in seconds for a negotiated `IUA2` audio session (900 s / 15 min).
pub const MAX_NEGOTIATED_AUDIO_TTL_SECS: u64 = AUDIO_SESSION_TTL_SECS;

/// Active audio capture/routing session metadata and cryptographic binding.
#[derive(Debug, Clone)]
pub struct ActiveCaptureTarget {
    /// IP address string of the remote peer currently bound to active capture or playback.
    pub peer_ip: String,
    /// 16-byte binary Ed25519-derived device ID of the active peer for constant-time packet checks.
    pub peer_device_id: [u8; 16],
    /// Keystore/transport trust generation active when this audio session was authorized.
    pub trust_generation: u64,
    /// Monotonic `ROUTING_GENERATION` token isolating this session from stale workers and RPCs.
    pub routing_generation: u64,
}

/// Latch set permanently during daemon shutdown to prevent post-shutdown task resurrection.
static AUDIO_SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Runtime feature gate mirroring `"audio"` in `FeatureManager` (`true` when enabled).
static AUDIO_ENABLED: AtomicBool = AtomicBool::new(true);
/// True while the UDP 58284 sink receiver task is bound and actively listening.
static SINK_LISTENING: AtomicBool = AtomicBool::new(false);
/// Monotonic generation counter for UDP sink listener lifecycles (`SinkListeningGuard`).
static SINK_GENERATION: AtomicU64 = AtomicU64::new(0);
/// True while the 5 ms playout worker and native macOS CoreAudio unit are active.
static PLAYOUT_ACTIVE: AtomicBool = AtomicBool::new(false);
/// True while an end-to-end audio routing session (capture or playback) is active.
static ROUTING_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Monotonic routing generation counter incremented on every start, stop, revocation, or shutdown.
static ROUTING_GENERATION: AtomicU64 = AtomicU64::new(1);
/// Unix epoch timestamp (milliseconds) of the most recent authenticated UDP audio packet received.
static LAST_PACKET_EPOCH_MS: AtomicU64 = AtomicU64::new(0);
/// Cumulative count of authenticated UDP audio packets drained by the sink receiver.
static PACKETS_DRAINED: AtomicU64 = AtomicU64::new(0);
/// Cross-platform audio mixer balance encoded as fixed-point millis in `-1000..=1000` (`-1.0..=+1.0`).
/// `-1.0` = boost Mac / mute Windows; `0.0` = balanced; `+1.0` = boost Windows / duck Mac.
static AUDIO_MIXER_BALANCE_MILLIS: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// Instant one-tap mute flag for the Windows remote audio soundbar sink.
static AUDIO_SINK_MUTED: AtomicBool = AtomicBool::new(false);

/// Serializes local lifecycle transitions (NEVER held across remote network RPC `.await` points).
static AUDIO_LIFECYCLE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
/// Short non-async lock coordinating `PLAYOUT_ACTIVE`, CoreAudio start/stop, `JitterBuffer` push/reset,
/// and generation-checked `PLAYOUT_WORKER_HANDLE` updates (never held across `.await`).
static PLAYOUT_STATE_LOCK: Mutex<()> = Mutex::new(());

/// Global registry holding active ChaCha20-Poly1305 `AudioSessionReceiver` instances keyed by `session_id`.
static AUDIO_SESSION_REGISTRY: OnceLock<Mutex<AudioSessionRegistry>> = OnceLock::new();
/// Serializes synthesis and playback of the local `spatial_test_chime.wav` file.
static CHIME_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
/// Global bounded 64-slot jitter buffer feeding the macOS CoreAudio playout worker.
static JITTER_BUFFER: OnceLock<Mutex<jitter::JitterBuffer>> = OnceLock::new();
/// Cooperative cancellation notifier waking the 5 ms playout worker immediately on stop/shutdown.
static PLAYOUT_CANCEL_NOTIFY: OnceLock<Notify> = OnceLock::new();
/// Cooperative cancellation notifier waking the UDP sink `recv_from` loop immediately on stop/shutdown.
static SINK_CANCEL_NOTIFY: OnceLock<Notify> = OnceLock::new();

/// Currently authorized remote capture/playback target bound to `ROUTING_GENERATION`.
static ACTIVE_CAPTURE_TARGET: Mutex<Option<ActiveCaptureTarget>> = Mutex::new(None);
/// JoinHandle of the outbound UDP AEAD encryption and transmission task.
static SENDER_TASK: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
/// JoinHandle of the inbound UDP port 58284 receiver task.
static SINK_RECEIVER_TASK: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
/// JoinHandle of the 5 ms jitter-buffer-to-CoreAudio playout worker task.
static PLAYOUT_WORKER_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
/// JoinHandle of the macOS HAL shared-memory capture polling task.
#[cfg(target_os = "macos")]
static MAC_CAPTURE_TASK: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

/// Single 5 ms PCM16 stereo capture frame transferred from OS capture callbacks to `SENDER_TASK`.
#[derive(Clone)]
struct CapturedFrameData {
    /// Valid PCM payload byte count (`<= CANONICAL_FRAME_BYTES` = 960 bytes; `0` when `is_silent`).
    len: usize,
    /// True when the capture backend detected digital silence (`AUDIO_FLAG_SILENCE` compact packet).
    is_silent: bool,
    /// Fixed-size stack buffer holding raw 48 kHz 2ch 16-bit little-endian PCM bytes.
    data: [u8; CANONICAL_FRAME_BYTES],
}

/// Bounded 16-slot MPSC sender connecting real-time OS capture callbacks to `SENDER_TASK`.
static SENDER_CHANNEL: Mutex<Option<tokio::sync::mpsc::Sender<CapturedFrameData>>> = Mutex::new(None);

#[cfg(target_os = "macos")]
extern "C" {
    /// Prewarms CoreAudio AudioUnit state before starting playback. Returns `0` on success.
    fn integrator_mac_audio_prewarm() -> i32;
    /// Starts the macOS CoreAudio output `AudioUnit`. Returns `0` on success or `-1` on HAL failure.
    fn integrator_mac_audio_start() -> i32;
    /// Stops and disposes the active macOS CoreAudio output `AudioUnit`.
    fn integrator_mac_audio_stop();
    /// Returns non-zero if the macOS CoreAudio output `AudioUnit` is actively rendering.
    fn integrator_mac_audio_is_active() -> i32;
    /// Writes `len` bytes of 48 kHz 2ch 16-bit PCM into the lock-free C11 SPSC ring buffer.
    fn integrator_mac_audio_write_pcm(data: *const u8, len: u32) -> u32;
    /// Returns the cumulative number of CoreAudio render-callback SPSC underruns.
    fn integrator_mac_audio_underruns() -> u64;
    /// Flushes any buffered audio frames in the macOS C11 SPSC ring buffer (test-only).
    #[cfg(test)]
    fn integrator_mac_audio_flush();
    /// Applies local macOS audio ducking corresponding to mixer `balance` (`-1.0..=+1.0`).
    fn integrator_mac_audio_set_local_duck(balance: f32);
    /// Returns the number of unread PCM bytes currently queued in the C11 SPSC ring buffer.
    #[cfg(test)]
    fn integrator_mac_audio_buffered_bytes() -> u32;
    /// Simulates a CoreAudio render pull of `requested_bytes` into `out` for SPSC unit testing.
    #[cfg(test)]
    fn integrator_mac_audio_test_render_pull(out: *mut u8, requested_bytes: u32) -> u32;
    /// Resets the C11 SPSC ring buffer and counters between unit tests.
    #[cfg(test)]
    fn integrator_mac_audio_test_reset();
}

#[cfg(target_os = "windows")]
extern "C" {
    /// Starts Windows WASAPI loopback capture bound to `capture_gen`. Returns `true` on success.
    fn integrator_win_audio_capture_start(capture_gen: u64) -> bool;
    /// Stops the active Windows WASAPI loopback capture session and joins the worker thread.
    fn integrator_win_audio_capture_stop();
    /// Stops Windows WASAPI loopback capture only if the active session matches `expected_gen`.
    fn integrator_win_audio_capture_stop_if_gen(expected_gen: u64);
    /// Returns `true` while the Windows WASAPI loopback capture worker is actively capturing.
    fn integrator_win_audio_capture_is_active() -> bool;
    /// Returns cumulative 5 ms frames read from the Windows WASAPI loopback endpoint.
    fn integrator_win_audio_capture_frames_read() -> u64;
    /// Returns cumulative WASAPI buffer discontinuity flags observed during capture.
    fn integrator_win_audio_capture_discontinuities() -> u64;
    /// Exercises the C1 `$C^1$`-smooth soft limiter DSP curve in unit tests.
    #[cfg(test)]
    fn integrator_win_audio_test_soft_limit(x: f32) -> f32;
    /// Exercises UB-free 24-bit signed PCM little-endian decoding in unit tests.
    #[cfg(test)]
    fn integrator_win_audio_test_decode_pcm24(b0: u8, b1: u8, b2: u8) -> f32;
    /// Exercises the `GetDevicePeriod`-calibrated silence-entry holdoff predicate in unit tests.
    #[cfg(test)]
    fn integrator_win_audio_test_should_emit_silence(
        elapsed_since_packet_us: f64,
        default_period_us: f64,
        already_in_silence: bool,
    ) -> bool;
    /// Exercises exact dynamic surround peak normalization across speaker layouts in unit tests.
    #[cfg(test)]
    fn integrator_win_audio_test_downmix_unity_peak(
        channels: u16,
        channel_mask: u32,
        out_l: *mut f32,
        out_r: *mut f32,
    ) -> f32;
}

/// Global C FFI callback invoked by `win_capture.cpp` on the real-time WASAPI audio thread.
#[no_mangle]
pub extern "C" fn integrator_on_win_audio_captured(
    data: *const u8,
    len: u32,
    is_silent: i32,
) {
    send_captured_audio_frame(data, len as usize, is_silent != 0);
}

/// Generation-scoped C FFI callback invoked by `win_capture.cpp` when WASAPI capture terminates
/// unexpectedly after successful startup (`NEW-05`, `NEW-1G8-03`, `NEW-1G8-06`).
#[no_mangle]
pub extern "C" fn integrator_on_win_audio_capture_ended(capture_gen: u64, reason_code: i32) {
    if ROUTING_GENERATION.load(Ordering::Acquire) != capture_gen {
        return;
    }
    tracing::warn!(
        "⚠️ Windows WASAPI capture gen {} ended unexpectedly (reason={}); cleaning up outbound sender",
        capture_gen,
        reason_code
    );
    // Only clean up if this generation is still active
    if ROUTING_GENERATION
        .compare_exchange(
            capture_gen,
            capture_gen.wrapping_add(1),
            Ordering::SeqCst,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    ROUTING_ACTIVE.store(false, Ordering::Release);
    {
        let mut chan_guard = SENDER_CHANNEL.lock().unwrap_or_else(|e| e.into_inner());
        chan_guard.take();
    }
    {
        let mut task_guard = SENDER_TASK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = task_guard.take() {
            task.abort();
        }
    }
    {
        let mut target_guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
        if target_guard.as_ref().map(|t| t.routing_generation) == Some(capture_gen) {
            target_guard.take();
        }
    }
}

/// Lock-free real-time capture trampoline enqueueing a 5 ms PCM frame onto `SENDER_CHANNEL`.
///
/// Uses `try_lock()` and `try_send()` so real-time audio capture threads (Windows WASAPI MMCSS)
/// never block on contention or backpressure.
fn send_captured_audio_frame(data: *const u8, len: usize, is_silent: bool) {
    if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
        return;
    }
    if let Ok(guard) = SENDER_CHANNEL.try_lock() {
        if let Some(tx) = guard.as_ref() {
            let mut frame = CapturedFrameData {
                len: len.min(CANONICAL_FRAME_BYTES),
                is_silent,
                data: [0u8; CANONICAL_FRAME_BYTES],
            };
            if !is_silent && !data.is_null() && len > 0 {
                let copy_len = frame.len;
                unsafe {
                    std::ptr::copy_nonoverlapping(data, frame.data.as_mut_ptr(), copy_len);
                }
            }
            let _ = tx.try_send(frame);
        }
    }
}

/// POSIX shared-memory object name shared between `IntegratorAudioDriver.c` and the Rust capture task.
#[cfg(target_os = "macos")]
pub const INTEGRATOR_AUDIO_SHM_NAME: &str = "/com.manveersingh.integrator.audio.sink.shm";
/// FourCC magic identifier (`'ITGS' = 0x4954_4753`) validating initialized HAL shared memory.
#[cfg(target_os = "macos")]
pub const INTEGRATOR_AUDIO_SHM_MAGIC: u32 = 0x4954_4753;
/// Byte capacity of the lock-free SPSC ring buffer inside `IntegratorAudioShmHeader` (128 KiB).
#[cfg(target_os = "macos")]
pub const INTEGRATOR_AUDIO_RING_BUFFER_BYTES: usize = 128 * 1024;

/// C-ABI shared-memory ring-buffer layout mapped between the macOS CoreAudio HAL plug-in and Rust.
#[cfg(target_os = "macos")]
#[repr(C, align(8))]
pub struct IntegratorAudioShmHeader {
    /// Magic sentinel (`INTEGRATOR_AUDIO_SHM_MAGIC`) indicating initialized header state.
    pub magic: u32,
    /// Shared-memory ABI version number.
    pub version: u32,
    /// Non-zero while CoreAudio IO is actively running inside the virtual HAL audio device.
    pub active: std::sync::atomic::AtomicU32,
    /// Negotiated wire audio format code.
    pub format: std::sync::atomic::AtomicU32,
    /// Active sample rate in Hz (canonical 48,000 Hz).
    pub sample_rate: std::sync::atomic::AtomicU32,
    /// Active channel count (canonical 2 channels).
    pub channels: std::sync::atomic::AtomicU32,
    /// Cumulative PCM frames written into `buffer` by the HAL producer.
    pub total_frames_written: std::sync::atomic::AtomicU64,
    /// Cumulative PCM frames consumed from `buffer` by the Rust consumer.
    pub total_frames_read: std::sync::atomic::AtomicU64,
    /// Producer write cursor byte offset within `buffer` (`0..INTEGRATOR_AUDIO_RING_BUFFER_BYTES`).
    pub write_pos: std::sync::atomic::AtomicU32,
    /// Consumer read cursor byte offset within `buffer` (`0..INTEGRATOR_AUDIO_RING_BUFFER_BYTES`).
    pub read_pos: std::sync::atomic::AtomicU32,
    /// Cumulative ring-buffer underrun count reported by the HAL driver.
    pub underruns: std::sync::atomic::AtomicU32,
    /// Circular PCM16 stereo byte ring buffer (128 KiB).
    pub buffer: [u8; INTEGRATOR_AUDIO_RING_BUFFER_BYTES],
}

/// Send/Sync newtype wrapper around the mmap'd `IntegratorAudioShmHeader` pointer.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct ShmHeaderPtr(*mut IntegratorAudioShmHeader);
#[cfg(target_os = "macos")]
unsafe impl Send for ShmHeaderPtr {}
#[cfg(target_os = "macos")]
unsafe impl Sync for ShmHeaderPtr {}

/// Spawns the generation-scoped macOS HAL shared-memory audio capture task.
///
/// Maps `INTEGRATOR_AUDIO_SHM_NAME` (`131,128` bytes), polls the SPSC ring buffer for 960-byte
/// canonical 5 ms frames, detects digital silence, and forwards frames via `send_captured_audio_frame`.
/// Automatically unmaps memory and closes the POSIX shm descriptor upon generation mismatch or shutdown.
#[cfg(target_os = "macos")]
pub(crate) fn start_mac_shm_audio_capture(gen: u64) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let shm_name_c = std::ffi::CString::new(INTEGRATOR_AUDIO_SHM_NAME).unwrap();
        let mut fd = unsafe { libc::shm_open(shm_name_c.as_ptr(), libc::O_RDWR, 0o666) };
        let mut mapped_header: Option<ShmHeaderPtr> = None;
        if fd >= 0 {
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    std::mem::size_of::<IntegratorAudioShmHeader>(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if ptr != libc::MAP_FAILED {
                mapped_header = Some(ShmHeaderPtr(ptr as *mut IntegratorAudioShmHeader));
            } else {
                // Close leaked fd if initial mmap fails so retry loop can reopen cleanly.
                unsafe { libc::close(fd) };
                fd = -1;
            }
        }

        let mut last_silence_emit = Instant::now();
        let mut frame_buf = [0u8; CANONICAL_FRAME_BYTES];

        while ROUTING_GENERATION.load(Ordering::Acquire) == gen
            && !AUDIO_SHUTDOWN.load(Ordering::Acquire)
            && AUDIO_ENABLED.load(Ordering::Acquire)
        {
            if mapped_header.is_none() {
                fd = unsafe { libc::shm_open(shm_name_c.as_ptr(), libc::O_RDWR, 0o666) };
                if fd >= 0 {
                    let ptr = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            std::mem::size_of::<IntegratorAudioShmHeader>(),
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_SHARED,
                            fd,
                            0,
                        )
                    };
                    if ptr != libc::MAP_FAILED {
                        mapped_header = Some(ShmHeaderPtr(ptr as *mut IntegratorAudioShmHeader));
                    } else {
                        unsafe { libc::close(fd) };
                        fd = -1;
                    }
                }
                if mapped_header.is_none() {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    continue;
                }
            }

            let header = unsafe { &*mapped_header.unwrap().0 };
            if header.magic != INTEGRATOR_AUDIO_SHM_MAGIC {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            let is_active = header.active.load(Ordering::Relaxed) != 0;
            // Acquire write_pos before reading ring buffer bytes written by the CoreAudio HAL producer.
            let write_pos = (header.write_pos.load(Ordering::Acquire) as usize)
                % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
            let read_pos = (header.read_pos.load(Ordering::Relaxed) as usize)
                % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;

            let available = if write_pos >= read_pos {
                write_pos - read_pos
            } else {
                INTEGRATOR_AUDIO_RING_BUFFER_BYTES - (read_pos - write_pos)
            };

            if available >= CANONICAL_FRAME_BYTES {
                let mut curr = read_pos;
                let mut all_silent = true;
                for i in 0..CANONICAL_FRAME_BYTES {
                    let b = header.buffer[curr];
                    if b != 0 {
                        all_silent = false;
                    }
                    frame_buf[i] = b;
                    curr = (curr + 1) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
                }
                // Publish updated read_pos with Release ordering so the HAL producer observes freed space.
                header.read_pos.store(curr as u32, Ordering::Release);
                header.total_frames_read.fetch_add(AUDIO_FRAME_SAMPLES_PER_CH as u64, Ordering::Relaxed);

                send_captured_audio_frame(frame_buf.as_ptr(), CANONICAL_FRAME_BYTES, all_silent);
                last_silence_emit = Instant::now();
            } else {
                if !is_active && last_silence_emit.elapsed() >= Duration::from_millis(50) {
                    send_captured_audio_frame(std::ptr::null(), 0, true);
                    last_silence_emit = Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        if let Some(ptr) = mapped_header {
            unsafe {
                libc::munmap(ptr.0 as *mut libc::c_void, std::mem::size_of::<IntegratorAudioShmHeader>());
            }
        }
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }))
}

/// Returns the lazily initialized global async lifecycle mutex.
fn lifecycle_lock() -> &'static tokio::sync::Mutex<()> {
    AUDIO_LIFECYCLE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Returns the lazily initialized global `IUA2` cryptographic session registry.
fn global_audio_registry() -> &'static Mutex<AudioSessionRegistry> {
    AUDIO_SESSION_REGISTRY.get_or_init(|| Mutex::new(AudioSessionRegistry::new()))
}

/// Returns the lazily initialized global 64-slot audio jitter buffer.
fn global_jitter_buffer() -> &'static Mutex<jitter::JitterBuffer> {
    JITTER_BUFFER.get_or_init(|| Mutex::new(jitter::JitterBuffer::new()))
}

/// Returns the lazily initialized mutex serializing test chime WAV generation and playback.
fn chime_file_lock() -> &'static Mutex<()> {
    CHIME_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

/// Returns the cooperative cancellation notifier for the 5 ms playout worker.
fn playout_cancel_notify() -> &'static Notify {
    PLAYOUT_CANCEL_NOTIFY.get_or_init(Notify::new)
}

/// Returns the cooperative cancellation notifier for the UDP port 58284 sink receiver task.
fn sink_cancel_notify() -> &'static Notify {
    SINK_CANCEL_NOTIFY.get_or_init(Notify::new)
}

/// Serde default provider returning `AUDIO_PORT` (`58284`) when deserializing legacy status payloads.
fn default_audio_port() -> u16 {
    AUDIO_PORT
}

/// Runtime status snapshot of the Dynamic Audio Routing subsystem serialized to UI & RPC callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioRoutingStatus {
    /// Human-readable topology description reflecting active capture, playback, standby, or offline state.
    pub topology: String,
    /// Estimated end-to-end audio pipeline latency in milliseconds (`25.0` ms when active, `0.0` ms idle).
    pub latency_ms: f32,
    /// Canonical PCM sample rate in Hz (`48,000`).
    pub sample_rate: u32,
    /// Canonical PCM bit depth in bits per sample (`16`).
    pub bit_depth: u8,
    /// True if native audio capture (Windows) or CoreAudio playout (macOS) is currently streaming.
    pub is_active: bool,
    /// UDP port bound by the `IUA2` sink (`58284`).
    #[serde(default = "default_audio_port")]
    pub port: u16,
    /// Cumulative audio frames read by the local capture backend (Windows WASAPI).
    #[serde(default)]
    pub frames_captured: u64,
    /// Cumulative authenticated `IUA2` packets processed by the local UDP sink (macOS).
    #[serde(default)]
    pub packets_drained: u64,
    /// Cumulative audio buffer underruns or capture discontinuities reported by the native backend.
    #[serde(default)]
    pub underruns: u64,
    /// Cross-platform mixer balance (`-1.0` Mac boost ↔ `0.0` balanced ↔ `+1.0` Windows boost).
    #[serde(default)]
    pub mixer_balance: f32,
    /// Whether the Windows remote soundbar sink is currently muted.
    #[serde(default)]
    pub sink_muted: bool,
}

impl Default for AudioRoutingStatus {
    fn default() -> Self {
        Self {
            topology: "UDP Audio Sink (Experimental Preview - Offline)".to_string(),
            latency_ms: 0.0,
            sample_rate: CANONICAL_SAMPLE_RATE,
            bit_depth: CANONICAL_BIT_DEPTH,
            is_active: false,
            port: AUDIO_PORT,
            frames_captured: 0,
            packets_drained: 0,
            underruns: 0,
            mixer_balance: 0.0,
            sink_muted: false,
        }
    }
}

/// Applies real-time cross-platform mixer gain and one-tap soundbar mute directly to a
/// 16-bit signed little-endian stereo PCM frame buffer (zero heap allocations).
///
/// - `muted == true`: zeros the buffer immediately while keeping the IUA2 transport live.
/// - `balance <= 0.0`: smoothly attenuates Windows remote audio from `1.0` down to `0.0` (Mac focus).
/// - `balance > 0.0`: smoothly boosts Windows remote audio up to `1.5x` (+3.5 dB) with saturating clamp.
pub fn apply_mixer_gain_pcm16(buf: &mut [u8], balance: f32, muted: bool) {
    if muted {
        buf.fill(0);
        return;
    }
    let bal = if balance.is_finite() {
        balance.clamp(-1.0, 1.0)
    } else {
        0.0
    };
    let gain: f32 = if bal <= 0.0 {
        (1.0 + bal).clamp(0.0, 1.0)
    } else {
        1.0 + bal * 0.5
    };
    if (gain - 1.0).abs() < 1e-4 {
        return;
    }
    if gain <= 1e-4 {
        buf.fill(0);
        return;
    }
    for chunk in buf.chunks_exact_mut(2) {
        let sample = i16::from_le_bytes([chunk[0], chunk[1]]) as f32;
        let scaled = (sample * gain).round().clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        let out = scaled.to_le_bytes();
        chunk[0] = out[0];
        chunk[1] = out[1];
    }
}

/// RAII guard clearing `SINK_LISTENING` only if `SINK_GENERATION` still matches `my_sink_gen`.
struct SinkListeningGuard {
    /// Generation token captured when this UDP sink receiver task was spawned.
    my_sink_gen: u64,
}

impl Drop for SinkListeningGuard {
    fn drop(&mut self) {
        if SINK_GENERATION.load(Ordering::Acquire) == self.my_sink_gen {
            SINK_LISTENING.store(false, Ordering::Release);
        }
    }
}

/// RAII ownership guard for the CoreAudio playout worker (`NEW-03`, `AUD-1G7-05`).
///
/// Acquires `PLAYOUT_STATE_LOCK` and calls `integrator_mac_audio_stop()` **BEFORE** clearing
/// `PLAYOUT_ACTIVE = false`, eliminating the idle-timeout silent-wedge window.
struct PlayoutWorkerGuard {
    /// Routing generation token owned by this playout worker instance.
    my_gen: u64,
}

impl Drop for PlayoutWorkerGuard {
    fn drop(&mut self) {
        let _state_guard = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if ROUTING_GENERATION.load(Ordering::Acquire) == self.my_gen {
            #[cfg(target_os = "macos")]
            unsafe {
                integrator_mac_audio_stop();
            }
            PLAYOUT_ACTIVE.store(false, Ordering::Release);
        }
    }
}

/// RAII ownership guard for the outbound UDP sender task (`NEW-05`, `AUD-1G7-12`).
///
/// Tears down `ROUTING_ACTIVE`, `SENDER_CHANNEL`, `ACTIVE_CAPTURE_TARGET`, and generation-scoped
/// Windows WASAPI capture (`integrator_win_audio_capture_stop_if_gen(my_gen)`) so a delayed exit
/// thread can NEVER stop a newer session's WASAPI capture.
struct SenderTaskGuard {
    /// Routing generation token owned by this outbound sender task.
    my_gen: u64,
}

impl Drop for SenderTaskGuard {
    fn drop(&mut self) {
        if ROUTING_GENERATION.load(Ordering::Acquire) == self.my_gen {
            ROUTING_ACTIVE.store(false, Ordering::Release);
            {
                let mut chan = SENDER_CHANNEL.lock().unwrap_or_else(|e| e.into_inner());
                chan.take();
            }
            {
                let mut target = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
                if target.as_ref().map(|t| t.routing_generation) == Some(self.my_gen) {
                    target.take();
                }
            }
            #[cfg(target_os = "windows")]
            {
                let gen_to_stop = self.my_gen;
                let _ = std::thread::Builder::new()
                    .name("win-audio-stop-on-exit".into())
                    .spawn(move || unsafe {
                        integrator_win_audio_capture_stop_if_gen(gen_to_stop);
                    });
            }
        }
    }
}

/// Token-bucket-style 30-second rate limiter suppressing log storms on malformed UDP floods.
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

/// Returns the current wall-clock Unix epoch timestamp in milliseconds.
fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Reaps an exited or backgrounded child process without blocking the caller thread.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn reap_child(mut child: std::process::Child) {
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

/// Cooperatively cancels and awaits the active playout worker handle (`AUD-1G7-04/05`).
async fn stop_playout_worker_await() {
    let handle = {
        let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PLAYOUT_ACTIVE.store(false, Ordering::Release);
        PLAYOUT_WORKER_HANDLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    };
    playout_cancel_notify().notify_waiters();

    if let Some(mut h) = handle {
        if tokio::time::timeout(Duration::from_millis(500), &mut h)
            .await
            .is_err()
        {
            h.abort();
            let _ = tokio::time::timeout(Duration::from_millis(250), h).await;
        }
    }
}

/// Cancels and awaits the active sender task and stops native Windows capture off-runtime (`AUD-1G7-17`).
async fn stop_capture_locked_await() -> String {
    ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
    ROUTING_ACTIVE.store(false, Ordering::Release);

    {
        let mut guard = SENDER_CHANNEL.lock().unwrap_or_else(|e| e.into_inner());
        guard.take();
    }

    #[cfg(target_os = "macos")]
    {
        let mut task_guard = MAC_CAPTURE_TASK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = task_guard.take() {
            task.abort();
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = tokio::task::spawn_blocking(|| unsafe {
            integrator_win_audio_capture_stop();
        })
        .await;
    }

    let sender_handle = {
        let mut guard = SENDER_TASK.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(mut h) = sender_handle {
        if tokio::time::timeout(Duration::from_millis(500), &mut h)
            .await
            .is_err()
        {
            h.abort();
            let _ = tokio::time::timeout(Duration::from_millis(250), h).await;
        }
    }

    let target = {
        let mut t = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
        t.take()
            .map(|tgt| tgt.peer_ip)
            .unwrap_or_else(|| "peer".to_string())
    };
    format!("Audio capture and streaming to {} stopped", target)
}

/// Spawns a single generation-owned playout worker after awaiting any prior worker, and
/// re-checks `ROUTING_GENERATION == worker_routing_gen` under `PLAYOUT_STATE_LOCK` before
/// publishing the handle so an older caller can NEVER overwrite or detach a newer worker (`NEW-04`).
async fn spawn_playout_worker_for_gen_await(worker_routing_gen: u64) {
    let prev = {
        let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if ROUTING_GENERATION.load(Ordering::Acquire) != worker_routing_gen
            || AUDIO_SHUTDOWN.load(Ordering::Acquire)
        {
            return;
        }
        PLAYOUT_WORKER_HANDLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    };
    if let Some(mut old) = prev {
        playout_cancel_notify().notify_waiters();
        if tokio::time::timeout(Duration::from_millis(300), &mut old)
            .await
            .is_err()
        {
            old.abort();
            let _ = tokio::time::timeout(Duration::from_millis(200), old).await;
        }
    }

    // Re-check generation under PLAYOUT_STATE_LOCK before spawning & storing handle (`NEW-04`)
    let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if ROUTING_GENERATION.load(Ordering::Acquire) != worker_routing_gen
        || !PLAYOUT_ACTIVE.load(Ordering::Acquire)
        || AUDIO_SHUTDOWN.load(Ordering::Acquire)
    {
        return;
    }

    let handle = tokio::spawn(async move {
        let _guard = PlayoutWorkerGuard {
            my_gen: worker_routing_gen,
        };
        let mut interval = tokio::time::interval(Duration::from_millis(CANONICAL_FRAME_MS as u64));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut frame_buf = [0u8; CANONICAL_FRAME_BYTES];

        while PLAYOUT_ACTIVE.load(Ordering::Acquire)
            && !AUDIO_SHUTDOWN.load(Ordering::Acquire)
            && ROUTING_GENERATION.load(Ordering::Acquire) == worker_routing_gen
        {
            tokio::select! {
                _ = interval.tick() => {}
                _ = playout_cancel_notify().notified() => {
                    if !PLAYOUT_ACTIVE.load(Ordering::Acquire)
                        || AUDIO_SHUTDOWN.load(Ordering::Acquire)
                        || ROUTING_GENERATION.load(Ordering::Acquire) != worker_routing_gen
                    {
                        break;
                    }
                    continue;
                }
            }

            if !PLAYOUT_ACTIVE.load(Ordering::Acquire)
                || AUDIO_SHUTDOWN.load(Ordering::Acquire)
                || ROUTING_GENERATION.load(Ordering::Acquire) != worker_routing_gen
            {
                break;
            }

            let now_ms = epoch_millis();
            let last_ms = LAST_PACKET_EPOCH_MS.load(Ordering::Acquire);
            if last_ms > 0 && now_ms.saturating_sub(last_ms) > RECENT_PACKET_WINDOW_MS {
                let _s = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                if ROUTING_GENERATION.load(Ordering::Acquire) == worker_routing_gen {
                    let mut jb = global_jitter_buffer().lock().unwrap_or_else(|e| e.into_inner());
                    jb.reset();
                }
                break;
            }

            let has_frame = {
                let mut jb = global_jitter_buffer().lock().unwrap_or_else(|e| e.into_inner());
                jb.pop_frame_into(&mut frame_buf)
            };

            if has_frame {
                let bal = AUDIO_MIXER_BALANCE_MILLIS.load(Ordering::Relaxed) as f32 / 1000.0;
                let muted = AUDIO_SINK_MUTED.load(Ordering::Relaxed);
                apply_mixer_gain_pcm16(&mut frame_buf, bal, muted);
                #[cfg(target_os = "macos")]
                unsafe {
                    integrator_mac_audio_write_pcm(frame_buf.as_ptr(), frame_buf.len() as u32);
                }
                #[cfg(not(target_os = "macos"))]
                let _ = &frame_buf;
            }
        }
    });

    // Guard handle publication under PLAYOUT_STATE_LOCK against concurrent stop/shutdown (`NEW-04`)
    let mut guard = PLAYOUT_WORKER_HANDLE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if ROUTING_GENERATION.load(Ordering::Acquire) != worker_routing_gen
        || !PLAYOUT_ACTIVE.load(Ordering::Acquire)
        || AUDIO_SHUTDOWN.load(Ordering::Acquire)
    {
        handle.abort();
        return;
    }
    if let Some(old_race) = guard.replace(handle) {
        old_race.abort();
    }
}

/// Top-level facade managing `IUA2` audio sessions, mixer gain, capture/playout lifecycles, and teardown.
pub struct AudioManager;

impl AudioManager {
    /// Synchronizes the atomic `"audio"` feature-enabled gate with `FeatureManager` (`AUD-1G7-07(2)`).
    #[cfg(test)]
    pub fn set_audio_feature_enabled(enabled: bool) {
        AUDIO_ENABLED.store(enabled, Ordering::SeqCst);
    }

    /// Resets `AUDIO_SHUTDOWN` and `AUDIO_ENABLED` latches between unit tests.
    #[cfg(test)]
    pub fn reset_shutdown_for_test() {
        AUDIO_SHUTDOWN.store(false, Ordering::SeqCst);
        AUDIO_ENABLED.store(true, Ordering::SeqCst);
    }

    /// Atomically disables the audio feature, stops active routing/playback/capture, and closes
    /// UDP 58284 under a single `AUDIO_LIFECYCLE_LOCK` acquisition (zero lockless gap; `AUD-1G7-07(2)`).
    #[cfg(test)]
    pub async fn disable_audio_feature_async() -> Result<String> {
        AUDIO_ENABLED.store(false, Ordering::SeqCst);
        let remote_ip = {
            let _lifecycle = lifecycle_lock().lock().await;
            let ip = Self::stop_local_audio_locked().await;
            Self::stop_sink_server_inner().await;
            ip
        };
        #[cfg(target_os = "macos")]
        if let Some(ip) = remote_ip.as_deref() {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                DisplayController::send_remote_rpc(ip, &DisplayRpcRequest::StopAudioCapture),
            )
            .await;
        }
        #[cfg(not(target_os = "macos"))]
        let _ = remote_ip;
        Ok("Dynamic Audio Routing disabled and stopped".to_string())
    }

    /// Returns the honest runtime status of the Dynamic Audio Routing subsystem.
    pub fn status() -> AudioRoutingStatus {
        let listening = SINK_LISTENING.load(Ordering::Acquire);
        #[cfg(target_os = "macos")]
        let is_active = unsafe { integrator_mac_audio_is_active() != 0 };
        #[cfg(target_os = "windows")]
        let is_active = unsafe { integrator_win_audio_capture_is_active() };
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        let is_active = PLAYOUT_ACTIVE.load(Ordering::Acquire)
            || SENDER_CHANNEL
                .lock()
                .map(|g| g.is_some())
                .unwrap_or(false);

        let last_ms = LAST_PACKET_EPOCH_MS.load(Ordering::Acquire);
        let now_ms = epoch_millis();
        let recently_active =
            last_ms > 0 && now_ms.saturating_sub(last_ms) <= RECENT_PACKET_WINDOW_MS;

        let topology = if is_active {
            #[cfg(target_os = "windows")]
            {
                "Dynamic Audio Routing (Windows WASAPI Loopback Capture Active -> Mac Playback)"
            }
            #[cfg(target_os = "macos")]
            {
                "Dynamic Audio Routing (macOS CoreAudio Playback Active <- Windows Capture)"
            }
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            {
                "Dynamic Audio Routing (Active)"
            }
        } else if recently_active {
            "Dynamic Audio Routing (Standby - Packets Received Recently)"
        } else if listening {
            "UDP Audio Sink (IUA2 Listening on UDP 58284 - Idle)"
        } else {
            "UDP Audio Sink (Experimental Preview - Offline)"
        };

        let latency_ms = if is_active { 25.0 } else { 0.0 };

        #[cfg(target_os = "windows")]
        let (frames_captured, packets_drained, underruns) = unsafe {
            (
                integrator_win_audio_capture_frames_read(),
                0,
                integrator_win_audio_capture_discontinuities(),
            )
        };
        #[cfg(target_os = "macos")]
        let (frames_captured, packets_drained, underruns) = unsafe {
            (
                0,
                PACKETS_DRAINED.load(Ordering::Relaxed),
                integrator_mac_audio_underruns(),
            )
        };
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        let (frames_captured, packets_drained, underruns) =
            (0, PACKETS_DRAINED.load(Ordering::Relaxed), 0);

        AudioRoutingStatus {
            topology: topology.to_string(),
            latency_ms,
            sample_rate: CANONICAL_SAMPLE_RATE,
            bit_depth: CANONICAL_BIT_DEPTH,
            is_active,
            port: AUDIO_PORT,
            frames_captured,
            packets_drained,
            underruns,
            mixer_balance: Self::mixer_balance(),
            sink_muted: Self::is_sink_muted(),
        }
    }

    /// Returns the current cross-platform audio mixer balance (`-1.0..=+1.0`).
    pub fn mixer_balance() -> f32 {
        AUDIO_MIXER_BALANCE_MILLIS.load(Ordering::Acquire) as f32 / 1000.0
    }

    /// Returns whether the Windows remote soundbar audio sink is currently muted.
    pub fn is_sink_muted() -> bool {
        AUDIO_SINK_MUTED.load(Ordering::Acquire)
    }

    /// Updates the cross-platform audio mixer balance (`-1.0..=+1.0`) and Windows sink mute state.
    pub fn set_mixer(balance: f32, muted: bool) -> (f32, bool) {
        let clamped = if balance.is_finite() {
            balance.clamp(-1.0, 1.0)
        } else {
            0.0
        };
        let millis = (clamped * 1000.0).round() as i32;
        AUDIO_MIXER_BALANCE_MILLIS.store(millis, Ordering::SeqCst);
        AUDIO_SINK_MUTED.store(muted, Ordering::SeqCst);
        #[cfg(target_os = "macos")]
        unsafe {
            integrator_mac_audio_set_local_duck(clamped);
        }
        (millis as f32 / 1000.0, muted)
    }

    /// Resolves peer credentials strictly by authenticated `TransportSessionV2` `peer_device_id`
    /// and enforces canonical Stage 1 PCM parameters (`48 kHz / 2ch / 16-bit`; `AUD-1G7-10/15`).
    pub fn handle_negotiate_session_for_peer(
        authenticated_peer_device_id: Option<&str>,
        caller_ip: IpAddr,
        sender_nonce_hex: &str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<NegotiatedAudioSessionWire, String> {
        if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
            return Err("Audio subsystem is shutting down".into());
        }
        if !AUDIO_ENABLED.load(Ordering::Acquire) {
            return Err("Dynamic Audio Routing feature is disabled".into());
        }
        if sample_rate != CANONICAL_SAMPLE_RATE
            || channels != CANONICAL_CHANNELS
            || bit_depth != CANONICAL_BIT_DEPTH
        {
            return Err(format!(
                "Stage 1 requires canonical 48000Hz/2ch/16-bit PCM (got {}Hz/{}ch/{}-bit)",
                sample_rate, channels, bit_depth
            ));
        }

        let Some(peer_id) = authenticated_peer_device_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Err("Audio session negotiation requires authenticated peer identity".into());
        };

        let Some(sender_nonce) = security::hex_decode_array::<32>(sender_nonce_hex) else {
            return Err("Invalid 32-byte sender_nonce_hex".into());
        };
        if sender_nonce.iter().all(|&b| b == 0) {
            return Err("Rejected all-zero audio sender_nonce".into());
        }

        let peer_creds = trust::lookup_verified_peer_by_id_at_ip(peer_id, caller_ip)
            .ok_or_else(|| {
                format!(
                    "No cryptographically paired non-blocked peer {} for {}",
                    peer_id, caller_ip
                )
            })?;

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

    /// Awaited asynchronous peer revocation handler called from `IntegratorCore::terminate_peer_connections_async`
    /// (`NEW-07`, `AUD-1G7-02`): evicts & invalidates registry sessions, awaits playout worker drain,
    /// stops CoreAudio + `JitterBuffer` under `PLAYOUT_STATE_LOCK`, and offloads Windows WASAPI join
    /// via `spawn_blocking` — strictly scoped to when the revoked peer owns the active target.
    #[cfg(test)]
    pub async fn revoke_peer_audio_sessions_async(peer_device_id_hex: &str) -> usize {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let Some(peer_bytes) = security::hex_decode_array::<16>(&clean_id) else {
            return 0;
        };

        // 1. Always evict & invalidate registry sessions belonging strictly to this peer
        let evicted = {
            let mut reg = global_audio_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            reg.revoke_peer_sessions(&peer_bytes)
        };

        // 2. Check active target directly by constant-time peer ID (no keystore lookup; never disrupts unrelated Peer A)
        let matched_info = {
            let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().and_then(|t| {
                if security::constant_time_eq(&t.peer_device_id, &peer_bytes) {
                    Some((t.trust_generation, t.routing_generation))
                } else {
                    None
                }
            })
        };

        if let Some((tg, _rg)) = matched_info {
            tracing::info!(
                "🛑 Async-revoking active audio target for peer {} (bound trust_gen={})",
                clean_id,
                tg
            );
            let _lifecycle = lifecycle_lock().lock().await;
            // Re-verify active target still belongs to this revoked peer after acquiring lock
            let still_matches = {
                let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .as_ref()
                    .map(|t| security::constant_time_eq(&t.peer_device_id, &peer_bytes))
                    .unwrap_or(false)
            };
            if still_matches {
                let _ = Self::stop_local_audio_locked().await;
            }
        }

        evicted
    }

    /// Synchronous peer revocation handler for non-async callers (`IntegratorCore::terminate_peer_connections`).
    /// Strictly scopes playback/capture teardown to when `ACTIVE_CAPTURE_TARGET` matches the revoked peer
    /// (so revoking an unrelated idle Peer B never disrupts Peer A's active stream; `AUD-1G7-02`).
    pub fn revoke_peer_audio_sessions(peer_device_id_hex: &str) -> usize {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let Some(peer_bytes) = security::hex_decode_array::<16>(&clean_id) else {
            return 0;
        };

        let evicted = {
            let mut reg = global_audio_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            reg.revoke_peer_sessions(&peer_bytes)
        };

        let matched_trust_gen = {
            let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().and_then(|t| {
                if security::constant_time_eq(&t.peer_device_id, &peer_bytes) {
                    Some(t.trust_generation)
                } else {
                    None
                }
            })
        };

        if let Some(tg) = matched_trust_gen {
            tracing::info!(
                "🛑 Revoking active audio target for peer {} (bound trust_gen={})",
                clean_id,
                tg
            );

            // Coordinate CoreAudio stop, PLAYOUT_ACTIVE, and JitterBuffer reset atomically under PLAYOUT_STATE_LOCK
            {
                let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
                ROUTING_ACTIVE.store(false, Ordering::Release);
                PLAYOUT_ACTIVE.store(false, Ordering::Release);
                if let Some(worker) = PLAYOUT_WORKER_HANDLE
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    worker.abort();
                }
                #[cfg(target_os = "macos")]
                unsafe {
                    integrator_mac_audio_stop();
                }
                {
                    let mut jb = global_jitter_buffer()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    jb.reset();
                }
            }
            playout_cancel_notify().notify_waiters();

            // Stop outbound capture + sender task (Windows / generic)
            let _ = Self::stop_capture();
        }

        evicted
    }

    /// Initiates a mutually authenticated `NegotiateAudioSession` RPC with `peer_ip`,
    /// validates non-zero `receiver_nonce` and positive TTL, and derives `AudioSessionSender`.
    async fn negotiate_sender_session_for_peer(
        peer_ip: &str,
        peer_creds: &VerifiedPeerCredentials,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<AudioSessionSender> {
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

    /// Starts local audio capture and outbound streaming to `peer_ip` bound to verified `peer_creds`.
    ///
    /// Uses a deadlock-free two-phase generation protocol (`NEW-01`), validates parameters and
    /// session ownership *before* touching any active capture (`NEW-06`), and re-verifies
    /// fail-closed trust after every `.await` and after WASAPI start (`AUD-1G7-01`).
    pub async fn start_capture_and_stream_for_peer(
        peer_ip: &str,
        peer_creds: VerifiedPeerCredentials,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<String> {
        // Pre-validate canonical parameters BEFORE acquiring lock or interrupting any session (`NEW-06`)
        if sample_rate != CANONICAL_SAMPLE_RATE
            || channels != CANONICAL_CHANNELS
            || bit_depth != CANONICAL_BIT_DEPTH
        {
            anyhow::bail!(
                "Stage 1 capture requires canonical 48000Hz/2ch/16-bit PCM (got {}Hz/{}ch/{}-bit)",
                sample_rate,
                channels,
                bit_depth
            );
        }
        let parsed_ip: IpAddr = peer_ip
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid audio peer IP '{}': {}", peer_ip, e))?;
        let peer_hex = security::hex_encode(&peer_creds.device_id);

        // Phase 1 (locked): check shutdown/feature/trust/ownership, stop only this peer's old capture,
        // and reserve `my_gen` — then DROP `AUDIO_LIFECYCLE_LOCK` before remote TCP negotiation (`NEW-01`).
        let my_gen = {
            let _lifecycle = lifecycle_lock().lock().await;
            if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
                anyhow::bail!("Audio subsystem is shutting down");
            }
            if !AUDIO_ENABLED.load(Ordering::Acquire) {
                anyhow::bail!("Dynamic Audio Routing feature is disabled");
            }
            if check_peer_trust_generation_fail_closed(&peer_hex, peer_creds.trust_generation)
                != PeerTrustCheck::Valid
            {
                anyhow::bail!("Peer {} is revoked or has stale trust generation", peer_hex);
            }

            // Ownership check (`NEW-06`): non-owner Peer B must NOT preempt Peer A's active capture
            let foreign_owner = {
                let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .as_ref()
                    .map(|cur| !security::constant_time_eq(&cur.peer_device_id, &peer_creds.device_id))
                    .unwrap_or(false)
            };
            if foreign_owner {
                anyhow::bail!(
                    "StartAudioCapture rejected: active audio session belongs to a different peer"
                );
            }

            let _ = stop_capture_locked_await().await;
            let gen = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            {
                let mut target_guard = ACTIVE_CAPTURE_TARGET
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                *target_guard = Some(ActiveCaptureTarget {
                    peer_ip: peer_ip.to_string(),
                    peer_device_id: peer_creds.device_id,
                    trust_generation: peer_creds.trust_generation,
                    routing_generation: gen,
                });
            }
            gen
        };

        // Phase 2 (UNLOCKED): remote TCP RPC negotiation + UDP socket bind (`NEW-01`)
        let neg_result: Result<(AudioSessionSender, std::net::SocketAddr, tokio::net::UdpSocket)> = async {
            let sender = Self::negotiate_sender_session_for_peer(
                peer_ip,
                &peer_creds,
                sample_rate,
                channels,
                bit_depth,
            )
            .await?;
            let peer_addr: std::net::SocketAddr = format!("{}:{}", peer_ip, AUDIO_PORT)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid audio destination {}:{}: {}", peer_ip, AUDIO_PORT, e))?;
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            Ok((sender, peer_addr, socket))
        }
        .await;

        let (mut sender, peer_addr, socket) = match neg_result {
            Ok(v) => v,
            Err(e) => {
                let _lifecycle = lifecycle_lock().lock().await;
                if ROUTING_GENERATION.load(Ordering::Acquire) == my_gen {
                    let mut t = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
                    if t.as_ref().map(|tgt| tgt.routing_generation) == Some(my_gen) {
                        t.take();
                    }
                }
                return Err(e);
            }
        };

        // Phase 3 (locked): re-verify generation, shutdown, feature flag, and fail-closed trust (`AUD-1G7-01`)
        let _lifecycle = lifecycle_lock().lock().await;
        if AUDIO_SHUTDOWN.load(Ordering::Acquire)
            || !AUDIO_ENABLED.load(Ordering::Acquire)
            || ROUTING_GENERATION.load(Ordering::Acquire) != my_gen
        {
            anyhow::bail!("Audio capture start cancelled by concurrent stop, disable, or shutdown");
        }
        let refreshed_creds = trust::lookup_verified_peer_by_id_at_ip(&peer_hex, parsed_ip)
            .ok_or_else(|| anyhow::anyhow!("Peer {} was untrusted/unpaired during audio startup", peer_hex))?;
        if refreshed_creds.trust_generation != peer_creds.trust_generation
            || check_peer_trust_generation_fail_closed(&peer_hex, peer_creds.trust_generation)
                != PeerTrustCheck::Valid
        {
            let _ = stop_capture_locked_await().await;
            anyhow::bail!("Peer {} was revoked or trust generation changed during audio startup", peer_hex);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedFrameData>(16);
        {
            let mut chan_guard = SENDER_CHANNEL.lock().unwrap_or_else(|e| e.into_inner());
            *chan_guard = Some(tx);
        }

        let task_peer_hex = peer_hex.clone();
        let expected_trust_gen = peer_creds.trust_generation;
        let sender_task = tokio::spawn(async move {
            let _guard = SenderTaskGuard { my_gen };
            let mut frame_index: u32 = 0;

            while let Some(frame) = rx.recv().await {
                if AUDIO_SHUTDOWN.load(Ordering::Acquire)
                    || !AUDIO_ENABLED.load(Ordering::Acquire)
                    || ROUTING_GENERATION.load(Ordering::Acquire) != my_gen
                    || check_peer_trust_generation_fail_closed(&task_peer_hex, expected_trust_gen)
                        != PeerTrustCheck::Valid
                {
                    tracing::info!(
                        "🛑 Stopping audio sender task for {} (revoked/generation changed)",
                        task_peer_hex
                    );
                    break;
                }

                // Seal plaintext frame into authenticated IUA2 datagram, ignoring transient send errors
                // on UDP, and tear down if session TTL expires or sequence cap is reached.
                let now = security::unix_epoch_secs();
                let (flags, payload): (u16, &[u8]) = if frame.is_silent {
                    (AUDIO_FLAG_SILENCE, &[0u8; 1])
                } else {
                    // Clamp PCM slice to `CANONICAL_FRAME_BYTES` (960 B) and ignore malformed partial lengths.
                    let slice_len = frame.len.min(CANONICAL_FRAME_BYTES);
                    if slice_len != CANONICAL_FRAME_BYTES {
                        continue;
                    }
                    (AUDIO_FLAG_PCM_FRAME, &frame.data[..slice_len])
                };
                frame_index = frame_index.wrapping_add(1);
                let timestamp_us = frame_index.wrapping_mul(CANONICAL_FRAME_MS * 1000);

                match sender.seal_datagram(
                    flags,
                    timestamp_us,
                    AUDIO_FRAME_SAMPLES_PER_CH,
                    payload,
                    now,
                ) {
                    Ok(dgram) => {
                        let _ = socket.send_to(&dgram, peer_addr).await;
                    }
                    Err(e) => {
                        tracing::info!("Audio sender seal ended ({}): tearing down capture", e);
                        break;
                    }
                }
            }
        });

        {
            let mut task_guard = SENDER_TASK.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old) = task_guard.take() {
                old.abort();
            }
            *task_guard = Some(sender_task);
        }

        #[cfg(target_os = "macos")]
        {
            let capture_task = start_mac_shm_audio_capture(my_gen);
            {
                let mut task_guard = MAC_CAPTURE_TASK.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(old) = task_guard.take() {
                    old.abort();
                }
                *task_guard = capture_task;
            }
            ROUTING_ACTIVE.store(true, Ordering::Release);
        }

        #[cfg(target_os = "windows")]
        {
            let started = tokio::task::spawn_blocking(move || unsafe {
                integrator_win_audio_capture_start(my_gen)
            })
            .await
            .unwrap_or(false);

            if !started {
                let _ = stop_capture_locked_await().await;
                anyhow::bail!("Failed to initialize Windows WASAPI audio capture");
            }

            if AUDIO_SHUTDOWN.load(Ordering::Acquire)
                || !AUDIO_ENABLED.load(Ordering::Acquire)
                || ROUTING_GENERATION.load(Ordering::Acquire) != my_gen
                || check_peer_trust_generation_fail_closed(&peer_hex, peer_creds.trust_generation)
                    != PeerTrustCheck::Valid
            {
                let _ = stop_capture_locked_await().await;
                anyhow::bail!("Peer {} was revoked or audio stopped during WASAPI startup", peer_hex);
            }
            ROUTING_ACTIVE.store(true, Ordering::Release);
        }

        tracing::info!(
            "🎙️ Dynamic Audio Routing capture started: streaming to {}:{} ({}Hz, {}ch, {}-bit, gen {})",
            peer_ip,
            AUDIO_PORT,
            sample_rate,
            channels,
            bit_depth,
            my_gen
        );

        Ok(format!(
            "Dynamic Audio Routing active: streaming to {}:{} ({}Hz, {}ch, {}-bit)",
            peer_ip, AUDIO_PORT, sample_rate, channels, bit_depth
        ))
    }

    /// Resolves peer credentials by IP and delegates to `start_capture_and_stream_for_peer`.
    #[cfg(not(target_os = "macos"))]
    pub async fn start_capture_and_stream(
        peer_ip: &str,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<String> {
        let peer_creds = trust::lookup_verified_peer_for_ip(peer_ip)
            .ok_or_else(|| anyhow::anyhow!("Peer {} is not paired or trusted", peer_ip))?;
        Self::start_capture_and_stream_for_peer(
            peer_ip,
            peer_creds,
            sample_rate,
            channels,
            bit_depth,
        )
        .await
    }

    /// Stops local capture ONLY if the active capture session belongs to `requesting_peer_id`
    /// (or if no capture is currently active), enforcing RPC session ownership (`AUD-1G7-15`).
    pub async fn stop_capture_for_peer(requesting_peer_id: &[u8; 16]) -> Result<String, String> {
        let _lifecycle = lifecycle_lock().lock().await;
        let owner_mismatch = {
            let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(tgt) => !security::constant_time_eq(&tgt.peer_device_id, requesting_peer_id),
                None => false,
            }
        };
        if owner_mismatch {
            return Err(
                "StopAudioCapture rejected: active capture session belongs to a different peer"
                    .to_string(),
            );
        }
        Ok(stop_capture_locked_await().await)
    }

    /// Synchronously stops local audio capture and closes the outbound stream.
    pub fn stop_capture() -> String {
        ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
        #[cfg(target_os = "windows")]
        ROUTING_ACTIVE.store(false, Ordering::Release);
        {
            let mut guard = SENDER_CHANNEL.lock().unwrap_or_else(|e| e.into_inner());
            guard.take();
        }
        #[cfg(target_os = "macos")]
        {
            let mut task_guard = MAC_CAPTURE_TASK.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(task) = task_guard.take() {
                task.abort();
            }
        }
        {
            let mut task_guard = SENDER_TASK.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(task) = task_guard.take() {
                task.abort();
            }
        }
        #[cfg(target_os = "windows")]
        unsafe {
            integrator_win_audio_capture_stop();
        }
        let target = {
            let mut t = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            t.take()
                .map(|tgt| tgt.peer_ip)
                .unwrap_or_else(|| "peer".to_string())
        };
        format!("Audio capture and streaming to {} stopped", target)
    }

    /// High-level API to start Dynamic Audio Routing using deadlock-free two-phase locking (`NEW-01`).
    pub async fn start_audio_routing(peer_ip: &str) -> Result<String> {
        if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
            anyhow::bail!("Audio subsystem is shutting down");
        }
        if !AUDIO_ENABLED.load(Ordering::Acquire) {
            anyhow::bail!("Dynamic Audio Routing feature is disabled");
        }

        #[cfg(target_os = "windows")]
        {
            Self::start_capture_and_stream(
                peer_ip,
                CANONICAL_SAMPLE_RATE,
                CANONICAL_CHANNELS,
                CANONICAL_BIT_DEPTH,
            )
            .await
        }

        #[cfg(target_os = "macos")]
        {
            // Phase 1 (locked): validate peer, prepare CoreAudio + sink + playout worker for `my_gen`,
            // then DROP `AUDIO_LIFECYCLE_LOCK` BEFORE remote TCP RPC (`NEW-01` — zero loopback deadlock
            // and zero 29 s stop/shutdown stall!).
            let (peer_creds, peer_hex, my_gen) = {
                let _lifecycle = lifecycle_lock().lock().await;
                if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
                    anyhow::bail!("Audio subsystem is shutting down");
                }
                if !AUDIO_ENABLED.load(Ordering::Acquire) {
                    anyhow::bail!("Dynamic Audio Routing feature is disabled");
                }

                let peer_creds = trust::lookup_verified_peer_for_ip(peer_ip)
                    .ok_or_else(|| anyhow::anyhow!("Peer {} is not paired or trusted", peer_ip))?;
                let peer_hex = security::hex_encode(&peer_creds.device_id);
                if check_peer_trust_generation_fail_closed(&peer_hex, peer_creds.trust_generation)
                    != PeerTrustCheck::Valid
                {
                    anyhow::bail!("Peer {} is revoked or has stale trust generation", peer_hex);
                }

                // Tear down any prior local session cleanly
                let _ = Self::stop_local_audio_locked().await;

                // Prewarm and start CoreAudio up front so HAL init failures propagate honestly (`AUD-1G7-15`)
                let prewarm_rc = unsafe { integrator_mac_audio_prewarm() };
                if prewarm_rc != 0 {
                    anyhow::bail!("Failed to prewarm macOS CoreAudio subsystem");
                }
                let start_rc = {
                    let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    unsafe { integrator_mac_audio_start() }
                };
                if start_rc != 0 {
                    anyhow::bail!("Failed to initialize macOS CoreAudio default output AudioUnit");
                }

                if let Err(e) = Self::start_sink_server_inner().await {
                    let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    unsafe {
                        integrator_mac_audio_stop();
                    }
                    return Err(e);
                }

                let gen = {
                    let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    let g = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
                    {
                        let mut target_guard = ACTIVE_CAPTURE_TARGET
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        *target_guard = Some(ActiveCaptureTarget {
                            peer_ip: peer_ip.to_string(),
                            peer_device_id: peer_creds.device_id,
                            trust_generation: peer_creds.trust_generation,
                            routing_generation: g,
                        });
                    }
                    // Keep LAST_PACKET_EPOCH_MS == 0 until RPC completes or first packet arrives
                    // so a >5 s remote WASAPI init never triggers premature idle timeout (`AUD-1G7-05(3)`).
                    LAST_PACKET_EPOCH_MS.store(0, Ordering::Release);
                    ROUTING_ACTIVE.store(true, Ordering::Release);
                    PLAYOUT_ACTIVE.store(true, Ordering::Release);
                    g
                };

                spawn_playout_worker_for_gen_await(gen).await;
                (peer_creds, peer_hex, gen)
            };

            // Phase 2 (UNLOCKED): invoke remote StartAudioCapture RPC with bounded timeout
            let req = DisplayRpcRequest::StartAudioCapture {
                sample_rate: CANONICAL_SAMPLE_RATE,
                channels: CANONICAL_CHANNELS,
                bit_depth: CANONICAL_BIT_DEPTH,
            };
            let rpc_res = match tokio::time::timeout(
                Duration::from_secs(10),
                DisplayController::send_remote_rpc(peer_ip, &req),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!(
                    "Timed out awaiting StartAudioCapture RPC response from {}",
                    peer_ip
                )),
            };

            // Phase 3 (locked): validate state or roll back ONLY if still owning `my_gen`
            let mut need_remote_cleanup_stop = false;
            let commit_res: Result<String> = {
                let _lifecycle = lifecycle_lock().lock().await;
                let still_valid = !AUDIO_SHUTDOWN.load(Ordering::Acquire)
                    && AUDIO_ENABLED.load(Ordering::Acquire)
                    && ROUTING_GENERATION.load(Ordering::Acquire) == my_gen
                    && check_peer_trust_generation_fail_closed(&peer_hex, peer_creds.trust_generation)
                        == PeerTrustCheck::Valid;

                match &rpc_res {
                    Ok(resp) if resp.success && still_valid => {
                        let _ = LAST_PACKET_EPOCH_MS.compare_exchange(
                            0,
                            epoch_millis(),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        Ok(format!(
                            "Dynamic Audio Routing started: Windows ({}) streaming desktop audio to macOS speakers",
                            peer_ip
                        ))
                    }
                    _ => {
                        if matches!(&rpc_res, Ok(resp) if resp.success) {
                            // Remote peer started capture while we were cancelled/revoked/shut down -> stop it (`NEW-01`)
                            need_remote_cleanup_stop = true;
                        }
                        if ROUTING_GENERATION.load(Ordering::Acquire) == my_gen {
                            let _ = Self::stop_local_audio_locked().await;
                            let mut reg = global_audio_registry()
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            reg.revoke_peer_sessions(&peer_creds.device_id);
                        }
                        match rpc_res {
                            Ok(resp) if !resp.success => {
                                Err(anyhow::anyhow!(
                                    "Remote peer {} rejected audio capture: {}",
                                    peer_ip,
                                    resp.message
                                ))
                            }
                            Err(e) => Err(e),
                            _ => Err(anyhow::anyhow!(
                                "Audio routing aborted due to concurrent stop, disable, revocation, or shutdown"
                            )),
                        }
                    }
                }
            };

            if need_remote_cleanup_stop {
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    DisplayController::send_remote_rpc(peer_ip, &DisplayRpcRequest::StopAudioCapture),
                )
                .await;
            }

            commit_res
        }

        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            Self::start_capture_and_stream(
                peer_ip,
                CANONICAL_SAMPLE_RATE,
                CANONICAL_CHANNELS,
                CANONICAL_BIT_DEPTH,
            )
            .await
        }
    }

    /// Internal locked helper stopping all local playback, sessions, jitter buffer, and outbound capture.
    /// Caller MUST hold `AUDIO_LIFECYCLE_LOCK`. Returns previous remote peer IP if any.
    async fn stop_local_audio_locked() -> Option<String> {
        let remote_ip = {
            let guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|t| t.peer_ip.clone())
        };

        // 1. Flip ROUTING_ACTIVE & bump generation first under PLAYOUT_STATE_LOCK
        {
            let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROUTING_ACTIVE.store(false, Ordering::Release);
            ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
        }

        // 2. Invalidate all receiver sessions immediately (invalidates detached Arcs too)
        {
            let mut reg = global_audio_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            reg.clear_all();
        }

        // 3. Await playout worker exit BEFORE stopping CoreAudio & resetting jitter buffer
        stop_playout_worker_await().await;

        {
            let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            #[cfg(target_os = "macos")]
            unsafe {
                integrator_mac_audio_stop();
            }
            let mut jb = global_jitter_buffer().lock().unwrap_or_else(|e| e.into_inner());
            jb.reset();
        }

        // 4. Stop any local outbound capture and await sender task
        let _ = stop_capture_locked_await().await;
        remote_ip
    }

    /// Stops dynamic audio routing on both local playback/capture and remote peer.
    /// Stops local audio immediately (never stalls 35 s awaiting unreachable peer), then notifies
    /// the remote peer outside the lock with a bounded 2 s timeout.
    pub async fn stop_audio_routing() -> Result<String> {
        let remote_ip = {
            let _lifecycle = lifecycle_lock().lock().await;
            Self::stop_local_audio_locked().await
        };

        #[cfg(target_os = "macos")]
        if let Some(ip) = remote_ip.as_deref() {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                DisplayController::send_remote_rpc(ip, &DisplayRpcRequest::StopAudioCapture),
            )
            .await;
        }

        let stop_detail = if let Some(ip) = remote_ip {
            format!("stopped local playback and notified remote {}", ip)
        } else {
            "audio capture and playback stopped".to_string()
        };

        Ok(format!("Dynamic Audio Routing stopped ({})", stop_detail))
    }

    /// Stops the UDP port 58284 sink receiver task while holding `AUDIO_LIFECYCLE_LOCK`.
    #[cfg(test)]
    async fn stop_sink_server_inner() {
        SINK_GENERATION.fetch_add(1, Ordering::SeqCst);
        SINK_LISTENING.store(false, Ordering::Release);
        sink_cancel_notify().notify_waiters();

        let handle = {
            let mut guard = SINK_RECEIVER_TASK.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        if let Some(mut h) = handle {
            if tokio::time::timeout(Duration::from_millis(500), &mut h)
                .await
                .is_err()
            {
                h.abort();
                let _ = tokio::time::timeout(Duration::from_millis(250), h).await;
            }
        }
    }

    /// Complete, awaited asynchronous teardown of Dynamic Audio Routing (`AUD-1G7-07`, `NEW-01`).
    /// Never blocked by remote RPCs because `AUDIO_LIFECYCLE_LOCK` is never held across network I/O.
    #[cfg(test)]
    pub async fn shutdown_async() {
        AUDIO_SHUTDOWN.store(true, Ordering::SeqCst);
        {
            let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROUTING_ACTIVE.store(false, Ordering::Release);
            PLAYOUT_ACTIVE.store(false, Ordering::Release);
            ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
        }

        // Perform local awaited teardown FIRST under lifecycle lock (guaranteed fast — zero RPC wait)
        let remote_ip = {
            let _lifecycle = lifecycle_lock().lock().await;
            Self::stop_sink_server_inner().await;
            Self::stop_local_audio_locked().await
        };

        // Best-effort bounded remote notification AFTER local teardown (500 ms max)
        #[cfg(target_os = "macos")]
        if let Some(ip) = remote_ip.as_deref() {
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                DisplayController::send_remote_rpc(ip, &DisplayRpcRequest::StopAudioCapture),
            )
            .await;
        }
        #[cfg(not(target_os = "macos"))]
        let _ = remote_ip;

        tracing::info!("🛑 Dynamic Audio Routing subsystem shut down cleanly (async awaited)");
    }

    /// Synchronous fallback teardown safe to invoke repeatedly or from non-async / FFI contexts.
    pub fn shutdown_sync() {
        AUDIO_SHUTDOWN.store(true, Ordering::SeqCst);
        SINK_GENERATION.fetch_add(1, Ordering::SeqCst);
        SINK_LISTENING.store(false, Ordering::Release);

        {
            let _state = PLAYOUT_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROUTING_ACTIVE.store(false, Ordering::Release);
            PLAYOUT_ACTIVE.store(false, Ordering::Release);
            ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst);
            if let Some(worker) = PLAYOUT_WORKER_HANDLE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                worker.abort();
            }
            #[cfg(target_os = "macos")]
            unsafe {
                integrator_mac_audio_stop();
            }
            let mut jb = global_jitter_buffer().lock().unwrap_or_else(|e| e.into_inner());
            jb.reset();
        }

        playout_cancel_notify().notify_waiters();
        sink_cancel_notify().notify_waiters();

        {
            let mut reg = global_audio_registry().lock().unwrap_or_else(|e| e.into_inner());
            reg.clear_all();
        }
        {
            let mut recv_guard = SINK_RECEIVER_TASK.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(recv) = recv_guard.take() {
                recv.abort();
            }
        }
        let _ = Self::stop_capture();

        tracing::info!("🛑 Dynamic Audio Routing subsystem shut down cleanly (sync)");
    }

    /// Generates and plays a stereo 24-bit 48 kHz spatial test chime through the local OS output device.
    ///
    /// Writes `spatial_test_chime.wav` under `app_data_dir()` with `0o600` permissions (Unix) and
    /// spawns `afplay` (macOS) or `PowerShell Media.SoundPlayer` (Windows) via `reap_child`.
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
        Self::synthesize_chime_wav(&wav_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&wav_path, std::fs::Permissions::from_mode(0o600));
        }

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

    /// Synthesizes a 1.2-second C5/G5/C6 triad chime into a 24-bit 48 kHz stereo PCM WAV file at `path`.
    fn synthesize_chime_wav(path: &Path) -> Result<()> {
        let sample_rate = 48000usize;
        let duration_secs = 1.2f32;
        let total_frames = (sample_rate as f32 * duration_secs) as usize;
        let num_channels = 2usize;
        let bytes_per_sample = 3usize;

        let raw_file = File::create(path)?;
        let mut file = BufWriter::with_capacity(64 * 1024, raw_file);

        let block_align = (num_channels * bytes_per_sample) as u16;
        let byte_rate = (sample_rate as u32) * (block_align as u32);
        let data_chunk_size = (total_frames * num_channels * bytes_per_sample) as u32;
        let riff_chunk_size = 36 + data_chunk_size;

        file.write_all(b"RIFF")?;
        file.write_all(&riff_chunk_size.to_le_bytes())?;
        file.write_all(b"WAVE")?;
        file.write_all(b"fmt ")?;
        file.write_all(&16u32.to_le_bytes())?;
        file.write_all(&1u16.to_le_bytes())?;
        file.write_all(&(num_channels as u16).to_le_bytes())?;
        file.write_all(&(sample_rate as u32).to_le_bytes())?;
        file.write_all(&byte_rate.to_le_bytes())?;
        file.write_all(&block_align.to_le_bytes())?;
        file.write_all(&24u16.to_le_bytes())?;
        file.write_all(b"data")?;
        file.write_all(&data_chunk_size.to_le_bytes())?;

        // Triad frequencies in Hz: C5 (523.25), G5 (783.99), C6 (1046.50).
        let f1 = 523.25f32;
        let f2 = 783.99f32;
        let f3 = 1046.50f32;
        let two_pi = std::f32::consts::PI * 2.0;

        for i in 0..total_frames {
            let t = i as f32 / sample_rate as f32;
            let attack = (t / 0.008).min(1.0);
            let decay = (-3.8 * t).exp();
            let env = attack * decay;

            let s1 = (two_pi * f1 * t).sin() * 0.45;
            let s2 = (two_pi * f2 * t).sin() * 0.35;
            let s3 = (two_pi * f3 * t).sin() * 0.15;
            let mono_sample = (s1 + s2 + s3) * env;

            // Subtle 10% stereo spatial offset (L=1.05, R=0.95) for channel verification.
            let sample_l = (mono_sample * 1.05f32).clamp(-1.0, 1.0);
            let sample_r = (mono_sample * 0.95f32).clamp(-1.0, 1.0);

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

    /// Acquires `AUDIO_LIFECYCLE_LOCK` and starts the authenticated `IUA2` UDP sink server on port 58284.
    pub async fn start_sink_server() -> Result<()> {
        let _lifecycle = lifecycle_lock().lock().await;
        Self::start_sink_server_inner().await
    }

    /// Binds `0.0.0.0:58284`, verifies shutdown/feature gates, and spawns the `IUA2` decrypt/playout loop.
    async fn start_sink_server_inner() -> Result<()> {
        if AUDIO_SHUTDOWN.load(Ordering::Acquire) {
            anyhow::bail!("Audio subsystem is shutting down");
        }
        if !AUDIO_ENABLED.load(Ordering::Acquire) {
            anyhow::bail!("Dynamic Audio Routing feature is disabled");
        }
        if SINK_LISTENING.load(Ordering::Acquire) {
            return Ok(());
        }

        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", AUDIO_PORT)).await?;

        // Re-check shutdown & feature gate AFTER UdpSocket::bind().await (`AUD-1G7-07(4)`)
        if AUDIO_SHUTDOWN.load(Ordering::Acquire) || !AUDIO_ENABLED.load(Ordering::Acquire) {
            anyhow::bail!("Audio subsystem shut down or disabled during UDP bind");
        }

        let my_sink_gen = SINK_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        SINK_LISTENING.store(true, Ordering::Release);
        let guard = SinkListeningGuard { my_sink_gen };

        tracing::info!(
            "🔊 Authenticated UDP Audio Sink (IUA2) listening on port {} (ChaCha20-Poly1305 + JitterBuffer + Native Playback)",
            AUDIO_PORT
        );

        let recv_handle = tokio::spawn(async move {
            let _guard = guard;
            let mut buf = vec![0u8; MAX_AUDIO_DATAGRAM_LEN + 1];
            let mut last_unauth_log: Option<Instant> = None;
            let mut last_bounds_log: Option<Instant> = None;
            let mut last_err_log: Option<Instant> = None;
            let mut last_format_log: Option<Instant> = None;
            let mut last_hal_attempt: Option<Instant> = None;
            let mut last_prune_secs: u64 = 0;

            loop {
                if AUDIO_SHUTDOWN.load(Ordering::Acquire)
                    || SINK_GENERATION.load(Ordering::Acquire) != my_sink_gen
                {
                    break;
                }

                let recv_res = tokio::select! {
                    r = socket.recv_from(&mut buf) => r,
                    _ = sink_cancel_notify().notified() => {
                        if AUDIO_SHUTDOWN.load(Ordering::Acquire)
                            || SINK_GENERATION.load(Ordering::Acquire) != my_sink_gen
                        {
                            break;
                        }
                        continue;
                    }
                };

                match recv_res {
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

                        if !ROUTING_ACTIVE.load(Ordering::Acquire)
                            || !AUDIO_ENABLED.load(Ordering::Acquire)
                            || AUDIO_SHUTDOWN.load(Ordering::Acquire)
                        {
                            continue;
                        }
                        let gen_before_decrypt = ROUTING_GENERATION.load(Ordering::Acquire);
                        let now_secs = security::unix_epoch_secs();

                        if now_secs > last_prune_secs {
                            last_prune_secs = now_secs;
                            let mut reg = global_audio_registry()
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            reg.prune_expired(now_secs);
                        }

                        let mut session_id = [0u8; 8];
                        session_id.copy_from_slice(&buf[8..16]);

                        let session_opt = {
                            let reg = global_audio_registry()
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            reg.get_session(&session_id)
                        };

                        let verify_res = match session_opt {
                            Some(session_arc) => {
                                let res = AudioSessionRegistry::open_datagram_detached_with_meta(
                                    &session_arc,
                                    &buf[..size],
                                    now_secs,
                                );
                                if matches!(
                                    res,
                                    Err(AudioUdpError::SessionExpired)
                                        | Err(AudioUdpError::SessionRevoked)
                                        | Err(AudioUdpError::SessionStaleGeneration)
                                ) {
                                    let mut reg = global_audio_registry()
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    reg.evict_session(&session_id);
                                }
                                res
                            }
                            None => Err(AudioUdpError::UnknownSession(session_id)),
                        };

                        match verify_res {
                            Ok((peer_id, session_order, is_canonical, hdr, plaintext)) => {
                                // Enforce active-source peer binding so unrelated paired Peer B cannot
                                // hijack macOS speakers or thrash Peer A's jitter buffer (`NEW-02`).
                                let authorized_source = {
                                    let target_guard = ACTIVE_CAPTURE_TARGET
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    target_guard
                                        .as_ref()
                                        .map(|t| {
                                            t.routing_generation == gen_before_decrypt
                                                && security::constant_time_eq(
                                                    &t.peer_device_id,
                                                    &peer_id,
                                                )
                                        })
                                        .unwrap_or(false)
                                };
                                if !authorized_source {
                                    if rate_limit_allow(&mut last_unauth_log) {
                                        tracing::warn!(
                                            "🚫 Dropped UDP audio packet from non-active peer {} (cross-peer speaker isolation)",
                                            peer.ip()
                                        );
                                    }
                                    continue;
                                }

                                // Filter authenticated keepalives BEFORE JitterBuffer / SPSC (`AUD-1G7-10`)
                                if hdr.flags == AUDIO_FLAG_KEEPALIVE {
                                    PACKETS_DRAINED.fetch_add(1, Ordering::Relaxed);
                                    LAST_PACKET_EPOCH_MS.store(epoch_millis(), Ordering::Relaxed);
                                    continue;
                                }

                                // Strict canonical Stage 1 format check (48 kHz / 2ch / 16-bit / 240 samples / 960 B; `AUD-1G7-10`)
                                let valid_canonical_frame = is_canonical
                                    && ((hdr.flags == AUDIO_FLAG_SILENCE
                                        && hdr.frame_samples == AUDIO_FRAME_SAMPLES_PER_CH)
                                        || (hdr.flags == AUDIO_FLAG_PCM_FRAME
                                            && hdr.frame_samples == AUDIO_FRAME_SAMPLES_PER_CH
                                            && plaintext.len() == CANONICAL_FRAME_BYTES));
                                if !valid_canonical_frame {
                                    if rate_limit_allow(&mut last_format_log) {
                                        tracing::warn!(
                                            "⚠️ Dropped non-canonical audio frame (canonical={}, samples={}, len={}) from {}",
                                            is_canonical,
                                            hdr.frame_samples,
                                            plaintext.len(),
                                            peer.ip()
                                        );
                                    }
                                    continue;
                                }

                                // Atomically validate generation/routing state, push to JitterBuffer,
                                // and optionally restart CoreAudio under PLAYOUT_STATE_LOCK (`NEW-03`, `NEW-04`, `AUD-1G7-08`).
                                let mut need_spawn_worker = false;
                                {
                                    let _state = PLAYOUT_STATE_LOCK
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if !ROUTING_ACTIVE.load(Ordering::Acquire)
                                        || !AUDIO_ENABLED.load(Ordering::Acquire)
                                        || AUDIO_SHUTDOWN.load(Ordering::Acquire)
                                        || ROUTING_GENERATION.load(Ordering::Acquire)
                                            != gen_before_decrypt
                                    {
                                        continue;
                                    }

                                    PACKETS_DRAINED.fetch_add(1, Ordering::Relaxed);
                                    LAST_PACKET_EPOCH_MS.store(epoch_millis(), Ordering::Relaxed);

                                    {
                                        let mut jb = global_jitter_buffer()
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        jb.push_packet_for_session(session_order, &hdr, &plaintext);
                                    }

                                    if !PLAYOUT_ACTIVE.load(Ordering::Acquire) {
                                        let allow_attempt = match last_hal_attempt {
                                            Some(prev) => prev.elapsed() >= HAL_RETRY_INTERVAL,
                                            None => true,
                                        };
                                        if allow_attempt {
                                            last_hal_attempt = Some(Instant::now());
                                            #[cfg(target_os = "macos")]
                                            let start_ok = unsafe { integrator_mac_audio_start() == 0 };
                                            #[cfg(not(target_os = "macos"))]
                                            let start_ok = true;

                                            if start_ok {
                                                PLAYOUT_ACTIVE.store(true, Ordering::Release);
                                                need_spawn_worker = true;
                                            } else if rate_limit_allow(&mut last_err_log) {
                                                tracing::error!(
                                                    "Failed to start native CoreAudio unit (rate-limited)"
                                                );
                                            }
                                        }
                                    }
                                }

                                if need_spawn_worker {
                                    spawn_playout_worker_for_gen_await(gen_before_decrypt).await;
                                }
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

        let mut recv_guard = SINK_RECEIVER_TASK.lock().unwrap_or_else(|e| e.into_inner());
        if AUDIO_SHUTDOWN.load(Ordering::Acquire) || SINK_GENERATION.load(Ordering::Acquire) != my_sink_gen {
            recv_handle.abort();
            return Ok(());
        }
        if let Some(old) = recv_guard.take() {
            old.abort();
        }
        *recv_guard = Some(recv_handle);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_AUDIO_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    fn lock_audio_sync() -> tokio::sync::MutexGuard<'static, ()> {
        let g = TEST_AUDIO_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .blocking_lock();
        AudioManager::reset_shutdown_for_test();
        g
    }

    async fn lock_audio_async() -> tokio::sync::MutexGuard<'static, ()> {
        let g = TEST_AUDIO_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        AudioManager::reset_shutdown_for_test();
        g
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_mac_audio_shm_struct_layout() {
        assert_eq!(std::mem::size_of::<IntegratorAudioShmHeader>(), 131128);
        assert_eq!(std::mem::offset_of!(IntegratorAudioShmHeader, write_pos), 40);
        assert_eq!(std::mem::offset_of!(IntegratorAudioShmHeader, read_pos), 44);
        assert_eq!(std::mem::offset_of!(IntegratorAudioShmHeader, underruns), 48);
        assert_eq!(std::mem::offset_of!(IntegratorAudioShmHeader, buffer), 52);
    }

    #[test]
    fn default_status_is_honest_experimental_preview() {
        let status = AudioRoutingStatus::default();
        assert!(!status.is_active);
        assert_eq!(status.latency_ms, 0.0);
        assert_eq!(status.sample_rate, CANONICAL_SAMPLE_RATE);
        assert_eq!(status.bit_depth, CANONICAL_BIT_DEPTH);
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
            "bit_depth": 16,
            "is_active": false
        }"#;
        let parsed: AudioRoutingStatus = serde_json::from_str(legacy_json)
            .expect("legacy AudioRoutingStatus JSON should deserialize");
        assert_eq!(parsed.port, AUDIO_PORT);
        assert_eq!(parsed.frames_captured, 0);
        assert_eq!(parsed.packets_drained, 0);
        assert_eq!(parsed.underruns, 0);

        let serialized =
            serde_json::to_string(&parsed).expect("AudioRoutingStatus should serialize");
        let roundtrip: AudioRoutingStatus =
            serde_json::from_str(&serialized).expect("AudioRoutingStatus should roundtrip");
        assert_eq!(roundtrip.port, AUDIO_PORT);
    }

    #[test]
    fn reject_all_zero_sender_nonce_non_canonical_and_authenticate_by_device_id() {
        let _test_lock = lock_audio_sync();
        let zeros = "00".repeat(32);
        let local_id = trust::local_device_id_hex();
        let nonce = security::hex_encode(&security::csprng_array::<32>());

        // Missing peer_device_id must fail closed
        assert!(AudioManager::handle_negotiate_session_for_peer(
            None,
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            16
        )
        .is_err());

        // Non-canonical 24-bit format rejected at Stage 1 negotiation (`AUD-1G7-10`)
        assert!(AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            24
        )
        .is_err());

        // All-zero nonce rejected
        assert!(AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &zeros,
            48_000,
            2,
            16
        )
        .is_err());

        let wire = AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            16,
        );
        assert!(wire.is_ok());

        // Unknown peer ID rejected
        assert!(AudioManager::handle_negotiate_session_for_peer(
            Some(&"ff".repeat(16)),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            16
        )
        .is_err());
    }

    #[test]
    fn negotiate_and_verify_loopback_iua2_session() {
        let _test_lock = lock_audio_sync();
        let local_id = trust::local_device_id_hex();
        let sender_nonce = security::csprng_array::<32>();
        let sender_nonce_hex = security::hex_encode(&sender_nonce);
        let wire = AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &sender_nonce_hex,
            48_000,
            2,
            16,
        )
        .expect("negotiate loopback audio session");

        let creds = trust::lookup_verified_peer_by_id_at_ip(&local_id, "127.0.0.1".parse().unwrap())
            .expect("local loopback creds");
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
            .seal_datagram(
                AUDIO_FLAG_PCM_FRAME,
                1000,
                AUDIO_FRAME_SAMPLES_PER_CH,
                &[0x11u8; CANONICAL_FRAME_BYTES],
                now,
            )
            .unwrap();
        let mut reg = global_audio_registry().lock().unwrap_or_else(|e| e.into_inner());
        let (peer_id, hdr, plain) = reg.open_incoming_datagram(&dgram, now).unwrap();
        assert_eq!(peer_id, creds.device_id);
        assert_eq!(hdr.pkt_seq, 1);
        assert_eq!(plain.len(), CANONICAL_FRAME_BYTES);
    }

    #[test]
    fn test_jitter_buffer_playout_roundtrip() {
        let mut jb = jitter::JitterBuffer::new();
        let test_pcm = vec![0x42u8; CANONICAL_FRAME_BYTES];

        for seq in 1..=4 {
            let hdr = crate::security::audio_udp::AudioDatagramHeader {
                version: 2,
                flags: AUDIO_FLAG_PCM_FRAME,
                session_id: [0u8; 8],
                pkt_seq: seq,
                timestamp_us: 1000,
                frame_samples: 240,
                payload_len: CANONICAL_FRAME_BYTES as u16,
            };
            jb.push_packet(&hdr, &test_pcm);
        }

        let out = jb.pop_frame().expect("playout frame");
        assert_eq!(out.len(), CANONICAL_FRAME_BYTES);
        assert_eq!(out[0], 0x42);
        assert_eq!(out[CANONICAL_FRAME_BYTES - 1], 0x42);
    }

    #[test]
    fn test_silence_packet_handling() {
        let mut jb = jitter::JitterBuffer::new();
        for seq in 1..=4 {
            let hdr = crate::security::audio_udp::AudioDatagramHeader {
                version: 2,
                flags: AUDIO_FLAG_SILENCE,
                session_id: [0u8; 8],
                pkt_seq: seq,
                timestamp_us: 1000,
                frame_samples: 240,
                payload_len: 1,
            };
            jb.push_packet(&hdr, &[0u8; 1]);
        }

        let out = jb.pop_frame().expect("playout frame");
        assert_eq!(out.len(), CANONICAL_FRAME_BYTES);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_peer_revocation_tears_down_capture_and_macos_playback_without_keystore_lookup() {
        let _test_lock = lock_audio_sync();
        let mock_peer_id = [0x55u8; 16];
        let mock_peer_hex = security::hex_encode(&mock_peer_id);
        let mock_ip = "192.168.1.99";

        ROUTING_ACTIVE.store(true, Ordering::SeqCst);
        PLAYOUT_ACTIVE.store(true, Ordering::SeqCst);
        let gen_before = ROUTING_GENERATION.load(Ordering::SeqCst);
        {
            let mut jb = global_jitter_buffer().lock().unwrap_or_else(|e| e.into_inner());
            for seq in 1..=4 {
                let hdr = crate::security::audio_udp::AudioDatagramHeader {
                    version: 2,
                    flags: AUDIO_FLAG_PCM_FRAME,
                    session_id: [0x55; 8],
                    pkt_seq: seq,
                    timestamp_us: 5000,
                    frame_samples: 240,
                    payload_len: CANONICAL_FRAME_BYTES as u16,
                };
                jb.push_packet(&hdr, &[0x7Fu8; CANONICAL_FRAME_BYTES]);
            }
            assert_eq!(jb.buffered_frames_count(), 4);
        }
        {
            let mut target_guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            *target_guard = Some(ActiveCaptureTarget {
                peer_ip: mock_ip.to_string(),
                peer_device_id: mock_peer_id,
                trust_generation: 1,
                routing_generation: gen_before,
            });
        }

        assert!(trust::lookup_verified_peer_for_ip(mock_ip).is_none());

        AudioManager::revoke_peer_audio_sessions(&mock_peer_hex);

        assert!(ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner()).is_none());
        assert!(!ROUTING_ACTIVE.load(Ordering::Acquire));
        assert!(!PLAYOUT_ACTIVE.load(Ordering::Acquire));
        assert!(ROUTING_GENERATION.load(Ordering::Acquire) > gen_before);
        assert_eq!(
            global_jitter_buffer()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .buffered_frames_count(),
            0
        );
    }

    #[test]
    fn test_unrelated_peer_revocation_spares_active_peer_even_with_registry_session() {
        let _test_lock = lock_audio_sync();
        let active_peer_id = [0x22u8; 16];
        let other_peer_id = [0x33u8; 16];
        let other_peer_hex = security::hex_encode(&other_peer_id);

        // Give unrelated Peer B an idle session in AUDIO_SESSION_REGISTRY (`AUD-1G7-02(3)`)
        crate::security::transport::register_peer_trust_generation(&other_peer_hex, 1);
        {
            let mut reg = global_audio_registry().lock().unwrap_or_else(|e| e.into_inner());
            let _ = reg.negotiate_receiver_session(
                other_peer_id,
                1,
                &[0x44; 32],
                &[0x11; 32],
                48_000,
                2,
                16,
                security::unix_epoch_secs(),
            );
        }

        ROUTING_ACTIVE.store(true, Ordering::SeqCst);
        {
            let mut target_guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            *target_guard = Some(ActiveCaptureTarget {
                peer_ip: "192.168.1.100".to_string(),
                peer_device_id: active_peer_id,
                trust_generation: 1,
                routing_generation: 11,
            });
        }

        let evicted = AudioManager::revoke_peer_audio_sessions(&other_peer_hex);
        assert_eq!(evicted, 1, "Unrelated Peer B's idle session must be evicted");

        // Peer A's active capture/routing target MUST remain completely undisturbed!
        let target_after = ACTIVE_CAPTURE_TARGET
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(target_after.is_some());
        assert_eq!(target_after.unwrap().peer_device_id, active_peer_id);
        assert!(ROUTING_ACTIVE.load(Ordering::Acquire));

        let _ = AudioManager::stop_capture();
        ROUTING_ACTIVE.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_audio_subsystem_shutdown_sync_teardown_and_resurrection_latch() {
        let _test_lock = lock_audio_sync();
        ROUTING_ACTIVE.store(true, Ordering::SeqCst);
        PLAYOUT_ACTIVE.store(true, Ordering::SeqCst);
        SINK_LISTENING.store(true, Ordering::SeqCst);

        {
            let mut target_guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            *target_guard = Some(ActiveCaptureTarget {
                peer_ip: "127.0.0.1".to_string(),
                peer_device_id: [0x77u8; 16],
                trust_generation: 2,
                routing_generation: 5,
            });
        }

        AudioManager::shutdown_sync();

        assert!(!ROUTING_ACTIVE.load(Ordering::Acquire));
        assert!(!PLAYOUT_ACTIVE.load(Ordering::Acquire));
        assert!(!SINK_LISTENING.load(Ordering::Acquire));
        assert!(ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner()).is_none());

        let local_id = trust::local_device_id_hex();
        let nonce = security::hex_encode(&security::csprng_array::<32>());
        assert!(AudioManager::handle_negotiate_session_for_peer(
            Some(&local_id),
            "127.0.0.1".parse().unwrap(),
            &nonce,
            48_000,
            2,
            16
        )
        .is_err());

        AudioManager::reset_shutdown_for_test();
    }

    #[test]
    fn test_playout_worker_guard_generation_ownership_and_panic_safety() {
        let _test_lock = lock_audio_sync();
        let gen1 = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        PLAYOUT_ACTIVE.store(true, Ordering::SeqCst);

        let gen2 = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let _stale_guard = PlayoutWorkerGuard { my_gen: gen1 };
        }
        assert!(
            PLAYOUT_ACTIVE.load(Ordering::Acquire),
            "Stale gen1 worker drop must NOT clear gen2 PLAYOUT_ACTIVE"
        );

        let panic_res = std::panic::catch_unwind(|| {
            let _active_guard = PlayoutWorkerGuard { my_gen: gen2 };
            panic!("simulated playout worker panic");
        });
        assert!(panic_res.is_err());
        assert!(
            !PLAYOUT_ACTIVE.load(Ordering::Acquire),
            "Panicking current-generation worker must clear PLAYOUT_ACTIVE via Drop guard"
        );
    }

    #[tokio::test]
    async fn test_start_and_stop_capture_enforce_session_ownership() {
        let _test_lock = lock_audio_async().await;
        let peer_a = [0xAAu8; 16];
        let peer_b = [0xBBu8; 16];
        let peer_b_hex = security::hex_encode(&peer_b);
        crate::security::transport::register_peer_trust_generation(&peer_b_hex, 1);

        {
            let mut guard = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(ActiveCaptureTarget {
                peer_ip: "192.168.1.50".to_string(),
                peer_device_id: peer_a,
                trust_generation: 1,
                routing_generation: 42,
            });
        }

        // 1. Non-owner Peer B calling StartAudioCapture (even with invalid params) MUST NOT kill Peer A (`NEW-06`)
        let fake_b_creds = VerifiedPeerCredentials {
            device_id: peer_b,
            device_id_hex: peer_b_hex.clone(),
            ed25519_pubkey: [0x22u8; 32],
            key_id: [0x33u8; 16],
            root_key: zeroize::Zeroizing::new([0x11u8; 32]),
            hostname: "PeerB".into(),
            os: "macos".into(),
            last_ip: "192.168.1.51".into(),
            paired_at_epoch: 1_750_000_000,
            via_direct_cable: false,
            trust_generation: 1,
        };
        assert!(AudioManager::start_capture_and_stream_for_peer(
            "192.168.1.51",
            fake_b_creds.clone(),
            0,
            0,
            0
        )
        .await
        .is_err());
        assert!(AudioManager::start_capture_and_stream_for_peer(
            "192.168.1.51",
            fake_b_creds,
            48_000,
            2,
            16
        )
        .await
        .is_err());
        assert_eq!(
            ACTIVE_CAPTURE_TARGET
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|t| t.peer_device_id),
            Some(peer_a),
            "Peer A's active capture must remain intact after Peer B StartAudioCapture rejection"
        );

        // 2. Non-owner Peer B calling StopAudioCapture MUST be rejected (`AUD-1G7-15`)
        assert!(AudioManager::stop_capture_for_peer(&peer_b).await.is_err());
        assert!(ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner()).is_some());

        // 3. Owner Peer A stops cleanly
        assert!(AudioManager::stop_capture_for_peer(&peer_a).await.is_ok());
        assert!(ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner()).is_none());
    }

    #[tokio::test]
    async fn test_async_playout_worker_handoff_disable_and_shutdown_await() {
        let _test_lock = lock_audio_async().await;
        let gen1 = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        LAST_PACKET_EPOCH_MS.store(epoch_millis(), Ordering::SeqCst);
        PLAYOUT_ACTIVE.store(true, Ordering::SeqCst);

        spawn_playout_worker_for_gen_await(gen1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(PLAYOUT_ACTIVE.load(Ordering::Acquire));

        let gen2 = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        spawn_playout_worker_for_gen_await(gen2).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(PLAYOUT_ACTIVE.load(Ordering::Acquire));

        // Disabling audio feature atomically tears down playback and rejects new starts (`AUD-1G7-07(2)`)
        AudioManager::disable_audio_feature_async().await.unwrap();
        assert!(!PLAYOUT_ACTIVE.load(Ordering::Acquire));
        assert!(!ROUTING_ACTIVE.load(Ordering::Acquire));
        assert!(AudioManager::start_sink_server().await.is_err());

        // Re-enable then test shutdown latch
        AudioManager::set_audio_feature_enabled(true);
        AudioManager::shutdown_async().await;
        assert!(!PLAYOUT_ACTIVE.load(Ordering::Acquire));
        assert!(!ROUTING_ACTIVE.load(Ordering::Acquire));
        assert!(AudioManager::start_sink_server().await.is_err());

        AudioManager::reset_shutdown_for_test();
    }

    #[tokio::test]
    async fn test_async_revocation_clears_matching_peer_cleanly() {
        let _test_lock = lock_audio_async().await;
        let peer_id = [0x66u8; 16];
        let peer_hex = security::hex_encode(&peer_id);
        let gen = ROUTING_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

        ROUTING_ACTIVE.store(true, Ordering::SeqCst);
        PLAYOUT_ACTIVE.store(true, Ordering::SeqCst);
        {
            let mut t = ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner());
            *t = Some(ActiveCaptureTarget {
                peer_ip: "192.168.1.77".to_string(),
                peer_device_id: peer_id,
                trust_generation: 3,
                routing_generation: gen,
            });
        }
        spawn_playout_worker_for_gen_await(gen).await;

        AudioManager::revoke_peer_audio_sessions_async(&peer_hex).await;

        assert!(!ROUTING_ACTIVE.load(Ordering::Acquire));
        assert!(!PLAYOUT_ACTIVE.load(Ordering::Acquire));
        assert!(ACTIVE_CAPTURE_TARGET.lock().unwrap_or_else(|e| e.into_inner()).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_native_c11_spsc_wrap_alignment_and_live_flush() {
        let _test_lock = lock_audio_sync();
        unsafe {
            integrator_mac_audio_test_reset();
            assert_eq!(integrator_mac_audio_prewarm(), 0);

            let unaligned = [1u8, 2, 3, 4, 5, 6, 7];
            assert_eq!(
                integrator_mac_audio_write_pcm(unaligned.as_ptr(), unaligned.len() as u32),
                4
            );
            assert_eq!(integrator_mac_audio_buffered_bytes(), 4);

            let mut out = [0u8; 8];
            let pulled = integrator_mac_audio_test_render_pull(out.as_mut_ptr(), 4);
            assert_eq!(pulled, 4);
            assert_eq!(&out[..4], &[1, 2, 3, 4]);
            assert_eq!(integrator_mac_audio_buffered_bytes(), 0);

            let mut pattern = [0u8; CANONICAL_FRAME_BYTES];
            let mut pull_buf = [0u8; CANONICAL_FRAME_BYTES];
            for iter in 0..160u32 {
                let tag = (iter & 0xFF) as u8;
                pattern.fill(tag);
                let w = integrator_mac_audio_write_pcm(pattern.as_ptr(), pattern.len() as u32);
                assert_eq!(w, CANONICAL_FRAME_BYTES as u32);
                let r = integrator_mac_audio_test_render_pull(pull_buf.as_mut_ptr(), pull_buf.len() as u32);
                assert_eq!(r, CANONICAL_FRAME_BYTES as u32);
                assert!(pull_buf.iter().all(|&b| b == tag), "SPSC wrap corruption at iter {}", iter);
            }

            let w = integrator_mac_audio_write_pcm(pattern.as_ptr(), pattern.len() as u32);
            assert_eq!(w, CANONICAL_FRAME_BYTES as u32);
            integrator_mac_audio_flush();
            assert_eq!(integrator_mac_audio_buffered_bytes(), 0);
            integrator_mac_audio_test_reset();
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_native_win_dsp_soft_limit_downmix_pcm24_and_silence_holdoff() {
        unsafe {
            // 1. soft_limit C1 continuity and strict monotonicity
            assert_eq!(integrator_win_audio_test_soft_limit(0.0), 0.0);
            assert!((integrator_win_audio_test_soft_limit(0.8) - 0.8).abs() < 1e-6);
            let at_0999 = integrator_win_audio_test_soft_limit(0.999);
            let at_1000 = integrator_win_audio_test_soft_limit(1.000);
            let at_1001 = integrator_win_audio_test_soft_limit(1.001);
            assert!((at_1000 - at_0999).abs() < 0.002 && (at_1001 - at_1000).abs() < 0.002);
            assert!(at_0999 < at_1000 && at_1000 < at_1001 && at_1001 < 1.0);
            assert!(integrator_win_audio_test_soft_limit(1.2) < 1.0);
            assert!(integrator_win_audio_test_soft_limit(-1.2) > -1.0);
            assert!(integrator_win_audio_test_soft_limit(3.0) <= 1.0);
            assert!(integrator_win_audio_test_soft_limit(-3.0) >= -1.0);
            assert_eq!(integrator_win_audio_test_soft_limit(f32::NAN), 0.0);

            // 2. Silence-entry holdoff prevents 5 ms cutout between 10 ms WASAPI packets (`NEW-1G8-01`)
            assert!(
                !integrator_win_audio_test_should_emit_silence(5_500.0, 10_000.0, false),
                "5.5 ms wait during 10 ms WASAPI cadence must NOT emit synthetic silence"
            );
            assert!(
                !integrator_win_audio_test_should_emit_silence(15_000.0, 10_000.0, false),
                "15 ms wait during 10 ms WASAPI cadence must NOT emit synthetic silence"
            );
            assert!(
                integrator_win_audio_test_should_emit_silence(26_000.0, 10_000.0, false),
                "26 ms elapsed past 25 ms holdoff must enter synthetic silence"
            );
            assert!(
                integrator_win_audio_test_should_emit_silence(5_000.0, 10_000.0, true),
                "Once already in silence, 5 ms ticks emit silence cleanly"
            );

            // 3. Surround downmix exact peak safety <= 1.0001 across all layouts including SPEAKER_ALL
            let layouts: &[(u16, u32, &str)] = &[
                (1, 0x4, "Mono"),
                (2, 0x3, "Stereo"),
                (4, 0x33, "Quad 4.0 Back"),
                (4, 0x603, "Quad 4.0 Side"),
                (4, 0x107, "Surround 4.0 FL|FR|FC|BC"),
                (6, 0x3F, "5.1 Back"),
                (6, 0x60F, "5.1 Side"),
                (8, 0x63F, "7.1 Surround"),
                (8, 0xFF, "7.1 Home"),
                (6, 0x8000_0000, "SPEAKER_ALL 6ch"),
            ];
            for &(ch, mask, name) in layouts {
                let mut l = 0.0f32;
                let mut r = 0.0f32;
                let peak = integrator_win_audio_test_downmix_unity_peak(ch, mask, &mut l, &mut r);
                assert!(
                    peak > 0.5 && peak <= 1.0001,
                    "Layout {} ({}ch mask 0x{:X}) out-of-range peak {} (L={}, R={})",
                    name,
                    ch,
                    mask,
                    peak,
                    l,
                    r
                );
            }

            // 4. UB-free 24-bit signed negative PCM decoding
            let neg_full = integrator_win_audio_test_decode_pcm24(0x00, 0x00, 0x80);
            assert!((neg_full + 1.0).abs() < 1e-6);
            let neg_one = integrator_win_audio_test_decode_pcm24(0xFF, 0xFF, 0xFF);
            assert!(neg_one < 0.0 && neg_one > -1e-5);
        }
    }

    #[test]
    fn test_audio_mixer_pcm16_gain_balance_and_mute() {
        // 1. Center balanced (0.0) leaves samples untouched
        let sample_val: i16 = 10_000;
        let orig = sample_val.to_le_bytes();
        let mut buf = [orig[0], orig[1], orig[0], orig[1]];
        apply_mixer_gain_pcm16(&mut buf, 0.0, false);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 10_000);

        // 2. Slide left (-0.5) attenuates Windows audio by 50%
        apply_mixer_gain_pcm16(&mut buf, -0.5, false);
        assert_eq!(i16::from_le_bytes([buf[0], buf[1]]), 5_000);

        // 3. Slide right (+1.0) boosts Windows audio 1.5x with saturation clamp
        let mut boost_buf = [orig[0], orig[1], 0xFF, 0x7F];
        apply_mixer_gain_pcm16(&mut boost_buf, 1.0, false);
        assert_eq!(i16::from_le_bytes([boost_buf[0], boost_buf[1]]), 15_000);
        assert_eq!(i16::from_le_bytes([boost_buf[2], boost_buf[3]]), i16::MAX);

        // 4. One-tap soundbar mute zeros entire PCM frame immediately
        apply_mixer_gain_pcm16(&mut boost_buf, 1.0, true);
        assert_eq!(boost_buf, [0, 0, 0, 0]);
    }
}
