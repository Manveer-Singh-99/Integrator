//! # Camera & Shared Microphone Subsystem: Mac -> Windows 11 Virtual Camera & Mic
//!
//! ## 1. Module Purpose & Scope
//! This module owns the end-to-end orchestration of the **Mac -> Windows 11 Shared Camera & Microphone**
//! pipeline (`camera` feature flag). It captures the Mac camera stream (and tracks shared microphone
//! device selection, mute, TCC permission, and input gain settings), transmits video over an encrypted,
//! mutually authenticated transport session, and injects it directly into the Windows 11 Media
//! Foundation FrameServer pipeline as a native standalone virtual webcam.
//!
//! ### Core Subsystem Responsibilities
//! - **Capture Ingestion (macOS)**: Interfaces via C-ABI FFI with `camera_macos.swift`, capturing
//!   uncompressed 720p30 `NV12` bi-planar frames (`kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange`)
//!   directly from built-in, USB, or Continuity Camera devices via AVFoundation, and discovering/selecting
//!   macOS AVFoundation microphone sources alongside TCC audio permission checks.
//! - **Wire Serialization**: Packages raw frame buffers into length-delimited, magic-tagged `ICAM`
//!   datagrams with microsecond-precision presentation timestamps and geometry validation.
//! - **Secure Streaming**: Transmits frames across `TransportSessionV2` (`ServiceId::CameraStream`,
//!   TCP port [`CAMERA_PORT`] = `58287`), utilizing ChaCha20-Poly1305 AEAD authenticated encryption
//!   and Ed25519 identity keys established via mutual SPAKE2 pairing.
//! - **Virtual Camera Feed (Windows 11)**: On Windows, accepts authenticated camera streams and
//!   forwards raw NV12 frames via C-ABI FFI (`camera_windows.cpp`) into an ACL-hardened double-buffered
//!   shared memory region (`Global\IntegratorVCamShm_v1`). This memory feeds `integrator_vcam.dll`, a
//!   standalone Media Foundation FrameServer COM component (`CLSID_IntegratorVCamActivate`) registered
//!   under the friendly name **"Integrator Mac Camera"**.
//!
//! ## 2. Architectural Linkages & Cross-Platform Flow
//! - **Upstream Callers**:
//!   - [`crate::core::IntegratorCore`]: Owns [`CameraService`], drives camera/mic RPC actions, privacy
//!     shutter toggles, and teardown on peer revocation (`terminate_peer_connections*`).
//!   - [`crate::display::controller::DisplayController`]: Dispatches authenticated remote camera and
//!     microphone RPCs (`StartCamera`, `CheckCameraConsent`, `ToggleCamera`, `StopCamera`,
//!     `GetCameraStatus`, `ListMics`, `SelectMic`, `SetMicSettings`).
//!   - [`integrator_on_mac_camera_frame`]: C-ABI callback invoked directly by `camera_macos.swift`.
//! - **Downstream Callees**:
//!   - `camera_macos.swift` & `permissions_macos.swift` (macOS FFI): AVFoundation camera/mic capture,
//!     device enumeration, selection, and scoped consent dialogs.
//!   - `camera_windows.cpp` / `vcam_windows.cpp` (`integrator_vcam.dll`, Windows FFI): Media Foundation
//!     virtual webcam registration, SHM ingestion, and scoped consent prompts.
//!   - [`authorization::CameraConsentManager`] & [`distribution::CameraFrameHub`]: Per-peer consent
//!     state machine, single-use lease redemption, and multi-subscriber fan-out mailboxes.
//!   - [`crate::security::keystore`], [`crate::security::transport`], [`crate::trust`].
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                           macOS (Sender)                               │
//! │                                                                        │
//! │  AVCaptureSession (FaceTime HD Camera, 720p30 NV12) + Audio Inputs     │
//! │         │                                                              │
//! │         ▼                                                              │
//! │  MacCameraCaptureController (`camera_macos.swift`)                     │
//! │         │                                                              │
//! │         ▼ (C-ABI: integrator_on_mac_camera_frame)                      │
//! │  Rust Camera FFI Handler (`camera/mod.rs`)                             │
//! │         │                                                              │
//! │         ▼ (CameraFrameHub::publish_frame)                              │
//! │  run_mac_sender_for_peer (`camera/mod.rs`)                             │
//! │         │                                                              │
//! │         ▼ (TransportSessionV2::send_message - ChaCha20-Poly1305)       │
//! └─────────┼──────────────────────────────────────────────────────────────┘
//!           │
//!           │  TCP :58287 (ServiceId::CameraStream)
//!           │  Encrypted Wire Magic: "ICAM" + 22-byte Header + NV12 Payload
//!           ▼
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                        Windows 11 (Receiver)                           │
//! │                                                                        │
//! │  TcpListener (:58287) -> handle_incoming_stream (`camera/mod.rs`)       │
//! │         │                                                              │
//! │         ▼ (TransportSessionV2::recv_message & decode_camera_frame)     │
//! │  integrator_win_vcam_push_nv12 (`camera_windows.cpp`)                  │
//! │         │                                                              │
//! │         ▼ (Atomic Slot Ping-Pong & MemoryBarrier)                      │
//! │  Shared Memory (`Global\IntegratorVCamShm_v1` - 2x 1,382,400 bytes)   │
//! │  Sync Event    (`Global\IntegratorVCamEvt_v1`)                         │
//! │         │                                                              │
//! │         ▼ (IMF2DBuffer2 / Lock2DSize row-copy)                         │
//! │  Windows 11 Media Foundation FrameServer (`integrator_vcam.dll`)       │
//! │  CLSID: {8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}                        │
//! │  Friendly Name: "Integrator Mac Camera"                                │
//! │         │                                                              │
//! │         ▼                                                              │
//! │  Target Consumer Apps (Microsoft Teams, Zoom, OBS, Windows Camera)    │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Standalone Virtual Camera Contract (Zero Third-Party Drivers)
//! Unlike legacy virtual webcams that install kernel filter drivers or require DirectShow source
//! filters, Integrator uses the Windows 11 native Media Foundation Virtual Camera API
//! (`MFCreateVirtualCamera` in `mfsensorgroup.dll`) registered as `MFVirtualCameraType_SoftwareCameraSource`
//! with `MFVirtualCameraLifetime_Session`. Crucially, physical camera wrapper attributes such as
//! `MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES` are **omitted**. This guarantees that the
//! virtual camera operates as a 100% independent, standalone software video source, requiring
//! no physical webcam hardware or third-party camera drivers on the Windows PC.
//!
//! ### Display Streaming Synergy
//! The camera subsystem operates concurrently alongside the display streaming subsystem
//! (which utilizes NVENC/D3D11 on Windows and VideoToolbox on Mac via Moonlight/Sunshine on ports
//! 47989/48989). Camera streaming runs on dedicated port 58287 and uses uncompressed NV12 over
//! local high-speed links (direct USB-C Thunderbolt or low-latency Wi-Fi 6), avoiding encoder
//! resource contention with high-framerate display streaming.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Multi-Threaded Async Runtime**: Manages the TCP listener on Windows (`start_server`)
//!   and the async per-peer sender loops on macOS (`run_mac_sender_for_peer`).
//! - **Single-Copy Fan-Out (`CameraFrameHub` / `SubscriberMailbox`)**: Bridges high-frequency
//!   AVFoundation camera callbacks to multiple Tokio async senders using reference-counted `Arc<Vec<u8>>`
//!   mailboxes paired with `Notify`. Stale unread frames are replaced in place per subscriber,
//!   preventing buffer bloat and head-of-line blocking across peers.
//! - **Strict Lifecycle Lock Hierarchy**: [`CameraLifecycleCoordinator`] enforces exact-once hardware
//!   teardown under `hardware_io_lock -> active_peer_streams -> peer_consent -> lingering_tasks -> hardware_state`.
//! - **Blocking OS Dispatches**: In-process camera/mic start, stop, enumeration, and consent calls are
//!   dispatched to `tokio::task::spawn_blocking` to avoid blocking async workers.
//!
//! ## 4. Security & Safety Invariants
//! - **Mutual Ed25519 Authentication**: Unauthenticated TCP connections are dropped immediately.
//!   Every stream must complete an encrypted `TransportSessionV2` handshake tied to paired device keys
//!   and redeem a single-use 256-bit authorization lease (`FLAG_AUTH_LEASE_REDEMPTION`).
//! - **Pre-Auth Connection Throttling**: Windows incoming connections are bounded by a semaphore
//!   ([`MAX_PRE_AUTH_CAMERA_CONNS`] = 8) to mitigate connection-flooding denial of service.
//! - **Memory Safety & Buffer Bounds**: All live frame packets are bound to exactly [`NV12_FRAME_BYTES`]
//!   (1,382,400 bytes for 1280x720 NV12). Packets exceeding this size or bearing invalid magic
//!   headers (`ICAM`) are rejected before slice memory is accessed.
//! - **Input Sanitization & Clamping**: Microphone gain is validated finite and clamped to `[0.0, 2.0]`,
//!   and device names/identifiers are sanitized against control characters and Unicode bidi overrides.
//! - **FFI Pointer Invariants**: Raw pointer inputs from native platform libraries are checked
//!   for nullity, valid buffer length, and expected dimensions prior to constructing Rust slices.

pub mod authorization;
pub mod distribution;

#[allow(unused_imports)]
use authorization::{
    CameraConsentManager, CameraConsentScope, CameraConsentState, CameraDenialAction,
    ConsentEvaluation, LeaseDirection, PersistentCameraConsent,
};
#[allow(unused_imports)]
use distribution::{CameraFrameHub, SharedCameraFrame, SubscriberMailbox};

#[cfg(target_os = "windows")]
use std::ffi::CStr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use tokio::net::TcpListener;
use tokio::sync::Notify;
#[cfg(target_os = "windows")]
use tokio::sync::Semaphore;
#[cfg(target_os = "windows")]
use tracing::warn;
use tracing::{error, info};

use crate::config::{
    CAMERA_PORT, DEFAULT_CAMERA_FPS, DEFAULT_CAMERA_FRIENDLY_NAME, DEFAULT_CAMERA_HEIGHT,
    DEFAULT_CAMERA_WIDTH,
};
use crate::discovery::DiscoveryManager;
use crate::features::FeatureManager;
use crate::security::transport::ServiceId;
use crate::trust;

/// Captured frame width in pixels (720p standard high definition).
pub const CAMERA_WIDTH: u32 = DEFAULT_CAMERA_WIDTH;

/// Captured frame height in pixels (720p standard high definition).
pub const CAMERA_HEIGHT: u32 = DEFAULT_CAMERA_HEIGHT;

/// Target camera capture and streaming frame rate in frames per second (fps).
pub const CAMERA_FPS: u32 = DEFAULT_CAMERA_FPS;

/// Total payload byte size for an uncompressed 1280x720 NV12 frame.
///
/// Calculation:
/// - Y (luma) plane: `width * height` = 1280 * 720 = 921,600 bytes.
/// - UV (chroma) plane: `width * (height / 2)` = 1280 * 360 = 460,800 bytes (subsampled 4:2:0).
/// - Total: `921,600 + 460,800` = `1,382,400` bytes (`width * height * 3 / 2`).
pub const NV12_FRAME_BYTES: usize = (CAMERA_WIDTH as usize) * (CAMERA_HEIGHT as usize) * 3 / 2;

/// Length of the binary camera frame transport header in bytes.
///
/// Binary Layout:
/// - `0..4`:   Magic bytes `b"ICAM"` (4 bytes)
/// - `4..6`:   Width in pixels, little-endian `u16` (2 bytes)
/// - `6..8`:   Height in pixels, little-endian `u16` (2 bytes)
/// - `8..9`:   Pixel format identifier, `u8` (1 byte, [`PIXEL_FMT_NV12`])
/// - `9..10`:  Flags bitfield, `u8` (1 byte, [`FLAG_STANDBY_KEEPALIVE`])
/// - `10..18`: Presentation timestamp in microseconds, little-endian `u64` (8 bytes)
/// - `18..22`: Payload length in bytes, little-endian `u32` (4 bytes)
/// - Total: 22 bytes.
pub const CAMERA_FRAME_HEADER_LEN: usize = 22;

/// Four-character wire magic identifier for Integrator Camera frame datagrams (`"ICAM"`).
pub const CAMERA_FRAME_MAGIC: [u8; 4] = *b"ICAM";

/// Pixel format tag representing Bi-Planar NV12 (Y plane followed by interleaved UV plane).
pub const PIXEL_FMT_NV12: u8 = 1;

/// Flag bit indicating a zero-payload standby keepalive datagram, maintaining the transport session
/// when the camera is paused or idling without transferring full uncompressed video frames.
pub const FLAG_STANDBY_KEEPALIVE: u8 = 0x01;

/// Flag bit indicating an initial authorization lease redemption datagram bridging RPC to stream.
pub const FLAG_AUTH_LEASE_REDEMPTION: u8 = 0x02;

/// Maximum timeout duration when establishing an outbound encrypted camera stream connection.
#[cfg(target_os = "macos")]
const CAMERA_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum timeout duration for transmitting a single encoded NV12 camera frame over the transport.
#[cfg(target_os = "macos")]
const CAMERA_FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of concurrent unauthenticated TCP connections allowed on the camera port.
#[cfg(target_os = "windows")]
const MAX_PRE_AUTH_CAMERA_CONNS: usize = 8;

/// Minimum allowed linear shared microphone gain multiplier (`0.0` = 0% silence).
const MIN_MIC_GAIN: f32 = 0.0;

/// Maximum allowed linear shared microphone gain multiplier (`2.0` = 200% boost).
const MAX_MIC_GAIN: f32 = 2.0;

/// Default linear shared microphone gain multiplier (`1.0` = 100% unity gain).
const DEFAULT_MIC_GAIN: f32 = 1.0;

/// Maximum UTF-8 character count retained when sanitizing external microphone device names or IDs.
#[cfg(target_os = "macos")]
const MAX_MIC_LABEL_CHARS: usize = 128;

/// Maximum UTF-8 byte length accepted for an incoming microphone unique device identifier.
const MAX_MIC_DEVICE_ID_BYTES: usize = 256;

/// Serde default helper providing the canonical virtual camera TCP streaming port.
fn default_camera_port() -> u16 {
    CAMERA_PORT
}

/// Serde default helper providing the canonical friendly virtual camera device name.
fn default_camera_device_name() -> String {
    DEFAULT_CAMERA_FRIENDLY_NAME.to_string()
}

/// Serde default helper indicating camera hardware availability when deserializing legacy status payloads.
fn default_camera_available() -> bool {
    true
}

/// Serde default helper providing unity (`1.0`) microphone gain when deserializing legacy status payloads.
fn default_mic_gain() -> f32 {
    DEFAULT_MIC_GAIN
}

/// Strips ASCII/Unicode control characters and Unicode bidirectional formatting overrides from
/// external audio/video device strings and truncates cleanly to `max_chars`.
#[cfg(any(target_os = "macos", test))]
fn sanitize_mic_label(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
                )
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Wire descriptor for an available microphone audio input device on the macOS host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MicDeviceWire {
    /// Platform unique device identifier (`AVCaptureDevice.uniqueID` on macOS).
    pub id: String,
    /// Human-readable localized device display name (sanitized against control/bidi chars).
    pub name: String,
    /// `true` if this device is currently the macOS system default audio input source.
    #[serde(default)]
    pub is_default: bool,
}

/// Diagnostic telemetry and status report for the Camera & Shared Microphone subsystem.
///
/// Returned over local RPC to the UI and CLI to display the live state of the camera pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraStatus {
    /// Whether the local platform supports camera operations (true on macOS and Windows 11).
    pub supported: bool,
    /// Whether a video capture source (built-in, USB webcam, or Continuity Camera on Mac; Virtual Camera on Windows) is available.
    #[serde(default = "default_camera_available")]
    pub camera_available: bool,
    /// Whether the camera capture or virtual camera publication loop is currently active.
    pub active: bool,
    /// Operating role of this machine: `"Mac Camera Sender"` or `"Windows 11 Virtual Webcam"`.
    pub role: String,
    /// Human-readable operational state label (e.g., `"Streaming 720p30"`, `"Standby"`, `"Error"`).
    pub state: String,
    /// Whether operating system privacy permissions (TCC / Camera access) are granted.
    pub permission_granted: bool,
    /// Output frame width in pixels (1280).
    pub width: u32,
    /// Output frame height in pixels (720).
    pub height: u32,
    /// Configured frame rate in frames per second (30).
    pub fps: u32,
    /// Cumulative count of video frames successfully transferred across the transport session.
    pub frames_transferred: u64,
    /// Optional error description from the most recent failure, if any.
    pub last_error: Option<String>,
    /// TCP streaming port carrying encrypted camera frames (defaults to [`CAMERA_PORT`]).
    #[serde(default = "default_camera_port")]
    pub port: u16,
    /// Friendly device name exposed for the shared virtual camera (defaults to [`DEFAULT_CAMERA_FRIENDLY_NAME`]).
    #[serde(default = "default_camera_device_name")]
    pub device_name: String,
    /// Whether the Hardware Camera Privacy Killswitch shutter is actively muting outgoing frames.
    #[serde(default)]
    pub privacy_muted: bool,
    /// Whether macOS-to-PC shared microphone capture/forwarding is enabled.
    #[serde(default)]
    pub mic_enabled: bool,
    /// Whether shared microphone output is currently muted.
    #[serde(default)]
    pub mic_muted: bool,
    /// Friendly display name of the currently selected macOS microphone source (empty if unselected).
    #[serde(default)]
    pub mic_device_name: String,
    /// Whether operating system microphone privacy permissions (`AVMediaType.audio` on macOS) are granted.
    #[serde(default)]
    pub mic_permission_granted: bool,
    /// Linear microphone input gain multiplier clamped to `0.0..=2.0` (`1.0` = 100% unity gain).
    #[serde(default = "default_mic_gain")]
    pub mic_gain: f32,
}

/// Parsed, zero-copy camera frame received over the network transport.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCameraFrame<'a> {
    /// Video frame width in pixels.
    pub width: u16,
    /// Video frame height in pixels.
    pub height: u16,
    /// Pixel format identifier (should match [`PIXEL_FMT_NV12`]).
    pub pix_fmt: u8,
    /// Frame control flags (e.g. [`FLAG_STANDBY_KEEPALIVE`]).
    pub flags: u8,
    /// Presentation timestamp in microseconds (derived from `CMSampleBuffer` or monotonic clock).
    pub timestamp_us: u64,
    /// Borrowed slice containing the raw pixel payload (or empty if standby keepalive).
    pub payload: &'a [u8],
}

/// Encodes an NV12 (or standby keepalive) camera frame packet bounded cleanly to `<= 2 MiB`.
///
/// # Arguments
/// - `width`: Frame width in pixels (must match [`CAMERA_WIDTH`] for live video).
/// - `height`: Frame height in pixels (must match [`CAMERA_HEIGHT`] for live video).
/// - `pix_fmt`: Pixel format tag ([`PIXEL_FMT_NV12`]).
/// - `flags`: Control flags bitmask ([`FLAG_STANDBY_KEEPALIVE`]).
/// - `timestamp_us`: Monotonic presentation timestamp in microseconds.
/// - `payload`: Raw NV12 pixel buffer or empty slice for keepalives.
///
/// # Errors
/// Returns `Err` if the payload exceeds [`NV12_FRAME_BYTES`], or if payload length does not match
/// [`NV12_FRAME_BYTES`] when [`FLAG_STANDBY_KEEPALIVE`] is clear.
pub fn encode_camera_frame(
    width: u16,
    height: u16,
    pix_fmt: u8,
    flags: u8,
    timestamp_us: u64,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    // Validate that the payload does not exceed the expected frame boundary.
    if payload.len() > NV12_FRAME_BYTES {
        return Err(format!(
            "Camera frame payload {} exceeds maximum {} bytes",
            payload.len(),
            NV12_FRAME_BYTES
        ));
    }
    // Non-keepalive live frames must match the exact NV12 geometry size.
    if (flags & (FLAG_STANDBY_KEEPALIVE | FLAG_AUTH_LEASE_REDEMPTION)) == 0 && payload.len() != NV12_FRAME_BYTES {
        return Err(format!(
            "Expected {} NV12 bytes for {}x{}, got {}",
            NV12_FRAME_BYTES,
            width,
            height,
            payload.len()
        ));
    }
    let total = CAMERA_FRAME_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| "Frame length overflow".to_string())?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&CAMERA_FRAME_MAGIC);
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.push(pix_fmt);
    out.push(flags);
    out.extend_from_slice(&timestamp_us.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Validates and parses an incoming `ICAM` camera frame buffer with full bounds checks.
///
/// # Arguments
/// - `raw`: Contiguous byte slice containing the wire packet (header + payload).
///
/// # Errors
/// Returns `Err` if the packet is shorter than [`CAMERA_FRAME_HEADER_LEN`], if the magic header
/// does not equal [`CAMERA_FRAME_MAGIC`], if packet size does not match header length fields,
/// or if dimensions/pixel format are unsupported.
#[cfg(any(target_os = "windows", test))]
pub fn decode_camera_frame(raw: &[u8]) -> Result<DecodedCameraFrame<'_>, String> {
    if raw.len() < CAMERA_FRAME_HEADER_LEN {
        return Err(format!("Truncated camera header ({} bytes)", raw.len()));
    }
    if raw[0..4] != CAMERA_FRAME_MAGIC {
        return Err("Invalid camera frame magic".into());
    }
    let width = u16::from_le_bytes([raw[4], raw[5]]);
    let height = u16::from_le_bytes([raw[6], raw[7]]);
    let pix_fmt = raw[8];
    let flags = raw[9];
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[10..18]);
    let timestamp_us = u64::from_le_bytes(ts_bytes);
    let payload_len = u32::from_le_bytes([raw[18], raw[19], raw[20], raw[21]]) as usize;

    let expected_end = CAMERA_FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| "Camera payload length overflow".to_string())?;
    if raw.len() != expected_end {
        return Err(format!(
            "Camera packet size mismatch: expected {}, got {}",
            expected_end,
            raw.len()
        ));
    }
    if (flags & (FLAG_STANDBY_KEEPALIVE | FLAG_AUTH_LEASE_REDEMPTION)) == 0 {
        if width as u32 != CAMERA_WIDTH || height as u32 != CAMERA_HEIGHT || pix_fmt != PIXEL_FMT_NV12 {
            return Err(format!(
                "Unsupported frame geometry {}x{} fmt {}",
                width, height, pix_fmt
            ));
        }
        if payload_len != NV12_FRAME_BYTES {
            return Err(format!(
                "Unexpected NV12 frame length {}, expected {}",
                payload_len, NV12_FRAME_BYTES
            ));
        }
    }
    Ok(DecodedCameraFrame {
        width,
        height,
        pix_fmt,
        flags,
        timestamp_us,
        payload: &raw[CAMERA_FRAME_HEADER_LEN..],
    })
}

/// Global lazy-initialized singleton instance of [`CameraFrameHub`].
static GLOBAL_FRAME_HUB: OnceLock<Arc<CameraFrameHub>> = OnceLock::new();

/// Returns the static reference to the shared [`CameraFrameHub`].
pub fn global_frame_hub() -> &'static Arc<CameraFrameHub> {
    GLOBAL_FRAME_HUB.get_or_init(|| Arc::new(CameraFrameHub::new()))
}

#[cfg(target_os = "macos")]
extern "C" {
    /// Returns current macOS TCC camera permission state (`2`: Authorized, `1`: Denied/Restricted, `0`: Not Determined).
    fn integrator_mac_camera_permission_state() -> i32;
    /// Returns `1` if the running bundle `Info.plist` includes `NSCameraUsageDescription`, else `0`.
    fn integrator_mac_camera_has_usage_desc() -> i32;
    /// Returns `1` if at least one active macOS video capture device is detected, else `0`.
    fn integrator_mac_camera_has_hardware() -> i32;
    /// Starts 720p30 NV12 AVFoundation camera capture; returns `0` on success or negative error code on failure.
    fn integrator_mac_camera_start() -> i32;
    /// Stops AVFoundation camera capture synchronously on the capture queue.
    fn integrator_mac_camera_stop();
    /// Returns `1` if AVFoundation capture is currently active and running, else `0`.
    fn integrator_mac_camera_is_running() -> i32;
    /// Serializes discovered camera devices into `out_buf` as UTF-8 JSON; returns byte length or `-1` on error.
    fn integrator_mac_camera_list_json(out_buf: *mut std::os::raw::c_char, cap: i32) -> i32;
    /// Selects active macOS video capture device by NUL-terminated UTF-8 `uniqueID`; returns `1` on success.
    fn integrator_mac_camera_select(device_id_utf8: *const std::os::raw::c_char) -> i32;
    /// Legacy consent prompt FFI symbol retained for ABI compatibility with `permissions_macos.swift` (OBS-1E-01).
    #[allow(dead_code)]
    fn integrator_mac_prompt_camera_consent(peer_name: *const std::os::raw::c_char) -> bool;
    /// Displays scoped macOS camera consent dialog (`1`: Once, `2`: Session, `3`: Always, `-1`: Block, `0`: Deny).
    fn integrator_mac_prompt_camera_consent_scoped(peer_name: *const std::os::raw::c_char, timeout_sec: i32) -> i32;
    /// Consent prompt cancellation FFI symbol retained for ABI compatibility with `permissions_macos.swift` (OBS-1E-01).
    #[allow(dead_code)]
    fn integrator_mac_cancel_camera_consent_prompt();
    /// Returns `true` if macOS TCC microphone authorization (`AVMediaType.audio`) is `.authorized`.
    fn integrator_mac_mic_permission_granted() -> bool;
    /// Serializes available macOS microphone inputs into `out_buf` as UTF-8 JSON; returns byte count written or `0`.
    fn integrator_mac_list_mics(out_buf: *mut u8, cap: usize) -> usize;
    /// Selects active macOS microphone device by NUL-terminated UTF-8 `uniqueID`; returns `true` if found/selected.
    fn integrator_mac_select_mic(device_id: *const std::ffi::c_char) -> bool;
    /// Requests macOS TCC microphone access if undetermined (bounded by 30s timeout off main thread); returns `true` if authorized.
    fn integrator_mac_request_mic_permission() -> bool;
}

/// Serializable descriptor for a discovered camera hardware/continuity device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CameraDeviceWire {
    /// Platform-assigned unique camera identifier (`AVCaptureDevice.uniqueID`).
    pub id: String,
    /// Human-readable localized camera display name.
    pub name: String,
    /// `true` if this camera is currently selected or the active default capture source.
    pub is_active: bool,
}

/// Enumerates all connected video capture devices on macOS (FaceTime HD, Continuity Camera, external webcams).
pub fn list_available_cameras() -> Vec<CameraDeviceWire> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 8192];
        // SAFETY: `buf` is a mutable 8 KiB heap allocation and `cap` matches `buf.len()`.
        let n = unsafe {
            integrator_mac_camera_list_json(buf.as_mut_ptr() as *mut std::os::raw::c_char, buf.len() as i32)
        };
        if n > 0 && (n as usize) <= buf.len() {
            if let Ok(s) = std::str::from_utf8(&buf[..n as usize]) {
                if let Ok(mut list) = serde_json::from_str::<Vec<CameraDeviceWire>>(s) {
                    for cam in &mut list {
                        cam.name = sanitize_mic_label(&cam.name, MAX_MIC_LABEL_CHARS);
                    }
                    return list;
                }
            }
        }
        Vec::new()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// Selects a specific video capture device by unique device identifier.
pub fn select_camera_device(device_id: &str) -> bool {
    let trimmed = device_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_MIC_DEVICE_ID_BYTES
        || trimmed.chars().any(|c| c.is_control())
    {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(c_str) = std::ffi::CString::new(trimmed) {
            // SAFETY: `c_str` points to a valid NUL-terminated UTF-8 string for the duration of the call.
            let res = unsafe { integrator_mac_camera_select(c_str.as_ptr()) };
            return res == 1;
        }
        false
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = trimmed;
        false
    }
}

/// Global atomic gate for the Hardware Camera Privacy Killswitch shutter.
///
/// When `true`, `integrator_on_mac_camera_frame` immediately substitutes a precomputed
/// studio-black privacy-shutter NV12 frame instead of live FaceTime HD pixels, keeping
/// the Windows virtual webcam stream alive (so Zoom/Teams/OBS never drops) while cutting
/// the live camera image instantaneously.
static CAMERA_PRIVACY_MUTED: AtomicBool = AtomicBool::new(false);

/// Precomputed 1280x720 NV12 privacy shutter frame (zero per-frame allocations).
///
/// Uses broadcast studio black (`Y = 16`, `UV = 128`) with a subtle centered matte slate
/// shutter band (`Y = 38`) so remote conferencing apps show a clean closed-shutter state.
fn privacy_shutter_nv12_frame() -> &'static [u8] {
    static FRAME: OnceLock<Vec<u8>> = OnceLock::new();
    FRAME.get_or_init(|| {
        let y_bytes = (CAMERA_WIDTH * CAMERA_HEIGHT) as usize;
        let mut buf = vec![16u8; NV12_FRAME_BYTES];
        // Neutral chroma (UV = 128) across the entire interleaved UV plane
        buf[y_bytes..].fill(128u8);
        // Subtle centered matte privacy-shutter bar (16px tall across center third)
        let w = CAMERA_WIDTH as usize;
        let y_start = (CAMERA_HEIGHT as usize / 2).saturating_sub(8);
        let y_end = y_start + 16;
        let x_start = w / 3;
        let x_end = (w * 2) / 3;
        for row in y_start..y_end {
            let row_off = row * w;
            buf[row_off + x_start..row_off + x_end].fill(40u8);
        }
        buf
    })
}

/// Returns whether the hardware camera privacy shutter killswitch is currently engaged.
pub fn is_camera_privacy_muted() -> bool {
    CAMERA_PRIVACY_MUTED.load(Ordering::Acquire)
}

/// Engages or disengages the hardware camera privacy shutter killswitch and notifies Touch Bar HUD.
pub fn set_camera_privacy_muted(muted: bool) -> bool {
    CAMERA_PRIVACY_MUTED.store(muted, Ordering::SeqCst);
    info!(
        "📹 Hardware Camera Privacy Shutter {}",
        if muted { "ENGAGED (feeding black NV12 shutter frames)" } else { "RELEASED (live camera active)" }
    );
    muted
}

/// C FFI callback invoked by `camera_macos.swift` upon capturing a new video sample buffer.
///
/// # Arguments
/// - `data`: Raw pointer to the contiguous NV12 frame buffer (1,382,400 bytes).
/// - `len`: Length of the buffer in bytes (must equal [`NV12_FRAME_BYTES`]).
/// - `width`: Frame width in pixels (must equal [`CAMERA_WIDTH`]).
/// - `height`: Frame height in pixels (must equal [`CAMERA_HEIGHT`]).
/// - `timestamp_us`: Microsecond timestamp derived from CoreMedia `CMSampleBuffer`.
///
/// # Safety
/// The caller (`camera_macos.swift`) guarantees that `data` points to a valid, allocated memory
/// region of at least `len` bytes for the entire duration of this function call.
#[no_mangle]
pub extern "C" fn integrator_on_mac_camera_frame(
    data: *const u8,
    len: u32,
    width: u32,
    height: u32,
    timestamp_us: u64,
) {
    if data.is_null() || len as usize != NV12_FRAME_BYTES || width != CAMERA_WIDTH || height != CAMERA_HEIGHT {
        return;
    }
    let slice: &[u8] = if CAMERA_PRIVACY_MUTED.load(Ordering::Acquire) {
        privacy_shutter_nv12_frame()
    } else {
        // SAFETY: Caller (`camera_macos.swift`) guarantees `data` stays valid for `len` bytes during callback.
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    };
    if let Ok(encoded) = encode_camera_frame(
        width as u16,
        height as u16,
        PIXEL_FMT_NV12,
        0,
        timestamp_us,
        slice,
    ) {
        global_frame_hub().publish_frame(encoded, false);
    }
}

#[cfg(target_os = "windows")]
extern "C" {
    /// Initializes Windows FrameServer virtual camera (`integrator_vcam.dll`) and ACL-hardened shared memory;
    /// returns `0` on success or writes a diagnostic message into `err_buf` on failure.
    fn integrator_win_vcam_start(err_buf: *mut std::os::raw::c_char, err_cap: i32) -> i32;
    /// Lock-free ingestion pushing one contiguous 720p NV12 frame into Windows shared memory ping-pong slots.
    fn integrator_win_vcam_push_nv12(data: *const u8, len: u32, timestamp_us: u64);
    /// Tears down the Windows virtual camera COM activation and unmaps shared memory safely.
    fn integrator_win_vcam_stop();
    /// Returns `1` if the Windows virtual camera receiver SHM/COM session is active, else `0`.
    fn integrator_win_vcam_is_active() -> i32;
    /// Displays scoped Windows receiver camera consent prompt (`1`: Once, `2`: Session, `3`: Always, `-1`: Block, `0`: Deny).
    fn integrator_win_prompt_camera_consent_scoped(peer_name: *const std::os::raw::c_char, timeout_sec: u32) -> i32;
    /// Consent prompt cancellation FFI symbol retained for ABI compatibility with `camera_windows.cpp` (OBS-1E-01).
    #[allow(dead_code)]
    fn integrator_win_cancel_camera_consent_prompt();
}

/// Maximum duration to await camera streaming task termination during teardown before escalating to abort (2.5 seconds).
pub const CAMERA_TEARDOWN_TIMEOUT: Duration = Duration::from_millis(2500);

/// Maximum duration to await task/native-operation drain after escalating to `JoinHandle::abort()` (500 ms).
pub const CAMERA_ABORT_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Abstraction over platform-native camera capture / virtual camera hardware lifecycle.
///
/// Production uses [`NativeCameraBackend`] (AVFoundation on macOS, Media Foundation Virtual Camera
/// on Windows 11). Deterministic lifecycle tests inject a controllable backend to verify exact-once
/// hardware shutdown and retention invariants without touching physical camera sensors.
pub trait CameraHardwareBackend: Send + Sync {
    /// Starts camera capture or virtual camera output.
    /// Returns `Err((state_label, error_msg))` on failure.
    fn start_capture(&self) -> Result<(), (String, String)>;
    /// Stops camera capture or virtual camera output cleanly.
    fn stop_capture(&self);
    /// Returns true if the native hardware backend reports capture is currently running.
    fn is_capture_running(&self) -> bool;
}

/// Production [`CameraHardwareBackend`] bridging to `camera_macos.swift` and `camera_windows.cpp`.
struct NativeCameraBackend;

impl CameraHardwareBackend for NativeCameraBackend {
    fn start_capture(&self) -> Result<(), (String, String)> {
        #[cfg(target_os = "windows")]
        {
            let mut err_buf = [0i8; 256];
            let rc = unsafe {
                integrator_win_vcam_start(err_buf.as_mut_ptr(), err_buf.len() as i32)
            };
            if rc == 0 {
                return Ok(());
            }
            let msg = unsafe { CStr::from_ptr(err_buf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(("Error".to_string(), msg));
        }

        #[cfg(target_os = "macos")]
        {
            let rc = unsafe { integrator_mac_camera_start() };
            if rc == 0 {
                return Ok(());
            }
            let (state_lbl, msg) = match rc {
                -2 => (
                    "Permission Needed",
                    "Launch Integrator.app bundle (NSCameraUsageDescription required for camera capture)".to_string(),
                ),
                -1 => (
                    "Permission Needed",
                    "macOS Camera permission denied — allow in System Settings > Privacy & Security > Camera".to_string(),
                ),
                -3 => (
                    "No Camera Detected",
                    "No Mac camera hardware detected (connect a USB webcam or Continuity Camera)".to_string(),
                ),
                _ => (
                    "Error",
                    format!("Failed to initialize AVFoundation camera capture (code {})", rc),
                ),
            };
            return Err((state_lbl.to_string(), msg));
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            Err((
                "Unsupported".to_string(),
                "Shared Camera is supported on macOS and Windows 11".to_string(),
            ))
        }
    }

    fn stop_capture(&self) {
        #[cfg(target_os = "macos")]
        unsafe {
            integrator_mac_camera_stop();
        }
        #[cfg(target_os = "windows")]
        unsafe {
            integrator_win_vcam_stop();
        }
    }

    fn is_capture_running(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            unsafe { integrator_mac_camera_is_running() != 0 }
        }
        #[cfg(target_os = "windows")]
        {
            unsafe { integrator_win_vcam_is_active() != 0 }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            false
        }
    }
}

/// Represents an active peer camera stream with its stream ID, cancellation sender, optional task handle, and generation.
pub struct ActivePeerStreamEntry {
    /// Monotonically assigned unique identifier for this stream instance (prevents same-generation clobbering).
    pub stream_id: u64,
    /// Watch channel sender signaling cooperative stream shutdown (`true`).
    pub cancel_tx: tokio::sync::watch::Sender<bool>,
    /// Spawned Tokio task handle retained for bounded timeout + `.abort()` escalation on teardown.
    pub task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Cryptographic peer trust generation bound when this stream was registered.
    #[allow(dead_code)]
    pub generation: u64,
}

/// Completion and reaping observability statistics for supervised lingering camera tasks and native operations.
#[derive(Debug, Clone, Default)]
pub struct CameraReapStats {
    /// Number of supervised lingering tasks or native ops that finished with `Ok(())`.
    pub reaped_ok: u64,
    /// Number of supervised lingering tasks observed cancelled via `.abort()`.
    pub reaped_cancelled: u64,
    /// Number of supervised lingering tasks or native ops caught panicking on unwind.
    pub reaped_panicked: u64,
    /// Number of supervised lingering tasks terminating with any other JoinError.
    pub reaped_other_err: u64,
    /// Diagnostic failure strings captured from unexpected panics or join errors.
    pub unexpected_failures: Vec<String>,
}

impl CameraReapStats {
    /// Total number of lingering tasks or native operations whose completion was observed and reaped.
    #[cfg(test)]
    pub fn total_reaped(&self) -> u64 {
        self.reaped_ok + self.reaped_cancelled + self.reaped_panicked + self.reaped_other_err
    }
}

/// Bookkeeping entry for an outer stream `JoinHandle` that exceeded bounded teardown timeout.
struct LingeringTaskEntry {
    /// Lowercased normalized hex device ID of the owning peer.
    peer_id: String,
    /// Diagnostic task origin label retained for observability and post-mortem debugging.
    #[allow(dead_code)]
    label: String,
    /// Populated only when supervision was registered outside any Tokio runtime context.
    fallback_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Bookkeeping entry tracking an active `spawn_blocking` native FFI call guarded by [`CameraNativeOpGuard`].
struct ActiveNativeOpRecord {
    /// Optional lowercased peer hex ID owning this blocking native call.
    peer_id: Option<String>,
    /// Optional unique `stream_id` associating this native op with a single stream instance.
    stream_id: Option<u64>,
    /// Diagnostic operation label (e.g. `"win_vcam_push_nv12"`).
    #[allow(dead_code)]
    label: String,
    /// Set to true if peer teardown timed out while this native resource operation remained active.
    lingering: bool,
}

/// Level-3 coordinator registry tracking lingering async handles, blocking native ops, and teardown drains.
#[derive(Default)]
struct LingeringRegistry {
    /// Supervised lingering JoinHandles awaiting asynchronous completion.
    tasks: HashMap<u64, LingeringTaskEntry>,
    /// Currently executing native/blocking camera resource operations tracked by [`CameraNativeOpGuard`].
    /// Even if an outer async JoinHandle is cancelled by `abort()`, an already-running `spawn_blocking`
    /// thread holds its guard until the native operation genuinely returns or unwinds.
    active_native_ops: HashMap<u64, ActiveNativeOpRecord>,
    /// Count of peer teardowns currently draining an extracted task handle / native operation.
    /// Prevents concurrent reapers from prematurely shutting down hardware mid-teardown.
    in_flight_teardowns: usize,
    /// Per-peer count of active in-flight teardowns so a concurrent second teardown for the
    /// same peer waits instead of returning false `Ok(())` while the first is still draining.
    in_flight_teardown_peers: HashMap<String, usize>,
    /// Accumulated completion/failure counters.
    stats: CameraReapStats,
}

impl LingeringRegistry {
    /// Returns total number of lingering outer task handles plus native ops marked lingering.
    fn lingering_count(&self) -> usize {
        self.tasks.len()
            + self
                .active_native_ops
                .values()
                .filter(|op| op.lingering)
                .count()
    }

    /// Returns `true` if any lingering task, active blocking native op, or in-flight teardown still depends on hardware.
    fn has_any_hardware_dependents(&self) -> bool {
        !self.tasks.is_empty()
            || !self.active_native_ops.is_empty()
            || self.in_flight_teardowns > 0
    }

    /// Returns `true` if `clean_peer_id` owns any lingering task, active native op, or active teardown drain.
    fn peer_has_lingering_or_active_native(&self, clean_peer_id: &str) -> bool {
        self.tasks.values().any(|t| t.peer_id == clean_peer_id)
            || self
                .active_native_ops
                .values()
                .any(|op| op.peer_id.as_deref() == Some(clean_peer_id))
            || self
                .in_flight_teardown_peers
                .get(clean_peer_id)
                .copied()
                .unwrap_or(0)
                > 0
    }

    /// Returns `true` if `stream_id` (or unscoped peer ops) still has an executing [`CameraNativeOpGuard`].
    fn stream_has_active_native_ops(&self, clean_peer_id: &str, stream_id: u64) -> bool {
        self.active_native_ops.values().any(|op| {
            op.peer_id.as_deref() == Some(clean_peer_id)
                && (op.stream_id.is_none() || op.stream_id == Some(stream_id))
        })
    }

    /// Marks active native operations belonging to `stream_id` as lingering and returns count marked.
    fn mark_stream_native_ops_lingering(&mut self, clean_peer_id: &str, stream_id: u64) -> usize {
        let mut marked = 0usize;
        for op in self.active_native_ops.values_mut() {
            if op.peer_id.as_deref() == Some(clean_peer_id)
                && (op.stream_id.is_none() || op.stream_id == Some(stream_id))
            {
                op.lingering = true;
                marked += 1;
            }
        }
        marked
    }

    /// Decrements global and per-peer in-flight teardown counters once teardown hands off or finishes.
    fn dec_in_flight_teardown(&mut self, clean_peer_id: &str) {
        self.in_flight_teardowns = self.in_flight_teardowns.saturating_sub(1);
        if let Some(cnt) = self.in_flight_teardown_peers.get_mut(clean_peer_id) {
            *cnt = cnt.saturating_sub(1);
            if *cnt == 0 {
                self.in_flight_teardown_peers.remove(clean_peer_id);
            }
        }
    }
}

/// Level-4 protected hardware run flag preventing duplicate start or double stop of native camera hardware.
#[derive(Default)]
struct HardwareState {
    /// `true` after `backend.start_capture()` succeeds until exact-once `backend.stop_capture()`.
    running: bool,
}

/// Shared lifecycle coordinator enforcing a strict total lock hierarchy across camera streams,
/// lingering-task supervision, native operation tracking, and exact-once hardware shutdown (SEC-1D-17).
///
/// Strict Lock Order (NEVER inverted, NEVER held across `.await`):
/// 0. `hardware_io_lock`
/// 1. `active_peer_streams`
/// 2. `peer_consent`
/// 3. `lingering_tasks`
/// 4. `hardware_state`
struct CameraLifecycleCoordinator {
    /// Hardware capture / virtual webcam backend implementation (production or deterministic test mock).
    backend: Arc<dyn CameraHardwareBackend>,
    /// Shared active flag exposed to [`CameraService::is_active`] and status snapshots.
    active: Arc<AtomicBool>,
    /// Session-scoped local camera user consent flag cleared upon idle hardware shutdown.
    local_consent: Arc<AtomicBool>,
    /// Indicates whether local preview currently pins capture hardware active.
    local_preview_active: Arc<AtomicBool>,
    /// Counter of in-progress stream or preview starts guarding against premature idle shutdown.
    starting_streams: Arc<AtomicUsize>,
    /// Total count of `backend.stop_capture()` executions (exact-once verification counter).
    shutdown_executions: Arc<AtomicU64>,
    /// Total count of idle hardware shutdown evaluations completed.
    shutdown_eval_count: Arc<AtomicU64>,
    /// Level-0 serialization mutex protecting `backend.start_capture()` / `backend.stop_capture()` I/O.
    hardware_io_lock: Mutex<()>,
    /// Level-1 map of active remote peer stream entries keyed by normalized peer device ID hex.
    active_peer_streams: Arc<Mutex<HashMap<String, ActivePeerStreamEntry>>>,
    /// Level-3 supervision registry tracking lingering tasks, active native ops, and teardown drains.
    lingering_tasks: Arc<Mutex<LingeringRegistry>>,
    /// Level-4 running state flag governing exact-once backend stop transitions.
    hardware_state: Mutex<HardwareState>,
    /// Shared operational status label (`"Standby"`, `"Streaming 720p30"`, etc.).
    state_label: Arc<Mutex<String>>,
    /// Shared most recent diagnostic error message.
    last_error: Arc<Mutex<Option<String>>>,
    /// Captured Tokio runtime handle used for completion-driven reaping from Drop threads.
    runtime_handle: Mutex<Option<tokio::runtime::Handle>>,
    /// Broadcast signal emitted whenever a native op, in-flight teardown, or lingering task completes.
    op_finished_notify: Arc<Notify>,
    /// Broadcast signal emitted after hardware idle evaluation or lingering count changes.
    lifecycle_notify: Arc<Notify>,
    /// Monotonic identifier generator shared across streams, native ops, and lingering tasks.
    next_id: AtomicU64,
    /// Bounded grace window awaiting cooperative stream cancellation before `.abort()`.
    teardown_timeout: Duration,
    /// Bounded drain window awaiting native blocking operations after outer task `.abort()`.
    abort_drain_timeout: Duration,
}

/// RAII guard protecting an in-progress stream/hardware startup against premature shutdown
/// triggered by a concurrently completing lingering task.
struct StreamStartGuard {
    /// Owning lifecycle coordinator.
    coord: Arc<CameraLifecycleCoordinator>,
    /// When `true` on drop, schedules idle hardware shutdown evaluation (failed/aborted startup).
    trigger_shutdown_on_drop: bool,
}

impl StreamStartGuard {
    /// Marks startup complete without triggering a deferred idle shutdown check (e.g. caller
    /// already inserted the active stream under `active_peer_streams` or enabled `local_preview_active`).
    fn finish_without_shutdown(mut self) {
        self.trigger_shutdown_on_drop = false;
    }
}

impl Drop for StreamStartGuard {
    fn drop(&mut self) {
        self.coord.starting_streams.fetch_sub(1, Ordering::SeqCst);
        if self.trigger_shutdown_on_drop {
            if let Some(rt) = self.coord.resolve_runtime_handle() {
                let coord = Arc::clone(&self.coord);
                rt.spawn_blocking(move || {
                    coord.try_shutdown_hardware_if_idle();
                    coord.lifecycle_notify.notify_waiters();
                });
            } else {
                self.coord.try_shutdown_hardware_if_idle();
                self.coord.lifecycle_notify.notify_waiters();
            }
        }
    }
}

/// Cancel-safe RAII guard keeping `in_flight_teardowns > 0` and owning the extracted stream
/// `JoinHandle` while `teardown_peer_stream_async` awaits termination.
///
/// If the teardown future is dropped/cancelled mid-`.await`, `Drop` automatically aborts any
/// remaining `JoinHandle`, marks active native operations lingering, transfers supervision into
/// `lingering_tasks` atomically before decrementing `in_flight_teardowns`, and dispatches deferred
/// hardware shutdown evaluation.
struct TeardownInFlightGuard {
    /// Owning lifecycle coordinator.
    coord: Arc<CameraLifecycleCoordinator>,
    /// Normalized peer hex identifier being torn down.
    peer_id: String,
    /// Unique stream identifier targeted by this teardown.
    stream_id: u64,
    /// Diagnostic label attached to supervised lingering entries.
    label: String,
    /// Extracted Tokio task handle owned until awaited, handed off, or dropped on cancellation.
    handle: Option<tokio::task::JoinHandle<()>>,
    /// Set to `true` after [`Self::handoff_to_lingering`] transfers ownership cleanly.
    disarmed: bool,
}

impl TeardownInFlightGuard {
    /// Atomically transitions this in-flight teardown into lingering supervision (if a handle
    /// timed out and/or stream native operations remain active) under Level 3 lock, ensuring
    /// zero gap where hardware could shut down prematurely.
    fn handoff_to_lingering(mut self) -> (Option<(u64, tokio::task::JoinHandle<()>)>, usize) {
        let lingering_handle = self.handle.take();
        let (task_to_watch, native_cnt) = {
            let mut reg = match self.coord.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };

            let native_cnt = reg.mark_stream_native_ops_lingering(&self.peer_id, self.stream_id);
            let task_to_watch = if let Some(handle) = lingering_handle {
                let task_id = self.coord.next_id();
                let has_rt = self.coord.has_runtime_handle();
                if has_rt {
                    reg.tasks.insert(
                        task_id,
                        LingeringTaskEntry {
                            peer_id: self.peer_id.clone(),
                            label: self.label.clone(),
                            fallback_handle: None,
                        },
                    );
                    Some((task_id, handle))
                } else {
                    reg.tasks.insert(
                        task_id,
                        LingeringTaskEntry {
                            peer_id: self.peer_id.clone(),
                            label: self.label.clone(),
                            fallback_handle: Some(handle),
                        },
                    );
                    None
                }
            } else {
                None
            };

            reg.dec_in_flight_teardown(&self.peer_id);
            self.disarmed = true;
            (task_to_watch, native_cnt)
        };
        self.coord.op_finished_notify.notify_waiters();
        (task_to_watch, native_cnt)
    }
}

impl Drop for TeardownInFlightGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            let leftover_handle = self.handle.take();
            if let Some(ref h) = leftover_handle {
                h.abort();
            }
            let task_to_watch = {
                let mut reg = match self.coord.lingering_tasks.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let _ = reg.mark_stream_native_ops_lingering(&self.peer_id, self.stream_id);
                let to_watch = if let Some(handle) = leftover_handle {
                    let task_id = self.coord.next_id();
                    let has_rt = self.coord.has_runtime_handle();
                    if has_rt {
                        reg.tasks.insert(
                            task_id,
                            LingeringTaskEntry {
                                peer_id: self.peer_id.clone(),
                                label: self.label.clone(),
                                fallback_handle: None,
                            },
                        );
                        Some((task_id, handle))
                    } else {
                        reg.tasks.insert(
                            task_id,
                            LingeringTaskEntry {
                                peer_id: self.peer_id.clone(),
                                label: self.label.clone(),
                                fallback_handle: Some(handle),
                            },
                        );
                        None
                    }
                } else {
                    None
                };
                reg.dec_in_flight_teardown(&self.peer_id);
                to_watch
            };

            if let Some((task_id, handle)) = task_to_watch {
                self.coord.spawn_lingering_watcher(
                    task_id,
                    self.peer_id.clone(),
                    self.label.clone(),
                    handle,
                );
            }

            self.coord.op_finished_notify.notify_waiters();

            if let Some(rt) = self.coord.resolve_runtime_handle() {
                let coord = Arc::clone(&self.coord);
                rt.spawn_blocking(move || {
                    coord.try_shutdown_hardware_if_idle();
                    coord.lifecycle_notify.notify_waiters();
                });
            } else {
                self.coord.try_shutdown_hardware_if_idle();
                self.coord.lifecycle_notify.notify_waiters();
            }
        }
    }
}

/// RAII guard tracking an in-flight blocking/native camera operation (e.g. `spawn_blocking` FFI call).
///
/// Aborting an outer Tokio task does NOT cancel an already-running `spawn_blocking` OS thread.
/// Moving this guard into the blocking/native operation ensures `CameraService` tracks actual
/// native resource completion, retains hardware while active, records panics on unwind, and
/// automatically triggers hardware shutdown once the final resource-using operation completes.
pub struct CameraNativeOpGuard {
    /// Owning lifecycle coordinator.
    coord: Arc<CameraLifecycleCoordinator>,
    /// Unique operation ID registered under `LingeringRegistry::active_native_ops`.
    op_id: u64,
    /// Optional peer hex identifier associated with this native operation.
    peer_id: Option<String>,
    /// Diagnostic label describing the native FFI call.
    label: String,
}

impl Drop for CameraNativeOpGuard {
    fn drop(&mut self) {
        let panicked = std::thread::panicking();
        let (err_to_record, was_lingering, no_dependents) = {
            let mut reg = match self.coord.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let removed = reg.active_native_ops.remove(&self.op_id);
            let was_lingering = removed.as_ref().map(|r| r.lingering).unwrap_or(false);
            let err = if panicked {
                reg.stats.reaped_panicked += 1;
                let msg = format!(
                    "Native camera operation #{} ({}) for peer {:?} panicked during execution",
                    self.op_id, self.label, self.peer_id
                );
                tracing::error!("{}", msg);
                reg.stats.unexpected_failures.push(msg.clone());
                Some(msg)
            } else if was_lingering {
                reg.stats.reaped_ok += 1;
                tracing::info!(
                    "Reaped completed lingering native camera operation #{} ({}) for peer {:?}",
                    self.op_id, self.label, self.peer_id
                );
                None
            } else {
                None
            };
            (err, was_lingering, !reg.has_any_hardware_dependents())
        };

        if let Some(msg) = err_to_record {
            if let Ok(mut le) = self.coord.last_error.lock() {
                *le = Some(msg);
            }
        }

        self.coord.op_finished_notify.notify_waiters();

        // Fast-path skip during steady-state high-FPS streaming when not lingering and streams remain active.
        let streams_empty = if was_lingering {
            true
        } else {
            self.coord
                .active_peer_streams
                .lock()
                .map(|s| s.is_empty())
                .unwrap_or(false)
        };

        if was_lingering || (no_dependents && streams_empty && self.coord.active.load(Ordering::SeqCst)) {
            // Dispatch completion-driven hardware shutdown outside the Drop thread's locks
            // to avoid any re-entrancy lock inversion and never block async worker threads.
            if let Some(rt) = self.coord.resolve_runtime_handle() {
                let coord = Arc::clone(&self.coord);
                rt.spawn_blocking(move || {
                    coord.try_shutdown_hardware_if_idle();
                    coord.lifecycle_notify.notify_waiters();
                });
            } else {
                self.coord.try_shutdown_hardware_if_idle();
                self.coord.lifecycle_notify.notify_waiters();
            }
        } else {
            self.coord.lifecycle_notify.notify_waiters();
        }
    }
}

impl CameraLifecycleCoordinator {
    /// Allocates a monotonically increasing unique identifier for streams, tasks, or native ops.
    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Captures the active Tokio runtime handle if invoked inside a Tokio runtime context.
    fn capture_runtime_handle(&self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if let Ok(mut slot) = self.runtime_handle.lock() {
                *slot = Some(handle);
            }
        }
    }

    /// Resolves the current or previously captured Tokio runtime handle.
    fn resolve_runtime_handle(&self) -> Option<tokio::runtime::Handle> {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return Some(handle);
        }
        self.runtime_handle.lock().ok().and_then(|g| g.clone())
    }

    /// Returns `true` if a Tokio runtime handle is available for spawning completion watchers.
    fn has_runtime_handle(&self) -> bool {
        self.resolve_runtime_handle().is_some()
    }

    /// Increments `starting_streams` and returns a guard protecting startup from premature reaping.
    fn begin_stream_start(self: &Arc<Self>) -> StreamStartGuard {
        self.starting_streams.fetch_add(1, Ordering::SeqCst);
        StreamStartGuard {
            coord: Arc::clone(self),
            trigger_shutdown_on_drop: true,
        }
    }

    /// Registers a cancel-safe in-flight teardown while caller holds Level 1 (`active_peer_streams`).
    /// Acquires Level 3 (`lingering_tasks`) strictly obeying lock order `1 < 3`.
    fn begin_in_flight_teardown_locked(
        self: &Arc<Self>,
        clean_peer_id: &str,
        stream_id: u64,
        label: &str,
        handle: Option<tokio::task::JoinHandle<()>>,
    ) -> TeardownInFlightGuard {
        let mut reg = match self.lingering_tasks.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        reg.in_flight_teardowns += 1;
        *reg.in_flight_teardown_peers
            .entry(clean_peer_id.to_string())
            .or_insert(0) += 1;
        TeardownInFlightGuard {
            coord: Arc::clone(self),
            peer_id: clean_peer_id.to_string(),
            stream_id,
            label: label.to_string(),
            handle,
            disarmed: false,
        }
    }

    /// Registers an active native camera operation and returns its RAII [`CameraNativeOpGuard`].
    fn begin_native_op(
        self: &Arc<Self>,
        peer_id: Option<&str>,
        stream_id: Option<u64>,
        label: &str,
    ) -> CameraNativeOpGuard {
        self.capture_runtime_handle();
        let op_id = self.next_id();
        let clean_peer = peer_id.map(|p| p.trim().to_ascii_lowercase());
        {
            let mut reg = match self.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            reg.active_native_ops.insert(
                op_id,
                ActiveNativeOpRecord {
                    peer_id: clean_peer.clone(),
                    stream_id,
                    label: label.to_string(),
                    lingering: false,
                },
            );
        }
        CameraNativeOpGuard {
            coord: Arc::clone(self),
            op_id,
            peer_id: clean_peer,
            label: label.to_string(),
        }
    }

    /// Inserts a lingering task entry under Level 3 (callable while holding Level 1, obeying `1 < 3`)
    /// and returns `(task_id, handle)` for spawning a completion watcher outside all locks.
    fn register_lingering_handle_locked(
        &self,
        clean_peer_id: &str,
        label: &str,
        handle: tokio::task::JoinHandle<()>,
    ) -> Option<(u64, tokio::task::JoinHandle<()>)> {
        let task_id = self.next_id();
        let has_rt = self.has_runtime_handle();
        let mut reg = match self.lingering_tasks.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if has_rt {
            reg.tasks.insert(
                task_id,
                LingeringTaskEntry {
                    peer_id: clean_peer_id.to_string(),
                    label: label.to_string(),
                    fallback_handle: None,
                },
            );
            Some((task_id, handle))
        } else {
            reg.tasks.insert(
                task_id,
                LingeringTaskEntry {
                    peer_id: clean_peer_id.to_string(),
                    label: label.to_string(),
                    fallback_handle: Some(handle),
                },
            );
            None
        }
    }

    /// Spawns a completion-driven watcher task that awaits `handle` outside all mutexes,
    /// observes its completion result (including panics), removes it from the registry,
    /// and triggers hardware shutdown if no dependents remain.
    fn spawn_lingering_watcher(
        self: &Arc<Self>,
        task_id: u64,
        peer_id: String,
        label: String,
        handle: tokio::task::JoinHandle<()>,
    ) {
        if let Some(rt) = self.resolve_runtime_handle() {
            let coord = Arc::clone(self);
            rt.spawn(async move {
                let join_res = handle.await;
                coord
                    .on_lingering_handle_completed(task_id, &peer_id, &label, join_res)
                    .await;
            });
        } else {
            // Runtime disappeared between registration and spawn: keep handle in fallback slot.
            let mut reg = match self.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(entry) = reg.tasks.get_mut(&task_id) {
                entry.fallback_handle = Some(handle);
            }
        }
    }

    /// Handles completion of a supervised lingering stream `JoinHandle`, recording stats/panics
    /// and dispatching an idle hardware shutdown check outside all locks.
    async fn on_lingering_handle_completed(
        self: Arc<Self>,
        task_id: u64,
        peer_id: &str,
        label: &str,
        join_res: Result<(), tokio::task::JoinError>,
    ) {
        let err_to_record = {
            let mut reg = match self.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            reg.tasks.remove(&task_id);
            match join_res {
                Ok(()) => {
                    reg.stats.reaped_ok += 1;
                    tracing::info!(
                        "Reaped completed lingering camera task #{} ({}) for peer {}",
                        task_id, label, peer_id
                    );
                    None
                }
                Err(e) if e.is_cancelled() => {
                    reg.stats.reaped_cancelled += 1;
                    tracing::info!(
                        "Reaped cancelled lingering camera task #{} ({}) for peer {}",
                        task_id, label, peer_id
                    );
                    None
                }
                Err(e) if e.is_panic() => {
                    reg.stats.reaped_panicked += 1;
                    let msg = format!(
                        "Lingering camera task #{} ({}) for peer {} panicked: {}",
                        task_id, label, peer_id, e
                    );
                    tracing::error!("{}", msg);
                    reg.stats.unexpected_failures.push(msg.clone());
                    Some(msg)
                }
                Err(e) => {
                    reg.stats.reaped_other_err += 1;
                    let msg = format!(
                        "Lingering camera task #{} ({}) for peer {} failed: {}",
                        task_id, label, peer_id, e
                    );
                    tracing::error!("{}", msg);
                    reg.stats.unexpected_failures.push(msg.clone());
                    Some(msg)
                }
            }
        };

        if let Some(msg) = err_to_record {
            if let Ok(mut le) = self.last_error.lock() {
                *le = Some(msg);
            }
        }

        self.op_finished_notify.notify_waiters();

        // Evaluate hardware shutdown on blocking pool outside all locks
        let coord = Arc::clone(&self);
        let _ = tokio::task::spawn_blocking(move || {
            coord.try_shutdown_hardware_if_idle();
        })
        .await;

        self.lifecycle_notify.notify_waiters();
    }

    /// Records failure statistics and `last_error` when an awaited stream handle panics or errors.
    fn record_completed_task_error(
        &self,
        peer_id: &str,
        label: &str,
        err: tokio::task::JoinError,
    ) {
        let err_to_record = {
            let mut reg = match self.lingering_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if err.is_panic() {
                reg.stats.reaped_panicked += 1;
                let msg = format!(
                    "Camera task ({}) for peer {} panicked: {}",
                    label, peer_id, err
                );
                tracing::error!("{}", msg);
                reg.stats.unexpected_failures.push(msg.clone());
                Some(msg)
            } else if err.is_cancelled() {
                reg.stats.reaped_cancelled += 1;
                None
            } else {
                reg.stats.reaped_other_err += 1;
                let msg = format!(
                    "Camera task ({}) for peer {} exited with error: {}",
                    label, peer_id, err
                );
                tracing::warn!("{}", msg);
                reg.stats.unexpected_failures.push(msg.clone());
                Some(msg)
            }
        };

        if let Some(msg) = err_to_record {
            if let Ok(mut le) = self.last_error.lock() {
                *le = Some(msg);
            }
        }
    }

    /// Upgrades any fallback handles to async completion watchers if a Tokio runtime is now available,
    /// or reaps finished fallback handles synchronously when no runtime exists.
    fn reap_fallback_handles(self: &Arc<Self>) -> usize {
        if self.has_runtime_handle() {
            let upgraded: Vec<(u64, String, String, tokio::task::JoinHandle<()>)> = {
                let mut reg = match self.lingering_tasks.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let mut out = Vec::new();
                for (&id, entry) in reg.tasks.iter_mut() {
                    if let Some(h) = entry.fallback_handle.take() {
                        out.push((id, entry.peer_id.clone(), entry.label.clone(), h));
                    }
                }
                out
            };
            let count = upgraded.len();
            for (task_id, peer_id, label, handle) in upgraded {
                self.spawn_lingering_watcher(task_id, peer_id, label, handle);
            }
            return count;
        }

        let mut reg = match self.lingering_tasks.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let finished_ids: Vec<u64> = reg
            .tasks
            .iter()
            .filter_map(|(&id, entry)| {
                entry
                    .fallback_handle
                    .as_ref()
                    .filter(|h| h.is_finished())
                    .map(|_| id)
            })
            .collect();
        let count = finished_ids.len();
        for id in finished_ids {
            reg.tasks.remove(&id);
            reg.stats.reaped_ok += 1;
        }
        count
    }

    #[cfg(test)]
    fn is_lingering_registry_poisoned(&self) -> bool {
        self.lingering_tasks.is_poisoned()
    }

    /// Returns the name of the first poisoned lifecycle mutex across Levels 0, 1, 3, and 4, if any.
    fn any_lifecycle_mutex_poisoned(&self) -> Option<&'static str> {
        if self.hardware_io_lock.is_poisoned() {
            Some("hardware_io_lock")
        } else if self.active_peer_streams.is_poisoned() {
            Some("active_peer_streams")
        } else if self.lingering_tasks.is_poisoned() {
            Some("lingering_tasks")
        } else if self.hardware_state.is_poisoned() {
            Some("hardware_state")
        } else {
            None
        }
    }

    /// Returns supervised lingering task/native-op count (never `< 1` if any lifecycle mutex is poisoned).
    fn lingering_count(&self) -> usize {
        let base = match self.lingering_tasks.lock() {
            Ok(reg) => reg.lingering_count(),
            Err(poisoned) => {
                // Never report an empty registry when mutex is poisoned (SEC-1D-17)
                poisoned.into_inner().lingering_count().max(1)
            }
        };
        if self.any_lifecycle_mutex_poisoned().is_some() {
            base.max(1)
        } else {
            base
        }
    }

    /// Returns whether `stream_id` (or unscoped peer native ops) still has an executing native op guard.
    fn stream_has_active_native_ops(&self, clean_peer_id: &str, stream_id: u64) -> bool {
        match self.lingering_tasks.lock() {
            Ok(reg) => reg.stream_has_active_native_ops(clean_peer_id, stream_id),
            Err(poisoned) => poisoned
                .into_inner()
                .stream_has_active_native_ops(clean_peer_id, stream_id),
        }
    }

    /// Returns whether `clean_peer_id` has any remaining lingering tasks, active native ops, or teardown drains.
    fn peer_has_lingering_or_active_native(&self, clean_peer_id: &str) -> bool {
        match self.lingering_tasks.lock() {
            Ok(reg) => reg.peer_has_lingering_or_active_native(clean_peer_id),
            Err(poisoned) => poisoned
                .into_inner()
                .peer_has_lingering_or_active_native(clean_peer_id),
        }
    }

    /// Clones accumulated lingering reap statistics for deterministic test assertions.
    #[cfg(test)]
    fn reap_stats(&self) -> CameraReapStats {
        match self.lingering_tasks.lock() {
            Ok(reg) => reg.stats.clone(),
            Err(poisoned) => poisoned.into_inner().stats.clone(),
        }
    }

    /// Evaluates all hardware retention invariants atomically under strict lock order `0 -> 1 -> 3 -> 4`,
    /// and if completely idle, transitions hardware state `running: true -> false` and invokes
    /// `backend.stop_capture()` **exact-once** while holding `hardware_io_lock` (Level 0).
    ///
    /// Does NOT wipe unrelated peers' `peer_consent` (eliminating concurrent `start_remote_request`
    /// consent-wipe races). Conservatively refuses shutdown if ANY lifecycle mutex is poisoned,
    /// if any stream is active or starting, if local preview is active, or if any lingering task,
    /// in-flight teardown, or active native operation remains.
    fn try_shutdown_hardware_if_idle(&self) -> bool {
        let stopped = self.try_shutdown_hardware_if_idle_inner();
        self.shutdown_eval_count.fetch_add(1, Ordering::SeqCst);
        stopped
    }

    /// Inner idle-hardware evaluation routine executed while incrementing `shutdown_eval_count` cleanly.
    fn try_shutdown_hardware_if_idle_inner(&self) -> bool {
        let _io_guard = match self.hardware_io_lock.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(
                    "CRITICAL: Camera hardware_io_lock is poisoned; refusing hardware shutdown"
                );
                return false;
            }
        };

        let should_stop = {
            // Level 1: active_peer_streams
            let streams = match self.active_peer_streams.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!(
                        "CRITICAL: Camera active_peer_streams mutex is poisoned; conservatively refusing hardware shutdown"
                    );
                    return false;
                }
            };
            if !streams.is_empty() {
                return false;
            }

            // Check starting_streams BEFORE local_preview_active (SeqCst ordering proof):
            // start() sets local_preview_active = true BEFORE decrementing starting_streams.
            if self.starting_streams.load(Ordering::SeqCst) > 0 {
                return false;
            }
            if self.local_preview_active.load(Ordering::SeqCst) {
                return false;
            }

            // Level 3: lingering_tasks (NEVER treat poisoned lock as empty!)
            let reg = match self.lingering_tasks.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!(
                        "CRITICAL: Camera lingering_tasks mutex is poisoned; conservatively refusing hardware shutdown (SEC-1D-17)"
                    );
                    return false;
                }
            };
            if reg.has_any_hardware_dependents() {
                tracing::warn!(
                    "Retaining camera hardware: {} lingering task(s), {} active native op(s), {} in-flight teardown(s)",
                    reg.tasks.len(),
                    reg.active_native_ops.len(),
                    reg.in_flight_teardowns
                );
                return false;
            }

            // Level 4: hardware_state
            let mut hw = match self.hardware_state.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!(
                        "CRITICAL: Camera hardware_state mutex is poisoned; conservatively refusing hardware shutdown"
                    );
                    return false;
                }
            };
            if !hw.running {
                false
            } else {
                hw.running = false;
                self.active.store(false, Ordering::SeqCst);
                self.local_consent.store(false, Ordering::SeqCst);
                true
            }
        };

        if !should_stop {
            return false;
        }

        self.shutdown_executions.fetch_add(1, Ordering::SeqCst);
        global_frame_hub().clear_all();

        self.backend.stop_capture();

        if let Ok(mut s) = self.state_label.lock() {
            *s = "Standby".to_string();
        }
        tracing::info!("📷 Camera hardware shut down cleanly after all streams and operations completed");
        true
    }

    /// Runs [`Self::try_shutdown_hardware_if_idle`] on `spawn_blocking` and wakes lifecycle waiters.
    async fn try_shutdown_hardware_if_idle_async(self: &Arc<Self>) -> bool {
        let coord = Arc::clone(self);
        let stopped = tokio::task::spawn_blocking(move || coord.try_shutdown_hardware_if_idle())
            .await
            .unwrap_or(false);
        self.lifecycle_notify.notify_waiters();
        stopped
    }
}

/// Central controller service for the Camera & Shared Microphone subsystem.
///
/// Manages activation lifecycles, network transport sessions, per-peer authorization,
/// shared microphone source/gain/mute state, and status reporting on both macOS and Windows 11.
pub struct CameraService {
    /// Dynamic feature flags manager governing subsystem activation.
    features: Arc<FeatureManager>,
    /// Atomic flag indicating whether camera capture or virtual camera service is active.
    active: Arc<AtomicBool>,
    /// Running counter of frames successfully transmitted or received.
    frames_transferred: Arc<AtomicU64>,
    /// Explicit session-scoped local user consent flag for camera streaming.
    local_consent: Arc<AtomicBool>,
    /// Explicit session-scoped local user consent granted per peer device ID hex bound to trust generation.
    peer_consent: Arc<Mutex<HashMap<String, u64>>>,
    /// Formal consent state machine and authorization lease manager.
    pub authorization: Arc<CameraConsentManager>,
    /// Isolated multi-peer frame distribution hub.
    pub frame_hub: Arc<CameraFrameHub>,
    /// Atomic flag indicating whether local camera preview is actively running.
    local_preview_active: Arc<AtomicBool>,
    /// Active remote peer camera streams mapped by peer device ID hex to their stream entries.
    active_peer_streams: Arc<Mutex<HashMap<String, ActivePeerStreamEntry>>>,
    /// Serializes concurrent user consent prompt dialogs across threads/requests.
    prompt_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Human-readable operational status label.
    state_label: Arc<Mutex<String>>,
    /// Most recent error message, if any.
    last_error: Arc<Mutex<Option<String>>>,
    /// Unified lifecycle supervisor managing lingering tasks, native operation guards, and exact-once hardware shutdown.
    lifecycle: Arc<CameraLifecycleCoordinator>,
    /// Atomic flag tracking whether shared Mac-to-PC microphone forwarding is enabled.
    mic_enabled: Arc<AtomicBool>,
    /// Atomic flag tracking whether shared Mac-to-PC microphone output is muted.
    mic_muted: Arc<AtomicBool>,
    /// IEEE-754 bit representation of linear microphone gain clamped to `0.0..=2.0` (`1.0` default).
    mic_gain_bits: Arc<AtomicU32>,
    /// Sanitized friendly name of the currently selected macOS microphone device (empty if unselected).
    selected_mic_name: Arc<Mutex<String>>,
}

impl CameraService {
    /// Instantiates a new [`CameraService`] with associated discovery and feature flag managers.
    pub fn new(discovery: DiscoveryManager, features: Arc<FeatureManager>) -> Arc<Self> {
        Self::new_with_backend_and_timeouts(
            discovery,
            features,
            Arc::new(NativeCameraBackend),
            CAMERA_TEARDOWN_TIMEOUT,
            CAMERA_ABORT_DRAIN_TIMEOUT,
        )
    }

    /// Internal constructor accepting a controllable [`CameraHardwareBackend`] and teardown timeouts.
    fn new_with_backend_and_timeouts(
        discovery: DiscoveryManager,
        features: Arc<FeatureManager>,
        backend: Arc<dyn CameraHardwareBackend>,
        teardown_timeout: Duration,
        abort_drain_timeout: Duration,
    ) -> Arc<Self> {
        // Peer endpoint resolution uses authenticated keystore records rather than raw discovery beacons.
        let _ = discovery;
        let active = Arc::new(AtomicBool::new(false));
        let local_consent = Arc::new(AtomicBool::new(false));
        let peer_consent = Arc::new(Mutex::new(HashMap::new()));
        let authorization = Arc::new(CameraConsentManager::new());
        let frame_hub = Arc::clone(global_frame_hub());
        let local_preview_active = Arc::new(AtomicBool::new(false));

        // Synchronize persistent permissions from global keystore
        {
            let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let all_consents = ks.all_camera_consents();
            let mut parsed_consents = HashMap::new();
            for (id, val) in all_consents {
                if val == "blocked" {
                    parsed_consents.insert(id, PersistentCameraConsent::Blocked);
                } else if let Some(gen_str) = val.strip_prefix("always_allow:") {
                    if let Ok(gen) = gen_str.parse::<u64>() {
                        parsed_consents.insert(id, PersistentCameraConsent::AlwaysAllow { generation: gen });
                    }
                }
            }
            authorization.load_persistent_consents(parsed_consents);
        }
        let active_peer_streams = Arc::new(Mutex::new(HashMap::new()));
        let state_label = Arc::new(Mutex::new("Standby".to_string()));
        let last_error = Arc::new(Mutex::new(None));
        let runtime_handle = tokio::runtime::Handle::try_current().ok();

        let lifecycle = Arc::new(CameraLifecycleCoordinator {
            backend,
            active: Arc::clone(&active),
            local_consent: Arc::clone(&local_consent),
            local_preview_active: Arc::clone(&local_preview_active),
            starting_streams: Arc::new(AtomicUsize::new(0)),
            shutdown_executions: Arc::new(AtomicU64::new(0)),
            shutdown_eval_count: Arc::new(AtomicU64::new(0)),
            hardware_io_lock: Mutex::new(()),
            active_peer_streams: Arc::clone(&active_peer_streams),
            lingering_tasks: Arc::new(Mutex::new(LingeringRegistry::default())),
            hardware_state: Mutex::new(HardwareState::default()),
            state_label: Arc::clone(&state_label),
            last_error: Arc::clone(&last_error),
            runtime_handle: Mutex::new(runtime_handle),
            op_finished_notify: Arc::new(Notify::new()),
            lifecycle_notify: Arc::new(Notify::new()),
            next_id: AtomicU64::new(1),
            teardown_timeout,
            abort_drain_timeout,
        });

        Arc::new(Self {
            features,
            active,
            frames_transferred: Arc::new(AtomicU64::new(0)),
            local_consent,
            peer_consent,
            authorization,
            frame_hub,
            local_preview_active,
            active_peer_streams,
            prompt_mutex: Arc::new(tokio::sync::Mutex::new(())),
            state_label,
            last_error,
            lifecycle,
            mic_enabled: Arc::new(AtomicBool::new(false)),
            mic_muted: Arc::new(AtomicBool::new(false)),
            mic_gain_bits: Arc::new(AtomicU32::new(DEFAULT_MIC_GAIN.to_bits())),
            selected_mic_name: Arc::new(Mutex::new(String::new())),
        })
    }

    /// Updates internal state label and optional error message in a thread-safe manner.
    fn set_state(&self, state: &str, err: Option<String>) {
        if let Ok(mut s) = self.state_label.lock() {
            *s = state.to_string();
        }
        if let Ok(mut e) = self.last_error.lock() {
            *e = err;
        }
    }

    /// Starts the background TCP listener on Windows to receive incoming Mac camera streams.
    ///
    /// Binds to port [`CAMERA_PORT`] (58287) and spawns an accept loop protected by a concurrency
    /// semaphore limiter ([`MAX_PRE_AUTH_CAMERA_CONNS`]).
    pub async fn start_server(self: &Arc<Self>) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let listener = TcpListener::bind(("0.0.0.0", CAMERA_PORT)).await?;
            info!("📷 Windows Virtual Camera receiver listening on TCP :{}", CAMERA_PORT);
            let svc = Arc::clone(self);
            let pre_auth_limiter = Arc::new(Semaphore::new(MAX_PRE_AUTH_CAMERA_CONNS));

            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            if !svc.features.is_enabled("camera") {
                                continue;
                            }
                            let Ok(permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned() else {
                                continue;
                            };
                            let svc_conn = Arc::clone(&svc);
                            tokio::spawn(async move {
                                let _permit = permit;
                                svc_conn.handle_incoming_stream(stream, addr.ip()).await;
                            });
                        }
                        Err(e) => {
                            warn!("Camera accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            });
        }
        Ok(())
    }

    /// Handles an incoming camera connection on Windows from an authenticated Mac peer.
    ///
    /// Establishes `TransportSessionV2` mutual authentication for [`ServiceId::CameraStream`],
    /// enforces receiver-side user consent policy, ensures the virtual camera driver is running,
    /// verifies lease tokens, and streams raw NV12 frames into shared memory.
    #[cfg(target_os = "windows")]
    async fn handle_incoming_stream(
        self: &Arc<Self>,
        stream: tokio::net::TcpStream,
        peer_ip: std::net::IpAddr,
    ) {
        let mut session = match trust::accept_transport_from_stream(
            stream,
            peer_ip,
            None,
            ServiceId::CameraStream,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!("Rejected unauthenticated camera stream from {}: {}", peer_ip, e);
                return;
            }
        };

        let peer_dev_id = session.peer_device_id_hex().to_string();
        let session_generation = session.trust_generation();
        if crate::security::transport::is_peer_revoked(&peer_dev_id)
            || crate::security::transport::get_peer_trust_generation(&peer_dev_id)
                != Some(session_generation)
        {
            warn!(
                "Rejected stale or revoked camera stream from {} (session gen {})",
                peer_dev_id, session_generation
            );
            let _ = session.close_notify().await;
            return;
        }

        // Enforce Windows receiver consent before publishing frames to virtual camera
        let eval = self.authorization.evaluate_receiver_consent(&peer_dev_id, session_generation);
        match eval {
            crate::camera::authorization::ConsentEvaluation::Granted => {}
            crate::camera::authorization::ConsentEvaluation::DeniedPersistent => {
                warn!("🚫 Rejected incoming camera stream from {}: peer is permanently blocked on receiver", peer_dev_id);
                let _ = session.close_notify().await;
                return;
            }
            crate::camera::authorization::ConsentEvaluation::DeniedTemporary { remaining, .. } => {
                warn!("🚫 Rejected incoming camera stream from {}: in denial cooldown ({:.1}s remaining)", peer_dev_id, remaining.as_secs_f32());
                let _ = session.close_notify().await;
                return;
            }
            crate::camera::authorization::ConsentEvaluation::Revoking => {
                warn!("🚫 Rejected incoming camera stream from {}: receiver session is revoking", peer_dev_id);
                let _ = session.close_notify().await;
                return;
            }
            crate::camera::authorization::ConsentEvaluation::RequiresPrompt => {
                let _prompt_guard = self.prompt_mutex.lock().await;
                let re_eval = self.authorization.evaluate_receiver_consent(&peer_dev_id, session_generation);
                if re_eval != crate::camera::authorization::ConsentEvaluation::Granted {
                    let target_display_name = {
                        let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
                        ks.get_peer(&peer_dev_id).map(|p| p.hostname.clone()).unwrap_or_else(|| peer_dev_id.clone())
                    };

                    let choice = tokio::task::spawn_blocking(move || {
                        let c_name = std::ffi::CString::new(target_display_name).unwrap_or_default();
                        unsafe { integrator_win_prompt_camera_consent_scoped(c_name.as_ptr(), 30) }
                    })
                    .await
                    .unwrap_or(0);

                    match choice {
                        1 => {
                            self.grant_receiver_consent(&peer_dev_id, session_generation, crate::camera::authorization::CameraConsentScope::AllowOnce);
                        }
                        2 => {
                            self.grant_receiver_consent(&peer_dev_id, session_generation, crate::camera::authorization::CameraConsentScope::ActiveSession);
                        }
                        3 => {
                            self.grant_receiver_consent(&peer_dev_id, session_generation, crate::camera::authorization::CameraConsentScope::AlwaysAllow);
                        }
                        -1 => {
                            self.record_peer_denial(
                                crate::camera::authorization::LeaseDirection::InboundReceiver,
                                &peer_dev_id,
                                crate::camera::authorization::CameraDenialAction::DenyAndBlock,
                            );
                            let _ = session.close_notify().await;
                            return;
                        }
                        _ => {
                            self.record_peer_denial(
                                crate::camera::authorization::LeaseDirection::InboundReceiver,
                                &peer_dev_id,
                                crate::camera::authorization::CameraDenialAction::Temporary,
                            );
                            let _ = session.close_notify().await;
                            return;
                        }
                    }
                }
            }
        }

        // Mandatory initial authorization lease redemption on Windows receiver
        let init_raw = match tokio::time::timeout(Duration::from_secs(5), session.recv_message()).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(e)) => {
                warn!("🚫 Rejected incoming camera stream from {}: failed to receive initial frame: {}", peer_dev_id, e);
                let _ = session.close_notify().await;
                return;
            }
            Err(_) => {
                warn!("🚫 Rejected incoming camera stream from {}: initial authorization handshake timed out", peer_dev_id);
                let _ = session.close_notify().await;
                return;
            }
        };

        let init_frame = match decode_camera_frame(&init_raw) {
            Ok(f) => f,
            Err(e) => {
                warn!("🚫 Rejected incoming camera stream from {}: malformed initial frame: {}", peer_dev_id, e);
                let _ = session.close_notify().await;
                return;
            }
        };

        if (init_frame.flags & FLAG_AUTH_LEASE_REDEMPTION) == 0 || init_frame.payload.len() != 32 {
            warn!(
                "🚫 Rejected incoming camera stream from {}: missing or malformed FLAG_AUTH_LEASE_REDEMPTION (flags={:#x}, payload_len={})",
                peer_dev_id, init_frame.flags, init_frame.payload.len()
            );
            let _ = session.close_notify().await;
            return;
        }

        let mut token = [0u8; 32];
        token.copy_from_slice(&init_frame.payload);

        let redeemed_lease = match self.authorization.redeem_authorization_lease(
            &token,
            &peer_dev_id,
            session_generation,
            crate::camera::authorization::LeaseDirection::InboundReceiver,
        ) {
            Ok(l) => l,
            Err(e) => {
                warn!("🚫 Rejected incoming camera stream from {}: authorization lease redemption failed: {}", peer_dev_id, e);
                let _ = session.close_notify().await;
                return;
            }
        };

        info!(
            "📷 Successfully redeemed single-use authorization lease for peer {} (request ID {})",
            peer_dev_id, redeemed_lease.request_id
        );

        info!(
            "📷 Authenticated Mac camera stream connected from {} (gen {})",
            peer_ip, session_generation
        );

        // Atomically start virtual camera hardware and register + spawn the peer-bound receiver loop
        // with an attached JoinHandle under Level 1 (`active_peer_streams`), preventing both
        // stale-generation eviction and Windows SHM use-after-unmap during teardown (SEC-1D-17).
        if let Err(e) = self
            .start_managed_peer_stream_replacing(
                &peer_dev_id,
                session_generation,
                move |svc, pid, _gen, stream_id, mut stream_cancel_rx| async move {
                    svc.set_state("Receiving 720p30", None);

                    loop {
                        if !svc.features.is_enabled("camera")
                            || !svc.active.load(Ordering::SeqCst)
                            || *stream_cancel_rx.borrow()
                            || !svc.has_receiver_consent(&pid, session_generation)
                        {
                            let _ = session.close_notify().await;
                            break;
                        }
                        let read_fut = session.recv_message();
                        let read_res = tokio::select! {
                            r = tokio::time::timeout(Duration::from_secs(5), read_fut) => r,
                            _ = stream_cancel_rx.changed() => {
                                let _ = session.close_notify().await;
                                break;
                            }
                        };
                        match read_res {
                            Ok(Ok(raw)) => match decode_camera_frame(&raw) {
                                Ok(frame) => {
                                    if (frame.flags & FLAG_STANDBY_KEEPALIVE) == 0
                                        && frame.payload.len() == NV12_FRAME_BYTES
                                    {
                                        // Acquire RAII native-op guard BEFORE re-checking cancel/active state
                                        // so `integrator_win_vcam_stop()` cannot unmap SHM mid-push (SEC-1D-17).
                                        let _native_op = svc.lifecycle.begin_native_op(
                                            Some(&pid),
                                            Some(stream_id),
                                            "win_vcam_push_nv12",
                                        );
                                        if *stream_cancel_rx.borrow()
                                            || !svc.active.load(Ordering::SeqCst)
                                            || !svc.has_receiver_consent(&pid, session_generation)
                                        {
                                            drop(_native_op);
                                            let _ = session.close_notify().await;
                                            break;
                                        }
                                        // Forward uncompressed NV12 buffer directly into Windows virtual camera shared memory.
                                        unsafe {
                                            integrator_win_vcam_push_nv12(
                                                frame.payload.as_ptr(),
                                                frame.payload.len() as u32,
                                                frame.timestamp_us,
                                            );
                                        }
                                        svc.frames_transferred.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(e) => {
                                    warn!("Malformed camera frame from {}: {}", peer_ip, e);
                                    break;
                                }
                            },
                            Ok(Err(_)) => break,
                            Err(_) => {
                                warn!(
                                    "Camera stream read timeout from {}, closing session to prevent framing desync",
                                    peer_ip
                                );
                                break;
                            }
                        }
                    }

                    // Unregister strictly by unique stream_id so a same-generation reconnect is never clobbered.
                    svc.unregister_peer_stream_by_id(&pid, stream_id);
                    svc.authorization.on_stream_closed(&pid, stream_id);
                    let _ = svc.lifecycle.try_shutdown_hardware_if_idle_async().await;

                    if svc.active.load(Ordering::Relaxed) {
                        svc.set_state("Virtual Camera Active", None);
                    } else {
                        svc.set_state("Standby", None);
                    }
                },
            )
            .await
        {
            warn!("Failed to start or register Windows incoming camera stream: {}", e);
        }
    }

    /// Returns true if camera capture or virtual camera service is currently active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Returns true if local user consent is active for the current camera session.
    pub fn has_local_consent(&self) -> bool {
        self.local_consent.load(Ordering::SeqCst)
    }

    /// Explicitly grants local user consent for the active camera session.
    pub fn grant_local_consent(&self) {
        self.local_consent.store(true, Ordering::SeqCst);
    }

    /// Resets session-scoped local camera consent without affecting remote peers' authorizations.
    pub fn reset_session_consent(&self) {
        self.local_consent.store(false, Ordering::SeqCst);
    }

    /// Registers an active camera stream for a given peer device ID hex bound to `generation`
    /// and returns a cancellation watch receiver.
    ///
    /// Rejects stale generations (returning an immediately-cancelled watch receiver) if a newer
    /// trust generation is already actively registered for this peer.
    pub fn register_peer_stream(&self, peer_device_id_hex: &str, generation: u64) -> tokio::sync::watch::Receiver<bool> {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let stream_id = self.lifecycle.next_id();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let (rejected_stale, replaced_handle) = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = streams.get(&clean_id) {
                if existing.generation > generation {
                    tracing::warn!(
                        "Rejected stale-generation camera stream registration for {} (got gen {}, active gen {})",
                        clean_id,
                        generation,
                        existing.generation
                    );
                    (true, None)
                } else {
                    let prev = streams.insert(
                        clean_id.clone(),
                        ActivePeerStreamEntry {
                            stream_id,
                            cancel_tx: tx,
                            task_handle: None,
                            generation,
                        },
                    );
                    let to_watch = if let Some(mut old) = prev {
                        let _ = old.cancel_tx.send(true);
                        let mut reg = match self.lifecycle.lingering_tasks.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let _ = reg.mark_stream_native_ops_lingering(&clean_id, old.stream_id);
                        drop(reg);
                        if let Some(h) = old.task_handle.take() {
                            h.abort();
                            self.lifecycle.register_lingering_handle_locked(
                                &clean_id,
                                "replaced_stream_handle",
                                h,
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    (false, to_watch)
                }
            } else {
                streams.insert(
                    clean_id.clone(),
                    ActivePeerStreamEntry {
                        stream_id,
                        cancel_tx: tx,
                        task_handle: None,
                        generation,
                    },
                );
                (false, None)
            }
        };
        if rejected_stale {
            let (_cancel_tx, cancelled_rx) = tokio::sync::watch::channel(true);
            return cancelled_rx;
        }
        if let Some((task_id, h)) = replaced_handle {
            self.lifecycle.spawn_lingering_watcher(
                task_id,
                clean_id,
                "replaced_stream_handle".to_string(),
                h,
            );
        }
        rx
    }

    /// Attaches the streaming task handle to an already registered peer stream entry.
    /// If the entry was already removed (e.g. teardown raced ahead), or if an existing handle
    /// is overwritten, the displaced/orphaned handle is aborted and atomically transferred into
    /// supervised lingering tracking under Level 1 -> Level 3 so no task is ever detached or
    /// orphaned and every handle is reaped upon completion (SEC-1D-17, SEC-1D-18).
    pub fn attach_stream_handle(&self, peer_device_id_hex: &str, handle: tokio::task::JoinHandle<()>) {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let handle_to_watch = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = streams.get_mut(&clean_id) {
                if let Some(old_handle) = entry.task_handle.replace(handle) {
                    tracing::warn!(
                        "Replaced existing attached stream handle for {}; aborting and supervising previous handle",
                        clean_id
                    );
                    old_handle.abort();
                    self.lifecycle
                        .register_lingering_handle_locked(&clean_id, "replaced_attached_handle", old_handle)
                        .map(|(id, h)| (id, "replaced_attached_handle".to_string(), h))
                } else {
                    None
                }
            } else {
                tracing::warn!(
                    "Stream entry for {} removed before task handle attachment; aborting and supervising to avoid orphan (SEC-1D-18)",
                    clean_id
                );
                handle.abort();
                // Register atomically under Level 1 -> Level 3 so hardware cannot shut down before supervision starts.
                self.lifecycle
                    .register_lingering_handle_locked(&clean_id, "orphaned_stream_handle", handle)
                    .map(|(id, h)| (id, "orphaned_stream_handle".to_string(), h))
            }
        };
        if let Some((task_id, label, handle)) = handle_to_watch {
            self.lifecycle.spawn_lingering_watcher(
                task_id,
                clean_id,
                label,
                handle,
            );
        }
    }

    /// Begins tracking an active blocking/native camera operation tied to a peer stream.
    /// Moving the returned [`CameraNativeOpGuard`] into `spawn_blocking` / native FFI ensures
    /// hardware remains retained even if an enclosing async task is cancelled via `abort()`.
    pub fn begin_peer_native_op(
        &self,
        peer_device_id_hex: &str,
        stream_id: Option<u64>,
        label: &str,
    ) -> CameraNativeOpGuard {
        self.lifecycle.begin_native_op(Some(peer_device_id_hex), stream_id, label)
    }

    /// Returns the number of supervised lingering camera tasks and lingering native operations.
    /// Never interprets a poisoned registry mutex as zero (returns at least 1 if poisoned).
    pub fn lingering_tasks_count(&self) -> usize {
        self.lifecycle.lingering_count()
    }

    /// Explicitly reaps any synchronous fallback lingering handles and evaluates deferred
    /// hardware shutdown if all streams, previews, and operations are idle. Idempotent.
    pub fn reap_lingering_tasks(&self) -> usize {
        self.lifecycle.reap_fallback_handles();
        self.lifecycle.try_shutdown_hardware_if_idle();
        self.lifecycle.lingering_count()
    }

    /// Returns true if any camera lifecycle mutex has been poisoned.
    #[cfg(test)]
    pub fn is_lingering_registry_poisoned(&self) -> bool {
        self.lifecycle.is_lingering_registry_poisoned()
    }

    /// Returns a snapshot of completion/reaping statistics for supervised lingering tasks.
    #[cfg(test)]
    pub fn reap_stats(&self) -> CameraReapStats {
        self.lifecycle.reap_stats()
    }

    /// Returns how many times `CameraHardwareBackend::stop_capture()` has been executed.
    #[cfg(test)]
    pub fn shutdown_execution_count(&self) -> u64 {
        self.lifecycle.shutdown_executions.load(Ordering::SeqCst)
    }

    /// Returns how many times `try_shutdown_hardware_if_idle()` has completed an evaluation.
    #[cfg(test)]
    pub fn shutdown_eval_count(&self) -> u64 {
        self.lifecycle.shutdown_eval_count.load(Ordering::SeqCst)
    }

    /// Unregisters an active camera stream when its stream task terminates.
    pub fn unregister_peer_stream(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
        streams.remove(&clean_id);
    }

    /// Unregisters an active camera stream only if its stored trust generation matches `generation`,
    /// preventing an exiting stale stream from evicting a newly re-paired stream entry.
    pub fn unregister_peer_stream_for_generation(&self, peer_device_id_hex: &str, generation: u64) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams.get(&clean_id).map(|e| e.generation == generation).unwrap_or(false) {
            streams.remove(&clean_id);
        }
    }

    /// Unregisters an active camera stream strictly by its unique `stream_id`, preventing a
    /// same-generation reconnect from being clobbered by a departing earlier connection.
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows", test)), allow(dead_code))]
    fn unregister_peer_stream_by_id(&self, peer_device_id_hex: &str, stream_id: u64) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams.get(&clean_id).map(|e| e.stream_id == stream_id).unwrap_or(false) {
            streams.remove(&clean_id);
        }
    }

    /// Checks if a camera stream is currently active for a specific peer.
    pub fn is_peer_stream_active(&self, peer_device_id_hex: &str) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
        streams.contains_key(&clean_id)
    }

    /// Explicitly grants session-scoped local user consent specifically for the given peer device ID hex
    /// bound to the specified trust generation.
    ///
    /// Fails closed (returns false) if the peer is actively revoked or if the peer's current keystore
    /// or transport trust generation does not match `generation`.
    pub fn grant_peer_consent(&self, peer_device_id_hex: &str, generation: u64) -> bool {
        self.grant_peer_consent_scoped(
            peer_device_id_hex,
            generation,
            crate::camera::authorization::CameraConsentScope::ActiveSession,
            0,
        )
    }

    /// Grants sender-side camera consent for `peer_device_id_hex` with an explicit duration/scope.
    pub fn grant_peer_consent_scoped(
        &self,
        peer_device_id_hex: &str,
        generation: u64,
        scope: crate::camera::authorization::CameraConsentScope,
        stream_id: u64,
    ) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return false;
        }
        let ks_gen = {
            let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.peer_trust_generation(&clean_id)
        };
        if ks_gen != Some(generation) {
            return false;
        }

        // Commit boundary under peer_consent lock: re-verify revocation and transport generation atomically
        let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return false;
        }
        if let Some(trans_gen) = crate::security::transport::get_peer_trust_generation(&clean_id) {
            if trans_gen != generation {
                return false;
            }
        }
        if scope == crate::camera::authorization::CameraConsentScope::AlwaysAllow {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.set_camera_consent(&clean_id, format!("always_allow:{}", generation));
        }
        self.authorization.grant_consent(
            crate::camera::authorization::LeaseDirection::OutboundSender,
            &clean_id,
            generation,
            scope,
            stream_id,
        );
        consent.insert(clean_id, generation);
        true
    }

    /// Checks whether local receiver-side user consent has been granted for an incoming camera stream.
    pub fn has_receiver_consent(&self, peer_device_id_hex: &str, expected_generation: u64) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return false;
        }
        if let Some(trans_gen) = crate::security::transport::get_peer_trust_generation(&clean_id) {
            if trans_gen != expected_generation {
                return false;
            }
        }
        self.authorization.evaluate_receiver_consent(&clean_id, expected_generation)
            == crate::camera::authorization::ConsentEvaluation::Granted
    }

    /// Grants receiver-side consent on Windows for an incoming stream from `peer_device_id_hex`.
    pub fn grant_receiver_consent(
        &self,
        peer_device_id_hex: &str,
        generation: u64,
        scope: crate::camera::authorization::CameraConsentScope,
    ) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return false;
        }
        if scope == crate::camera::authorization::CameraConsentScope::AlwaysAllow {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.set_camera_consent(&clean_id, format!("always_allow:{}", generation));
        }
        self.authorization.grant_consent(
            crate::camera::authorization::LeaseDirection::InboundReceiver,
            &clean_id,
            generation,
            scope,
            0,
        )
    }

    /// Records a denial on sender or receiver side.
    pub fn record_peer_denial(
        &self,
        direction: crate::camera::authorization::LeaseDirection,
        peer_device_id_hex: &str,
        action: crate::camera::authorization::CameraDenialAction,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if action == crate::camera::authorization::CameraDenialAction::DenyAndBlock {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.set_camera_consent(&clean_id, "blocked".to_string());
        }
        self.authorization.record_denial(direction, &clean_id, action);
        let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
        consent.remove(&clean_id);
    }

    /// Unblocks a peer from persistent block or temporary cooldown.
    pub fn unblock_peer_camera(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.remove_camera_consent(&clean_id);
        }
        self.authorization.unblock_peer(&clean_id);
    }

    /// Queries consent status for `peer_device_id_hex` to return via RPC.
    pub fn query_consent_status(&self, peer_device_id_hex: &str) -> crate::camera::authorization::CameraConsentStatusWire {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let gen = crate::security::transport::get_peer_trust_generation(&clean_id).or_else(|| {
            let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.peer_trust_generation(&clean_id)
        }).unwrap_or(0);
        self.authorization.get_consent_status_wire(crate::camera::authorization::LeaseDirection::OutboundSender, &clean_id, gen)
    }

    /// Checks whether local user consent has been granted specifically for the given peer device ID hex
    /// and matches the expected trust generation.
    ///
    /// Fails closed if the peer is actively revoked or if the active trust generation has changed.
    /// Does not hold keystore mutex during frame-rate checks.
    pub fn has_peer_consent(&self, peer_device_id_hex: &str, expected_generation: u64) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return false;
        }
        if let Some(trans_gen) = crate::security::transport::get_peer_trust_generation(&clean_id) {
            if trans_gen != expected_generation {
                return false;
            }
        }
        let eval = self.authorization.evaluate_sender_consent(&clean_id, expected_generation);
        if eval == crate::camera::authorization::ConsentEvaluation::Granted {
            return true;
        }
        let consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
        consent.get(&clean_id).copied() == Some(expected_generation)
    }

    /// Checks whether local user consent has been granted for the peer's current active trust generation.
    pub fn has_active_peer_consent(&self, peer_device_id_hex: &str) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let current_gen = crate::security::transport::get_peer_trust_generation(&clean_id).or_else(|| {
            let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.peer_trust_generation(&clean_id)
        });
        match current_gen {
            Some(gen) => self.has_peer_consent(&clean_id, gen),
            None => false,
        }
    }

    /// Sets whether local camera preview is actively running.
    pub fn set_local_preview_active(&self, active: bool) {
        self.local_preview_active.store(active, Ordering::SeqCst);
    }

    /// Returns true if local camera preview is actively running.
    pub fn is_local_preview_active(&self) -> bool {
        self.local_preview_active.load(Ordering::SeqCst)
    }

    /// Explicitly revokes session-scoped consent for `peer_device_id_hex` and terminates any active stream.
    pub fn revoke_peer_consent(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let current_gen = crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        self.authorization.revoke_consent(&clean_id, current_gen);
        self.frame_hub.unsubscribe(&clean_id);
        {
            let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
            consent.remove(&clean_id);
        }
        self.teardown_peer_stream(&clean_id);
    }

    /// Asynchronously tears down the camera stream for `peer_device_id_hex`, signaling cancellation,
    /// awaiting task termination with bounded timeout, escalating to `.abort()` if needed, supervising
    /// any lingering tasks or in-flight native operations until completion, and honestly reporting
    /// termination results while retaining hardware resources until all dependents finish (SEC-1D-17).
    ///
    /// Fully cancel-safe: `TeardownInFlightGuard` retains ownership of any extracted `JoinHandle`,
    /// automatically aborting, supervising, and dispatching deferred hardware shutdown if this future
    /// is dropped mid-`.await`.
    pub async fn teardown_peer_stream_async(&self, peer_device_id_hex: &str) -> Result<(), String> {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();

        let (cancel_tx, mut in_flight_guard) = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
            consent.remove(&clean_id);
            self.authorization.revoke_consent(&clean_id, 0);
            self.frame_hub.unsubscribe(&clean_id);
            if let Some(mut entry) = streams.remove(&clean_id) {
                let stream_id = entry.stream_id;
                let handle = entry.task_handle.take();
                // Atomically register cancel-safe in-flight teardown under Level 1 -> Level 3 BEFORE dropping Level 1
                // so concurrent reapers cannot shut down hardware mid-drain and cancellation cannot detach `handle`.
                let guard = self.lifecycle.begin_in_flight_teardown_locked(
                    &clean_id,
                    stream_id,
                    "stream_task",
                    handle,
                );
                (Some(entry.cancel_tx), Some(guard))
            } else {
                (None, None)
            }
        };

        let mut teardown_err: Option<String> = None;

        if let Some(mut guard) = in_flight_guard.take() {
            let stream_id = guard.stream_id;
            if let Some(tx) = cancel_tx {
                let _ = tx.send(true);
            }

            if let Some(ref mut handle) = guard.handle {
                match tokio::time::timeout(self.lifecycle.teardown_timeout, handle).await {
                    Ok(join_res) => {
                        guard.handle = None;
                        if let Err(e) = join_res {
                            self.lifecycle.record_completed_task_error(&clean_id, "stream_task", e);
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Camera streaming task for peer {} did not terminate within {:?}; escalating to abort()",
                            clean_id,
                            self.lifecycle.teardown_timeout
                        );
                        if let Some(ref mut handle) = guard.handle {
                            handle.abort();
                            match tokio::time::timeout(self.lifecycle.abort_drain_timeout, handle).await {
                                Ok(join_res) => {
                                    guard.handle = None;
                                    if let Err(e) = join_res {
                                        if e.is_panic() {
                                            self.lifecycle.record_completed_task_error(
                                                &clean_id,
                                                "aborted_stream_task",
                                                e,
                                            );
                                        } else {
                                            tracing::warn!(
                                                "Aborted camera streaming task for peer {} exited with: {}",
                                                clean_id, e
                                            );
                                        }
                                    }
                                }
                                Err(_) => {
                                    tracing::error!(
                                        "CRITICAL: Camera streaming task for peer {} did not terminate after abort escalation (hung in native call)",
                                        clean_id
                                    );
                                    teardown_err = Some(format!(
                                        "Camera streaming task for peer {} did not terminate within timeout after abort escalation",
                                        clean_id
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Even if the outer async JoinHandle was cancelled immediately upon `abort()`,
            // an inner `spawn_blocking` / native FFI operation holding a `CameraNativeOpGuard`
            // may still be actively executing! Drain up to `abort_drain_timeout` before handing off.
            if guard.handle.is_none()
                && self.lifecycle.stream_has_active_native_ops(&clean_id, stream_id)
            {
                let deadline = Instant::now() + self.lifecycle.abort_drain_timeout;
                while self.lifecycle.stream_has_active_native_ops(&clean_id, stream_id) {
                    let notified = self.lifecycle.op_finished_notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if !self.lifecycle.stream_has_active_native_ops(&clean_id, stream_id) {
                        break;
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    if tokio::time::timeout(remaining, notified).await.is_err() {
                        break;
                    }
                }
            }

            // Atomic handoff from `in_flight_teardowns` -> lingering supervision under Level 3 (ZERO gap!)
            let (task_to_watch, lingering_native_count) = guard.handoff_to_lingering();
            if let Some((task_id, handle)) = task_to_watch {
                self.lifecycle.spawn_lingering_watcher(
                    task_id,
                    clean_id.clone(),
                    "stream_task".to_string(),
                    handle,
                );
            }

            if lingering_native_count > 0 && teardown_err.is_none() {
                tracing::error!(
                    "CRITICAL: {} native camera operation(s) for peer {} remained active after outer task cancellation; retaining hardware",
                    lingering_native_count,
                    clean_id
                );
                teardown_err = Some(format!(
                    "{} native camera operation(s) for peer {} remained active after task cancellation",
                    lingering_native_count, clean_id
                ));
            }

            if teardown_err.is_none() {
                tracing::info!("🛑 Camera stream terminated and task awaited for peer {}", clean_id);
            }
        } else if self.lifecycle.peer_has_lingering_or_active_native(&clean_id) {
            // Teardown retry or concurrent teardown while a prior teardown for this peer is still draining
            // or has lingering tasks/native ops: wait up to abort_drain_timeout and report Err honestly.
            let deadline = Instant::now() + self.lifecycle.abort_drain_timeout;
            while self.lifecycle.peer_has_lingering_or_active_native(&clean_id) {
                let notified = self.lifecycle.op_finished_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if !self.lifecycle.peer_has_lingering_or_active_native(&clean_id) {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if tokio::time::timeout(remaining, notified).await.is_err() {
                    break;
                }
            }
            if self.lifecycle.peer_has_lingering_or_active_native(&clean_id) {
                teardown_err = Some(format!(
                    "Peer {} still has lingering camera task(s) or native operation(s) that have not terminated",
                    clean_id
                ));
            }
        }

        // Reap or upgrade any synchronous fallback handles (no-op when watcher-supervised)
        self.lifecycle.reap_fallback_handles();

        // Conservatively fail teardown if ANY lifecycle mutex is poisoned
        if let Some(lock_name) = self.lifecycle.any_lifecycle_mutex_poisoned() {
            if teardown_err.is_none() {
                teardown_err = Some(format!(
                    "Camera lifecycle mutex '{}' is poisoned; hardware conservatively retained",
                    lock_name
                ));
            }
        }

        // Only shut down camera hardware if all streams are terminated, no stream is starting,
        // no local preview is active, no lingering tasks or active native ops remain,
        // and no lifecycle mutex is poisoned (SEC-1D-17).
        let _ = self.lifecycle.try_shutdown_hardware_if_idle_async().await;

        if let Some(err) = teardown_err {
            return Err(err);
        }

        Ok(())
    }

    /// Tears down only the camera session and consent belonging to `peer_device_id_hex`.
    ///
    /// If other peers still maintain active camera sessions, their streams continue unaffected
    /// and the local camera hardware is NOT stopped. Any aborted task handle (even if already
    /// finished, so panics are observed) is transferred into completion-driven lingering supervision,
    /// active native operations are marked lingering, and deferred hardware shutdown is offloaded
    /// to the Tokio blocking pool when called from an async worker thread.
    pub fn teardown_peer_stream(&self, peer_device_id_hex: &str) {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let (entry_signaled, handle_to_watch) = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
            consent.remove(&clean_id);
            self.authorization.revoke_consent(&clean_id, 0);
            self.frame_hub.unsubscribe(&clean_id);
            if let Some(mut entry) = streams.remove(&clean_id) {
                let _ = entry.cancel_tx.send(true);
                {
                    let mut reg = match self.lifecycle.lingering_tasks.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    let _ = reg.mark_stream_native_ops_lingering(&clean_id, entry.stream_id);
                }
                let to_watch = if let Some(handle) = entry.task_handle.take() {
                    handle.abort();
                    // Always supervise the handle (even if already finished) so panics are observed
                    // and recorded in reap_stats / last_error.
                    self.lifecycle.register_lingering_handle_locked(
                        &clean_id,
                        "sync_teardown_stream",
                        handle,
                    )
                } else {
                    None
                };
                (true, to_watch)
            } else {
                (false, None)
            }
        };

        if let Some((task_id, handle)) = handle_to_watch {
            self.lifecycle.spawn_lingering_watcher(
                task_id,
                clean_id.clone(),
                "sync_teardown_stream".to_string(),
                handle,
            );
        }

        if entry_signaled {
            tracing::info!("🛑 Camera stream signaled for revoked peer {}", clean_id);
        }

        self.lifecycle.reap_fallback_handles();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let coord = Arc::clone(&self.lifecycle);
            rt.spawn_blocking(move || {
                coord.try_shutdown_hardware_if_idle();
                coord.lifecycle_notify.notify_waiters();
            });
        } else {
            self.lifecycle.try_shutdown_hardware_if_idle();
            self.lifecycle.lifecycle_notify.notify_waiters();
        }
    }

    /// Activates the camera pipeline initiated by a remote paired peer.
    ///
    /// Requires explicit, session-scoped local user consent specific to the requesting peer and bound
    /// to the peer's current trust generation. Resolves the authenticated peer identity strictly against
    /// verified keystore records, rejects unverified or revoked peers, serializes prompt dialogs,
    /// enforces prompt rate-limiting, and spawns a peer-bound encrypted transport stream.
    pub async fn start_remote_request(self: &Arc<Self>, peer_identifier: Option<&str>) -> Result<(String, [u8; 32]), String> {
        if !self.features.is_enabled("camera") {
            return Err("Rejected: Camera feature disabled".into());
        }

        let clean_id = match peer_identifier.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            Some(id) => id.to_ascii_lowercase(),
            None => return Err("Rejected: Camera request requires authenticated peer identity".into()),
        };

        // 1. Resolve requesting peer strictly using verified keystore record (never use unverified names or discovery)
        let (target_device_id_hex, target_display_name, target_ip, target_generation) = {
            let ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let peer = ks.get_peer(&clean_id).ok_or_else(|| {
                format!("Rejected: Peer '{}' is not a verified paired identity", clean_id)
            })?;
            if peer.last_ip.trim().is_empty() {
                return Err(format!("Rejected: Verified peer '{}' has no known network endpoint", clean_id));
            }
            (
                peer.device_id_hex.clone(),
                peer.hostname.clone(),
                peer.last_ip.trim().to_string(),
                peer.trust_generation,
            )
        };

        // 2. Fail closed if peer is revoked in transport registry
        if crate::security::transport::is_peer_revoked(&target_device_id_hex) {
            return Err(format!("Rejected: Peer {} trust has been revoked", target_device_id_hex));
        }

        let direction = if cfg!(target_os = "windows") {
            crate::camera::authorization::LeaseDirection::InboundReceiver
        } else {
            crate::camera::authorization::LeaseDirection::OutboundSender
        };

        // 3. Evaluate consent state machine (checking both sender and receiver denials)
        let eval_sender = self.authorization.evaluate_sender_consent(&target_device_id_hex, target_generation);
        let eval_receiver = self.authorization.evaluate_receiver_consent(&target_device_id_hex, target_generation);

        let eval = match (&eval_sender, &eval_receiver) {
            (ConsentEvaluation::DeniedPersistent, _) | (_, ConsentEvaluation::DeniedPersistent) => {
                ConsentEvaluation::DeniedPersistent
            }
            (ConsentEvaluation::DeniedTemporary { remaining: r1, consecutive_denials: _c1 },
             ConsentEvaluation::DeniedTemporary { remaining: r2, consecutive_denials: _c2 }) => {
                if r1 >= r2 { eval_sender.clone() } else { eval_receiver.clone() }
            }
            (ConsentEvaluation::DeniedTemporary { .. }, _) => eval_sender.clone(),
            (_, ConsentEvaluation::DeniedTemporary { .. }) => eval_receiver.clone(),
            (ConsentEvaluation::Revoking, _) | (_, ConsentEvaluation::Revoking) => {
                ConsentEvaluation::Revoking
            }
            (ConsentEvaluation::Granted, _) if cfg!(not(target_os = "windows")) => ConsentEvaluation::Granted,
            (_, ConsentEvaluation::Granted) if cfg!(target_os = "windows") => ConsentEvaluation::Granted,
            _ => ConsentEvaluation::RequiresPrompt,
        };

        match eval {
            ConsentEvaluation::Granted => {
                // Pre-authorized or remembered consent
            }
            ConsentEvaluation::DeniedPersistent => {
                return Err(format!("Rejected: Camera access is permanently blocked for peer {}", target_display_name));
            }
            ConsentEvaluation::DeniedTemporary { remaining, consecutive_denials } => {
                return Err(format!(
                    "Rejected: Camera request denied; cooldown active ({:.1}s remaining, {} consecutive denials)",
                    remaining.as_secs_f32(),
                    consecutive_denials
                ));
            }
            ConsentEvaluation::Revoking => {
                return Err("Rejected: Camera stream is currently revoking".into());
            }
            ConsentEvaluation::RequiresPrompt => {
                let _prompt_guard = self.prompt_mutex.lock().await;

                // Re-evaluate under prompt lock to avoid racing duplicate prompts
                #[cfg(target_os = "windows")]
                let re_eval = self.authorization.evaluate_receiver_consent(&target_device_id_hex, target_generation);
                #[cfg(not(target_os = "windows"))]
                let re_eval = self.authorization.evaluate_sender_consent(&target_device_id_hex, target_generation);

                if re_eval != ConsentEvaluation::Granted {
                    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                    {
                        let _ = &target_display_name;
                        return Err("Rejected: Local camera consent required on camera host".into());
                    }

                    #[cfg(any(target_os = "macos", target_os = "windows"))]
                    {
                        let _req_id = self.authorization.try_begin_prompt(
                            direction,
                            &target_device_id_hex,
                        )?;

                        #[cfg(target_os = "windows")]
                        {
                            let display_c = std::ffi::CString::new(target_display_name.clone()).unwrap_or_default();
                            // Treat JoinError as denied (0) so a panicked prompt task never leaks a pending prompt slot.
                            let choice = tokio::task::spawn_blocking(move || {
                                unsafe { integrator_win_prompt_camera_consent_scoped(display_c.as_ptr(), 30) }
                            })
                            .await
                            .unwrap_or(0);

                            match choice {
                                1 => {
                                    self.grant_receiver_consent(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::AllowOnce,
                                    );
                                }
                                2 => {
                                    self.grant_receiver_consent(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::ActiveSession,
                                    );
                                }
                                3 => {
                                    self.grant_receiver_consent(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::AlwaysAllow,
                                    );
                                }
                                -1 => {
                                    self.record_peer_denial(
                                        direction,
                                        &target_device_id_hex,
                                        CameraDenialAction::DenyAndBlock,
                                    );
                                    return Err("Rejected: User denied and blocked camera access".into());
                                }
                                _ => {
                                    self.record_peer_denial(
                                        direction,
                                        &target_device_id_hex,
                                        CameraDenialAction::Temporary,
                                    );
                                    return Err("Rejected: User denied camera access".into());
                                }
                            }
                        }

                        #[cfg(target_os = "macos")]
                        {
                            let display_c = std::ffi::CString::new(target_display_name.clone()).unwrap_or_default();
                            // Treat JoinError as denied (0) so a panicked prompt task never leaks a pending prompt slot.
                            let choice = tokio::task::spawn_blocking(move || {
                                unsafe { integrator_mac_prompt_camera_consent_scoped(display_c.as_ptr(), 30) }
                            })
                            .await
                            .unwrap_or(0);

                            match choice {
                                1 => {
                                    // Allow Once (Single continuous stream)
                                    self.grant_peer_consent_scoped(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::AllowOnce,
                                        _req_id,
                                    );
                                }
                                2 => {
                                    // Allow for this Session
                                    self.grant_peer_consent_scoped(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::ActiveSession,
                                        0,
                                    );
                                }
                                3 => {
                                    // Always Allow
                                    self.grant_peer_consent_scoped(
                                        &target_device_id_hex,
                                        target_generation,
                                        CameraConsentScope::AlwaysAllow,
                                        0,
                                    );
                                }
                                -1 => {
                                    // Deny and Block persistently
                                    self.record_peer_denial(
                                        direction,
                                        &target_device_id_hex,
                                        CameraDenialAction::DenyAndBlock,
                                    );
                                    return Err("Rejected: Local user denied and blocked remote camera access".into());
                                }
                                _ => {
                                    // Deny / Timeout
                                    self.record_peer_denial(
                                        direction,
                                        &target_device_id_hex,
                                        CameraDenialAction::Temporary,
                                    );
                                    return Err("Rejected: Local user denied remote camera access".into());
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4. Create single-use authorization lease bridging RPC and camera streaming socket
        let lease = self.authorization.create_authorization_lease(
            &target_device_id_hex,
            target_generation,
            &clean_id,
            self.authorization.next_request_id(),
            direction,
            crate::camera::authorization::DEFAULT_LEASE_TTL,
        );
        let lease_token = lease.lease_token;

        // 5. Start capture hardware (without forcing local_preview_active) and atomically spawn
        //    and register the peer-bound streaming task under StreamStartGuard (SEC-1D-17, SEC-1D-18).
        #[cfg(target_os = "macos")]
        {
            let tip = target_ip.clone();
            self.start_managed_peer_stream(
                &target_device_id_hex,
                target_generation,
                move |svc, tid, tgen, stream_id, rx| async move {
                    svc.run_mac_sender_for_peer(tid, tgen, stream_id, tip, lease_token, rx).await;
                },
            )
            .await?;
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&target_device_id_hex, &target_ip, target_generation);
            let start_guard = self.lifecycle.begin_stream_start();
            self.ensure_capture_hardware_started().await?;
            start_guard.finish_without_shutdown();
        }

        let msg = if cfg!(target_os = "windows") {
            format!("Camera streaming session authorized on Windows Virtual Camera for peer {}", target_display_name)
        } else {
            format!("Streaming Mac Camera (720p30) to Windows Virtual Camera for peer {}", target_display_name)
        };

        Ok((msg, lease_token))
    }

    /// Production-path peer stream startup that atomically replaces any older or same-generation
    /// connection for `peer_device_id_hex` (aborting and supervising its prior handle/native ops)
    /// while rejecting stale generations (`existing.generation > generation`).
    #[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
    pub(crate) async fn start_managed_peer_stream_replacing<F, Fut>(
        self: &Arc<Self>,
        peer_device_id_hex: &str,
        generation: u64,
        task_factory: F,
    ) -> Result<u64, String>
    where
        F: FnOnce(Arc<Self>, String, u64, u64, tokio::sync::watch::Receiver<bool>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let start_guard = self.lifecycle.begin_stream_start();

        self.ensure_capture_hardware_started().await?;

        let (res, replaced_to_watch) = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = streams.get(&clean_id) {
                if existing.generation > generation {
                    (
                        Err(format!(
                            "Rejected stale camera stream for {} (session gen {}, active gen {})",
                            clean_id, generation, existing.generation
                        )),
                        None,
                    )
                } else {
                    let stream_id = self.lifecycle.next_id();
                    let (tx, rx) = tokio::sync::watch::channel(false);
                    let svc = Arc::clone(self);
                    let tid = clean_id.clone();
                    let fut = task_factory(svc, tid, generation, stream_id, rx);
                    let handle = tokio::spawn(fut);
                    let prev = streams.insert(
                        clean_id.clone(),
                        ActivePeerStreamEntry {
                            stream_id,
                            cancel_tx: tx,
                            task_handle: Some(handle),
                            generation,
                        },
                    );
                    let to_watch = if let Some(mut old) = prev {
                        let _ = old.cancel_tx.send(true);
                        let mut reg = match self.lifecycle.lingering_tasks.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let _ = reg.mark_stream_native_ops_lingering(&clean_id, old.stream_id);
                        drop(reg);
                        if let Some(h) = old.task_handle.take() {
                            h.abort();
                            self.lifecycle.register_lingering_handle_locked(
                                &clean_id,
                                "replaced_stream_handle",
                                h,
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    start_guard.finish_without_shutdown();
                    (Ok(stream_id), to_watch)
                }
            } else {
                let stream_id = self.lifecycle.next_id();
                let (tx, rx) = tokio::sync::watch::channel(false);
                let svc = Arc::clone(self);
                let tid = clean_id.clone();
                let fut = task_factory(svc, tid, generation, stream_id, rx);
                let handle = tokio::spawn(fut);
                streams.insert(
                    clean_id.clone(),
                    ActivePeerStreamEntry {
                        stream_id,
                        cancel_tx: tx,
                        task_handle: Some(handle),
                        generation,
                    },
                );
                start_guard.finish_without_shutdown();
                (Ok(stream_id), None)
            }
        };

        if let Some((task_id, h)) = replaced_to_watch {
            self.lifecycle.spawn_lingering_watcher(
                task_id,
                clean_id,
                "replaced_stream_handle".to_string(),
                h,
            );
        }

        res
    }

    /// Production-path peer stream startup: acquires `StreamStartGuard`, ensures camera capture
    /// hardware is running without enabling local preview, and atomically spawns + registers
    /// the peer's stream task under `active_peer_streams` (zero spawn-to-attachment orphan window
    /// and zero startup-vs-reap shutdown race).
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    pub(crate) async fn start_managed_peer_stream<F, Fut>(
        self: &Arc<Self>,
        peer_device_id_hex: &str,
        generation: u64,
        task_factory: F,
    ) -> Result<u64, String>
    where
        F: FnOnce(Arc<Self>, String, u64, u64, tokio::sync::watch::Receiver<bool>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.lifecycle.capture_runtime_handle();
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let start_guard = self.lifecycle.begin_stream_start();

        self.ensure_capture_hardware_started().await?;

        let stream_id = {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = streams.get(&clean_id) {
                let existing_id = existing.stream_id;
                start_guard.finish_without_shutdown();
                existing_id
            } else {
                let stream_id = self.lifecycle.next_id();
                let (tx, rx) = tokio::sync::watch::channel(false);
                let svc = Arc::clone(self);
                let tid = clean_id.clone();
                let fut = task_factory(svc, tid, generation, stream_id, rx);
                let handle = tokio::spawn(fut);
                streams.insert(
                    clean_id,
                    ActivePeerStreamEntry {
                        stream_id,
                        cancel_tx: tx,
                        task_handle: Some(handle),
                        generation,
                    },
                );
                // Release StreamStartGuard WHILE holding Level 1 so hardware stays continuously owned!
                start_guard.finish_without_shutdown();
                stream_id
            }
        };

        Ok(stream_id)
    }

    /// Ensures the camera capture / virtual camera hardware backend is running without enabling
    /// `local_preview_active`. Serialized under Level 0 (`hardware_io_lock`).
    async fn ensure_capture_hardware_started(&self) -> Result<bool, String> {
        self.lifecycle.capture_runtime_handle();
        let coord = Arc::clone(&self.lifecycle);
        let frames_transferred = Arc::clone(&self.frames_transferred);
        let start_res = tokio::task::spawn_blocking(move || -> Result<bool, (String, String)> {
            let _io_guard = coord.hardware_io_lock.lock().unwrap_or_else(|e| e.into_inner());
            {
                let hw = coord.hardware_state.lock().unwrap_or_else(|e| e.into_inner());
                if hw.running {
                    return Ok(false);
                }
            }

            frames_transferred.store(0, Ordering::Relaxed);

            if let Err(err) = coord.backend.start_capture() {
                coord.active.store(false, Ordering::SeqCst);
                return Err(err);
            }

            {
                let mut hw = coord.hardware_state.lock().unwrap_or_else(|e| e.into_inner());
                hw.running = true;
                coord.active.store(true, Ordering::SeqCst);
            }
            Ok(true)
        })
        .await
        .map_err(|e| e.to_string())?;

        match start_res {
            Ok(started_fresh) => {
                if started_fresh {
                    #[cfg(target_os = "windows")]
                    {
                        self.set_state("Virtual Camera Active", None);
                        info!("📷 Virtual camera '{}' active", DEFAULT_CAMERA_FRIENDLY_NAME);
                    }
                    #[cfg(target_os = "macos")]
                    {
                        self.set_state("Camera Active", None);
                        crate::core::notify_touchbar_camera_state(true, is_camera_privacy_muted());
                        info!("📷 Mac camera capture started (720p30 NV12)");
                    }
                }
                Ok(started_fresh)
            }
            Err((state_lbl, msg)) => {
                self.set_state(&state_lbl, Some(msg.clone()));
                Err(msg)
            }
        }
    }

    /// Toggles the camera pipeline initiated by a remote paired peer, enforcing local consent if transitioning to active.
    pub async fn toggle_remote_request(self: &Arc<Self>, peer_identifier: Option<&str>) -> Result<String, String> {
        if self.is_active() {
            self.stop().await;
            self.local_consent.store(false, Ordering::SeqCst);
            Ok("Camera stopped".into())
        } else {
            self.start_remote_request(peer_identifier).await.map(|(msg, _)| msg)
        }
    }

    /// Activates the camera pipeline on the local machine (enables local preview).
    ///
    /// - **On Windows**: Installs and registers the virtual camera DLL (`integrator_vcam.dll`),
    ///   creates the shared memory mapping, and invokes `MFCreateVirtualCamera`.
    /// - **On macOS**: Validates TCC camera permissions and bundle descriptors, starts AVFoundation
    ///   720p30 capture via `camera_macos.swift`, and enables local capture hardware.
    pub async fn start(self: &Arc<Self>) -> Result<String, String> {
        self.lifecycle.capture_runtime_handle();
        if !self.features.is_enabled("camera") {
            self.features.set_flag_checked("camera", true)?;
        }

        let start_guard = self.lifecycle.begin_stream_start();
        let started_fresh = self.ensure_capture_hardware_started().await?;
        // Set local_preview_active BEFORE dropping StreamStartGuard (SeqCst ordering guarantees
        // concurrent reapers cannot shut down hardware during local preview activation).
        self.local_preview_active.store(true, Ordering::SeqCst);
        start_guard.finish_without_shutdown();

        #[cfg(target_os = "windows")]
        {
            let _ = started_fresh;
            return Ok(format!(
                "Windows Virtual Camera '{}' started",
                DEFAULT_CAMERA_FRIENDLY_NAME
            ));
        }

        #[cfg(target_os = "macos")]
        {
            if started_fresh {
                return Ok("Mac Camera capture started".into());
            } else {
                return Ok("Mac camera stream is already running".into());
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = started_fresh;
            Ok("Camera capture started".into())
        }
    }

    /// Background async loop on macOS polling frames from [`CameraFrameHub`] and streaming to an authenticated peer.
    ///
    /// Cryptographically binds to `target_peer_id` and `target_generation`, redeems single-use authorization lease,
    /// connects to `target_ip:CAMERA_PORT`, verifies mutual authentication, checks generation-bound consent on every
    /// frame, and streams NV12 frames from an isolated per-peer subscriber mailbox.
    #[cfg(target_os = "macos")]
    async fn run_mac_sender_for_peer(
        self: Arc<Self>,
        target_peer_id: String,
        target_generation: u64,
        stream_id: u64,
        target_ip: String,
        lease_token: [u8; 32],
        mut stream_cancel_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let mailbox = self.frame_hub.subscribe(&target_peer_id);
        struct HubSubscriptionGuard {
            hub: Arc<CameraFrameHub>,
            peer: String,
        }
        impl Drop for HubSubscriptionGuard {
            fn drop(&mut self) {
                self.hub.unsubscribe(&self.peer);
            }
        }
        let _sub_guard = HubSubscriptionGuard {
            hub: Arc::clone(&self.frame_hub),
            peer: target_peer_id.clone(),
        };

        let mut lease_redeemed = false;

        while self.active.load(Ordering::Relaxed)
            && self.features.is_enabled("camera")
            && !*stream_cancel_rx.borrow()
            && self.has_peer_consent(&target_peer_id, target_generation)
        {
            let mut session = tokio::select! {
                res = trust::connect_transport_to_hinted_ip(
                    &target_ip,
                    CAMERA_PORT,
                    ServiceId::CameraStream,
                    CAMERA_CONNECT_TIMEOUT,
                    Some(&target_peer_id),
                    None,
                ) => match res {
                    Ok(s) => s,
                    Err(e) => {
                        self.set_state("Waiting for Windows Camera", Some(e));
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(900)) => {},
                            _ = stream_cancel_rx.changed() => break,
                        }
                        continue;
                    }
                },
                _ = stream_cancel_rx.changed() => break,
            };

            // Cryptographically verify destination identity matches target_peer_id
            if !session.peer_device_id_hex().eq_ignore_ascii_case(&target_peer_id) {
                tracing::error!(
                    "🚫 Outbound camera stream destination identity mismatch: expected {}, got {}",
                    target_peer_id,
                    session.peer_device_id_hex()
                );
                let _ = tokio::time::timeout(Duration::from_millis(500), session.close_notify()).await;
                break;
            }

            // Verify generation and consent still valid
            if !self.has_peer_consent(&target_peer_id, target_generation) {
                tracing::warn!("🚫 Camera stream stopped: consent revoked for peer {}", target_peer_id);
                let _ = tokio::time::timeout(Duration::from_millis(500), session.close_notify()).await;
                break;
            }

            // Atomically redeem the single-use authorization lease on first successful connection
            if !lease_redeemed {
                if let Err(e) = self.authorization.redeem_authorization_lease(
                    &lease_token,
                    &target_peer_id,
                    target_generation,
                    crate::camera::authorization::LeaseDirection::OutboundSender,
                ) {
                    tracing::error!("🚫 Single-use authorization lease redemption failed for peer {}: {:?}", target_peer_id, e);
                    let _ = tokio::time::timeout(Duration::from_millis(500), session.close_notify()).await;
                    break;
                }
                lease_redeemed = true;
            }

            // Transmit initial frame carrying FLAG_AUTH_LEASE_REDEMPTION
            if let Ok(init_frame) = encode_camera_frame(
                0,
                0,
                PIXEL_FMT_NV12,
                FLAG_STANDBY_KEEPALIVE | FLAG_AUTH_LEASE_REDEMPTION,
                0,
                &lease_token,
            ) {
                let send_res = tokio::time::timeout(
                    CAMERA_FRAME_SEND_TIMEOUT,
                    session.send_message(&init_frame),
                ).await;
                if let Err(e) = send_res {
                    tracing::warn!("Failed to send lease redemption frame: {:?}", e);
                    let _ = tokio::time::timeout(Duration::from_millis(500), session.close_notify()).await;
                    continue;
                }
            }

            self.set_state("Streaming 720p30", None);
            let mut last_send_instant = std::time::Instant::now();

            while self.active.load(Ordering::Relaxed)
                && self.features.is_enabled("camera")
                && !*stream_cancel_rx.borrow()
                && self.has_peer_consent(&target_peer_id, target_generation)
            {
                if let Some(frame_bytes) = mailbox.take() {
                    let send_res = tokio::select! {
                        res = tokio::time::timeout(
                            CAMERA_FRAME_SEND_TIMEOUT,
                            session.send_message(&frame_bytes),
                        ) => res.unwrap_or_else(|_| Err(crate::security::transport::TransportError::IoFailure("send timeout".into()))),
                        _ = stream_cancel_rx.changed() => {
                            tracing::info!("Camera stream send aborted by cancellation signal for peer {}", target_peer_id);
                            break;
                        }
                    };
                    if let Err(e) = send_res {
                        self.set_state("Reconnecting...", Some(e.to_string()));
                        break;
                    }
                    last_send_instant = std::time::Instant::now();
                    self.frames_transferred.fetch_add(1, Ordering::Relaxed);
                } else {
                    let notified_res = tokio::select! {
                        r = tokio::time::timeout(Duration::from_millis(250), mailbox.notify.notified()) => r.is_ok(),
                        _ = stream_cancel_rx.changed() => break,
                    };
                    if !notified_res && last_send_instant.elapsed() > Duration::from_secs(2) {
                        if let Ok(keepalive) = encode_camera_frame(
                            0,
                            0,
                            PIXEL_FMT_NV12,
                            FLAG_STANDBY_KEEPALIVE,
                            0,
                            &[],
                        ) {
                            let ka_res = tokio::select! {
                                res = tokio::time::timeout(
                                    CAMERA_FRAME_SEND_TIMEOUT,
                                    session.send_message(&keepalive),
                                ) => res.unwrap_or_else(|_| Err(crate::security::transport::TransportError::IoFailure("send timeout".into()))),
                                _ = stream_cancel_rx.changed() => {
                                    tracing::info!("Camera stream keepalive aborted by cancellation signal for peer {}", target_peer_id);
                                    break;
                                }
                            };
                            if let Err(e) = ka_res {
                                self.set_state("Reconnecting...", Some(e.to_string()));
                                break;
                            }
                            last_send_instant = std::time::Instant::now();
                        }
                    }
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(500), session.close_notify()).await;
        }

        self.unregister_peer_stream_by_id(&target_peer_id, stream_id);
        self.authorization.on_stream_closed(&target_peer_id, stream_id);
        let _ = self.lifecycle.try_shutdown_hardware_if_idle_async().await;
    }

    /// Stops camera streaming or virtual camera publication cleanly.
    /// Cancels active peer streams, clears local preview and consent, and shuts down capture
    /// hardware once all active/lingering native operations have exited.
    pub async fn stop(self: &Arc<Self>) {
        self.lifecycle.capture_runtime_handle();
        self.local_consent.store(false, Ordering::SeqCst);
        self.local_preview_active.store(false, Ordering::SeqCst);

        let peer_ids: Vec<String> = {
            let streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            streams.keys().cloned().collect()
        };
        for peer_id in peer_ids {
            let _ = self.teardown_peer_stream_async(&peer_id).await;
        }

        {
            let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
            consent.clear();
        }
        global_frame_hub().clear_all();

        let stopped = self.lifecycle.try_shutdown_hardware_if_idle_async().await;
        if stopped {
            self.set_state("Standby", None);
            info!("📷 Shared camera stopped cleanly");
        }
    }

    /// Synchronous shutdown routine invoked during application termination or emergency teardown.
    ///
    /// Signals all active streams to stop, drains short in-flight native operations up to a bounded
    /// budget so native shared-memory mappings are not unmapped mid-write, and conservatively skips
    /// `stop_capture()` if a native operation remains stuck or lifecycle locks are poisoned.
    pub fn shutdown_sync(&self) {
        self.local_consent.store(false, Ordering::SeqCst);
        self.local_preview_active.store(false, Ordering::SeqCst);
        let _io_guard = match self.lifecycle.hardware_io_lock.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        // Level 1 -> Level 2: cancel all active streams and clear consent
        {
            let mut streams = self.active_peer_streams.lock().unwrap_or_else(|e| e.into_inner());
            for (_, mut entry) in streams.drain() {
                let _ = entry.cancel_tx.send(true);
                if let Some(h) = entry.task_handle.take() {
                    h.abort();
                }
            }
            let mut consent = self.peer_consent.lock().unwrap_or_else(|e| e.into_inner());
            consent.clear();
        }
        global_frame_hub().clear_all();

        // Bounded drain for short-lived in-flight native FFI writes (e.g. Windows NV12 SHM memcpy)
        let drain_deadline = Instant::now() + Duration::from_millis(200);
        loop {
            let has_native = match self.lifecycle.lingering_tasks.lock() {
                Ok(reg) => !reg.active_native_ops.is_empty(),
                Err(_) => {
                    tracing::error!(
                        "CRITICAL: lingering_tasks poisoned during shutdown_sync; skipping backend.stop_capture()"
                    );
                    return;
                }
            };
            if !has_native {
                break;
            }
            if Instant::now() >= drain_deadline {
                tracing::warn!(
                    "Active native camera operation still executing during shutdown_sync; skipping backend.stop_capture() to prevent native UAF"
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        let was_running = {
            let mut hw = self
                .lifecycle
                .hardware_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let prev = hw.running;
            hw.running = false;
            prev
        };
        self.active.store(false, Ordering::SeqCst);
        crate::core::notify_touchbar_camera_state(false, is_camera_privacy_muted());
        if was_running || self.lifecycle.backend.is_capture_running() {
            self.lifecycle.backend.stop_capture();
            self.lifecycle
                .shutdown_executions
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Synchronizes camera subsystem state with a changed feature flag configuration.
    pub async fn sync_with_feature_flag(self: &Arc<Self>, enabled: bool) {
        if enabled {
            if let Err(e) = self.start().await {
                error!("Shared camera activation warning: {}", e);
            }
        } else {
            self.stop().await;
        }
    }

    /// Toggles the camera state between active and standby.
    pub async fn toggle(self: &Arc<Self>) -> Result<String, String> {
        if self.active.load(Ordering::Relaxed) {
            let _ = self.features.set_flag_checked("camera", false);
            self.stop().await;
            Ok("Shared Camera stopped".into())
        } else {
            self.start().await
        }
    }

    /// Queries the current operational snapshot of the Camera & Shared Microphone subsystem.
    pub fn status(&self) -> CameraStatus {
        let active = self.active.load(Ordering::Acquire);
        let enabled = self.features.is_enabled("camera");
        #[cfg(target_os = "macos")]
        let (permission_granted, camera_available, mic_permission_granted) = unsafe {
            (
                integrator_mac_camera_permission_state() == 2
                    && integrator_mac_camera_has_usage_desc() == 1,
                integrator_mac_camera_has_hardware() != 0,
                integrator_mac_mic_permission_granted(),
            )
        };
        #[cfg(target_os = "windows")]
        let (permission_granted, camera_available, mic_permission_granted) = (true, true, true);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let (permission_granted, camera_available, mic_permission_granted) = (false, false, false);

        let role = if cfg!(target_os = "macos") {
            "Mac Camera Sender"
        } else if cfg!(target_os = "windows") {
            "Windows 11 Virtual Webcam"
        } else {
            "Unsupported"
        };

        let state = if !camera_available && !active {
            "No Camera Detected".to_string()
        } else if !enabled {
            "Disabled".to_string()
        } else {
            self.state_label
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| if active { "Active".into() } else { "Standby".into() })
        };

        let raw_gain = f32::from_bits(self.mic_gain_bits.load(Ordering::Acquire));
        let mic_gain = if raw_gain.is_finite() {
            raw_gain.clamp(MIN_MIC_GAIN, MAX_MIC_GAIN)
        } else {
            DEFAULT_MIC_GAIN
        };
        let mic_device_name = self
            .selected_mic_name
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();

        CameraStatus {
            supported: cfg!(any(target_os = "macos", target_os = "windows")),
            camera_available,
            active,
            role: role.to_string(),
            state,
            permission_granted,
            width: CAMERA_WIDTH,
            height: CAMERA_HEIGHT,
            fps: CAMERA_FPS,
            frames_transferred: self.frames_transferred.load(Ordering::Relaxed),
            last_error: self.last_error.lock().ok().and_then(|e| e.clone()),
            port: CAMERA_PORT,
            device_name: DEFAULT_CAMERA_FRIENDLY_NAME.to_string(),
            privacy_muted: is_camera_privacy_muted(),
            mic_enabled: self.mic_enabled.load(Ordering::Acquire),
            mic_muted: self.mic_muted.load(Ordering::Acquire),
            mic_device_name,
            mic_permission_granted,
            mic_gain,
        }
    }

    /// Enumerates available microphone audio input devices on the macOS host (or empty outside macOS).
    ///
    /// Device display labels are stripped of control/bidi formatting characters and bounded by
    /// [`MAX_MIC_LABEL_CHARS`]; entries with invalid or control-laden IDs are filtered out.
    pub fn list_mics(&self) -> Vec<MicDeviceWire> {
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; 8192];
            // SAFETY: `buf` provides `buf.len()` writable bytes for the UTF-8 JSON output.
            let n = unsafe { integrator_mac_list_mics(buf.as_mut_ptr(), buf.len()) };
            if n > 0 && n <= buf.len() {
                if let Ok(json_str) = std::str::from_utf8(&buf[..n]) {
                    if let Ok(parsed) = serde_json::from_str::<Vec<MicDeviceWire>>(json_str) {
                        return parsed
                            .into_iter()
                            .filter(|m| {
                                let id_t = m.id.trim();
                                !id_t.is_empty()
                                    && id_t.len() <= MAX_MIC_DEVICE_ID_BYTES
                                    && !id_t.chars().any(|c| c.is_control())
                            })
                            .map(|mut m| {
                                m.name = sanitize_mic_label(&m.name, MAX_MIC_LABEL_CHARS);
                                m
                            })
                            .collect();
                    }
                }
            }
            Vec::new()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Vec::new()
        }
    }

    /// Selects the active macOS microphone source by unique identifier (`AVCaptureDevice.uniqueID`),
    /// returning the sanitized localized device name on success.
    pub fn select_mic(&self, device_id: &str) -> Result<String, String> {
        let trimmed = device_id.trim();
        if trimmed.is_empty()
            || trimmed.len() > MAX_MIC_DEVICE_ID_BYTES
            || trimmed.chars().any(|c| c.is_control())
        {
            return Err("Rejected select_mic: invalid or overlong microphone device_id".into());
        }

        #[cfg(target_os = "macos")]
        {
            let c_id = std::ffi::CString::new(trimmed)
                .map_err(|_| "Microphone device_id contains embedded NUL byte".to_string())?;
            // SAFETY: `c_id` is a valid NUL-terminated UTF-8 C string for the duration of the call.
            let ok = unsafe { integrator_mac_select_mic(c_id.as_ptr()) };
            if !ok {
                return Err(format!(
                    "Microphone '{}' was not found or is unavailable",
                    sanitize_mic_label(trimmed, 64)
                ));
            }
            let friendly = self
                .list_mics()
                .into_iter()
                .find(|m| m.id == trimmed)
                .map(|m| m.name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| sanitize_mic_label(trimmed, MAX_MIC_LABEL_CHARS));
            if let Ok(mut guard) = self.selected_mic_name.lock() {
                *guard = friendly.clone();
            }
            info!("🎤 Selected shared microphone device: '{}'", friendly);
            Ok(friendly)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("Microphone selection is only supported on the macOS host".into())
        }
    }

    /// Updates shared microphone capture enablement, mute state, and linear gain (`0.0..=2.0`),
    /// returning the refreshed [`CameraStatus`] snapshot.
    pub fn set_mic_settings(&self, enabled: bool, muted: bool, gain: f32) -> CameraStatus {
        let safe_gain = if gain.is_finite() {
            gain.clamp(MIN_MIC_GAIN, MAX_MIC_GAIN)
        } else {
            DEFAULT_MIC_GAIN
        };
        self.mic_enabled.store(enabled, Ordering::SeqCst);
        self.mic_muted.store(muted, Ordering::SeqCst);
        self.mic_gain_bits
            .store(safe_gain.to_bits(), Ordering::SeqCst);
        info!(
            "🎤 Shared microphone settings updated: enabled={}, muted={}, gain={:.0}%",
            enabled,
            muted,
            safe_gain * 100.0
        );
        self.status()
    }

    /// Prompts macOS TCC for microphone capture permission (`AVMediaType.audio`) if not yet granted.
    pub fn request_mic_permission(&self) -> Result<bool, String> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `integrator_mac_request_mic_permission` takes no pointer arguments and handles threading internally.
            Ok(unsafe { integrator_mac_request_mic_permission() })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("Microphone permission requests are only applicable on macOS".into())
        }
    }

    /// Sets the hardware privacy shutter mute state and updates the macOS Touch Bar pill immediately.
    pub fn set_privacy_muted(&self, muted: bool) -> bool {
        let res = set_camera_privacy_muted(muted);
        let active = self.active.load(Ordering::Relaxed);
        crate::core::notify_touchbar_camera_state(active, res);
        res
    }

    /// Toggles the hardware privacy shutter killswitch and returns the new muted state.
    pub fn toggle_privacy_muted(&self) -> bool {
        let next = !is_camera_privacy_muted();
        self.set_privacy_muted(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_valid_nv12_frame_roundtrip() {
        assert_eq!(NV12_FRAME_BYTES, 1280 * 720 * 3 / 2);
        let payload = vec![0x7Au8; NV12_FRAME_BYTES];
        let pkt = encode_camera_frame(
            CAMERA_WIDTH as u16,
            CAMERA_HEIGHT as u16,
            PIXEL_FMT_NV12,
            0,
            1_234_567,
            &payload,
        )
        .expect("valid frame");
        assert_eq!(pkt.len(), CAMERA_FRAME_HEADER_LEN + NV12_FRAME_BYTES);
        let decoded = decode_camera_frame(&pkt).expect("decode succeeds");
        assert_eq!(decoded.width, CAMERA_WIDTH as u16);
        assert_eq!(decoded.height, CAMERA_HEIGHT as u16);
        assert_eq!(decoded.pix_fmt, PIXEL_FMT_NV12);
        assert_eq!(decoded.timestamp_us, 1_234_567);
        assert_eq!(decoded.payload.len(), NV12_FRAME_BYTES);
        assert_eq!(decoded.payload[0], 0x7A);
    }

    #[test]
    fn decode_rejects_corrupt_magic_and_size_mismatch() {
        assert!(decode_camera_frame(&[0u8; 10]).is_err());
        let mut bad = vec![0u8; CAMERA_FRAME_HEADER_LEN];
        bad[0..4].copy_from_slice(b"BAD!");
        assert!(decode_camera_frame(&bad).is_err());

        let oversized = vec![0u8; NV12_FRAME_BYTES + 1];
        assert!(encode_camera_frame(
            CAMERA_WIDTH as u16,
            CAMERA_HEIGHT as u16,
            PIXEL_FMT_NV12,
            0,
            0,
            &oversized,
        )
        .is_err());
    }

    #[test]
    fn keepalive_frame_encodes_and_decodes_with_empty_payload() {
        let pkt = encode_camera_frame(
            CAMERA_WIDTH as u16,
            CAMERA_HEIGHT as u16,
            PIXEL_FMT_NV12,
            FLAG_STANDBY_KEEPALIVE,
            42,
            &[],
        )
        .expect("keepalive frame");
        let dec = decode_camera_frame(&pkt).expect("decode keepalive");
        assert_eq!(dec.flags, FLAG_STANDBY_KEEPALIVE);
        assert!(dec.payload.is_empty());
    }

    #[test]
    fn camera_status_serde_defaults_preserve_backward_compatibility() {
        let legacy_json = r#"{
            "supported": true,
            "active": false,
            "role": "MacBook Camera Sender",
            "state": "Standby",
            "permission_granted": true,
            "width": 1280,
            "height": 720,
            "fps": 30,
            "frames_transferred": 0,
            "last_error": null
        }"#;
        let parsed: CameraStatus =
            serde_json::from_str(legacy_json).expect("legacy CameraStatus JSON should deserialize");
        assert!(parsed.camera_available);
        assert_eq!(parsed.port, CAMERA_PORT);
        assert_eq!(parsed.device_name, DEFAULT_CAMERA_FRIENDLY_NAME);
        assert_eq!(parsed.device_name, "Integrator Mac Camera");
        assert!(!parsed.mic_enabled);
        assert!(!parsed.mic_muted);
        assert_eq!(parsed.mic_device_name, "");
        assert!(!parsed.mic_permission_granted);
        assert!((parsed.mic_gain - 1.0).abs() < f32::EPSILON);

        let serialized = serde_json::to_string(&parsed).expect("CameraStatus should serialize");
        let roundtrip: CameraStatus =
            serde_json::from_str(&serialized).expect("CameraStatus should roundtrip");
        assert!(roundtrip.camera_available);
        assert_eq!(roundtrip.port, CAMERA_PORT);
        assert_eq!(roundtrip.device_name, DEFAULT_CAMERA_FRIENDLY_NAME);
        assert!((roundtrip.mic_gain - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_mic_settings_clamping_sanitization_and_wire_roundtrip() {
        let svc = CameraService::new(
            DiscoveryManager::new("cam_mic_settings_test"),
            Arc::new(FeatureManager::new()),
        );

        let initial = svc.status();
        assert!(!initial.mic_enabled);
        assert!(!initial.mic_muted);
        assert!((initial.mic_gain - 1.0).abs() < f32::EPSILON);

        // Gain clamps cleanly below 0.0 and above 2.0, and handles non-finite inputs safely.
        let low = svc.set_mic_settings(true, false, -0.75);
        assert!(low.mic_enabled);
        assert!(!low.mic_muted);
        assert_eq!(low.mic_gain, 0.0);

        let high = svc.set_mic_settings(true, true, 5.25);
        assert!(high.mic_enabled);
        assert!(high.mic_muted);
        assert_eq!(high.mic_gain, 2.0);

        let nan_status = svc.set_mic_settings(false, false, f32::NAN);
        assert!(!nan_status.mic_enabled);
        assert_eq!(nan_status.mic_gain, 1.0);

        let exact = svc.set_mic_settings(true, false, 1.35);
        assert!((exact.mic_gain - 1.35).abs() < 1e-6);

        // Input validation rejects empty, control-char, or overlong mic device IDs before FFI.
        assert!(svc.select_mic("").is_err());
        assert!(svc.select_mic("  \t\n ").is_err());
        assert!(svc.select_mic("mic\x00bad").is_err());
        assert!(svc.select_mic(&"a".repeat(300)).is_err());

        // Sanitization strips Unicode bidi overrides and ASCII control characters.
        assert_eq!(
            sanitize_mic_label("  MacBook \u{202E}Mic\x07 Pro  ", 64),
            "MacBook Mic Pro"
        );

        let mic_wire: MicDeviceWire =
            serde_json::from_str(r#"{"id":"mic-builtin","name":"MacBook Pro Microphone"}"#)
                .expect("MicDeviceWire without is_default must deserialize");
        assert!(!mic_wire.is_default);
        assert_eq!(mic_wire.id, "mic-builtin");
    }

    #[tokio::test]
    async fn test_camera_session_consent_lifecycle() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_test_dev");
        let svc = CameraService::new(discovery, features);

        // 1. Initial state: consent is false
        assert!(!svc.has_local_consent());

        // 2. Granting local consent
        svc.grant_local_consent();
        assert!(svc.has_local_consent());

        // 3. Resetting session consent returns to false
        svc.reset_session_consent();
        assert!(!svc.has_local_consent());

        // 4. Stopping camera clears consent
        svc.grant_local_consent();
        assert!(svc.has_local_consent());
        svc.stop().await;
        assert!(!svc.has_local_consent());
    }

    #[tokio::test]
    async fn test_camera_peer_scoped_teardown_multi_peer() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_multi_peer");
        let svc = CameraService::new(discovery, features);

        let peer_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer_a, 1);
            ks.register_test_peer_with_generation(peer_b, 1);
        }

        let rx_a = svc.register_peer_stream(peer_a, 1);
        let rx_b = svc.register_peer_stream(peer_b, 1);

        assert!(svc.grant_peer_consent(peer_a, 1));
        assert!(svc.grant_peer_consent(peer_b, 1));

        assert!(svc.is_peer_stream_active(peer_a));
        assert!(svc.is_peer_stream_active(peer_b));
        assert!(svc.has_peer_consent(peer_a, 1));
        assert!(svc.has_peer_consent(peer_b, 1));
        assert!(!*rx_a.borrow());
        assert!(!*rx_b.borrow());

        // Teardown Peer A
        svc.teardown_peer_stream(peer_a);

        // Peer A stream must be canceled and consent removed
        assert!(!svc.is_peer_stream_active(peer_a));
        assert!(!svc.has_peer_consent(peer_a, 1));
        assert!(*rx_a.borrow(), "Peer A stream cancellation watch must be notified");

        // Peer B must remain active and unaffected!
        assert!(svc.is_peer_stream_active(peer_b));
        assert!(svc.has_peer_consent(peer_b, 1));
        assert!(!*rx_b.borrow(), "Peer B stream cancellation watch must not be signaled");

        // Teardown Peer B
        svc.teardown_peer_stream(peer_b);
        assert!(!svc.is_peer_stream_active(peer_b));
        assert!(!svc.has_peer_consent(peer_b, 1));
        assert!(*rx_b.borrow());
    }

    #[tokio::test]
    async fn test_camera_consent_rejects_unconsented_peer_even_if_other_peer_consented() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_consent_isolation");
        let svc = CameraService::new(discovery, features);

        let peer_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01";
        let peer_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer_a, 1);
            ks.register_test_peer_with_generation(peer_b, 1);
        }

        // Explicitly grant consent only to Peer A
        assert!(svc.grant_peer_consent(peer_a, 1));

        // Peer A must have consent
        assert!(svc.has_peer_consent(peer_a, 1));

        // Peer B must NOT have consent even though Peer A was consented (no global bool leak)
        assert!(
            !svc.has_peer_consent(peer_b, 1),
            "Peer B must remain unconsented when consent was only granted to Peer A"
        );
        assert!(!svc.has_active_peer_consent(peer_b));
    }

    #[tokio::test]
    async fn test_camera_local_preview_does_not_grant_remote_consent() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_local_preview_test");
        let svc = CameraService::new(discovery, features);

        let remote_peer = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        // Starting local camera / preview must NOT grant remote consent
        let _ = svc.start().await;

        assert!(
            !svc.has_peer_consent(remote_peer, 1),
            "Local camera start must not grant remote camera consent"
        );
        assert!(!svc.has_active_peer_consent(remote_peer));
    }

    #[tokio::test]
    async fn test_camera_request_uses_authenticated_peer_identity() {
        let features = Arc::new(FeatureManager::new());
        let _ = features.set_flag_checked("camera", true);
        let discovery = DiscoveryManager::new("cam_auth_identity_test");
        let svc = CameraService::new(discovery, features);

        // An unverified or unauthenticated peer name/id must be rejected
        let res = svc.start_remote_request(Some("attacker_unverified_device")).await;
        assert!(
            res.is_err(),
            "start_remote_request must reject unverified peer identities"
        );
        let err = res.unwrap_err();
        assert!(
            err.contains("is not a verified paired identity") || err.contains("Unverified"),
            "Error must identify unverified peer rejection: {}",
            err
        );

        // A None or empty peer identifier must also be strictly rejected
        let res_none = svc.start_remote_request(None).await;
        assert!(res_none.is_err());
        assert!(res_none.unwrap_err().contains("requires authenticated peer identity"));
    }

    #[tokio::test]
    async fn test_camera_consent_revocation_stops_active_peer_stream() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_consent_revocation_test");
        let svc = CameraService::new(discovery, features);

        let peer = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 1);
        }

        let cancel_rx = svc.register_peer_stream(peer, 1);
        assert!(svc.grant_peer_consent(peer, 1));

        assert!(svc.has_peer_consent(peer, 1));
        assert!(svc.is_peer_stream_active(peer));
        assert!(!*cancel_rx.borrow());

        // Revoke consent specifically for this peer
        svc.revoke_peer_consent(peer);

        // Consent must be revoked and stream watch receiver canceled
        assert!(!svc.has_peer_consent(peer, 1));
        assert!(!svc.is_peer_stream_active(peer));
        assert!(
            *cancel_rx.borrow(),
            "Revoking consent must notify stream cancellation receiver immediately"
        );
    }

    #[tokio::test]
    async fn test_camera_consent_revocation_race_before_insertion() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_race_before");
        let svc = CameraService::new(discovery, features);

        let peer = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 1);
        }

        // Revocation intervenes before grant_peer_consent is called
        crate::security::transport::invalidate_peer_trust(peer, 2);

        // grant_peer_consent must fail closed and return false
        let granted = svc.grant_peer_consent(peer, 1);
        assert!(!granted, "grant_peer_consent must fail closed when peer is revoked");

        // Peer must have no consent
        assert!(!svc.has_peer_consent(peer, 1));
        assert!(!svc.has_active_peer_consent(peer));
    }

    #[tokio::test]
    async fn test_camera_consent_revocation_race_after_insertion() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_race_after");
        let svc = CameraService::new(discovery, features);

        let peer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 1);
        }

        // Consent was granted for generation 1
        assert!(svc.grant_peer_consent(peer, 1));
        assert!(svc.has_peer_consent(peer, 1));

        // Revocation/unpair occurs: trust generation updated to 2 and peer marked revoked
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.unpair_peer(peer);
        }

        // has_peer_consent for generation 1 MUST immediately fail closed
        assert!(
            !svc.has_peer_consent(peer, 1),
            "Consent for stale generation 1 must be immediately invalid after unpair"
        );
        assert!(
            !svc.has_active_peer_consent(peer),
            "Active consent must be false after peer unpair"
        );
    }

    #[tokio::test]
    async fn test_camera_repair_invalidates_stale_consent_request() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_repair_test");
        let svc = CameraService::new(discovery, features);

        let peer = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 1);
        }

        // Grant consent for initial pairing generation 1
        assert!(svc.grant_peer_consent(peer, 1));
        assert!(svc.has_peer_consent(peer, 1));

        // Peer is re-paired with generation 2 (simulated by updating generation)
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 2);
        }
        svc.revoke_peer_consent(peer);

        // Previous generation consent is completely invalid
        assert!(!svc.has_peer_consent(peer, 1));
        // New generation does not inherit old consent
        assert!(!svc.has_peer_consent(peer, 2));
        assert!(!svc.has_active_peer_consent(peer));

        // New consent for generation 2 must be explicitly granted
        assert!(svc.grant_peer_consent(peer, 2));
        assert!(svc.has_peer_consent(peer, 2));
        assert!(!svc.has_peer_consent(peer, 1));
    }

    #[tokio::test]
    async fn test_camera_peer_scoped_stream_isolation_and_preview_preservation() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_isolation_test");
        let svc = CameraService::new(discovery, features);

        let peer_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer_a, 1);
            ks.register_test_peer_with_generation(peer_b, 1);
        }

        // 1. Enable local preview
        svc.set_local_preview_active(true);
        assert!(svc.is_local_preview_active());

        // 2. Grant consent and register streams for both Peer A and Peer B
        assert!(svc.grant_peer_consent(peer_a, 1));
        assert!(svc.grant_peer_consent(peer_b, 1));
        let cancel_a = svc.register_peer_stream(peer_a, 1);
        let cancel_b = svc.register_peer_stream(peer_b, 1);

        assert!(svc.has_peer_consent(peer_a, 1));
        assert!(svc.has_peer_consent(peer_b, 1));
        assert!(svc.is_peer_stream_active(peer_a));
        assert!(svc.is_peer_stream_active(peer_b));
        assert!(!*cancel_a.borrow());
        assert!(!*cancel_b.borrow());

        // 3. Teardown Peer A's stream (simulating peer_scoped StopCamera or revocation)
        svc.teardown_peer_stream(peer_a);

        // Peer A is torn down
        assert!(!svc.has_peer_consent(peer_a, 1));
        assert!(!svc.is_peer_stream_active(peer_a));
        assert!(*cancel_a.borrow(), "Peer A's stream must be cancelled");

        // Peer B is completely unaffected!
        assert!(svc.has_peer_consent(peer_b, 1), "Peer B consent must remain valid");
        assert!(svc.is_peer_stream_active(peer_b), "Peer B stream must remain active");
        assert!(!*cancel_b.borrow(), "Peer B cancellation must NOT fire");

        // Local preview remains active
        assert!(svc.is_local_preview_active(), "Local preview must remain active");

        // 4. Teardown Peer B's stream
        svc.teardown_peer_stream(peer_b);
        assert!(!svc.has_peer_consent(peer_b, 1));
        assert!(!svc.is_peer_stream_active(peer_b));
        assert!(*cancel_b.borrow());

        // Local preview still protected
        assert!(svc.is_local_preview_active());
        svc.set_local_preview_active(false);
        assert!(!svc.is_local_preview_active());
    }

    #[tokio::test]
    async fn test_camera_no_abba_deadlock_concurrent_pairing_and_consent() {
        let features = Arc::new(FeatureManager::new());
        let discovery = DiscoveryManager::new("cam_abba_test");
        let svc = CameraService::new(discovery, features);

        let peer = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer, 1);
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        // Task 1: Repeatedly grants peer consent (locks peer_consent, reads transport generation)
        let svc_1 = Arc::clone(&svc);
        let b_1 = Arc::clone(&barrier);
        let t1 = tokio::spawn(async move {
            for i in 1..=50u64 {
                b_1.wait().await;
                let _ = svc_1.grant_peer_consent(peer, i);
            }
        });

        // Task 2: Repeatedly updates peer generation in keystore and revokes consent
        let svc_2 = Arc::clone(&svc);
        let b_2 = Arc::clone(&barrier);
        let t2 = tokio::spawn(async move {
            for i in 1..=50u64 {
                b_2.wait().await;
                {
                    let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
                    ks.register_test_peer_with_generation(peer, i);
                }
                // Revoke consent outside keystore lock
                svc_2.revoke_peer_consent(peer);
            }
        });

        // Both tasks must complete cleanly without deadlocking
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (r1, r2) = tokio::join!(t1, t2);
            r1.unwrap();
            r2.unwrap();
        }).await;

        assert!(res.is_ok(), "Concurrent consent and keystore operations must never deadlock");
    }

    #[tokio::test]
    async fn test_camera_teardown_awaits_streaming_task_termination() {
        let disc = DiscoveryManager::new("cam_teardown_test");
        let fm = Arc::new(FeatureManager::new());
        let svc = CameraService::new(disc, fm);
        let peer = "ffff0000ffff0000ffff0000ffff0000";

        // Register stream and attach a mock task that respects cancellation
        let mut cancel_rx = svc.register_peer_stream(peer, 1);
        let task_completed = Arc::new(AtomicBool::new(false));
        let tc = Arc::clone(&task_completed);

        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    tc.store(true, Ordering::SeqCst);
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        });
        svc.attach_stream_handle(peer, handle);

        assert!(svc.is_peer_stream_active(peer));

        // Teardown should signal cancellation and await completion
        let teardown_res = svc.teardown_peer_stream_async(peer).await;
        assert!(teardown_res.is_ok());

        assert!(task_completed.load(Ordering::SeqCst), "Streaming task must have completed upon teardown return");
        assert!(!svc.is_peer_stream_active(peer));
    }

    #[tokio::test]
    async fn test_camera_teardown_escalates_to_abort_on_hung_task() {
        let disc = DiscoveryManager::new("cam_hung_test");
        let fm = Arc::new(FeatureManager::new());
        let svc = CameraService::new(disc, fm);
        let peer = "11110000111100001111000011110000";

        // Register stream and attach a hung task that ignores cancel_rx
        let _cancel_rx = svc.register_peer_stream(peer, 1);
        let handle = tokio::spawn(async move {
            // Hung task: sleep without listening to cancel
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        svc.attach_stream_handle(peer, handle);

        assert!(svc.is_peer_stream_active(peer));

        // Teardown should hit bounded timeout and abort the task
        let start = Instant::now();
        let teardown_res = svc.teardown_peer_stream_async(peer).await;
        assert!(teardown_res.is_ok());
        let elapsed = start.elapsed();

        // Must have completed within bounded timeout (~2.5s + 0.5s)
        assert!(elapsed < Duration::from_secs(4), "Teardown must abort hung task within bounded timeout");
        assert!(!svc.is_peer_stream_active(peer));
    }

    #[tokio::test]
    async fn test_camera_teardown_hung_native_task_reports_err_and_retains_hardware() {
        let disc = DiscoveryManager::new("cam_hung_native_test");
        let fm = Arc::new(FeatureManager::new());
        let svc = CameraService::new(disc, fm);
        let peer = "22220000222200002222000022220000";

        let _cancel_rx = svc.register_peer_stream(peer, 1);

        let stop_blocking = Arc::new(AtomicBool::new(false));
        let sb = Arc::clone(&stop_blocking);

        // Spawn a native blocking task via spawn_blocking that DOES NOT exit on abort()
        let handle = tokio::task::spawn_blocking(move || {
            while !sb.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        svc.attach_stream_handle(peer, handle);
        assert!(svc.is_peer_stream_active(peer));

        // Teardown should attempt cancellation, escalate to abort, timeout on post-abort drain,
        // report Err honestly, and retain the task in lingering_tasks (SEC-1D-17).
        let teardown_res = svc.teardown_peer_stream_async(peer).await;
        assert!(teardown_res.is_err(), "Teardown must report Err on hung native task (SEC-1D-17)");
        assert!(svc.lingering_tasks_count() >= 1, "Hung task must be retained in lingering_tasks");

        // Hardware must NOT be shutdown while tasks linger
        assert!(!svc.is_peer_stream_active(peer));

        // Unblock native thread to prevent test leak
        stop_blocking.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn test_camera_atomic_registration_and_orphaned_handle_safety() {
        let disc = DiscoveryManager::new("cam_orphan_test");
        let fm = Arc::new(FeatureManager::new());
        let svc = CameraService::new(disc, fm);
        let peer = "33330000333300003333000033330000";

        // Attempt to attach handle to a peer stream that was NOT registered or was already removed
        let task_ran = Arc::new(AtomicBool::new(false));
        let tr = Arc::clone(&task_ran);
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tr.store(true, Ordering::SeqCst);
        });

        svc.attach_stream_handle(peer, handle);

        // The handle must have been aborted and added to lingering_tasks (SEC-1D-18)
        assert!(svc.lingering_tasks_count() >= 1, "Orphaned handle must be retained in lingering_tasks");
    }

    /// Controllable test camera backend for deterministic hardware start/stop verification.
    struct MockCameraBackend {
        start_calls: AtomicU64,
        stop_calls: AtomicU64,
        running: AtomicBool,
        stop_notify: Arc<Notify>,
    }

    impl MockCameraBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                start_calls: AtomicU64::new(0),
                stop_calls: AtomicU64::new(0),
                running: AtomicBool::new(false),
                stop_notify: Arc::new(Notify::new()),
            })
        }

        fn start_calls(&self) -> u64 {
            self.start_calls.load(Ordering::SeqCst)
        }

        fn stop_calls(&self) -> u64 {
            self.stop_calls.load(Ordering::SeqCst)
        }

        async fn wait_for_stop_count(&self, expected: u64) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let notified = self.stop_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.stop_calls() >= expected {
                    return;
                }
                let rem = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !rem.is_zero(),
                    "Timed out waiting for hardware stop_calls >= {} (got {})",
                    expected,
                    self.stop_calls()
                );
                let _ = tokio::time::timeout(rem, notified).await;
            }
        }
    }

    impl CameraHardwareBackend for MockCameraBackend {
        fn start_capture(&self) -> Result<(), (String, String)> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn stop_capture(&self) {
            self.running.store(false, Ordering::SeqCst);
            self.stop_calls.fetch_add(1, Ordering::SeqCst);
            self.stop_notify.notify_waiters();
        }

        fn is_capture_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    fn new_test_camera_service(
        label: &str,
        backend: Arc<MockCameraBackend>,
        cancel_timeout: Duration,
        abort_drain_timeout: Duration,
    ) -> Arc<CameraService> {
        let disc = DiscoveryManager::new(label);
        let fm = Arc::new(FeatureManager::new());
        let _ = fm.set_flag_checked("camera", true);
        CameraService::new_with_backend_and_timeouts(
            disc,
            fm,
            backend,
            cancel_timeout,
            abort_drain_timeout,
        )
    }

    async fn wait_for_lingering_count(svc: &CameraService, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = svc.lifecycle.lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if svc.lingering_tasks_count() == expected {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(
                !rem.is_zero(),
                "Timed out waiting for lingering_tasks_count == {} (got {})",
                expected,
                svc.lingering_tasks_count()
            );
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }

    async fn wait_for_reaped_total(svc: &CameraService, expected_min: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = svc.lifecycle.lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if svc.reap_stats().total_reaped() >= expected_min {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(
                !rem.is_zero(),
                "Timed out waiting for total_reaped >= {} (got {})",
                expected_min,
                svc.reap_stats().total_reaped()
            );
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }

    async fn wait_for_shutdown_eval_after(svc: &CameraService, prev_eval: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let notified = svc.lifecycle.lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if svc.shutdown_eval_count() > prev_eval {
                return;
            }
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(
                !rem.is_zero(),
                "Timed out waiting for shutdown_eval_count > {} (got {})",
                prev_eval,
                svc.shutdown_eval_count()
            );
            let _ = tokio::time::timeout(rem, notified).await;
        }
    }

    /// Required SEC-1D-17 production-path regression test:
    /// Exercises both (A) an outer async stream task with an inner blocking native operation guarded by
    /// `CameraNativeOpGuard` (where aborting the outer task cancels the outer future while the native
    /// thread remains active behind a barrier), and (B) a direct blocking `JoinHandle` that refuses abort.
    /// Verifies teardown reports Err, hardware stays active while blocked, and upon barrier release the
    /// completion-driven reaper observes completion, empties the lingering registry, and shuts down
    /// hardware exactly once with NO additional teardown call.
    #[tokio::test]
    async fn test_camera_lingering_task_reaped_and_hardware_eventually_shutdown() {
        // --- Part A: Production-path stream (`start_managed_peer_stream`) with outer async task + inner blocking native op ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_reap_native_op",
                Arc::clone(&backend),
                Duration::from_millis(40),
                Duration::from_millis(40),
            );
            let peer = "a1000000000000000000000000000001";

            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
            let release_barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_worker = Arc::clone(&release_barrier);

            // 1. Start a real production-path camera stream using the controllable capture backend
            let _stream_id = svc
                .start_managed_peer_stream(peer, 1, move |svc_inner, pid, _gen, sid, _rx| async move {
                    // 2. Hold a simulated native operation behind a synchronization barrier on a blocking OS thread
                    let op_guard = svc_inner.begin_peer_native_op(&pid, Some(sid), "avfoundation_capture_op");
                    let _ = tokio::task::spawn_blocking(move || {
                        let _guard = op_guard;
                        let _ = entered_tx.send(());
                        barrier_worker.wait();
                    })
                    .await;
                })
                .await
                .expect("start_managed_peer_stream must succeed");

            // Deterministically wait until the native operation is actively executing behind the barrier
            entered_rx.await.expect("native op entered");
            assert_eq!(backend.start_calls(), 1);
            assert_eq!(backend.stop_calls(), 0);
            assert!(svc.is_active());

            // 3-5. Initiate peer teardown -> forces initial cancellation timeout -> abort escalation -> native drain timeout
            let teardown_res = svc.teardown_peer_stream_async(peer).await;

            // 6. Verify teardown returns an error (outer task was cancelled by abort, but native op is STILL active!)
            assert!(
                teardown_res.is_err(),
                "Teardown must fail honestly while inner blocking native operation remains active"
            );
            // 7. Verify the outstanding operation remains supervised
            assert_eq!(svc.lingering_tasks_count(), 1, "Outstanding native operation must remain supervised");
            // 8. Verify camera hardware is NOT shut down while the operation remains active
            assert_eq!(backend.stop_calls(), 0, "Camera hardware must NOT shut down while native op is active");
            assert!(svc.is_active(), "CameraService must remain active while native op holds hardware");

            // 9-10. Release the barrier so the former native operation finishes
            release_barrier.wait();

            // 11-13. Without ANY additional teardown call, verify the reaper observes completion,
            // empties the lingering registry, and shuts down hardware EXACTLY ONCE!
            backend.wait_for_stop_count(1).await;
            wait_for_lingering_count(&svc, 0).await;
            wait_for_reaped_total(&svc, 1).await;

            assert_eq!(svc.lingering_tasks_count(), 0, "Lingering registry must become empty");
            assert_eq!(backend.stop_calls(), 1, "Hardware shutdown must execute exactly once");
            assert_eq!(svc.shutdown_execution_count(), 1);
            assert!(!svc.is_active(), "CameraService must transition to inactive after hardware shutdown");
        }

        // --- Part B: Direct blocking `JoinHandle` lingering past abort escalation ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_reap_blocking_jh",
                Arc::clone(&backend),
                Duration::from_millis(40),
                Duration::from_millis(40),
            );
            let peer = "a1000000000000000000000000000002";

            // Start hardware cleanly without enabling local preview
            svc.ensure_capture_hardware_started()
                .await
                .expect("start hardware");
            assert_eq!(backend.start_calls(), 1);
            assert_eq!(backend.stop_calls(), 0);

            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
            let release_barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_worker = Arc::clone(&release_barrier);

            let _cancel_rx = svc.register_peer_stream(peer, 1);
            let handle = tokio::task::spawn_blocking(move || {
                let _ = entered_tx.send(());
                barrier_worker.wait();
            });
            svc.attach_stream_handle(peer, handle);

            entered_rx.await.expect("blocking task entered");

            let teardown_res = svc.teardown_peer_stream_async(peer).await;
            assert!(teardown_res.is_err(), "Teardown must return Err on hung blocking JoinHandle");
            assert_eq!(svc.lingering_tasks_count(), 1);
            assert_eq!(backend.stop_calls(), 0);

            // Release barrier -> completion watcher awaits JoinHandle, reaps it, and shuts down hardware once
            release_barrier.wait();

            backend.wait_for_stop_count(1).await;
            wait_for_lingering_count(&svc, 0).await;
            wait_for_reaped_total(&svc, 1).await;

            assert_eq!(svc.lingering_tasks_count(), 0);
            assert_eq!(svc.reap_stats().reaped_ok, 1);
            assert_eq!(backend.stop_calls(), 1);
            assert_eq!(svc.shutdown_execution_count(), 1);
            assert!(!svc.is_active());
        }
    }

    #[tokio::test]
    async fn test_camera_two_lingering_tasks_completing_out_of_order_and_simultaneously() {
        // --- Subcase 1: Reverse completion order (Peer B finishes before Peer A) ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_two_out_of_order",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let peer_a = "b1000000000000000000000000000001";
            let peer_b = "b1000000000000000000000000000002";

            let (enter_a_tx, enter_a_rx) = tokio::sync::oneshot::channel::<()>();
            let (enter_b_tx, enter_b_rx) = tokio::sync::oneshot::channel::<()>();
            let barrier_a = Arc::new(std::sync::Barrier::new(2));
            let barrier_b = Arc::new(std::sync::Barrier::new(2));

            let ba = Arc::clone(&barrier_a);
            svc.start_managed_peer_stream(peer_a, 1, move |s, pid, _g, sid, _rx| async move {
                let g = s.begin_peer_native_op(&pid, Some(sid), "native_a");
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = g;
                    let _ = enter_a_tx.send(());
                    ba.wait();
                })
                .await;
            })
            .await
            .unwrap();

            let bb = Arc::clone(&barrier_b);
            svc.start_managed_peer_stream(peer_b, 1, move |s, pid, _g, sid, _rx| async move {
                let g = s.begin_peer_native_op(&pid, Some(sid), "native_b");
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = g;
                    let _ = enter_b_tx.send(());
                    bb.wait();
                })
                .await;
            })
            .await
            .unwrap();

            enter_a_rx.await.unwrap();
            enter_b_rx.await.unwrap();
            assert_eq!(backend.start_calls(), 1);

            assert!(svc.teardown_peer_stream_async(peer_a).await.is_err());
            assert_eq!(svc.lingering_tasks_count(), 1);
            assert_eq!(backend.stop_calls(), 0);

            assert!(svc.teardown_peer_stream_async(peer_b).await.is_err());
            assert_eq!(svc.lingering_tasks_count(), 2);
            assert_eq!(backend.stop_calls(), 0);

            // Release Peer B first (reverse order) -> Peer A still holds hardware
            let eval_before = svc.shutdown_eval_count();
            barrier_b.wait();
            wait_for_lingering_count(&svc, 1).await;
            wait_for_shutdown_eval_after(&svc, eval_before).await;
            assert_eq!(backend.stop_calls(), 0, "Hardware must remain active while Peer A still lingers");
            assert!(svc.is_active());

            // Now release Peer A -> hardware shuts down exactly once
            barrier_a.wait();
            backend.wait_for_stop_count(1).await;
            wait_for_lingering_count(&svc, 0).await;
            assert_eq!(backend.stop_calls(), 1);
            assert_eq!(svc.shutdown_execution_count(), 1);
        }

        // --- Subcase 2: Simultaneous completion on shared barrier -> exact-once shutdown, no lock inversion ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_two_simultaneous",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let peer_1 = "b2000000000000000000000000000001";
            let peer_2 = "b2000000000000000000000000000002";

            svc.ensure_capture_hardware_started().await.unwrap();

            let (e1_tx, e1_rx) = tokio::sync::oneshot::channel::<()>();
            let (e2_tx, e2_rx) = tokio::sync::oneshot::channel::<()>();
            let shared_release = Arc::new(std::sync::Barrier::new(3));

            let r1 = Arc::clone(&shared_release);
            let _rx1 = svc.register_peer_stream(peer_1, 1);
            svc.attach_stream_handle(
                peer_1,
                tokio::task::spawn_blocking(move || {
                    let _ = e1_tx.send(());
                    r1.wait();
                }),
            );

            let r2 = Arc::clone(&shared_release);
            let _rx2 = svc.register_peer_stream(peer_2, 1);
            svc.attach_stream_handle(
                peer_2,
                tokio::task::spawn_blocking(move || {
                    let _ = e2_tx.send(());
                    r2.wait();
                }),
            );

            e1_rx.await.unwrap();
            e2_rx.await.unwrap();

            assert!(svc.teardown_peer_stream_async(peer_1).await.is_err());
            assert!(svc.teardown_peer_stream_async(peer_2).await.is_err());
            assert_eq!(svc.lingering_tasks_count(), 2);
            assert_eq!(backend.stop_calls(), 0);

            // Release BOTH tasks simultaneously
            shared_release.wait();

            backend.wait_for_stop_count(1).await;
            wait_for_lingering_count(&svc, 0).await;
            wait_for_reaped_total(&svc, 2).await;

            assert_eq!(
                backend.stop_calls(),
                1,
                "Simultaneous lingering completions must execute hardware shutdown exactly once"
            );
            assert_eq!(svc.shutdown_execution_count(), 1);
        }
    }

    #[tokio::test]
    async fn test_camera_new_peer_registering_while_old_lingering_task_completes() {
        // --- Subcase 1: Active new peer stream registered before old task finishes ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_new_peer_race",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let old_peer = "c1000000000000000000000000000001";
            let new_peer = "c1000000000000000000000000000002";

            let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let b_w = Arc::clone(&barrier);

            svc.start_managed_peer_stream(old_peer, 1, move |s, pid, _g, sid, _rx| async move {
                let g = s.begin_peer_native_op(&pid, Some(sid), "old_native");
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = g;
                    let _ = enter_tx.send(());
                    b_w.wait();
                })
                .await;
            })
            .await
            .unwrap();
            enter_rx.await.unwrap();

            assert!(svc.teardown_peer_stream_async(old_peer).await.is_err());
            assert_eq!(svc.lingering_tasks_count(), 1);

            // New peer starts a cooperative stream while old_peer is lingering
            svc.start_managed_peer_stream(new_peer, 1, move |_s, _pid, _g, _sid, mut rx| async move {
                let _ = rx.changed().await;
            })
            .await
            .unwrap();
            assert!(svc.is_peer_stream_active(new_peer));
            assert_eq!(backend.start_calls(), 1, "New peer should reuse already-running hardware");

            // Old task completes while new_peer is active -> MUST NOT shut down hardware!
            let eval_before = svc.shutdown_eval_count();
            barrier.wait();
            wait_for_lingering_count(&svc, 0).await;
            wait_for_reaped_total(&svc, 1).await;
            wait_for_shutdown_eval_after(&svc, eval_before).await;

            assert_eq!(backend.stop_calls(), 0, "Hardware must NOT shut down while new_peer is active");
            assert!(svc.is_active());

            // Now tear down new_peer cleanly -> hardware shuts down exactly once
            assert!(svc.teardown_peer_stream_async(new_peer).await.is_ok());
            assert_eq!(backend.stop_calls(), 1);
            assert!(!svc.is_active());
        }

        // --- Subcase 2: New stream in mid-startup (`StreamStartGuard` held) while old task completes ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_mid_start_race",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let old_peer = "c2000000000000000000000000000001";

            let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let b_w = Arc::clone(&barrier);

            svc.start_managed_peer_stream(old_peer, 1, move |s, pid, _g, sid, _rx| async move {
                let g = s.begin_peer_native_op(&pid, Some(sid), "old_native_mid_start");
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = g;
                    let _ = enter_tx.send(());
                    b_w.wait();
                })
                .await;
            })
            .await
            .unwrap();
            enter_rx.await.unwrap();

            assert!(svc.teardown_peer_stream_async(old_peer).await.is_err());
            assert_eq!(svc.lingering_tasks_count(), 1);

            // Hold StreamStartGuard (simulating a new stream mid-initialization before insertion)
            let start_guard = svc.lifecycle.begin_stream_start();

            // Old task completes while new stream is starting -> hardware MUST NOT shut down!
            let eval_before = svc.shutdown_eval_count();
            barrier.wait();
            wait_for_lingering_count(&svc, 0).await;
            wait_for_reaped_total(&svc, 1).await;
            wait_for_shutdown_eval_after(&svc, eval_before).await;
            assert_eq!(
                backend.stop_calls(),
                0,
                "Hardware must NOT shut down while a new stream startup guard is active"
            );
            assert!(svc.is_active());

            // Simulate aborted startup: dropping start_guard triggers deferred shutdown cleanly once
            drop(start_guard);
            backend.wait_for_stop_count(1).await;
            assert_eq!(backend.stop_calls(), 1);
            assert!(!svc.is_active());
        }
    }

    #[tokio::test]
    async fn test_camera_local_preview_prevents_shutdown_during_lingering_task_completion() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_preview_lingering",
            Arc::clone(&backend),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let peer = "d1000000000000000000000000000001";

        // Enable local preview via production `start()`
        svc.start().await.expect("local preview start");
        assert!(svc.is_local_preview_active());
        assert_eq!(backend.start_calls(), 1);

        let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b_w = Arc::clone(&barrier);

        svc.start_managed_peer_stream(peer, 1, move |s, pid, _g, sid, _rx| async move {
            let g = s.begin_peer_native_op(&pid, Some(sid), "preview_peer_native");
            let _ = tokio::task::spawn_blocking(move || {
                let _guard = g;
                let _ = enter_tx.send(());
                b_w.wait();
            })
            .await;
        })
        .await
        .unwrap();
        enter_rx.await.unwrap();

        assert!(svc.teardown_peer_stream_async(peer).await.is_err());
        assert_eq!(svc.lingering_tasks_count(), 1);

        // Old task completes while local preview is active -> hardware MUST remain active!
        let eval_before = svc.shutdown_eval_count();
        barrier.wait();
        wait_for_lingering_count(&svc, 0).await;
        wait_for_reaped_total(&svc, 1).await;
        wait_for_shutdown_eval_after(&svc, eval_before).await;
        assert_eq!(
            backend.stop_calls(),
            0,
            "Hardware must NOT shut down while local preview remains active"
        );
        assert!(svc.is_active());
        assert!(svc.is_local_preview_active());

        // Stopping local preview shuts down hardware cleanly once
        svc.stop().await;
        assert_eq!(backend.stop_calls(), 1);
        assert!(!svc.is_active());
        assert!(!svc.is_local_preview_active());
    }

    #[tokio::test]
    async fn test_camera_repeated_reaping_and_teardown_retry_after_failure() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_retry_reap",
            Arc::clone(&backend),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let peer = "e1000000000000000000000000000001";

        let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b_w = Arc::clone(&barrier);

        svc.start_managed_peer_stream(peer, 1, move |s, pid, _g, sid, _rx| async move {
            let g = s.begin_peer_native_op(&pid, Some(sid), "retry_native");
            let _ = tokio::task::spawn_blocking(move || {
                let _guard = g;
                let _ = enter_tx.send(());
                b_w.wait();
            })
            .await;
        })
        .await
        .unwrap();
        enter_rx.await.unwrap();

        // Initial teardown fails
        assert!(svc.teardown_peer_stream_async(peer).await.is_err());
        assert_eq!(svc.lingering_tasks_count(), 1);
        assert_eq!(backend.stop_calls(), 0);

        // Repeated reaping calls while still running must report 1 and keep hardware active
        assert_eq!(svc.reap_lingering_tasks(), 1);
        assert_eq!(svc.reap_lingering_tasks(), 1);
        assert_eq!(backend.stop_calls(), 0);

        // Teardown RETRY while peer's native op is still stuck MUST STILL return Err (no false Ok!)
        let retry_while_stuck = svc.teardown_peer_stream_async(peer).await;
        assert!(
            retry_while_stuck.is_err(),
            "Teardown retry while peer's lingering operation is still running must return Err"
        );
        assert_eq!(svc.lingering_tasks_count(), 1);
        assert_eq!(backend.stop_calls(), 0);

        // Release barrier -> automatic reap + hardware shutdown
        barrier.wait();
        backend.wait_for_stop_count(1).await;
        wait_for_lingering_count(&svc, 0).await;

        // Teardown retry AFTER completion succeeds cleanly and does NOT double-shutdown
        let retry_after_done = svc.teardown_peer_stream_async(peer).await;
        assert!(retry_after_done.is_ok(), "Teardown retry after completion must return Ok");

        // Repeated reaping calls after idle must be idempotent with exact-once hardware shutdown
        assert_eq!(svc.reap_lingering_tasks(), 0);
        assert_eq!(svc.reap_lingering_tasks(), 0);
        assert_eq!(backend.stop_calls(), 1);
        assert_eq!(svc.shutdown_execution_count(), 1);
    }

    #[tokio::test]
    async fn test_camera_lingering_task_panic_observed_reaped_and_hardware_shutdown() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_panic_reap",
            Arc::clone(&backend),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let peer = "f1000000000000000000000000000001";

        svc.ensure_capture_hardware_started().await.unwrap();
        let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b_w = Arc::clone(&barrier);

        let _cancel_rx = svc.register_peer_stream(peer, 1);
        let handle = tokio::task::spawn_blocking(move || {
            let _ = enter_tx.send(());
            b_w.wait();
            panic!("simulated native driver abnormal panic");
        });
        svc.attach_stream_handle(peer, handle);

        enter_rx.await.unwrap();

        assert!(svc.teardown_peer_stream_async(peer).await.is_err());
        assert_eq!(svc.lingering_tasks_count(), 1);
        assert_eq!(backend.stop_calls(), 0);

        // Release barrier -> blocking task panics -> watcher observes panic, records it, reaps handle, shuts down hardware!
        barrier.wait();

        backend.wait_for_stop_count(1).await;
        wait_for_lingering_count(&svc, 0).await;
        wait_for_reaped_total(&svc, 1).await;

        let stats = svc.reap_stats();
        assert_eq!(stats.reaped_panicked, 1, "Reaper must observe and count panicked lingering task");
        assert!(
            !stats.unexpected_failures.is_empty(),
            "Reaper must record unexpected panic details"
        );
        assert!(
            svc.status().last_error.is_some(),
            "Unexpected lingering task panic must be recorded in CameraService last_error"
        );
        assert_eq!(backend.stop_calls(), 1, "Hardware must shut down once after panicked task exits");
        assert!(!svc.is_active());
    }

    #[tokio::test]
    async fn test_camera_poisoned_lingering_registry_refuses_hardware_shutdown() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_poison_registry",
            Arc::clone(&backend),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let peer = "f2000000000000000000000000000001";

        svc.ensure_capture_hardware_started().await.unwrap();
        assert_eq!(backend.start_calls(), 1);
        assert!(svc.is_active());

        // Deterministically poison the lingering_tasks mutex on a separate thread
        let lingering_mutex = Arc::clone(&svc.lifecycle.lingering_tasks);
        let join_res = std::thread::spawn(move || {
            let _guard = lingering_mutex.lock().unwrap();
            panic!("intentional poison of lingering_tasks mutex");
        })
        .join();
        assert!(join_res.is_err());

        assert!(svc.is_lingering_registry_poisoned());
        // Must NEVER interpret a poisoned lingering-task mutex as an empty registry!
        assert!(
            svc.lingering_tasks_count() >= 1,
            "Poisoned lingering registry must never report 0 tasks"
        );

        // Teardown must return Err and conservatively REFUSE hardware shutdown
        let td = svc.teardown_peer_stream_async(peer).await;
        assert!(td.is_err(), "Teardown must fail when lingering registry is poisoned");
        assert_eq!(
            backend.stop_calls(),
            0,
            "Hardware shutdown MUST be conservatively refused when lingering registry is poisoned"
        );
        assert!(svc.is_active());

        // Explicit reaping must also refuse shutdown and never report 0
        assert!(svc.reap_lingering_tasks() >= 1);
        assert_eq!(backend.stop_calls(), 0);
    }

    #[tokio::test]
    async fn test_camera_inflight_teardown_prevents_premature_shutdown_on_concurrent_reap() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_inflight_td_race",
            Arc::clone(&backend),
            Duration::from_millis(400),
            Duration::from_millis(40),
        );
        let peer_a = "f3000000000000000000000000000001";
        let peer_b = "f3000000000000000000000000000002";

        // Peer B: lingering native task behind barrier
        let (enter_b_tx, enter_b_rx) = tokio::sync::oneshot::channel::<()>();
        let barrier_b = Arc::new(std::sync::Barrier::new(2));
        let bb = Arc::clone(&barrier_b);

        svc.start_managed_peer_stream(peer_b, 1, move |s, pid, _g, sid, _rx| async move {
            let g = s.begin_peer_native_op(&pid, Some(sid), "peer_b_native");
            let _ = tokio::task::spawn_blocking(move || {
                let _guard = g;
                let _ = enter_b_tx.send(());
                bb.wait();
            })
            .await;
        })
        .await
        .unwrap();
        enter_b_rx.await.unwrap();

        // Peer A: cooperative task that pauses at a deterministic channel after seeing cancel
        let (a_cancel_seen_tx, a_cancel_seen_rx) = tokio::sync::oneshot::channel::<()>();
        let (a_allow_exit_tx, a_allow_exit_rx) = tokio::sync::oneshot::channel::<()>();
        svc.start_managed_peer_stream(peer_a, 1, move |_s, _pid, _g, _sid, mut rx| async move {
            let _ = rx.changed().await;
            let _ = a_cancel_seen_tx.send(());
            let _ = a_allow_exit_rx.await;
        })
        .await
        .unwrap();

        // Peer B times out and transitions into lingering supervision while Peer A stays active
        assert!(svc.teardown_peer_stream_async(peer_b).await.is_err());
        assert_eq!(svc.lingering_tasks_count(), 1);
        assert_eq!(backend.stop_calls(), 0);

        // Start Peer A teardown in background: removes Peer A from active_peer_streams and awaits Peer A's task
        let svc_a = Arc::clone(&svc);
        let td_a_task = tokio::spawn(async move { svc_a.teardown_peer_stream_async(peer_a).await });

        // Wait deterministically until Peer A is mid-teardown (active_peer_streams is now EMPTY, in_flight_teardowns == 1!)
        a_cancel_seen_rx.await.expect("Peer A saw cancel");
        assert!(!svc.is_peer_stream_active(peer_a));

        // Release Peer B while Peer A is STILL draining mid-teardown!
        let eval_before = svc.shutdown_eval_count();
        barrier_b.wait();
        wait_for_lingering_count(&svc, 0).await;
        wait_for_reaped_total(&svc, 1).await;
        wait_for_shutdown_eval_after(&svc, eval_before).await;

        // Hardware MUST NOT shut down yet because Peer A's teardown is still in-flight!
        assert_eq!(
            backend.stop_calls(),
            0,
            "Concurrent lingering task reap MUST NOT shut down hardware while another peer teardown is in-flight"
        );
        assert!(svc.is_active());

        // Now allow Peer A's task to finish -> Peer A teardown completes Ok and shuts down hardware once
        let _ = a_allow_exit_tx.send(());
        let td_a_res = td_a_task.await.unwrap();
        assert!(td_a_res.is_ok());
        assert_eq!(backend.stop_calls(), 1);
        assert_eq!(svc.shutdown_execution_count(), 1);
        assert!(!svc.is_active());
    }

    #[tokio::test]
    async fn test_camera_teardown_future_cancellation_supervises_handle_and_reaps_hardware() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_td_cancel_safe",
            Arc::clone(&backend),
            Duration::from_secs(5),
            Duration::from_millis(40),
        );
        let peer = "f4000000000000000000000000000001";

        let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
        let (cancel_seen_tx, cancel_seen_rx) = tokio::sync::oneshot::channel::<()>();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b_w = Arc::clone(&barrier);

        svc.start_managed_peer_stream(peer, 1, move |s, pid, _g, sid, mut rx| async move {
            let g = s.begin_peer_native_op(&pid, Some(sid), "cancel_safe_native_op");
            let blocking = tokio::task::spawn_blocking(move || {
                let _guard = g;
                let _ = enter_tx.send(());
                b_w.wait();
            });
            let _ = rx.changed().await;
            let _ = cancel_seen_tx.send(());
            let _ = blocking.await;
        })
        .await
        .unwrap();
        enter_rx.await.unwrap();

        // Launch teardown_peer_stream_async in a task and cancel/abort the teardown future mid-await!
        let svc_td = Arc::clone(&svc);
        let td_handle = tokio::spawn(async move {
            let _ = svc_td.teardown_peer_stream_async(peer).await;
        });

        cancel_seen_rx.await.expect("stream saw cancel from teardown");
        // Drop/abort the teardown future while it is still awaiting the stream task!
        td_handle.abort();
        let _ = td_handle.await;

        // Cancel-safe TeardownInFlightGuard::drop must have marked native op lingering and supervised the stream handle!
        assert!(
            svc.lingering_tasks_count() >= 1,
            "Cancelling teardown future mid-await must transfer remaining handle/native op to lingering supervision"
        );
        assert_eq!(backend.stop_calls(), 0, "Hardware must remain retained while native op is blocked");
        assert!(svc.is_active());

        // Release barrier -> completion-driven reaper finishes reaping and shuts down hardware exact-once!
        barrier.wait();
        backend.wait_for_stop_count(1).await;
        wait_for_lingering_count(&svc, 0).await;
        wait_for_reaped_total(&svc, 1).await;
        assert_eq!(backend.stop_calls(), 1);
        assert_eq!(svc.shutdown_execution_count(), 1);
        assert!(!svc.is_active());
    }

    #[tokio::test]
    async fn test_camera_unscoped_native_op_and_non_lingering_poisoned_mutex_protection() {
        // --- Subcase 1: Peer native op registered with stream_id == None still blocks false Ok and retains hardware ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_none_stream_id_op",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let peer = "f5000000000000000000000000000001";

            let (enter_tx, enter_rx) = tokio::sync::oneshot::channel::<()>();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let b_w = Arc::clone(&barrier);

            svc.start_managed_peer_stream(peer, 1, move |s, pid, _g, _sid, _rx| async move {
                // Deliberately pass stream_id = None
                let g = s.begin_peer_native_op(&pid, None, "unscoped_native_op");
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = g;
                    let _ = enter_tx.send(());
                    b_w.wait();
                })
                .await;
            })
            .await
            .unwrap();
            enter_rx.await.unwrap();

            let td = svc.teardown_peer_stream_async(peer).await;
            assert!(
                td.is_err(),
                "Teardown must fail honestly when a peer native op with stream_id=None remains active"
            );
            assert_eq!(svc.lingering_tasks_count(), 1);
            assert_eq!(backend.stop_calls(), 0);

            barrier.wait();
            backend.wait_for_stop_count(1).await;
            wait_for_lingering_count(&svc, 0).await;
            assert_eq!(backend.stop_calls(), 1);
        }

        // --- Subcase 2: Poisoned non-lingering lifecycle mutex (`active_peer_streams`) returns Err and refuses shutdown ---
        {
            let backend = MockCameraBackend::new();
            let svc = new_test_camera_service(
                "cam_poison_streams_mutex",
                Arc::clone(&backend),
                Duration::from_millis(30),
                Duration::from_millis(30),
            );
            let peer = "f5000000000000000000000000000002";

            svc.ensure_capture_hardware_started().await.unwrap();

            let streams_mutex = Arc::clone(&svc.active_peer_streams);
            let join_res = std::thread::spawn(move || {
                let _g = streams_mutex.lock().unwrap();
                panic!("intentional poison of active_peer_streams");
            })
            .join();
            assert!(join_res.is_err());

            assert!(svc.lingering_tasks_count() >= 1);
            let td = svc.teardown_peer_stream_async(peer).await;
            assert!(
                td.is_err(),
                "Teardown must return Err when active_peer_streams mutex is poisoned"
            );
            assert_eq!(backend.stop_calls(), 0, "Hardware shutdown must be conservatively refused");
            assert!(svc.is_active());
        }
    }

    #[tokio::test]
    async fn test_camera_same_generation_reconnect_and_stale_generation_rejection() {
        let backend = MockCameraBackend::new();
        let svc = new_test_camera_service(
            "cam_reconnect_gen",
            Arc::clone(&backend),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let peer = "f6000000000000000000000000000001";

        let (conn1_exited_tx, conn1_exited_rx) = tokio::sync::oneshot::channel::<()>();
        // Conn 1 starts at generation 3
        let stream1_id = svc
            .start_managed_peer_stream_replacing(peer, 3, move |s, pid, _g, sid, mut rx| async move {
                let _ = rx.changed().await;
                s.unregister_peer_stream_by_id(&pid, sid);
                let _ = s.lifecycle.try_shutdown_hardware_if_idle_async().await;
                let _ = conn1_exited_tx.send(());
            })
            .await
            .expect("conn1 start");

        // Stale generation 1 MUST be rejected without disturbing active generation 3!
        let stale_res = svc
            .start_managed_peer_stream_replacing(peer, 1, move |_s, _pid, _g, _sid, _rx| async move {})
            .await;
        assert!(stale_res.is_err(), "Stale generation 1 must not evict active generation 3 stream");
        assert!(svc.is_peer_stream_active(peer));
        assert_eq!(backend.stop_calls(), 0);

        // Same-generation reconnect (Conn 2 at generation 3) replaces Conn 1 cleanly
        let eval_before = svc.shutdown_eval_count();
        let stream2_id = svc
            .start_managed_peer_stream_replacing(peer, 3, move |_s, _pid, _g, _sid, mut rx| async move {
                let _ = rx.changed().await;
            })
            .await
            .expect("conn2 reconnect");
        assert_ne!(stream1_id, stream2_id);

        // Wait for Conn 1's watcher / exit to complete -> Conn 2 MUST remain active and hardware MUST stay running!
        let _ = conn1_exited_rx.await;
        wait_for_lingering_count(&svc, 0).await;
        wait_for_shutdown_eval_after(&svc, eval_before).await;

        assert!(
            svc.is_peer_stream_active(peer),
            "Departing Conn 1 must NOT clobber same-generation reconnect Conn 2"
        );
        assert_eq!(backend.stop_calls(), 0, "Hardware must NOT shut down while Conn 2 is active");
        assert!(svc.is_active());

        // Tear down Conn 2 cleanly -> hardware shuts down exact-once
        assert!(svc.teardown_peer_stream_async(peer).await.is_ok());
        assert_eq!(backend.stop_calls(), 1);
        assert!(!svc.is_active());
    }

    fn make_test_camera_svc(label: &str) -> Arc<CameraService> {
        let features = Arc::new(FeatureManager::new());
        let _ = features.set_flag_checked("camera", true);
        let discovery = DiscoveryManager::new(label);
        CameraService::new(discovery, features)
    }

    #[tokio::test]
    async fn test_camera_consent_rejects_unpaired_or_unknown_peer() {
        let svc = make_test_camera_svc("cam_unknown_test");

        // 1. Unpaired peer ID must be rejected by start_remote_request
        let unknown_peer = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000";
        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap_or_else(|e| e.into_inner());
            let _ = ks.unpair_peer(unknown_peer);
            crate::security::transport::clear_peer_revocation(unknown_peer);
        }
        let res = svc.start_remote_request(Some(unknown_peer)).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("not a verified paired identity"));

        // 2. None peer identifier must fail closed
        let res_none = svc.start_remote_request(None).await;
        assert!(res_none.is_err());
        assert!(res_none.unwrap_err().contains("requires authenticated peer identity"));
    }

    #[tokio::test]
    async fn test_camera_consent_pairing_alone_does_not_grant_access() {
        let svc = make_test_camera_svc("cam_pairing_alone");
        let peer = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap();
            ks.register_test_peer_with_generation(peer, 1);
        }

        // Pairing alone must NEVER automatically grant camera permission
        assert!(!svc.has_peer_consent(peer, 1), "Pairing alone must not grant camera consent");
        assert_eq!(
            svc.query_consent_status(peer),
            crate::camera::authorization::CameraConsentStatusWire::RequiresPrompt
        );
    }

    #[tokio::test]
    async fn test_camera_consent_denial_enters_temporary_cooldown_integration() {
        let svc = make_test_camera_svc("cam_denial_cooldown");
        let peer = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap();
            ks.register_test_peer_with_generation(peer, 1);
        }

        // Record temporary denial
        svc.record_peer_denial(
            crate::camera::authorization::LeaseDirection::OutboundSender,
            peer,
            crate::camera::authorization::CameraDenialAction::Temporary,
        );

        // Subsequent remote request must fail immediately due to active cooldown
        let res = svc.start_remote_request(Some(peer)).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("cooldown active") && err_msg.contains("consecutive denials"));

        // Unblock device clears cooldown
        svc.unblock_peer_camera(peer);
        assert_eq!(
            svc.query_consent_status(peer),
            crate::camera::authorization::CameraConsentStatusWire::RequiresPrompt
        );
    }

    #[tokio::test]
    async fn test_camera_consent_windows_receiver_consent_lifecycle() {
        let svc = make_test_camera_svc("cam_receiver_consent");
        let peer = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap();
            ks.register_test_peer_with_generation(peer, 2);
        }

        // Initially receiver consent is NOT granted
        assert!(!svc.has_receiver_consent(peer, 2));

        // Grant receiver consent for active session
        assert!(svc.grant_receiver_consent(
            peer,
            2,
            crate::camera::authorization::CameraConsentScope::ActiveSession
        ));
        assert!(svc.has_receiver_consent(peer, 2));

        // Mismatched generation fails closed
        assert!(!svc.has_receiver_consent(peer, 1));
        assert!(!svc.has_receiver_consent(peer, 3));

        // Revoking peer in transport registry immediately fails closed
        crate::security::transport::terminate_active_sessions_for_peer(peer);
        assert!(!svc.has_receiver_consent(peer, 2));
        crate::security::transport::clear_peer_revocation(peer);
    }

    #[tokio::test]
    async fn test_camera_consent_always_allow_persists_in_keystore_and_reloads() {
        let peer = "99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff";
        let gen = 5;

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap();
            ks.register_test_peer_with_generation(peer, gen);
        }

        let svc = make_test_camera_svc("cam_always_allow_test");

        // Grant AlwaysAllow
        assert!(svc.grant_peer_consent_scoped(
            peer,
            gen,
            crate::camera::authorization::CameraConsentScope::AlwaysAllow,
            0
        ));
        assert!(svc.has_peer_consent(peer, gen));

        // Verify it was persisted into Keystore
        {
            let ks = crate::security::keystore::global_keystore().lock().unwrap();
            assert_eq!(
                ks.get_camera_consent(peer),
                Some(format!("always_allow:{}", gen))
            );
        }

        // Simulate daemon restart: create a new CameraService instance
        let svc_restarted = make_test_camera_svc("cam_always_allow_reloaded");

        // Must still have consent for generation 5
        assert!(
            svc_restarted.has_peer_consent(peer, gen),
            "AlwaysAllow must persist and load into newly initialized CameraService"
        );
        // But NOT for older or newer generation
        assert!(!svc_restarted.has_peer_consent(peer, gen + 1));

        // Clean up: unblock peer
        svc_restarted.unblock_peer_camera(peer);
        assert!(!svc_restarted.has_peer_consent(peer, gen));
    }

    #[tokio::test]
    async fn test_camera_consent_midstream_revocation_stops_frame_dispatch() {
        let svc = make_test_camera_svc("cam_midstream_revocation");
        let peer = "cafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeefcafebeef";

        {
            let mut ks = crate::security::keystore::global_keystore().lock().unwrap();
            ks.register_test_peer_with_generation(peer, 1);
        }

        let rx = svc.register_peer_stream(peer, 1);
        assert!(svc.grant_peer_consent(peer, 1));
        assert!(svc.has_peer_consent(peer, 1));
        assert!(!*rx.borrow());

        let mailbox = svc.frame_hub.subscribe(peer);
        svc.frame_hub.publish_frame(vec![1, 2, 3], false);
        assert_eq!(*mailbox.take().unwrap(), vec![1, 2, 3]);

        // Revoke consent midstream
        svc.revoke_peer_consent(peer);

        // Consent immediately revoked, stream signaled, hub unsubscribed
        assert!(!svc.has_peer_consent(peer, 1));
        assert!(*rx.borrow(), "Revocation must signal stream cancellation watch");
        assert_eq!(svc.frame_hub.active_subscriber_count(), 0);
    }

    #[test]
    fn test_camera_privacy_shutter_nv12_frame_and_toggle() {
        let frame = privacy_shutter_nv12_frame();
        assert_eq!(frame.len(), NV12_FRAME_BYTES);
        let y_bytes = (CAMERA_WIDTH * CAMERA_HEIGHT) as usize;
        // Top-left corner luma is studio black (16), entire UV plane is neutral (128)
        assert_eq!(frame[0], 16);
        assert!(frame[y_bytes..].iter().all(|&b| b == 128));

        let prev = is_camera_privacy_muted();
        assert!(set_camera_privacy_muted(true));
        assert!(is_camera_privacy_muted());
        assert!(!set_camera_privacy_muted(false));
        assert!(!is_camera_privacy_muted());
        let _ = set_camera_privacy_muted(prev);
    }
}
