//! # Camera Subsystem: Mac -> Windows 11 Shared Virtual Camera
//!
//! ## 1. Module Purpose & Scope
//! This module owns the end-to-end orchestration of the **Mac -> Windows 11 Shared Camera** pipeline
//! (`camera` feature flag). It captures the FaceTime HD camera stream on macOS, transmits it over
//! an encrypted, mutually authenticated transport session, and injects it directly into the
//! Windows 11 Media Foundation FrameServer pipeline as a native standalone virtual webcam.
//!
//! ### Core Subsystem Responsibilities
//! - **Capture Ingestion (macOS)**: Interfaces via C-ABI FFI with `camera_macos.swift`, capturing
//!   uncompressed 720p30 `NV12` bi-planar frames (`kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange`)
//!   directly from the built-in FaceTime HD camera via AVFoundation.
//! - **Wire Serialization**: Packages raw frame buffers into length-delimited, magic-tagged `ICAM`
//!   datagrams with microsecond-precision presentation timestamps and geometry validation.
//! - **Secure Streaming**: Transmits frames across `TransportSessionV2` (`ServiceId::CameraStream`,
//!   TCP port [`CAMERA_PORT`] = `58287`), utilizing ChaCha20-Poly1305 AEAD authenticated encryption
//!   and Ed25519 identity keys established via mutual SPAKE2 pairing.
//! - **Virtual Camera Feed (Windows 11)**: On Windows, accepts authenticated camera streams and
//!   forwards raw NV12 frames via C-ABI FFI (`camera_windows.cpp`) into an ACL-hardened double-buffered
//!   shared memory region (`Global\IntegratorVCamShm_v1`). This memory feeds `integrator_vcam.dll`, a
//!   standalone Media Foundation FrameServer COM component (`CLSID_IntegratorVCamActivate`) registered
//!   under the friendly name **"Integrator MacBook Camera"**.
//!
//! ## 2. Architectural Linkages & Cross-Platform Flow
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                           macOS (Sender)                               │
//! │                                                                        │
//! │  AVCaptureSession (FaceTime HD Camera, 720p30 NV12)                    │
//! │         │                                                              │
//! │         ▼                                                              │
//! │  MacCameraCaptureController (`camera_macos.swift`)                     │
//! │         │                                                              │
//! │         ▼ (C-ABI: integrator_on_mac_camera_frame)                      │
//! │  Rust Camera FFI Handler (`camera/mod.rs`)                             │
//! │         │                                                              │
//! │         ▼ (LatestFrameSlot::publish / notify)                          │
//! │  run_mac_sender_loop (`camera/mod.rs`)                                 │
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
//! │  Friendly Name: "Integrator MacBook Camera"                            │
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
//!   and the async sender loop on macOS (`run_mac_sender_loop`).
//! - **Single-Slot Buffer Swapping (`LatestFrameSlot`)**: Bridges high-frequency AVFoundation camera
//!   delegate callbacks to the Tokio async sender. Uses a `std::sync::Mutex` protecting an
//!   `Option<Vec<u8>>` paired with a `tokio::sync::Notify`. New frames replace older unread frames,
//!   preventing buffer bloat and ensuring sub-millisecond transmission latency.
//! - **Blocking OS Dispatches**: In-process camera start/stop calls (`integrator_mac_camera_start`,
//!   `integrator_win_vcam_start`) are dispatched to `tokio::task::spawn_blocking` to avoid
//!   blocking the async worker threads during COM or AVFoundation session initialization.
//!
//! ## 4. Security & Safety Invariants
//! - **Mutual Ed25519 Authentication**: Unauthenticated TCP connections are dropped immediately.
//!   Every stream must complete an encrypted `TransportSessionV2` handshake tied to paired device keys.
//! - **Pre-Auth Connection Throttling**: Windows incoming connections are bounded by a semaphore
//!   ([`MAX_PRE_AUTH_CAMERA_CONNS`] = 8) to mitigate connection-flooding denial of service.
//! - **Memory Safety & Buffer Bounds**: All frame packets are bound to exactly [`NV12_FRAME_BYTES`]
//!   (1,382,400 bytes for 1280x720 NV12). Packets exceeding this size or bearing invalid magic
//!   headers (`ICAM`) are rejected before slice memory is accessed.
//! - **FFI Pointer Invariants**: Raw pointer inputs from native platform libraries are checked
//!   for nullity, valid buffer length, and expected dimensions prior to constructing Rust slices.

#[cfg(target_os = "windows")]
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use tokio::net::TcpListener;
use tokio::sync::Notify;
#[cfg(target_os = "windows")]
use tokio::sync::Semaphore;
#[cfg(target_os = "windows")]
use tracing::warn;
use tracing::{error, info};

use crate::config::CAMERA_PORT;
use crate::discovery::DiscoveryManager;
use crate::features::FeatureManager;
use crate::security::transport::ServiceId;
use crate::trust;

/// Captured frame width in pixels (720p standard high definition).
pub const CAMERA_WIDTH: u32 = 1280;

/// Captured frame height in pixels (720p standard high definition).
pub const CAMERA_HEIGHT: u32 = 720;

/// Target camera capture and streaming frame rate in frames per second (fps).
pub const CAMERA_FPS: u32 = 30;

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

/// Maximum number of concurrent unauthenticated TCP connections allowed on the camera port.
#[cfg(target_os = "windows")]
const MAX_PRE_AUTH_CAMERA_CONNS: usize = 8;

/// Diagnostic telemetry and status report for the Camera subsystem.
///
/// Returned over local RPC to the UI and CLI to display the live state of the camera pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraStatus {
    /// Whether the local platform supports camera operations (true on macOS and Windows 11).
    pub supported: bool,
    /// Whether the camera capture or virtual camera publication loop is currently active.
    pub active: bool,
    /// Operating role of this machine: `"MacBook Camera Sender"` or `"Windows 11 Virtual Webcam"`.
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
}

/// Parsed, zero-copy camera frame received over the network transport.
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
    if (flags & FLAG_STANDBY_KEEPALIVE) == 0 && payload.len() != NV12_FRAME_BYTES {
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
    if (flags & FLAG_STANDBY_KEEPALIVE) == 0 {
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

/// Single-slot concurrent buffer bridging synchronous video callbacks to async network dispatch.
///
/// Ensures zero-latency frame delivery by replacing stale unread frames with newly arrived frames.
struct LatestFrameSlot {
    /// Mutex-guarded storage holding the latest serialized camera frame datagram.
    latest: Mutex<Option<Vec<u8>>>,
    /// Async notification trigger woken when a new frame is published.
    notify: Notify,
}

impl LatestFrameSlot {
    /// Creates an empty frame slot with an initialized async notification handle.
    fn new() -> Self {
        Self {
            latest: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    /// Stores the newly encoded frame datagram, discarding any prior unread frame, and signals waiters.
    fn publish(&self, encoded: Vec<u8>) {
        if let Ok(mut guard) = self.latest.lock() {
            *guard = Some(encoded);
        }
        self.notify.notify_one();
    }

    /// Takes the currently pending frame datagram out of the slot, leaving it empty.
    fn take(&self) -> Option<Vec<u8>> {
        self.latest.lock().ok()?.take()
    }

    /// Clears any pending frame data from the slot.
    fn clear(&self) {
        if let Ok(mut guard) = self.latest.lock() {
            *guard = None;
        }
    }
}

/// Global lazy-initialized singleton instance of [`LatestFrameSlot`].
static GLOBAL_FRAME_SLOT: OnceLock<Arc<LatestFrameSlot>> = OnceLock::new();

/// Returns the static reference to the shared [`LatestFrameSlot`].
fn global_frame_slot() -> &'static Arc<LatestFrameSlot> {
    GLOBAL_FRAME_SLOT.get_or_init(|| Arc::new(LatestFrameSlot::new()))
}

#[cfg(target_os = "macos")]
extern "C" {
    fn integrator_mac_camera_permission_state() -> i32;
    fn integrator_mac_camera_has_usage_desc() -> i32;
    fn integrator_mac_camera_start() -> i32;
    fn integrator_mac_camera_stop();
    fn integrator_mac_camera_is_running() -> i32;
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
    // SAFETY: Caller (`camera_macos.swift`) guarantees `data` stays valid for `len` bytes during callback.
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    if let Ok(encoded) = encode_camera_frame(
        width as u16,
        height as u16,
        PIXEL_FMT_NV12,
        0,
        timestamp_us,
        slice,
    ) {
        global_frame_slot().publish(encoded);
    }
}

#[cfg(target_os = "windows")]
extern "C" {
    fn integrator_win_vcam_start(err_buf: *mut std::os::raw::c_char, err_cap: i32) -> i32;
    fn integrator_win_vcam_push_nv12(data: *const u8, len: u32, timestamp_us: u64);
    fn integrator_win_vcam_stop();
    fn integrator_win_vcam_is_active() -> i32;
}

/// Central controller service for the Camera subsystem.
///
/// Manages the activation lifecycle, network transport session, and status reporting on both
/// macOS (capture sender) and Windows 11 (virtual camera receiver).
pub struct CameraService {
    /// Peer discovery manager for resolving counterpart device IP addresses.
    discovery: DiscoveryManager,
    /// Dynamic feature flags manager governing subsystem activation.
    features: Arc<FeatureManager>,
    /// Atomic flag indicating whether camera capture or virtual camera service is active.
    active: Arc<AtomicBool>,
    /// Running counter of frames successfully transmitted or received.
    frames_transferred: Arc<AtomicU64>,
    /// Human-readable operational status label.
    state_label: Arc<Mutex<String>>,
    /// Most recent error message, if any.
    last_error: Arc<Mutex<Option<String>>>,
}

impl CameraService {
    /// Instantiates a new [`CameraService`] with associated discovery and feature flag managers.
    pub fn new(discovery: DiscoveryManager, features: Arc<FeatureManager>) -> Arc<Self> {
        Arc::new(Self {
            discovery,
            features,
            active: Arc::new(AtomicBool::new(false)),
            frames_transferred: Arc::new(AtomicU64::new(0)),
            state_label: Arc::new(Mutex::new("Standby".to_string())),
            last_error: Arc::new(Mutex::new(None)),
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
    /// ensures the virtual camera driver is running, and streams raw NV12 frames into shared memory.
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

        info!("📷 Authenticated Mac camera stream connected from {}", peer_ip);
        if !self.active.load(Ordering::Relaxed) {
            if let Err(e) = self.start().await {
                warn!("Failed to start virtual camera for incoming stream: {}", e);
                return;
            }
        }
        self.set_state("Receiving 720p30", None);

        loop {
            if !self.features.is_enabled("camera") || !self.active.load(Ordering::Relaxed) {
                let _ = session.close_notify().await;
                break;
            }
            match tokio::time::timeout(Duration::from_secs(5), session.recv_message()).await {
                Ok(Ok(raw)) => match decode_camera_frame(&raw) {
                    Ok(frame) => {
                        if (frame.flags & FLAG_STANDBY_KEEPALIVE) == 0 && frame.payload.len() == NV12_FRAME_BYTES {
                            // Forward uncompressed NV12 buffer directly into Windows virtual camera shared memory.
                            unsafe {
                                integrator_win_vcam_push_nv12(
                                    frame.payload.as_ptr(),
                                    frame.payload.len() as u32,
                                    frame.timestamp_us,
                                );
                            }
                            self.frames_transferred.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        warn!("Malformed camera frame from {}: {}", peer_ip, e);
                        break;
                    }
                },
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }

        if self.active.load(Ordering::Relaxed) {
            self.set_state("Virtual Camera Active", None);
        } else {
            self.set_state("Standby", None);
        }
    }

    /// Activates the camera pipeline on the local machine.
    ///
    /// - **On Windows**: Installs and registers the virtual camera DLL (`integrator_vcam.dll`),
    ///   creates the shared memory mapping, and invokes `MFCreateVirtualCamera`.
    /// - **On macOS**: Validates TCC camera permissions and bundle descriptors, starts AVFoundation
    ///   720p30 capture via `camera_macos.swift`, and spawns the network sender loop.
    pub async fn start(self: &Arc<Self>) -> Result<String, String> {
        if !self.features.is_enabled("camera") {
            self.features.set_flag_checked("camera", true)?;
        }

        #[cfg(target_os = "windows")]
        {
            let res = tokio::task::spawn_blocking(|| {
                let mut err_buf = [0i8; 256];
                let rc = unsafe { integrator_win_vcam_start(err_buf.as_mut_ptr(), err_buf.len() as i32) };
                if rc == 0 {
                    Ok(())
                } else {
                    let msg = unsafe { CStr::from_ptr(err_buf.as_ptr()) }
                        .to_string_lossy()
                        .into_owned();
                    Err(msg)
                }
            })
            .await
            .map_err(|e| e.to_string())?;

            match res {
                Ok(()) => {
                    self.active.store(true, Ordering::Relaxed);
                    self.set_state("Virtual Camera Active", None);
                    info!("📷 Virtual camera 'Integrator MacBook Camera' active");
                    return Ok("Windows Virtual Camera 'Integrator MacBook Camera' started".into());
                }
                Err(e) => {
                    self.active.store(false, Ordering::Relaxed);
                    self.set_state("Error", Some(e.clone()));
                    return Err(e);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if self.active.swap(true, Ordering::SeqCst) {
                return Ok("Mac camera stream is already running".into());
            }
            self.frames_transferred.store(0, Ordering::Relaxed);
            global_frame_slot().clear();

            let rc = tokio::task::spawn_blocking(|| unsafe { integrator_mac_camera_start() })
                .await
                .map_err(|e| e.to_string())?;
            if rc != 0 {
                self.active.store(false, Ordering::SeqCst);
                let msg = match rc {
                    -2 => "Launch Integrator.app bundle (NSCameraUsageDescription required for camera capture)".to_string(),
                    -1 => "macOS Camera permission denied — allow in System Settings > Privacy & Security > Camera".to_string(),
                    -3 => "No MacBook camera hardware detected".to_string(),
                    _ => format!("Failed to initialize AVFoundation camera capture (code {})", rc),
                };
                self.set_state("Permission Needed", Some(msg.clone()));
                return Err(msg);
            }

            self.set_state("Streaming 720p30", None);
            let svc = Arc::clone(self);
            tokio::spawn(async move {
                svc.run_mac_sender_loop().await;
            });
            info!("📷 Mac camera capture started (720p30 NV12)");
            return Ok("Streaming MacBook Camera (720p30) to Windows Virtual Camera".into());
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        Err("Shared Camera is supported on macOS and Windows 11".into())
    }

    /// Background async loop on macOS polling frames from [`LatestFrameSlot`] and streaming to Windows.
    #[cfg(target_os = "macos")]
    async fn run_mac_sender_loop(&self) {
        let slot = global_frame_slot();
        while self.active.load(Ordering::Relaxed) && self.features.is_enabled("camera") {
            let Some(peer) = self.discovery.get_best_peer().await else {
                self.set_state("Waiting for Peer", None);
                tokio::time::sleep(Duration::from_millis(600)).await;
                continue;
            };
            let peer_ip = peer.addr.ip().to_string();

            let mut session = match trust::connect_transport_to_ip(
                &peer_ip,
                CAMERA_PORT,
                ServiceId::CameraStream,
                Duration::from_secs(3),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    self.set_state("Waiting for Windows Camera", Some(e));
                    tokio::time::sleep(Duration::from_millis(900)).await;
                    continue;
                }
            };

            self.set_state("Streaming 720p30", None);
            while self.active.load(Ordering::Relaxed) && self.features.is_enabled("camera") {
                if let Some(frame_bytes) = slot.take() {
                    if let Err(e) = tokio::time::timeout(
                        Duration::from_secs(2),
                        session.send_message(&frame_bytes),
                    )
                    .await
                    .unwrap_or_else(|_| Err(crate::security::transport::TransportError::IoFailure("send timeout".into())))
                    {
                        self.set_state("Reconnecting...", Some(e.to_string()));
                        break;
                    }
                    self.frames_transferred.fetch_add(1, Ordering::Relaxed);
                } else {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(250),
                        slot.notify.notified(),
                    )
                    .await;
                }
            }
            let _ = session.close_notify().await;
        }
    }

    /// Stops camera streaming or virtual camera publication cleanly.
    pub async fn stop(self: &Arc<Self>) {
        let was_active = self.active.swap(false, Ordering::SeqCst);
        global_frame_slot().clear();
        global_frame_slot().notify.notify_waiters();

        #[cfg(target_os = "macos")]
        if was_active || unsafe { integrator_mac_camera_is_running() } != 0 {
            let _ = tokio::task::spawn_blocking(|| unsafe { integrator_mac_camera_stop() }).await;
        }

        #[cfg(target_os = "windows")]
        if was_active || unsafe { integrator_win_vcam_is_active() } != 0 {
            let _ = tokio::task::spawn_blocking(|| unsafe { integrator_win_vcam_stop() }).await;
        }

        self.set_state("Standby", None);
        if was_active {
            info!("📷 Shared camera stopped cleanly");
        }
    }

    /// Synchronous shutdown routine invoked during application termination or emergency teardown.
    pub fn shutdown_sync(&self) {
        self.active.store(false, Ordering::SeqCst);
        global_frame_slot().clear();
        global_frame_slot().notify.notify_waiters();
        #[cfg(target_os = "macos")]
        unsafe {
            integrator_mac_camera_stop();
        }
        #[cfg(target_os = "windows")]
        unsafe {
            integrator_win_vcam_stop();
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

    /// Queries the current operational snapshot of the Camera subsystem.
    pub fn status(&self) -> CameraStatus {
        let active = self.active.load(Ordering::Relaxed);
        let enabled = self.features.is_enabled("camera");
        #[cfg(target_os = "macos")]
        let permission_granted = unsafe { integrator_mac_camera_permission_state() == 2 && integrator_mac_camera_has_usage_desc() == 1 };
        #[cfg(target_os = "windows")]
        let permission_granted = true;
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let permission_granted = false;

        let role = if cfg!(target_os = "macos") {
            "MacBook Camera Sender"
        } else if cfg!(target_os = "windows") {
            "Windows 11 Virtual Webcam"
        } else {
            "Unsupported"
        };

        let state = if !enabled {
            "Disabled".to_string()
        } else {
            self.state_label
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| if active { "Active".into() } else { "Standby".into() })
        };

        CameraStatus {
            supported: cfg!(any(target_os = "macos", target_os = "windows")),
            active,
            role: role.to_string(),
            state,
            permission_granted,
            width: CAMERA_WIDTH,
            height: CAMERA_HEIGHT,
            fps: CAMERA_FPS,
            frames_transferred: self.frames_transferred.load(Ordering::Relaxed),
            last_error: self.last_error.lock().ok().and_then(|e| e.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_valid_nv12_frame_roundtrip() {
        let payload = vec![0x7Au8; NV12_FRAME_BYTES];
        let pkt = encode_camera_frame(1280, 720, PIXEL_FMT_NV12, 0, 1_234_567, &payload)
            .expect("valid frame");
        assert_eq!(pkt.len(), CAMERA_FRAME_HEADER_LEN + NV12_FRAME_BYTES);
        let decoded = decode_camera_frame(&pkt).expect("decode succeeds");
        assert_eq!(decoded.width, 1280);
        assert_eq!(decoded.height, 720);
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
        assert!(encode_camera_frame(1280, 720, PIXEL_FMT_NV12, 0, 0, &oversized).is_err());
    }

    #[test]
    fn keepalive_frame_encodes_and_decodes_with_empty_payload() {
        let pkt = encode_camera_frame(1280, 720, PIXEL_FMT_NV12, FLAG_STANDBY_KEEPALIVE, 42, &[])
            .expect("keepalive frame");
        let dec = decode_camera_frame(&pkt).expect("decode keepalive");
        assert_eq!(dec.flags, FLAG_STANDBY_KEEPALIVE);
        assert!(dec.payload.is_empty());
    }
}
