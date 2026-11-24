//! # Display Control RPC Wire Protocol
//!
//! ## 1. Module Purpose & Scope
//! This module defines the request and response wire protocol data structures for the
//! **Integrator Control & RPC Subsystem**, transmitted over mutually authenticated
//! `TransportSessionV2` sessions (`ServiceId::DisplayRpc`, TCP port [`crate::config::CONTROL_PORT`] = `58281`).
//!
//! The RPC protocol governs cross-device session coordination for both the **Display Subsystem**
//! (Moonlight/Sunshine extended desktop) and the **Shared Camera & Microphone Subsystem** (Mac
//! camera and microphone to Windows 11 Virtual Webcam & Audio), along with auxiliary subsystems
//! (Clipboard sharing, True Tone calibration, Network storage mounting, and UDP Audio streaming).
//!
//! ## 2. Cross-Platform Architectural Roles
//!
//! ### Upstream Callers
//! - [`crate::core::IntegratorCore`]: Constructs outbound [`DisplayRpcRequest`] payloads for peer
//!   RPC invocation and consumes [`DisplayRpcResponse`] snapshots.
//! - [`super::server::DisplayServer`]: Deserializes inbound [`DisplayRpcRequest`] frames on TCP port
//!   [`crate::config::CONTROL_PORT`] (`58281`), enforces [`required_feature_for_rpc`], and serializes
//!   the resulting [`DisplayRpcResponse`].
//!
//! ### Downstream Callees
//! - [`super::controller::DisplayController::handle_rpc`]: Executes validated requests against local
//!   display, camera, microphone, audio, True Tone, clipboard, storage, and passkey/Touch ID services.
//!
//! ### Extended Display Streaming Pipeline
//! - **Start / Stop Moonlight RPC**: The host device (Mac or Windows) configures its local virtual display
//!   (`CGVirtualDisplay` on Mac or `IddSampleDriver` / Apollo on Windows) and Sunshine server (port 47989 or 48989),
//!   then issues a [`DisplayRpcRequest::StartMoonlight`] request to the client device over this protocol.
//! - **Geometry & Bitrate Negotiation**: Transveys target dimensions (`width`, `height`), refresh rate (`fps`),
//!   and network-adapted bitrate ([`DisplayRpcRequest::StartMoonlight::bitrate_kbps`]).
//! - **Hardware Encoders/Decoders**: Sunshine captures desktop imagery via ScreenCaptureKit (macOS) or
//!   DXGI Desktop Duplication (Windows), encoding with Apple VideoToolbox or NVIDIA NVENC / AMD AMF /
//!   Intel QuickSync. Moonlight decodes with low latency via VideoToolbox (Mac) or D3D11 / NVDEC (Windows).
//!
//! ### Shared Camera & Microphone Control
//! - **Camera & Mic RPC Commands**: Control methods [`DisplayRpcRequest::StartCamera`], [`DisplayRpcRequest::ToggleCamera`],
//!   [`DisplayRpcRequest::StopCamera`], [`DisplayRpcRequest::GetCameraStatus`], [`DisplayRpcRequest::ListCameras`],
//!   [`DisplayRpcRequest::SelectCamera`], [`DisplayRpcRequest::ListMics`], [`DisplayRpcRequest::SelectMic`], and
//!   [`DisplayRpcRequest::SetMicSettings`] route state transitions between UI view models and the core
//!   [`crate::camera::CameraService`].
//! - **Zero Third-Party Driver Architecture**: Signals the capture loop on Mac (AVFoundation 720p30 NV12)
//!   and initiates the standalone Media Foundation FrameServer virtual webcam DLL (`integrator_vcam.dll` /
//!   `Integrator Mac Camera`) on Windows 11 without requiring physical camera wrapper attributes
//!   (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).
//!
//! ## 3. Threading & Serialization Wire Framing
//! - **Thread Safety**: All wire types implement `Clone + Send + Sync` and are serialized/deserialized
//!   on Tokio async worker tasks without blocking lock contention.
//! - **Format**: Canonical UTF-8 JSON serialization (`serde_json`), bounded to a maximum payload size
//!   of 64 KiB (`MAX_RPC_BYTES`) on ingress and 1 MiB (`MAX_RPC_RESPONSE_BYTES`) on response to prevent
//!   memory exhaustion attacks.
//! - **Transport Security**: Transported inside encrypted `TransportSessionV2` frames utilizing
//!   ChaCha20-Poly1305 AEAD and mutual Ed25519 identity verification.
//! - **Redaction Invariants**: Sensitive credentials, including the 6-digit SPAKE2 pairing PIN
//!   ([`DisplayRpcRequest::PairWithPeer::pin`]), authentication tokens ([`DisplayRpcResponse::pairing_token`]),
//!   and single-use camera lease bearer tokens ([`DisplayRpcResponse::camera_lease_token_hex`]),
//!   are unconditionally redacted in `fmt::Debug` implementations (`"<REDACTED>"`).
//!
//! ## 4. Feature Gate Mapping
//! The [`required_feature_for_rpc`] function maps each RPC request variant to its governing feature
//! flag (`display`, `input_kvm`, `clipboard`, `truetone`, `storage`, `audio`, `camera`, `touchid`).
//! Requests referencing disabled features are rejected before dispatch.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Wire request payload sent over `TransportSessionV2` to invoke actions on a local or remote node.
#[derive(Clone, Serialize, Deserialize)]
pub enum DisplayRpcRequest {
    /// Connectivity health probe returning `"pong"`.
    Ping,

    /// Queries the target machine's hardware profile (hostname, primary display geometry, GPU models).
    GetHardwareProfile,

    /// Launches the Moonlight client on the target peer to receive a Sunshine video stream.
    StartMoonlight {
        /// Target Sunshine host IPv4 address.
        host_ip: String,
        /// Sunshine web/RTSP port (typically 47989 for primary instance, 48989 for secondary).
        #[serde(default)]
        host_port: u16,
        /// Host display name or hostname for Moonlight pairing slot resolution.
        #[serde(default)]
        host_name: String,
        /// Target horizontal display resolution in pixels (e.g. 1920, 2560, 3840).
        width: u32,
        /// Target vertical display resolution in pixels (e.g. 1080, 1440, 2160).
        height: u32,
        /// Target refresh rate in frames per second (e.g. 60, 120, 144, 240).
        fps: u32,
        /// Maximum stream bitrate in kilobits per second (e.g. 65000 for 65 Mbps).
        bitrate_kbps: u32,
        /// Whether audio should remain on host rather than being streamed to client.
        audio_on_host: bool,
        /// Whether HDR video streaming should be enabled in Moonlight.
        #[serde(default)]
        hdr: bool,
    },

    /// Gracefully terminates the running Moonlight client process on the target machine.
    StopMoonlight,

    /// Toggles Mac-as-Host extended desktop mode (spawns virtual display on Mac, launches Moonlight on PC).
    ToggleMacToPc,

    /// Toggles PC-as-Host extended desktop mode (enables VDD on PC, launches Moonlight on Mac).
    TogglePcToMac,

    /// Stops all running display extensions, virtual displays, and client viewers on both platforms.
    StopAll,

    /// Queries the current display extension operational status (active state and active mode label).
    GetStatus,

    /// Queries real-time GPU telemetry metrics (utilization percentage, VRAM usage, temperature).
    GetGpuTelemetry,

    /// Pastes a remote clipboard item into the local focused window.
    PasteRemote,

    /// Requests that the application's graphical window be brought to the foreground and focused.
    ShowWindow,

    /// Applies ambient light sensor True Tone calibration or raw ALS telemetry on the local display.
    SyncTrueTone {
        /// Ambient illuminance in Lux (units: lx, valid range: 0.0 to 200,000.0).
        lux: f32,
        /// Correlated Color Temperature in Kelvin (`1000..=15000`, or `0` when `raw_als` is `true` for PC-side calculation).
        cct: u32,
        /// Hardware gamma compensation factor (typically 1.0; valid range: 0.2 to 3.0).
        gamma_comp: f32,
        /// When true, `SyncTrueTone` carries raw Mac ALS sensor channels and the receiving PC performs all color math.
        #[serde(default)]
        raw_als: bool,
        /// Optional raw ALS warm/red sensor channel count (`ch0`).
        #[serde(default)]
        als_ch0: Option<f32>,
        /// Optional raw ALS green sensor channel count (`ch1`).
        #[serde(default)]
        als_ch1: Option<f32>,
        /// Optional raw ALS cool/blue sensor channel count (`ch2`).
        #[serde(default)]
        als_ch2: Option<f32>,
        /// Optional calibrated CIE 1931 X tristimulus reading from Apple HID ALS.
        #[serde(default)]
        cie_x: Option<f32>,
        /// Optional calibrated CIE 1931 Y tristimulus reading from Apple HID ALS.
        #[serde(default)]
        cie_y: Option<f32>,
        /// Optional calibrated CIE 1931 Z tristimulus reading from Apple HID ALS.
        #[serde(default)]
        cie_z: Option<f32>,
    },

    /// Mounts the peer's shared storage filesystem over SMB/WebDAV.
    MountStorage,

    /// Unmounts the remote peer's storage filesystem cleanly.
    UnmountStorage,

    /// Negotiates an authenticated, low-latency IUA2 UDP audio streaming session.
    NegotiateAudioSession {
        /// Hex-encoded sender nonce for key derivation and replay protection.
        sender_nonce_hex: String,
        /// Audio sample rate in Hertz (e.g. 48000).
        sample_rate: u32,
        /// Audio channel count (e.g. 2 for stereo).
        channels: u8,
        /// Audio bit depth per sample (e.g. 16 for 16-bit PCM).
        bit_depth: u8,
    },

    /// Starts local audio capture and streaming to the requesting peer over authenticated IUA2 UDP.
    StartAudioCapture {
        /// Audio sample rate in Hertz (e.g. 48000).
        sample_rate: u32,
        /// Audio channel count (e.g. 2 for stereo).
        channels: u8,
        /// Audio bit depth per sample (e.g. 16 for 16-bit PCM).
        bit_depth: u8,
    },

    /// Stops local audio capture and streaming to the peer.
    StopAudioCapture,

    /// Requests the local engine to route audio from the remote peer to local speakers.
    RouteRemoteAudio {
        /// Remote peer IPv4/IPv6 address.
        peer_ip: String,
    },

    /// Requests the local engine to stop all active audio routing.
    StopAudioRouting,

    /// Requests the audio status snapshot from the local engine.
    GetAudioStatus,

    /// Generates or queries the active 6-digit SPAKE2 mutual pairing PIN.
    GetPairingPin,

    /// Initiates mutual SPAKE2 cryptographic pairing with a remote peer at `ip` using `pin`.
    PairWithPeer {
        /// Target peer IPv4 or IPv6 address.
        ip: String,
        /// 6-digit numeric pairing PIN code.
        pin: String,
    },

    /// Queries the aggregated status of the local hardware bridging daemon.
    GetBridgeStatus,

    /// Starts the Shared Camera pipeline (AVFoundation capture on Mac / FrameServer virtual webcam on PC).
    StartCamera,

    /// Queries camera consent status for the requesting peer without granting consent or showing prompts.
    CheckCameraConsent,

    /// Toggles the Shared Camera pipeline between active and standby states.
    ToggleCamera,

    /// Stops the Shared Camera pipeline and releases camera hardware and shared memory.
    StopCamera,

    /// Queries the current operational snapshot of the Shared Camera pipeline.
    GetCameraStatus,

    /// Enumerates video capture devices available on the target Mac.
    ListCameras,

    /// Switches the active camera device on the target Mac.
    SelectCamera {
        /// Target camera device unique ID.
        device_id: String,
    },

    /// Enumerates audio input (microphone) devices available on the target Mac.
    ListMics,

    /// Switches the active microphone audio capture device on the target Mac.
    SelectMic {
        /// Target microphone device unique ID.
        device_id: String,
    },

    /// Updates shared microphone capture enablement, mute state, and linear input gain (`0.0..=2.0`).
    SetMicSettings {
        /// Whether shared microphone capture is enabled.
        enabled: bool,
        /// Whether shared microphone output is muted.
        muted: bool,
        /// Linear microphone input gain multiplier (clamped to `0.0..=2.0`, where `1.0` = 100%).
        gain: f32,
    },

    /// Requests an interactive macOS Touch ID Secure Enclave biometric verification over `TransportSessionV2`,
    /// binding the peer's one-time 32-byte `challenge_nonce_hex` into an Ed25519 signed assertion.
    VerifyTouchId {
        /// 32-byte (64-hex) CSPRNG challenge nonce generated by the requesting peer.
        challenge_nonce_hex: String,
        /// Hostname of the requesting peer displayed in the native macOS Touch ID prompt.
        requester_hostname: String,
    },

    /// Requests WebAuthn passkey credential creation on the remote peer, verified by Touch ID.
    PasskeyMakeCredential(crate::security::passkey::PasskeyMakeCredentialRequest),

    /// Requests WebAuthn passkey assertion signing on the remote peer, verified by Touch ID.
    PasskeyGetAssertion(crate::security::passkey::PasskeyGetAssertionRequest),

    /// Illuminates or dismisses the visual Touch ID passkey/UAC guidance strip on the Mac Touch Bar.
    NotifyTouchIdPrompt {
        /// Prompt headline displayed on the Mac Touch Bar pointing toward the Touch ID sensor.
        label: String,
        /// `true` to illuminate the animated Touch ID pulse, `false` to dismiss it.
        active: bool,
    },

    /// Dynamically reconfigures extended display resolution, refresh rate (Hz), and HDR state.
    SetDisplayMode {
        /// Desired width in pixels (`0` keeps current/native width).
        width: u32,
        /// Desired height in pixels (`0` keeps current/native height).
        height: u32,
        /// Desired refresh rate in Hertz (`60`, `120`, `165`, etc.).
        fps: u32,
        /// Whether HDR mode should be enabled.
        #[serde(default)]
        hdr: bool,
    },

    /// Synchronizes KVM Gaming Boundary Lock state so the cursor stays locked to the target PC/Mac screen.
    SetKvmBoundaryLock {
        /// `true` to lock the cursor boundary and freeze edge-hopping.
        locked: bool,
    },

    /// Queries the currently playing Windows media session (Spotify, YouTube, VLC, etc.) via GSMTC.
    GetMediaState,

    /// Dispatches a media playback transport command (`PlayPause`, `Next`, `Previous`, `Seek`) to Windows.
    SendMediaCommand {
        /// Requested media transport action.
        action: crate::media::MediaControlAction,
    },
}

impl fmt::Debug for DisplayRpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ping => f.write_str("Ping"),
            Self::GetHardwareProfile => f.write_str("GetHardwareProfile"),
            Self::StartMoonlight {
                host_ip,
                host_port,
                host_name,
                width,
                height,
                fps,
                bitrate_kbps,
                audio_on_host,
                hdr,
            } => f
                .debug_struct("StartMoonlight")
                .field("host_ip", host_ip)
                .field("host_port", host_port)
                .field("host_name", host_name)
                .field("width", width)
                .field("height", height)
                .field("fps", fps)
                .field("bitrate_kbps", bitrate_kbps)
                .field("audio_on_host", audio_on_host)
                .field("hdr", hdr)
                .finish(),
            Self::StopMoonlight => f.write_str("StopMoonlight"),
            Self::ToggleMacToPc => f.write_str("ToggleMacToPc"),
            Self::TogglePcToMac => f.write_str("TogglePcToMac"),
            Self::StopAll => f.write_str("StopAll"),
            Self::GetStatus => f.write_str("GetStatus"),
            Self::GetGpuTelemetry => f.write_str("GetGpuTelemetry"),
            Self::PasteRemote => f.write_str("PasteRemote"),
            Self::ShowWindow => f.write_str("ShowWindow"),
            Self::SyncTrueTone {
                lux,
                cct,
                gamma_comp,
                raw_als,
                ..
            } => f
                .debug_struct("SyncTrueTone")
                .field("lux", lux)
                .field("cct", cct)
                .field("gamma_comp", gamma_comp)
                .field("raw_als", raw_als)
                .finish(),
            Self::MountStorage => f.write_str("MountStorage"),
            Self::UnmountStorage => f.write_str("UnmountStorage"),
            Self::NegotiateAudioSession {
                sender_nonce_hex,
                sample_rate,
                channels,
                bit_depth,
            } => f
                .debug_struct("NegotiateAudioSession")
                .field("sender_nonce_hex", sender_nonce_hex)
                .field("sample_rate", sample_rate)
                .field("channels", channels)
                .field("bit_depth", bit_depth)
                .finish(),
            Self::StartAudioCapture {
                sample_rate,
                channels,
                bit_depth,
            } => f
                .debug_struct("StartAudioCapture")
                .field("sample_rate", sample_rate)
                .field("channels", channels)
                .field("bit_depth", bit_depth)
                .finish(),
            Self::StopAudioCapture => f.write_str("StopAudioCapture"),
            Self::RouteRemoteAudio { peer_ip } => f
                .debug_struct("RouteRemoteAudio")
                .field("peer_ip", peer_ip)
                .finish(),
            Self::StopAudioRouting => f.write_str("StopAudioRouting"),
            Self::GetAudioStatus => f.write_str("GetAudioStatus"),
            Self::GetPairingPin => f.write_str("GetPairingPin"),
            Self::PairWithPeer { ip, pin: _ } => f
                .debug_struct("PairWithPeer")
                .field("ip", ip)
                .field("pin", &"<REDACTED>")
                .finish(),
            Self::GetBridgeStatus => f.write_str("GetBridgeStatus"),
            Self::StartCamera => f.write_str("StartCamera"),
            Self::CheckCameraConsent => f.write_str("CheckCameraConsent"),
            Self::ToggleCamera => f.write_str("ToggleCamera"),
            Self::StopCamera => f.write_str("StopCamera"),
            Self::GetCameraStatus => f.write_str("GetCameraStatus"),
            Self::ListCameras => f.write_str("ListCameras"),
            Self::SelectCamera { device_id } => f
                .debug_struct("SelectCamera")
                .field("device_id", device_id)
                .finish(),
            Self::ListMics => f.write_str("ListMics"),
            Self::SelectMic { device_id } => f
                .debug_struct("SelectMic")
                .field("device_id", device_id)
                .finish(),
            Self::SetMicSettings {
                enabled,
                muted,
                gain,
            } => f
                .debug_struct("SetMicSettings")
                .field("enabled", enabled)
                .field("muted", muted)
                .field("gain", gain)
                .finish(),
            Self::VerifyTouchId {
                challenge_nonce_hex,
                requester_hostname,
            } => f
                .debug_struct("VerifyTouchId")
                .field("challenge_nonce_hex", challenge_nonce_hex)
                .field("requester_hostname", requester_hostname)
                .finish(),
            Self::PasskeyMakeCredential(req) => f
                .debug_struct("PasskeyMakeCredential")
                .field("rp_id", &req.rp_id)
                .field("user_name", &req.user_name)
                .finish(),
            Self::PasskeyGetAssertion(req) => f
                .debug_struct("PasskeyGetAssertion")
                .field("rp_id", &req.rp_id)
                .finish(),
            Self::NotifyTouchIdPrompt { label, active } => f
                .debug_struct("NotifyTouchIdPrompt")
                .field("label", label)
                .field("active", active)
                .finish(),
            Self::SetDisplayMode {
                width,
                height,
                fps,
                hdr,
            } => f
                .debug_struct("SetDisplayMode")
                .field("width", width)
                .field("height", height)
                .field("fps", fps)
                .field("hdr", hdr)
                .finish(),
            Self::SetKvmBoundaryLock { locked } => f
                .debug_struct("SetKvmBoundaryLock")
                .field("locked", locked)
                .finish(),
            Self::GetMediaState => f.write_str("GetMediaState"),
            Self::SendMediaCommand { action } => f
                .debug_struct("SendMediaCommand")
                .field("action", action)
                .finish(),
        }
    }
}

/// Wire response payload returned over `TransportSessionV2` answering a [`DisplayRpcRequest`].
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DisplayRpcResponse {
    /// Whether the requested RPC operation succeeded.
    pub success: bool,
    /// Informational or error message explaining the execution result.
    pub message: String,
    /// Whether display streaming or virtual display is currently active.
    pub is_active: bool,
    /// Active display streaming mode description (e.g. `"Mac -> PC (1920x1080 @ 60Hz)"`), if active.
    pub active_mode: Option<String>,
    /// Live GPU telemetry data returned by [`DisplayRpcRequest::GetGpuTelemetry`].
    pub gpu_telemetry: Option<crate::telemetry::GpuTelemetry>,
    /// Ambient light reading returned by [`DisplayRpcRequest::SyncTrueTone`].
    pub ambient_light: Option<crate::truetone::AmbientLightData>,
    /// Storage mount status returned by [`DisplayRpcRequest::MountStorage`].
    pub storage_status: Option<crate::storage::StorageStatus>,
    /// System bridging status JSON object returned by [`DisplayRpcRequest::GetBridgeStatus`].
    #[serde(default)]
    pub bridge_status: Option<serde_json::Value>,
    /// Camera subsystem diagnostic snapshot returned by camera-related RPC requests.
    #[serde(default)]
    pub camera_status: Option<crate::camera::CameraStatus>,
    /// Available camera devices on the remote host returned by [`DisplayRpcRequest::ListCameras`].
    #[serde(default)]
    pub available_cameras: Option<Vec<crate::camera::CameraDeviceWire>>,
    /// Available microphone audio input devices on the remote host returned by [`DisplayRpcRequest::ListMics`].
    #[serde(default)]
    pub available_mics: Option<Vec<crate::camera::MicDeviceWire>>,
    /// Local hardware profile returned by [`DisplayRpcRequest::GetHardwareProfile`].
    #[serde(default)]
    pub hardware_profile: Option<crate::system_info::LocalHardwareProfile>,
    /// Sensitive pairing token or PIN code returned by [`DisplayRpcRequest::GetPairingPin`].
    #[serde(default)]
    pub pairing_token: Option<String>,
    /// Device identifier hex string of the responding host.
    #[serde(default)]
    pub host_device_id: Option<String>,
    /// Hostname of the responding host.
    #[serde(default)]
    pub host_name: Option<String>,
    /// Negotiated UDP audio session metadata returned by [`DisplayRpcRequest::NegotiateAudioSession`].
    #[serde(default)]
    pub audio_session: Option<crate::security::audio_udp::NegotiatedAudioSessionWire>,
    /// Audio routing subsystem status snapshot returned by audio-related RPC requests.
    #[serde(default)]
    pub audio_status: Option<crate::audio::AudioRoutingStatus>,
    /// Signed Touch ID Secure Enclave biometric assertion returned by [`DisplayRpcRequest::VerifyTouchId`].
    #[serde(default)]
    pub touchid_assertion: Option<crate::trust::TouchIdSignedAssertion>,
    /// Camera consent status returned by [`DisplayRpcRequest::CheckCameraConsent`].
    #[serde(default)]
    pub camera_consent_status: Option<crate::camera::authorization::CameraConsentStatusWire>,
    /// Hex-encoded 32-byte authorization lease token returned upon successful camera consent approval.
    #[serde(default)]
    pub camera_lease_token_hex: Option<String>,
    /// Unique lease request identifier.
    #[serde(default)]
    pub camera_lease_id: Option<u64>,
    /// Passkey credential creation response returned by [`DisplayRpcRequest::PasskeyMakeCredential`].
    #[serde(default)]
    pub passkey_credential: Option<crate::security::passkey::PasskeyMakeCredentialResponse>,
    /// Passkey assertion signature response returned by [`DisplayRpcRequest::PasskeyGetAssertion`].
    #[serde(default)]
    pub passkey_assertion: Option<crate::security::passkey::PasskeyGetAssertionResponse>,
    /// Active Windows GSMTC media playback state returned by [`DisplayRpcRequest::GetMediaState`].
    #[serde(default)]
    pub media_state: Option<crate::media::MediaPlaybackState>,
}

impl fmt::Debug for DisplayRpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisplayRpcResponse")
            .field("success", &self.success)
            .field("message", &self.message)
            .field("is_active", &self.is_active)
            .field("active_mode", &self.active_mode)
            .field("gpu_telemetry", &self.gpu_telemetry)
            .field("ambient_light", &self.ambient_light)
            .field("storage_status", &self.storage_status)
            .field("bridge_status", &self.bridge_status)
            .field("camera_status", &self.camera_status)
            .field("available_cameras", &self.available_cameras)
            .field("available_mics", &self.available_mics)
            .field("hardware_profile", &self.hardware_profile)
            .field(
                "pairing_token",
                &self.pairing_token.as_ref().map(|_| "<REDACTED>"),
            )
            .field(
                "camera_lease_token_hex",
                &self.camera_lease_token_hex.as_ref().map(|_| "<REDACTED>"),
            )
            .field("camera_consent_status", &self.camera_consent_status)
            .field("camera_lease_id", &self.camera_lease_id)
            .field("host_device_id", &self.host_device_id)
            .field("host_name", &self.host_name)
            .field("audio_session", &self.audio_session)
            .field("audio_status", &self.audio_status)
            .field("touchid_assertion", &self.touchid_assertion)
            .field("passkey_credential", &self.passkey_credential)
            .field("passkey_assertion", &self.passkey_assertion)
            .field("media_state", &self.media_state)
            .finish()
    }
}

/// Maps an incoming [`DisplayRpcRequest`] to the corresponding feature flag name required to execute it.
///
/// Returns `Some("feature_name")` if the RPC is protected by a feature toggle, or `None` if it is
/// universally available (e.g. `Ping`, diagnostics, pairing).
pub(crate) fn required_feature_for_rpc(req: &DisplayRpcRequest) -> Option<&'static str> {
    match req {
        DisplayRpcRequest::StartMoonlight { .. }
        | DisplayRpcRequest::StopMoonlight
        | DisplayRpcRequest::ToggleMacToPc
        | DisplayRpcRequest::TogglePcToMac
        | DisplayRpcRequest::SetDisplayMode { .. }
        | DisplayRpcRequest::StopAll => Some("display"),
        DisplayRpcRequest::SetKvmBoundaryLock { .. } => Some("input_kvm"),
        DisplayRpcRequest::PasteRemote => Some("clipboard"),
        DisplayRpcRequest::SyncTrueTone { .. } => Some("truetone"),
        DisplayRpcRequest::MountStorage | DisplayRpcRequest::UnmountStorage => Some("storage"),
        DisplayRpcRequest::NegotiateAudioSession { .. }
        | DisplayRpcRequest::StartAudioCapture { .. }
        | DisplayRpcRequest::RouteRemoteAudio { .. }
        | DisplayRpcRequest::GetAudioStatus => Some("audio"),
        DisplayRpcRequest::StopAudioCapture | DisplayRpcRequest::StopAudioRouting => None,
        DisplayRpcRequest::StartCamera
        | DisplayRpcRequest::CheckCameraConsent
        | DisplayRpcRequest::ToggleCamera
        | DisplayRpcRequest::StopCamera
        | DisplayRpcRequest::GetCameraStatus
        | DisplayRpcRequest::ListCameras
        | DisplayRpcRequest::SelectCamera { .. }
        | DisplayRpcRequest::ListMics
        | DisplayRpcRequest::SelectMic { .. }
        | DisplayRpcRequest::SetMicSettings { .. } => Some("camera"),
        DisplayRpcRequest::VerifyTouchId { .. }
        | DisplayRpcRequest::NotifyTouchIdPrompt { .. }
        | DisplayRpcRequest::PasskeyMakeCredential(_)
        | DisplayRpcRequest::PasskeyGetAssertion(_) => Some("touchid"),
        DisplayRpcRequest::Ping
        | DisplayRpcRequest::GetHardwareProfile
        | DisplayRpcRequest::GetStatus
        | DisplayRpcRequest::GetGpuTelemetry
        | DisplayRpcRequest::GetMediaState
        | DisplayRpcRequest::SendMediaCommand { .. }
        | DisplayRpcRequest::ShowWindow
        | DisplayRpcRequest::GetPairingPin
        | DisplayRpcRequest::PairWithPeer { .. }
        | DisplayRpcRequest::GetBridgeStatus => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_pin_and_pairing_token() {
        let req = DisplayRpcRequest::PairWithPeer {
            ip: "10.0.0.2".to_string(),
            pin: "849201".to_string(),
        };
        let req_dbg = format!("{:?}", req);
        assert!(req_dbg.contains("<REDACTED>"));
        assert!(!req_dbg.contains("849201"));

        let resp = DisplayRpcResponse {
            success: true,
            pairing_token: Some("654321".to_string()),
            camera_lease_token_hex: Some("deadbeef".repeat(8)),
            ..Default::default()
        };
        let resp_dbg = format!("{:?}", resp);
        assert!(resp_dbg.contains("<REDACTED>"));
        assert!(!resp_dbg.contains("654321"));
        assert!(!resp_dbg.contains("deadbeef"));

        // Legacy DisplayRpcResponse JSON without `available_mics` must deserialize cleanly.
        let legacy_resp: DisplayRpcResponse = serde_json::from_str(
            r#"{"success":true,"message":"ok","is_active":false,"active_mode":null,"gpu_telemetry":null,"ambient_light":null,"storage_status":null}"#,
        )
        .expect("legacy DisplayRpcResponse JSON must deserialize");
        assert!(legacy_resp.available_mics.is_none());
    }

    #[test]
    fn required_feature_mapping_matches_subsystem_keys() {
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::ToggleMacToPc),
            Some("display")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::PasteRemote),
            Some("clipboard")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::MountStorage),
            Some("storage")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SyncTrueTone {
                lux: 100.0,
                cct: 5000,
                gamma_comp: 1.0,
                raw_als: false,
                als_ch0: None,
                als_ch1: None,
                als_ch2: None,
                cie_x: None,
                cie_y: None,
                cie_z: None,
            }),
            Some("truetone")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::NegotiateAudioSession {
                sender_nonce_hex: String::new(),
                sample_rate: 48000,
                channels: 2,
                bit_depth: 16,
            }),
            Some("audio")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::StartAudioCapture {
                sample_rate: 48000,
                channels: 2,
                bit_depth: 16,
            }),
            Some("audio")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::StopAudioCapture),
            None
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::RouteRemoteAudio {
                peer_ip: "127.0.0.1".into(),
            }),
            Some("audio")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::StopAudioRouting),
            None
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::GetAudioStatus),
            Some("audio")
        );
        assert_eq!(required_feature_for_rpc(&DisplayRpcRequest::Ping), None);
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::GetGpuTelemetry),
            None
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::NotifyTouchIdPrompt {
                label: "Approve Windows Hello Login".into(),
                active: true,
            }),
            Some("touchid")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SetDisplayMode {
                width: 2560,
                height: 1440,
                fps: 165,
                hdr: true,
            }),
            Some("display")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SetKvmBoundaryLock { locked: true }),
            Some("input_kvm")
        );
        assert_eq!(required_feature_for_rpc(&DisplayRpcRequest::GetMediaState), None);
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SendMediaCommand {
                action: crate::media::MediaControlAction::PlayPause,
            }),
            None
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::ListCameras),
            Some("camera")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SelectCamera {
                device_id: "cam-0".into(),
            }),
            Some("camera")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::ListMics),
            Some("camera")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SelectMic {
                device_id: "mic-0".into(),
            }),
            Some("camera")
        );
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::SetMicSettings {
                enabled: true,
                muted: false,
                gain: 1.25,
            }),
            Some("camera")
        );
        let mic_req_dbg = format!(
            "{:?}",
            DisplayRpcRequest::SetMicSettings {
                enabled: true,
                muted: false,
                gain: 1.5,
            }
        );
        assert!(mic_req_dbg.contains("SetMicSettings"));
    }
}
