//! # Display Control RPC Wire Protocol
//!
//! ## 1. Module Purpose & Scope
//! This module defines the request and response wire protocol data structures for the
//! **Integrator Control & RPC Subsystem**, transmitted over mutually authenticated
//! `TransportSessionV2` sessions (`ServiceId::DisplayRpc`, TCP port [`crate::config::CONTROL_PORT`] = `58281`).
//!
//! The RPC protocol governs cross-device session coordination for both the **Display Subsystem**
//! (Moonlight/Sunshine extended desktop) and the **Shared Camera Subsystem** (MacBook camera to Windows 11
//! Virtual Webcam), along with auxiliary subsystems (Clipboard sharing, True Tone calibration,
//! Network storage mounting, and UDP Audio streaming).
//!
//! ## 2. Cross-Platform Architectural Roles
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
//! ### Shared Camera Control
//! - **Camera RPC Commands**: Control methods [`DisplayRpcRequest::StartCamera`], [`DisplayRpcRequest::ToggleCamera`],
//!   [`DisplayRpcRequest::StopCamera`], and [`DisplayRpcRequest::GetCameraStatus`] route state transitions
//!   between UI view models and the core [`crate::camera::CameraService`].
//! - **Zero Third-Party Driver Architecture**: Signals the capture loop on Mac (AVFoundation 720p30 NV12)
//!   and initiates the standalone Media Foundation FrameServer virtual webcam DLL (`integrator_vcam.dll` /
//!   `Integrator MacBook Camera`) on Windows 11 without requiring physical camera wrapper attributes
//!   (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).
//!
//! ## 3. Serialization & Wire Framing
//! - **Format**: Canonical UTF-8 JSON serialization (`serde_json`), bounded to a maximum payload size
//!   of 64 KiB (`MAX_RPC_BYTES`) to prevent memory exhaustion attacks.
//! - **Transport Security**: Transported inside encrypted `TransportSessionV2` frames utilizing
//!   ChaCha20-Poly1305 AEAD and mutual Ed25519 identity verification.
//! - **Redaction Invariants**: Sensitive credentials, including the 6-digit SPAKE2 pairing PIN
//!   ([`DisplayRpcRequest::PairWithPeer::pin`]) and authentication tokens ([`DisplayRpcResponse::pairing_token`]),
//!   are unconditionally redacted in `fmt::Debug` implementations (`"<REDACTED>"`).
//!
//! ## 4. Feature Gate Mapping
//! The [`required_feature_for_rpc`] function maps each RPC request variant to its governing feature
//! flag (`display`, `clipboard`, `truetone`, `storage`, `audio`). Requests referencing disabled
//! features are rejected before dispatch.

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

    /// Applies ambient light sensor True Tone calibration to the local display hardware LUT.
    SyncTrueTone {
        /// Ambient illuminance in Lux (units: lx, valid range: 0.0 to 200,000.0).
        lux: f32,
        /// Correlated Color Temperature in Kelvin (units: K, valid range: 1000 to 15,000).
        cct: u32,
        /// Hardware gamma compensation factor (typically 1.0; valid range: 0.2 to 3.0).
        gamma_comp: f32,
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

    /// Toggles the Shared Camera pipeline between active and standby states.
    ToggleCamera,

    /// Stops the Shared Camera pipeline and releases camera hardware and shared memory.
    StopCamera,

    /// Queries the current operational snapshot of the Shared Camera pipeline.
    GetCameraStatus,

    /// Requests an interactive macOS Touch ID Secure Enclave biometric verification over `TransportSessionV2`,
    /// binding the peer's one-time 32-byte `challenge_nonce_hex` into an Ed25519 signed assertion.
    VerifyTouchId {
        /// 32-byte (64-hex) CSPRNG challenge nonce generated by the requesting peer.
        challenge_nonce_hex: String,
        /// Hostname of the requesting peer displayed in the native macOS Touch ID prompt.
        requester_hostname: String,
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
            } => f
                .debug_struct("SyncTrueTone")
                .field("lux", lux)
                .field("cct", cct)
                .field("gamma_comp", gamma_comp)
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
            Self::GetPairingPin => f.write_str("GetPairingPin"),
            Self::PairWithPeer { ip, pin: _ } => f
                .debug_struct("PairWithPeer")
                .field("ip", ip)
                .field("pin", &"<REDACTED>")
                .finish(),
            Self::GetBridgeStatus => f.write_str("GetBridgeStatus"),
            Self::StartCamera => f.write_str("StartCamera"),
            Self::ToggleCamera => f.write_str("ToggleCamera"),
            Self::StopCamera => f.write_str("StopCamera"),
            Self::GetCameraStatus => f.write_str("GetCameraStatus"),
            Self::VerifyTouchId {
                challenge_nonce_hex,
                requester_hostname,
            } => f
                .debug_struct("VerifyTouchId")
                .field("challenge_nonce_hex", challenge_nonce_hex)
                .field("requester_hostname", requester_hostname)
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
    /// Signed Touch ID Secure Enclave biometric assertion returned by [`DisplayRpcRequest::VerifyTouchId`].
    #[serde(default)]
    pub touchid_assertion: Option<crate::trust::TouchIdSignedAssertion>,
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
            .field("hardware_profile", &self.hardware_profile)
            .field(
                "pairing_token",
                &self.pairing_token.as_ref().map(|_| "<REDACTED>"),
            )
            .field("host_device_id", &self.host_device_id)
            .field("host_name", &self.host_name)
            .field("audio_session", &self.audio_session)
            .field("touchid_assertion", &self.touchid_assertion)
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
        | DisplayRpcRequest::StopAll => Some("display"),
        DisplayRpcRequest::PasteRemote => Some("clipboard"),
        DisplayRpcRequest::SyncTrueTone { .. } => Some("truetone"),
        DisplayRpcRequest::MountStorage | DisplayRpcRequest::UnmountStorage => Some("storage"),
        DisplayRpcRequest::NegotiateAudioSession { .. } => Some("audio"),
        DisplayRpcRequest::Ping
        | DisplayRpcRequest::GetHardwareProfile
        | DisplayRpcRequest::GetStatus
        | DisplayRpcRequest::GetGpuTelemetry
        | DisplayRpcRequest::ShowWindow
        | DisplayRpcRequest::GetPairingPin
        | DisplayRpcRequest::PairWithPeer { .. }
        | DisplayRpcRequest::GetBridgeStatus
        | DisplayRpcRequest::StartCamera
        | DisplayRpcRequest::ToggleCamera
        | DisplayRpcRequest::StopCamera
        | DisplayRpcRequest::GetCameraStatus
        | DisplayRpcRequest::VerifyTouchId { .. } => None,
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
            ..Default::default()
        };
        let resp_dbg = format!("{:?}", resp);
        assert!(resp_dbg.contains("<REDACTED>"));
        assert!(!resp_dbg.contains("654321"));
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
        assert_eq!(required_feature_for_rpc(&DisplayRpcRequest::Ping), None);
        assert_eq!(
            required_feature_for_rpc(&DisplayRpcRequest::GetGpuTelemetry),
            None
        );
    }
}
