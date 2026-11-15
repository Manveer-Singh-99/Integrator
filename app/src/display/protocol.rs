use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Serialize, Deserialize)]
pub enum DisplayRpcRequest {
    Ping,
    GetHardwareProfile,
    StartMoonlight {
        host_ip: String,
        #[serde(default)]
        host_port: u16,
        #[serde(default)]
        host_name: String,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        audio_on_host: bool,
    },
    StopMoonlight,
    ToggleMacToPc,
    TogglePcToMac,
    StopAll,
    GetStatus,
    GetGpuTelemetry,
    PasteRemote,
    ShowWindow,
    SyncTrueTone {
        lux: f32,
        cct: u32,
        gamma_comp: f32,
    },
    MountStorage,
    UnmountStorage,
    NegotiateAudioSession {
        sender_nonce_hex: String,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    },
    GetPairingPin,
    PairWithPeer {
        ip: String,
        pin: String,
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
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DisplayRpcResponse {
    pub success: bool,
    pub message: String,
    pub is_active: bool,
    pub active_mode: Option<String>,
    pub gpu_telemetry: Option<crate::telemetry::GpuTelemetry>,
    pub ambient_light: Option<crate::truetone::AmbientLightData>,
    pub storage_status: Option<crate::storage::StorageStatus>,
    #[serde(default)]
    pub hardware_profile: Option<crate::system_info::LocalHardwareProfile>,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub host_device_id: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    #[serde(default)]
    pub audio_session: Option<crate::security::audio_udp::NegotiatedAudioSessionWire>,
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
            .finish()
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
        | DisplayRpcRequest::PairWithPeer { .. } => None,
    }
}
