use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
