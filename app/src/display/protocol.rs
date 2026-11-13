//! Display control protocol for cross-platform second-screen extensions.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisplayRpcRequest {
    /// Remote command: Launch Moonlight client to stream from host
    StartMoonlight {
        host_ip: String,
        app_name: String,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        audio_on_host: bool,
        fullscreen: bool,
    },
    /// Remote command: Terminate Moonlight client
    StopMoonlight,
    /// Local/Remote command: Toggle Mac-to-PC extended screen (Mac as host, PC as 165Hz second screen)
    ToggleMacToPc,
    /// Local/Remote command: Toggle PC-to-Mac extended screen (PC as host, Mac as second screen)
    TogglePcToMac,
    /// Stop all active second screen extensions
    StopAll,
    /// Query current display extension status
    GetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayRpcResponse {
    pub success: bool,
    pub message: String,
    pub is_active: bool,
    pub active_mode: Option<String>,
}
