//! Default network and port configurations for the mac-windows-usbc-bridge companion app.

pub const DEFAULT_MAC_IP: &str = "10.99.99.2";
pub const DEFAULT_WIN_IP: &str = "10.99.99.1";
pub const CONTROL_PORT: u16 = 58280;
pub const AUDIO_PORT: u16 = 58281;
pub const TELEMETRY_PORT: u16 = 58282;
pub const CLIPBOARD_PORT: u16 = 58283;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub peer_ip: String,
    pub control_port: u16,
    pub heartbeat_interval_ms: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        #[cfg(target_os = "macos")]
        let peer_ip = DEFAULT_WIN_IP.to_string();

        #[cfg(target_os = "windows")]
        let peer_ip = DEFAULT_MAC_IP.to_string();

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let peer_ip = "127.0.0.1".to_string();

        Self {
            peer_ip,
            control_port: CONTROL_PORT,
            heartbeat_interval_ms: 1000,
        }
    }
}
