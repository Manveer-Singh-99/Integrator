//! Dynamic multi-subnet network and port configurations.
//! Supports USB-C cable (10.99.99.x), Mac Internet Sharing (192.168.2.x),
//! Windows Wi-Fi Hotspot (192.168.137.x), and local Wi-Fi LANs.

pub const DISCOVERY_PORT: u16 = 58280;
pub const CONTROL_PORT: u16 = 58281;
pub const CLIPBOARD_PORT: u16 = 58283;
pub const AUDIO_PORT: u16 = 58284;
pub const TELEMETRY_PORT: u16 = 58285;

/// Known candidate IP endpoints for peer connection attempts.
#[cfg(target_os = "macos")]
pub const CANDIDATE_PEER_IPS: &[&str] = &[
    "10.99.99.1",      // Direct USB-C NCM (Windows)
    "192.168.2.2",     // Mac Internet Sharing to PC
    "192.168.137.1",   // Windows PC Wi-Fi Hotspot Gateway
];

#[cfg(target_os = "windows")]
pub const CANDIDATE_PEER_IPS: &[&str] = &[
    "10.99.99.2",      // Direct USB-C NCM (Mac)
    "192.168.2.1",     // Mac Internet Sharing Gateway
    "192.168.137.2",   // Common Mac IP on Windows Hotspot
    "192.168.137.3",
    "192.168.137.4",
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub const CANDIDATE_PEER_IPS: &[&str] = &["127.0.0.1"];
