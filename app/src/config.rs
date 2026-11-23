//! # Network Protocol Configuration & Static Constants Registry (`config.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `config.rs` provides the centralized, canonical definition of well-known TCP and UDP port
//! numbers, protocol defaults, display/media bounds, external tool identifiers, and OS system
//! binary paths used across the entire Integrator peer-to-peer ecosystem.
//!
//! While network interface addresses, subnets, and routing topologies are probed dynamically
//! at runtime by `system_info.rs` and negotiated via `discovery.rs`, all Integrator services
//! bind to predictable, deterministic port numbers in the dynamic/private port range (58280–58287)
//! to avoid collisions with standard IANA registered services.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core.rs`: Initializes background listener daemons, firewall rules, and client transport sessions.
//! - `discovery.rs`: Broadcasts discovery beacons containing control and service port metadata.
//! - `bridge.rs`: Performs TCP RTT probes against peer service endpoints using `CONTROL_PORT`.
//! - `display/`, `kvm/`, `clipboard/`, `audio/`, `camera/`, `storage/`, `truetone/`, `telemetry/`:
//!   Subsystems consume canonical ports, defaults, bounds, and OS utility paths from this registry.
//!
//! ### Downstream Callees:
//! - Standard library primitives (`std::net::Ipv4Addr`).
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Both macOS and Windows 11 instances bind listener sockets to `0.0.0.0:<PORT>` or `[::]:<PORT>`
//! across all active physical and virtual interfaces (Ethernet, Wi-Fi, Thunderbolt bridge).
//! The peer connects directly to `<PEER_IP>:<PORT>` once discovery has resolved peer reachability.
//!
//! ## 3. Threading & Concurrency Model
//! Constants defined in this module are immutable compile-time primitives (`u16`, `u32`, `f32`, `f64`,
//! `&str`, `Ipv4Addr`). They are safe for lockless, concurrent read access from any asynchronous task,
//! thread, or interrupt handler.
//!
//! ## 4. Security & Safety Invariants
//! - **Static Allocation Boundary**: All core Integrator ports reside in the 58280–58287 block.
//! - **Traffic Segregation**: Independent functional services run on dedicated distinct ports.
//!   This prevents head-of-line blocking (e.g., bulk clipboard transfers stalling real-time KVM input)
//!   and allows OS-level QoS packet prioritization (e.g., DSCP tagging for audio and KVM datagrams).
//! - **Mutual Authentication Prerequisite**: With the exception of discovery beacons, no unauthenticated
//!   traffic is accepted on any TCP/UDP port; incoming streams must immediately execute the encrypted
//!   handshake (`security::transport::TransportSessionV2`).
//! - **Qualified macOS System Binaries**: macOS utility paths are pinned to Apple SIP-protected system
//!   directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) to prevent `PATH`-hijacking attacks.

use std::net::Ipv4Addr;

// ============================================================================
// Core Integrator Network Ports (58280–58287)
// ============================================================================

/// UDP Multicast / Broadcast Discovery Port (58280).
///
/// Used exclusively for zero-configuration peer announcement and query beacons.
/// Nodes broadcast signed discovery payloads over IPv4 subnet broadcast (`255.255.255.255`
/// and interface directed broadcast) and link-local multicast.
pub const DISCOVERY_PORT: u16 = 58280;

/// Primary Control and Handshake Port (58281, TCP).
///
/// Handles session establishment, SPAKE2+ password-authenticated key exchange,
/// cryptographic capability negotiation, pairing confirmations, and top-level session control.
/// Also used by `bridge::LinkMonitor` to measure baseline TCP connection latency (RTT).
pub const CONTROL_PORT: u16 = 58281;

/// High-Capacity Clipboard Synchronization Port (58283, TCP).
///
/// Dedicated TCP stream used for transferring clipboard contents, including plain text,
/// UTF-8/RTF payloads, high-resolution image bitstreams (PNG/TIFF), and lazy-read file descriptors.
/// Isolating clipboard traffic on port 58283 ensures that multi-megabyte image transfers do not
/// compete with or delay low-latency input or display stream frames.
pub const CLIPBOARD_PORT: u16 = 58283;

/// Low-Latency Bidirectional Audio Streaming Port (58284, UDP/TCP).
///
/// Carries 48 kHz 16-bit/24-bit stereo PCM audio packets encapsulated in encrypted datagrams
/// with sequence numbers, sample timestamps, and drift correction markers.
/// Primarily operates over UDP for sub-10ms delivery, falling back to TCP when firewall
/// configurations restrict UDP hole punching.
pub const AUDIO_PORT: u16 = 58284;

/// Real-Time Telemetry and Health Streaming Port (58285, TCP).
///
/// Transmits periodic diagnostic metrics, link quality estimations, packet loss percentages,
/// CPU/GPU thermal states, and frame timing histograms between peers and local UI diagnostics views.
pub const TELEMETRY_PORT: u16 = 58285;

/// High-Priority Low-Latency Input (KVM) Port (58286, TCP/UDP).
///
/// Handles remote keyboard keycodes, mouse pointer delta movements, absolute coordinate mappings,
/// mouse wheel delta events, and multi-touch trackpad gestures.
/// Designed for maximum throughput and minimal queueing delay to preserve 120Hz/144Hz input responsiveness.
pub const INPUT_PORT: u16 = 58286;

/// High-Bandwidth Virtual Camera Streaming Port (58287, TCP).
///
/// Transmits uncompressed/compressed virtual camera frames from the capturing host
/// to the peer's virtual camera driver (CoreMediaIO DAL plugin on macOS, Media Foundation FrameServer on Windows).
pub const CAMERA_PORT: u16 = 58287;

/// All Integrator core TCP listener ports exposed through OS firewall rules.
#[allow(dead_code)]
pub const TCP_SERVICE_PORTS: [u16; 5] = [
    CONTROL_PORT,
    CLIPBOARD_PORT,
    TELEMETRY_PORT,
    INPUT_PORT,
    CAMERA_PORT,
];

/// All Integrator core UDP listener ports exposed through OS firewall rules.
#[allow(dead_code)]
pub const UDP_SERVICE_PORTS: [u16; 2] = [DISCOVERY_PORT, AUDIO_PORT];

// ============================================================================
// Standard External Service Ports & Network Defaults
// ============================================================================

/// Standard SMB (Server Message Block) direct-hosting TCP port (IANA 445).
#[allow(dead_code)]
pub const SMB_TCP_PORT: u16 = 445;

/// Standard NetBIOS Session Service TCP port used by legacy SMB discovery (IANA 139).
#[allow(dead_code)]
pub const NETBIOS_SSN_PORT: u16 = 139;

/// SMB and NetBIOS TCP ports opened for local peer file sharing rules.
#[allow(dead_code)]
pub const SMB_SERVICE_PORTS: [u16; 2] = [SMB_TCP_PORT, NETBIOS_SSN_PORT];

/// Default primary Sunshine host HTTP/pairing base port (47989).
#[allow(dead_code)]
pub const SUNSHINE_DEFAULT_PORT: u16 = 47989;

/// Default secondary Sunshine host HTTP/pairing base port used for dedicated virtual display slot 1 (48989).
#[allow(dead_code)]
pub const SUNSHINE_SECONDARY_PORT: u16 = 48989;

/// Offset from Sunshine's base port to its HTTPS web administration API port (`base_port + 1`).
#[allow(dead_code)]
pub const SUNSHINE_WEB_PORT_OFFSET: u16 = 1;

/// Default primary Sunshine HTTPS web administration port (`47989 + 1 = 47990`).
#[allow(dead_code)]
pub const SUNSHINE_DEFAULT_WEB_PORT: u16 = SUNSHINE_DEFAULT_PORT + SUNSHINE_WEB_PORT_OFFSET;

/// Default secondary Sunshine HTTPS web administration port (`48989 + 1 = 48990`).
#[allow(dead_code)]
pub const SUNSHINE_SECONDARY_WEB_PORT: u16 = SUNSHINE_SECONDARY_PORT + SUNSHINE_WEB_PORT_OFFSET;

/// RFC 3927 IPv4 link-local (APIPA) CIDR range (`169.254.0.0/16`) for zero-conf direct cable links.
#[allow(dead_code)]
pub const IPV4_LINK_LOCAL_CIDR: &str = "169.254.0.0/16";

/// Default `/24` IPv4 subnet mask fallback used only when an OS adapter reports a zero netmask.
#[allow(dead_code)]
pub const DEFAULT_IPV4_FALLBACK_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

// ============================================================================
// Sunshine, Moonlight & Virtual Display Driver (VDD) Defaults
// ============================================================================

/// Default Sunshine primary configuration filename.
#[allow(dead_code)]
pub const SUNSHINE_CONF_FILENAME: &str = "sunshine.conf";

/// Default Sunshine secondary configuration filename for dedicated extended display sessions.
#[allow(dead_code)]
pub const SUNSHINE_SECONDARY_CONF_NAME: &str = "sunshine_mac2.conf";

/// Default Windows Task Scheduler task name supervising the secondary Sunshine host instance.
#[allow(dead_code)]
pub const SUNSHINE_SECONDARY_TASK_NAME: &str = "SunshineSecondary";

/// Default Windows Service name for the primary Sunshine host daemon.
#[allow(dead_code)]
pub const SUNSHINE_SERVICE_NAME: &str = "SunshineService";

/// Default Windows Task Scheduler task name for the dynamic VDD resolution watcher.
#[allow(dead_code)]
pub const VDD_DYNAMIC_WATCHER_TASK: &str = "VddDynamicWatcher";

/// Default Virtual Display Driver slot identifier passed to `VddCtl.exe`.
#[allow(dead_code)]
pub const VDD_DEFAULT_SLOT: &str = "1";

/// Relative installation path under the system drive for `VddCtl.exe`.
#[allow(dead_code)]
pub const VDD_CTL_REL_PATH: &str = r"VirtualDisplayDriver\VddCtl.exe";

/// Marker file created in `app_data_dir()` when a Windows virtual display adapter is active without `VddCtl.exe`.
#[allow(dead_code)]
pub const WIN_VDD_ACTIVE_MARKER: &str = "win_vdd.active";

/// Marker file maintained beside `VddCtl.exe` when VDD slot 1 is attached.
#[allow(dead_code)]
pub const VDD_SLOT1_ACTIVE_MARKER: &str = "slot1.active";

/// Sunshine REST API endpoint path to gracefully close any active streaming session.
#[allow(dead_code)]
pub const SUNSHINE_API_CLOSE_PATH: &str = "/api/apps/close";

/// Sunshine REST API endpoint path to reset display device persistence metadata.
#[allow(dead_code)]
pub const SUNSHINE_API_RESET_PERSISTENCE_PATH: &str = "/api/reset-display-device-persistence";

/// Protected filename prefix for Sunshine GPU adapter override state files in `app_data_dir()`.
#[allow(dead_code)]
pub const SUNSHINE_ADAPTER_OVERRIDE_PREFIX: &str = "sunshine_adapter_override";

/// Default Moonlight stream application profile name.
#[allow(dead_code)]
pub const MOONLIGHT_DEFAULT_APP_NAME: &str = "Desktop";

/// macOS `defaults` preference domain and bundle identifier for Moonlight Game Streaming.
#[allow(dead_code)]
pub const MOONLIGHT_MACOS_PREFS_DOMAIN: &str = "com.moonlight-stream.Moonlight";

/// Custom EDID Vendor ID ("IN") assigned to Integrator's macOS `CGVirtualDisplay`.
#[allow(dead_code)]
pub const INTEGRATOR_EDID_VENDOR_ID: u32 = 0x494E;

/// Custom EDID Product ID assigned to Integrator's macOS `CGVirtualDisplay`.
#[allow(dead_code)]
pub const INTEGRATOR_EDID_PRODUCT_ID: u32 = 0x0165;

// ============================================================================
// Display Geometry, Clamping & Adaptive Bitrate Ladder
// ============================================================================

/// Fallback display width in pixels when OS geometry probes are unavailable (1080p).
#[allow(dead_code)]
pub const DEFAULT_DISPLAY_WIDTH: u32 = 1920;

/// Fallback display height in pixels when OS geometry probes are unavailable (1080p).
#[allow(dead_code)]
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1080;

/// Fallback display refresh rate in Hz when OS geometry probes are unavailable.
#[allow(dead_code)]
pub const DEFAULT_DISPLAY_FPS: u32 = 60;

/// Fallback macOS logical screen width in points when CoreGraphics bounds query fails.
#[allow(dead_code)]
pub const DEFAULT_MACOS_DISPLAY_WIDTH: f64 = 1440.0;

/// Fallback macOS logical screen height in points when CoreGraphics bounds query fails.
#[allow(dead_code)]
pub const DEFAULT_MACOS_DISPLAY_HEIGHT: f64 = 900.0;

/// Default maximum virtual display width in pixels for secondary VDD slot sessions.
#[allow(dead_code)]
pub const VDD_DEFAULT_MAX_WIDTH: u32 = 2560;

/// Default maximum virtual display height in pixels for secondary VDD slot sessions.
#[allow(dead_code)]
pub const VDD_DEFAULT_MAX_HEIGHT: u32 = 1600;

/// Minimum permitted stream display width in pixels.
#[allow(dead_code)]
pub const MIN_DISPLAY_WIDTH: u32 = 800;

/// Maximum permitted stream display width in pixels (8K UHD).
#[allow(dead_code)]
pub const MAX_DISPLAY_WIDTH: u32 = 7680;

/// Minimum permitted stream display height in pixels.
#[allow(dead_code)]
pub const MIN_DISPLAY_HEIGHT: u32 = 600;

/// Maximum permitted stream display height in pixels (8K UHD).
#[allow(dead_code)]
pub const MAX_DISPLAY_HEIGHT: u32 = 4320;

/// Minimum valid screen width in points/pixels for KVM coordinate mapping.
#[allow(dead_code)]
pub const MIN_KVM_DISPLAY_WIDTH: f32 = 320.0;

/// Minimum valid screen height in points/pixels for KVM coordinate mapping.
#[allow(dead_code)]
pub const MIN_KVM_DISPLAY_HEIGHT: f32 = 200.0;

/// Minimum permitted display refresh rate in Hz.
#[allow(dead_code)]
pub const MIN_DISPLAY_FPS: u32 = 30;

/// Maximum permitted display refresh rate in Hz.
#[allow(dead_code)]
pub const MAX_DISPLAY_FPS: u32 = 240;

/// Refresh rate threshold in Hz above which high-framerate bitrate tiers are selected.
#[allow(dead_code)]
pub const HIGH_FPS_THRESHOLD: u32 = 120;

/// Minimum stream video bitrate in kilobits per second (5 Mbps).
#[allow(dead_code)]
pub const MIN_BITRATE_KBPS: u32 = 5_000;

/// Maximum stream video bitrate in kilobits per second (500 Mbps).
#[allow(dead_code)]
pub const MAX_BITRATE_KBPS: u32 = 500_000;

/// Default stream video bitrate fallback in kilobits per second (100 Mbps).
#[allow(dead_code)]
pub const DEFAULT_BITRATE_KBPS: u32 = 100_000;

/// Link speed threshold in Mbps classifying 2.5GbE+ multi-gigabit links.
#[allow(dead_code)]
pub const LINK_SPEED_2500M_THRESHOLD_MBPS: u32 = 2500;

/// Link speed threshold in Mbps classifying Gigabit links.
#[allow(dead_code)]
pub const LINK_SPEED_1000M_THRESHOLD_MBPS: u32 = 1000;

/// Direct Thunderbolt/USB4 cable bitrate at standard refresh rates (100 Mbps).
#[allow(dead_code)]
pub const BITRATE_DIRECT_CABLE_STANDARD_KBPS: u32 = 100_000;

/// Direct Thunderbolt/USB4 cable bitrate at >=120Hz refresh rates (150 Mbps).
#[allow(dead_code)]
pub const BITRATE_DIRECT_CABLE_HIGH_FPS_KBPS: u32 = 150_000;

/// 2.5GbE+ link bitrate at standard refresh rates (100 Mbps).
#[allow(dead_code)]
pub const BITRATE_2500M_STANDARD_KBPS: u32 = 100_000;

/// 2.5GbE+ link bitrate at >=120Hz refresh rates (150 Mbps).
#[allow(dead_code)]
pub const BITRATE_2500M_HIGH_FPS_KBPS: u32 = 150_000;

/// Gigabit link bitrate at standard refresh rates (65 Mbps).
#[allow(dead_code)]
pub const BITRATE_1000M_STANDARD_KBPS: u32 = 65_000;

/// Gigabit link bitrate at >=120Hz refresh rates (85 Mbps).
#[allow(dead_code)]
pub const BITRATE_1000M_HIGH_FPS_KBPS: u32 = 85_000;

/// Adaptive bitrate scaling factor (kbps per reported link Mbps) for sub-gigabit links.
#[allow(dead_code)]
pub const BITRATE_SUB_GIG_MBPS_MULTIPLIER: u32 = 350;

/// Minimum adaptive bitrate floor in kbps for sub-gigabit links (15 Mbps).
#[allow(dead_code)]
pub const BITRATE_SUB_GIG_MIN_KBPS: u32 = 15_000;

/// Maximum adaptive bitrate ceiling in kbps for sub-gigabit links (55 Mbps).
#[allow(dead_code)]
pub const BITRATE_SUB_GIG_MAX_KBPS: u32 = 55_000;

/// Fallback Ethernet bitrate at standard refresh rates when link speed is unreported (60 Mbps).
#[allow(dead_code)]
pub const BITRATE_ETH_FALLBACK_STANDARD_KBPS: u32 = 60_000;

/// Fallback Ethernet bitrate at >=120Hz when link speed is unreported (80 Mbps).
#[allow(dead_code)]
pub const BITRATE_ETH_FALLBACK_HIGH_FPS_KBPS: u32 = 80_000;

/// Fallback Wi-Fi bitrate when link speed is unreported (35 Mbps).
#[allow(dead_code)]
pub const BITRATE_WIFI_FALLBACK_KBPS: u32 = 35_000;

/// Multiplier converting nominal 802.11 Wi-Fi PHY link speed (Mbps) to sustainable low-jitter video bitrate (kbps).
/// Accounts for half-duplex CSMA/CA airtime overhead (e.g. 866 Mbps PHY -> 43.3 Mbps stream).
#[allow(dead_code)]
pub const BITRATE_WIFI_PHY_MBPS_MULTIPLIER: u32 = 50;

/// Maximum streaming bitrate for 802.11 Wi-Fi LAN at standard (<120Hz) refresh rates (45 Mbps).
#[allow(dead_code)]
pub const BITRATE_WIFI_MAX_STANDARD_KBPS: u32 = 45_000;

/// Maximum streaming bitrate for 802.11 Wi-Fi LAN at high (>=120Hz) refresh rates (55 Mbps).
#[allow(dead_code)]
pub const BITRATE_WIFI_MAX_HIGH_FPS_KBPS: u32 = 55_000;

/// Multiplier converting nominal Mobile Hotspot PHY link speed (Mbps) to sustainable video bitrate (kbps).
#[allow(dead_code)]
pub const BITRATE_HOTSPOT_PHY_MBPS_MULTIPLIER: u32 = 30;

/// Minimum streaming bitrate floor for Mobile Hotspot links (10 Mbps).
#[allow(dead_code)]
pub const BITRATE_HOTSPOT_MIN_KBPS: u32 = 10_000;

/// Target streaming bitrate cap for Mobile Hotspot links (PC Hotspot / Phone Hotspot) at standard (<120Hz) refresh rates (20 Mbps).
#[allow(dead_code)]
pub const BITRATE_HOTSPOT_STANDARD_KBPS: u32 = 20_000;

/// Target streaming bitrate cap for Mobile Hotspot links (PC Hotspot / Phone Hotspot) at high (>=120Hz) refresh rates (25 Mbps).
#[allow(dead_code)]
pub const BITRATE_HOTSPOT_HIGH_FPS_KBPS: u32 = 25_000;

/// Generic fallback bitrate when both transport and link speed are unknown (60 Mbps).
#[allow(dead_code)]
pub const BITRATE_UNKNOWN_FALLBACK_KBPS: u32 = 60_000;

// ============================================================================
// Media, Camera, Audio & TrueTone Defaults
// ============================================================================

/// Default virtual camera frame width in pixels (720p HD).
#[allow(dead_code)]
pub const DEFAULT_CAMERA_WIDTH: u32 = 1280;

/// Default virtual camera frame height in pixels (720p HD).
#[allow(dead_code)]
pub const DEFAULT_CAMERA_HEIGHT: u32 = 720;

/// Default virtual camera frame rate in frames per second.
#[allow(dead_code)]
pub const DEFAULT_CAMERA_FPS: u32 = 30;

/// Default friendly device name exposed to Windows Media Foundation for the shared camera.
#[allow(dead_code)]
pub const DEFAULT_CAMERA_FRIENDLY_NAME: &str = "Integrator Mac Camera";

/// Default bidirectional audio sample rate in Hz (48 kHz).
#[allow(dead_code)]
pub const DEFAULT_AUDIO_SAMPLE_RATE: u32 = 48_000;

/// Default bidirectional audio PCM bit depth.
#[allow(dead_code)]
pub const DEFAULT_AUDIO_BIT_DEPTH: u8 = 24;

/// CIE D65 standard daylight white point color temperature in Kelvin.
#[allow(dead_code)]
pub const D65_CCT_KELVIN: u32 = 6500;

/// Minimum supported TrueTone correlated color temperature in Kelvin.
#[allow(dead_code)]
pub const MIN_CCT_KELVIN: u32 = 2500;

/// Maximum supported TrueTone correlated color temperature in Kelvin.
#[allow(dead_code)]
pub const MAX_CCT_KELVIN: u32 = 9000;

/// Minimum permitted TrueTone gamma compensation factor.
#[allow(dead_code)]
pub const MIN_GAMMA_COMP_FACTOR: f32 = 0.5;

/// Maximum permitted TrueTone gamma compensation factor.
#[allow(dead_code)]
pub const MAX_GAMMA_COMP_FACTOR: f32 = 1.5;

// ============================================================================
// Application Storage, Pairing & Platform Identifiers
// ============================================================================

/// Persistent hidden application data directory name under the user home directory.
/// Retained for backward compatibility with existing paired keystores and settings.
#[allow(dead_code)]
pub const APP_DATA_DIR_NAME: &str = ".usbc_clipboard_cache";

/// Application user path/override configuration filename within `app_data_dir()`.
#[allow(dead_code)]
pub const APP_CONFIG_FILENAME: &str = "app_config.json";

/// Rotating diagnostic log filename within the user home directory.
#[allow(dead_code)]
pub const LOG_FILE_NAME: &str = ".integrator.log";

/// Subdirectory within `app_data_dir()` storing cached lazy-transferred clipboard files.
#[allow(dead_code)]
pub const CLIPBOARD_CACHE_DIR_NAME: &str = "clipboard_cache";

/// Subdirectory within `app_data_dir()` storing staged cross-screen drag-and-drop payloads.
#[allow(dead_code)]
pub const DRAG_STAGING_DIR_NAME: &str = "drag_staging";

/// Persistent KVM layout topology configuration filename within `app_data_dir()`.
#[allow(dead_code)]
pub const KVM_LAYOUT_FILE: &str = "kvm_layout.json";

/// Required numeric digit length for SPAKE2+ peer pairing PINs.
#[allow(dead_code)]
pub const PAIRING_PIN_LENGTH: usize = 6;

/// Relative path under `%SystemRoot%\System32` for Windows PowerShell 5.1.
#[allow(dead_code)]
pub const POWERSHELL_SYSTEM32_REL_PATH: &str = r"WindowsPowerShell\v1.0\powershell.exe";

/// Synthetic fallback GPU adapter display label when no hardware GPU is enumerated.
#[allow(dead_code)]
pub const DEFAULT_SYSTEM_GPU_NAME: &str = "Default System GPU";

// ============================================================================
// Qualified macOS SIP-Protected System Utility Paths
// ============================================================================

/// Qualified path to macOS `curl` binary (SIP-protected).
#[allow(dead_code)]
pub const MACOS_CURL_BIN: &str = "/usr/bin/curl";

/// Qualified path to macOS `defaults` preference tool (SIP-protected).
#[allow(dead_code)]
pub const MACOS_DEFAULTS_BIN: &str = "/usr/bin/defaults";

/// Qualified path to macOS `pgrep` process inspection tool (SIP-protected).
#[allow(dead_code)]
pub const MACOS_PGREP_BIN: &str = "/usr/bin/pgrep";

/// Qualified path to macOS `killall` process termination tool (SIP-protected).
#[allow(dead_code)]
pub const MACOS_KILLALL_BIN: &str = "/usr/bin/killall";

/// Qualified path to macOS AppleScript interpreter `osascript` (SIP-protected).
#[allow(dead_code)]
pub const MACOS_OSASCRIPT_BIN: &str = "/usr/bin/osascript";

/// Qualified path to macOS LaunchServices `open` command (SIP-protected).
#[allow(dead_code)]
pub const MACOS_OPEN_BIN: &str = "/usr/bin/open";

/// Qualified path to macOS CoreAudio CLI player `afplay` (SIP-protected).
#[allow(dead_code)]
pub const MACOS_AFPLAY_BIN: &str = "/usr/bin/afplay";

/// Qualified path to macOS IOKit registry utility `ioreg` (SIP-protected).
#[allow(dead_code)]
pub const MACOS_IOREG_BIN: &str = "/usr/sbin/ioreg";

/// Qualified path to macOS `diskutil` disk management utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_DISKUTIL_BIN: &str = "/usr/sbin/diskutil";

/// Qualified path to macOS `umount` filesystem unmount utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_UMOUNT_BIN: &str = "/sbin/umount";

/// Qualified path to macOS `smbutil` SMB control utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_SMBUTIL_BIN: &str = "/usr/bin/smbutil";

/// Qualified path to macOS `mount` table inspection utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_MOUNT_BIN: &str = "/sbin/mount";

/// Qualified path to macOS `id` user identity utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_ID_BIN: &str = "/usr/bin/id";

/// Qualified path to macOS `launchctl` LaunchAgent controller (SIP-protected).
#[allow(dead_code)]
pub const MACOS_LAUNCHCTL_BIN: &str = "/bin/launchctl";

/// Qualified path to macOS `scutil` system configuration utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_SCUTIL_BIN: &str = "/usr/sbin/scutil";

/// Qualified path to macOS `hostname` utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_HOSTNAME_BIN: &str = "/bin/hostname";

/// Qualified path to macOS `sysctl` kernel parameter utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_SYSCTL_BIN: &str = "/usr/sbin/sysctl";

/// Qualified path to macOS `system_profiler` hardware inventory utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_SYSTEM_PROFILER_BIN: &str = "/usr/sbin/system_profiler";

/// Qualified path to macOS Spotlight query utility `mdfind` (SIP-protected).
#[allow(dead_code)]
pub const MACOS_MDFIND_BIN: &str = "/usr/bin/mdfind";

/// Qualified path to macOS file-sharing utility `sharing` (SIP-protected).
#[allow(dead_code)]
pub const MACOS_SHARING_BIN: &str = "/usr/sbin/sharing";

/// Qualified path to macOS `networksetup` interface utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_NETWORKSETUP_BIN: &str = "/usr/sbin/networksetup";

/// Qualified path to macOS `ifconfig` network interface utility (SIP-protected).
#[allow(dead_code)]
pub const MACOS_IFCONFIG_BIN: &str = "/sbin/ifconfig";

/// Qualified path to macOS `/bin/bash` shell interpreter (SIP-protected).
#[allow(dead_code)]
pub const MACOS_BASH_BIN: &str = "/bin/bash";

// ============================================================================
// Setup, Drivers & OS Permissions Assistant Constants
// ============================================================================

/// Default Homebrew binary location on Apple Silicon Macs (`/opt/homebrew/bin/brew`).
#[allow(dead_code)]
pub const MACOS_BREW_APPLE_SILICON_BIN: &str = "/opt/homebrew/bin/brew";

/// Default Homebrew binary location on Intel Macs (`/usr/local/bin/brew`).
#[allow(dead_code)]
pub const MACOS_BREW_INTEL_BIN: &str = "/usr/local/bin/brew";

/// macOS LaunchDaemon plist path for the event-driven Apple USB-C NCM direct-link watchdog.
#[allow(dead_code)]
pub const MACOS_USBNCM_PLIST_PATH: &str = "/Library/LaunchDaemons/com.integrator.usbncm.plist";

/// macOS privileged helper script path for the Apple USB-C NCM direct-link watchdog.
#[allow(dead_code)]
pub const MACOS_USBNCM_WATCHDOG_PATH: &str =
    "/Library/PrivilegedHelperTools/apple-usb-ncm-watchdog.sh";

/// Relative repository path to the macOS USB-C NCM LaunchDaemon installer script.
#[allow(dead_code)]
pub const MACOS_INSTALL_SCRIPT_REL_PATH: &str = "macos/install-macos.sh";

/// Windows Task Scheduler task name for the Apple USB-C NCM WinTun bridge service.
#[allow(dead_code)]
pub const WINDOWS_USBNCM_TASK_NAME: &str = "AppleUsbNcmBridge";

/// Subdirectory under `%ProgramData%` where the Windows Apple USB-C NCM bridge & `wintun.dll` reside.
#[allow(dead_code)]
pub const WINDOWS_USBNCM_PROGRAMDATA_SUBDIR: &str = "AppleUsbNcm";

/// Filename of the signed WinTun userspace tunnel library deployed by `Install-AppleUsbNcm.ps1`.
#[allow(dead_code)]
pub const WINDOWS_WINTUN_DLL_FILENAME: &str = "wintun.dll";

/// Relative repository path to the Windows Apple USB-C NCM installer PowerShell script.
#[allow(dead_code)]
pub const WINDOWS_INSTALL_USBNCM_REL_PATH: &str = r"windows\Install-AppleUsbNcm.ps1";

/// Windows COM CLSID for the standalone Media Foundation Virtual Camera (`integrator_vcam.dll`).
#[allow(dead_code)]
pub const WINDOWS_VCAM_CLSID: &str = "{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}";

/// Windows Registry HKCR key path verifying registration of the Virtual Camera COM class.
#[allow(dead_code)]
pub const WINDOWS_VCAM_HKCR_CLSID_KEY: &str =
    r"HKCR\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}";

/// Windows Registry HKLM key path verifying system-wide registration of the Virtual Camera COM class.
#[allow(dead_code)]
pub const WINDOWS_VCAM_HKLM_CLSID_KEY: &str =
    r"HKLM\SOFTWARE\Classes\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}";

/// Filename of the compiled Windows 11 Media Foundation FrameServer COM DLL.
#[allow(dead_code)]
pub const WINDOWS_VCAM_DLL_FILENAME: &str = "integrator_vcam.dll";

/// Subdirectory under `%ProgramFiles%` where Integrator binaries and `integrator_vcam.dll` reside.
#[allow(dead_code)]
pub const WINDOWS_INTEGRATOR_INSTALL_SUBDIR: &str = "Integrator";

/// Windows Registry key storing per-user webcam privacy consent policy.
#[allow(dead_code)]
pub const WINDOWS_CAMERA_CONSENT_REG_KEY: &str =
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam";

/// Windows Service name for the SMB File Server (`LanmanServer`).
#[allow(dead_code)]
pub const WINDOWS_LANMAN_SERVER_SERVICE: &str = "LanmanServer";

/// Windows Defender Firewall rule name for core Integrator TCP services.
#[allow(dead_code)]
pub const WIN_FW_RULE_CORE_TCP: &str = "Integrator Core (TCP)";

/// Windows Defender Firewall rule name for core Integrator UDP services.
#[allow(dead_code)]
pub const WIN_FW_RULE_CORE_UDP: &str = "Integrator Core (UDP)";

/// Windows Defender Firewall rule name for inbound SMB file sharing.
#[allow(dead_code)]
pub const WIN_FW_RULE_SMB_TCP: &str = "Integrator SMB File Sharing (TCP)";

/// macOS System Settings deep link opening Privacy & Security -> Accessibility.
#[allow(dead_code)]
pub const MACOS_SETTINGS_ACCESSIBILITY_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

/// macOS System Settings deep link opening Privacy & Security -> Input Monitoring.
#[allow(dead_code)]
pub const MACOS_SETTINGS_INPUT_MONITORING_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent";

/// macOS System Settings deep link opening Privacy & Security -> Screen Recording.
#[allow(dead_code)]
pub const MACOS_SETTINGS_SCREEN_RECORDING_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture";

/// macOS System Settings deep link opening Privacy & Security -> Camera.
#[allow(dead_code)]
pub const MACOS_SETTINGS_CAMERA_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera";

/// macOS System Settings deep link opening Privacy & Security -> Local Network.
#[allow(dead_code)]
pub const MACOS_SETTINGS_LOCAL_NETWORK_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork";

/// macOS System Settings deep link opening General -> Sharing (File Sharing).
#[allow(dead_code)]
pub const MACOS_SETTINGS_FILE_SHARING_URL: &str =
    "x-apple.systempreferences:com.apple.Sharing-Settings.extension";

/// Windows Settings URI opening Windows Security / Defender Firewall.
#[allow(dead_code)]
pub const WINDOWS_SETTINGS_FIREWALL_URL: &str = "ms-settings:windowsdefender";

/// Windows Settings URI opening Network & Internet status and profile settings.
#[allow(dead_code)]
pub const WINDOWS_SETTINGS_NETWORK_STATUS_URL: &str = "ms-settings:network-status";

/// Windows Settings URI opening Privacy & Security -> Camera settings.
#[allow(dead_code)]
pub const WINDOWS_SETTINGS_CAMERA_PRIVACY_URL: &str = "ms-settings:privacy-webcam";

/// Windows Settings URI opening Advanced network sharing settings.
#[allow(dead_code)]
pub const WINDOWS_SETTINGS_ADVANCED_SHARING_URL: &str = "ms-settings:network-advancedsettings";

/// Official GitHub releases URL for LizardByte Sunshine streaming host.
#[allow(dead_code)]
pub const SUNSHINE_DOWNLOAD_URL: &str = "https://github.com/LizardByte/Sunshine/releases/latest";

/// Official GitHub releases URL for Moonlight Game Streaming client.
#[allow(dead_code)]
pub const MOONLIGHT_DOWNLOAD_URL: &str =
    "https://github.com/moonlight-stream/moonlight-qt/releases/latest";

/// Official GitHub releases URL for the Windows Virtual Display Driver (IddSampleDriver / MTT VDD).
#[allow(dead_code)]
pub const VDD_DOWNLOAD_URL: &str =
    "https://github.com/VirtualDrivers/Virtual-Display-Driver/releases/latest";

/// Official download and documentation URL for the WinTun userspace tunnel driver used by USB-C NCM.
#[allow(dead_code)]
pub const USBNCM_GUIDE_URL: &str = "https://www.wintun.net/";

/// Official documentation and releases URL for the Integrator Virtual Camera Extension.
#[allow(dead_code)]
pub const VCAM_DOCS_URL: &str = "https://github.com/manveersingh/Integrator";

/// Homebrew Cask identifier for LizardByte Sunshine on macOS.
#[allow(dead_code)]
pub const BREW_CASK_SUNSHINE: &str = "lizardbyte/homebrew/sunshine";

/// Homebrew Cask identifier for Moonlight client on macOS.
#[allow(dead_code)]
pub const BREW_CASK_MOONLIGHT: &str = "moonlight";

/// Guided CLI command to install Sunshine via Homebrew on macOS.
#[allow(dead_code)]
pub const BREW_INSTALL_SUNSHINE_CMD: &str = "brew install --cask lizardbyte/homebrew/sunshine";

/// Guided CLI command to install Moonlight via Homebrew on macOS.
#[allow(dead_code)]
pub const BREW_INSTALL_MOONLIGHT_CMD: &str = "brew install --cask moonlight";

/// WinGet package identifier for LizardByte Sunshine on Windows.
#[allow(dead_code)]
pub const WINGET_PACKAGE_SUNSHINE: &str = "LizardByte.Sunshine";

/// WinGet package identifier for Moonlight client on Windows.
#[allow(dead_code)]
pub const WINGET_PACKAGE_MOONLIGHT: &str = "MoonlightGameStreamingProject.Moonlight";

/// Guided CLI command to install Sunshine via WinGet on Windows.
#[allow(dead_code)]
pub const WINGET_INSTALL_SUNSHINE_CMD: &str =
    "winget install --id LizardByte.Sunshine -e --accept-source-agreements --accept-package-agreements";

/// Guided CLI command to install Moonlight via WinGet on Windows.
#[allow(dead_code)]
pub const WINGET_INSTALL_MOONLIGHT_CMD: &str =
    "winget install --id MoonlightGameStreamingProject.Moonlight -e --accept-source-agreements --accept-package-agreements";

/// macOS System Settings deep-link URI for Privacy & Security -> Bluetooth (BLE Discovery).
#[allow(dead_code)]
pub const MACOS_SETTINGS_BLUETOOTH_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Bluetooth";

// ============================================================================
// Bonjour / mDNS (RFC 6762 / 6763) & BLE Magic-Packet Discovery Constants
// ============================================================================

/// Private Bonjour / DNS-SD service type exclusively owned by Integrator.
///
/// Using a dedicated `_integrator._tcp.local.` service type ensures zero collision or
/// interference with Apple AirPlay (`_airplay._tcp`), AirDrop, HomeKit, or printers.
#[allow(dead_code)]
pub const BONJOUR_SERVICE_TYPE: &str = "_integrator._tcp.local.";

/// Bonjour TXT record key carrying the Integrator discovery protocol version (`"2"`).
#[allow(dead_code)]
pub const BONJOUR_TXT_KEY_VERSION: &str = "v";

/// Bonjour TXT record key carrying the sender's 32-char lowercase hex `device_id`.
#[allow(dead_code)]
pub const BONJOUR_TXT_KEY_DEVICE_ID: &str = "id";

/// Bonjour TXT record key carrying the sender's OS platform string (`"macos"` / `"windows"`).
#[allow(dead_code)]
pub const BONJOUR_TXT_KEY_OS: &str = "os";

/// Bonjour TXT record key carrying the sender's hardware form factor (`"laptop"` / `"desktop"`).
#[allow(dead_code)]
pub const BONJOUR_TXT_KEY_FORM_FACTOR: &str = "ff";

/// Bonjour TXT record key carrying the sender's TCP control RPC port.
#[allow(dead_code)]
pub const BONJOUR_TXT_KEY_PORT: &str = "port";

/// Dedicated private 128-bit RFC 4122 v4 Bluetooth LE Service UUID for Integrator discovery.
///
/// Completely distinct from Apple's Continuity (`0x004C`) and Bluetooth SIG standard UUIDs
/// so nearby iPhones, iPads, Apple TVs, and AirPods completely ignore Integrator BLE beacons.
#[allow(dead_code)]
pub const BLE_SERVICE_UUID: &str = "7A4E9C10-5B2F-4D81-9E3A-1C6F8B2D4E90";

/// Read-only GATT characteristic UUID mirrored alongside macOS BLE advertisements.
#[allow(dead_code)]
pub const BLE_CHARACTERISTIC_UUID: &str = "7A4E9C11-5B2F-4D81-9E3A-1C6F8B2D4E90";

/// Bluetooth SIG reserved internal/custom Manufacturer Company ID (`0xFFFF`) used for Windows
/// BLE `ManufacturerData` magic packets (never collides with Apple's `0x004C`).
#[allow(dead_code)]
pub const BLE_MANUFACTURER_COMPANY_ID: u16 = 0xFFFF;

/// Three-byte ASCII magic header (`"IG2"`) identifying Integrator v2 BLE magic packets.
#[allow(dead_code)]
pub const BLE_PACKET_MAGIC: [u8; 3] = *b"IG2";

/// Three-character ASCII prefix identifying Integrator v2 BLE LocalName scan-response payloads.
#[allow(dead_code)]
pub const BLE_LOCAL_NAME_PREFIX: &str = "IG2";

/// Domain separation string used with SHA-256 to mask IPv4/port fields inside BLE magic packets.
#[allow(dead_code)]
pub const BLE_MASK_DOMAIN_SEP: &[u8] = b"integrator-ble-mask-v2";

/// Interval in seconds between rotating the ephemeral 16-bit BLE anti-tracking nonce and
/// refreshing the advertised active IPv4 address.
#[allow(dead_code)]
pub const BLE_PAYLOAD_REFRESH_SECS: u64 = 15;
