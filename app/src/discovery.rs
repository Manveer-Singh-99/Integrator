//! # Dynamic Zero-Configuration Peer Discovery & Route Selection (`discovery.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `discovery.rs` implements zero-configuration peer discovery, link qualification, and dynamic route
//! selection for Integrator. It enables paired or newly introduced macOS and Windows 11 machines to
//! find each other automatically across physical and virtual network interfaces without manual IP entry.
//!
//! Supported network link media include:
//! - Direct Thunderbolt 3/4 and USB4 bridge cables (sub-millisecond latency, multi-gigabit throughput).
//! - USB-C CDC-NCM virtual Ethernet connections.
//! - High-speed wired Local Area Networks (1GbE / 2.5GbE / 10GbE).
//! - 5GHz / 6GHz Wi-Fi infrastructure networks.
//! - User-configured static unicast peer IP addresses (for routed multi-subnet environments).
//!
//! ### Core Responsibilities:
//! 1. **Signed Beacon Broadcast**: Periodically broadcasts Ed25519-signed discovery beacons over local interface
//!    broadcast addresses (`bcast_str`), global broadcast (`255.255.255.255`), and unicast addresses.
//! 2. **Multi-Stage Beacon Verification**: Validates protocol versions, timestamp freshness (±60s),
//!    cryptographic Ed25519 signatures, port safety bounds, and Unicode character safety.
//! 3. **Anti-Replay Protection (`BeaconReplayCache`)**: Rejects duplicate or replayed discovery frames
//!    across single or multiple network interfaces while allowing valid multi-interface bursts.
//! 4. **Route Characterization & Metric Ranking**: Probes candidate link latency (TCP RTT) and evaluates
//!    transport hierarchy (Thunderbolt > Direct USB > Ethernet > Wi-Fi) to elect the lowest-latency,
//!    highest-bandwidth communication route.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`: Instantiates `DiscoveryManager`, spawns the discovery daemon (`start()`),
//!   and continuously queries `get_peer_ip()` and `get_best_peer()` to initiate transport sessions.
//! - Native UI Frontends (via `ffi.rs`): Call `get_all_peers()`, `add_manual_peer_ip()`, and
//!   `remove_manual_peer_ip()` to display live discovery candidate lists and manage manual IP overrides.
//!
//! ### Downstream Callees:
//! - `system_info`: Queries host profile (`collect_local_profile`), enumerates physical interface endpoints
//!   (`discovery_interface_endpoints`), and resolves OS routing tables (`describe_route_to_peer`).
//! - `trust`: Cryptographically signs outgoing beacons (`sign_discovery_beacon_v2_full`) and verifies
//!   incoming beacon authenticity and authorization states (`verify_discovery_beacon_v2_full`, `observe_discovered_peer`).
//! - `config`: Reads well-known port definitions (`DISCOVERY_PORT`, `CONTROL_PORT`, `CLIPBOARD_PORT`).
//! - Native OS Sockets: Utilizes `tokio::net::UdpSocket` and native C sockets (`setsockopt` with `IP_BOUND_IF`
//!   on macOS) to bind outgoing broadcast packets to specific physical network adapters.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! The broadcaster daemon compiles host display geometry, GPU models, OS version, and service ports into a JSON
//! beacon, signs it with the local device's Ed25519 private key, and transmits it via UDP port 58280.
//! The counterpart device's receiver verifies the signature against its trusted peer keystore, measures
//! round-trip connection latency to the sender's control port, and updates its active peer candidate table.
//!
//! ## 3. Threading & Concurrency Model
//! - **Asynchronous Tokio Green Threads**: Hosts independent broadcaster and listener tasks.
//! - **Blocking Offloading**: Synchronous OS routing queries and disk persistence operations are offloaded
//!   to `tokio::task::spawn_blocking` to prevent stalling the async executor worker threads.
//! - **Concurrent RTT Probe Limiting**: Background TCP RTT probes are governed by a `Semaphore`
//!   (`MAX_CONCURRENT_RTT_PROBES = 8`) to avoid socket starvation during network bursts.
//! - **Locking Hierarchy**: Shared state (`candidates`, `rtt_cache`, `manual_ips`) is guarded by `tokio::sync::RwLock`
//!   for concurrent reader throughput.
//!
//! ## 4. Security & Safety Invariants
//! - **Cryptographic Authenticity**: Unsigned or invalidly signed beacons are dropped before route inspection.
//! - **Replay Attack Resistance**: Monotonic timestamp tracking rejects delayed, re-routed, or captured beacons.
//! - **Text Sanitization & Anti-Spoofing**: Hostnames, OS descriptions, and GPU strings containing control
//!   characters or Unicode bidirectional formatting markers (e.g. `\u{202E}` right-to-left override) are rejected.
//! - **Privileged Port Protection**: Beacons specifying service ports below 1024 are rejected to prevent
//!   traffic redirection attacks against root-owned system daemons.
//! - **History Poisoning Defense**: Only verified, cryptographically trusted peer IPs are persisted to disk.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore};

use crate::config::{
    CLIPBOARD_PORT, CONTROL_PORT, DISCOVERY_PORT, MAX_DISPLAY_FPS, MAX_DISPLAY_HEIGHT,
    MAX_DISPLAY_WIDTH, SUNSHINE_DEFAULT_PORT,
};
use crate::system_info::{self, LinkTransport};
use crate::trust;

/// Protocol version number for discovery beacon format negotiation.
pub const DISCOVERY_PROTOCOL_VERSION: u16 = 2;

/// Time-To-Live for peer candidates. Candidates not refreshed within 10 seconds are evicted.
const PEER_CANDIDATE_TTL: Duration = Duration::from_secs(10);

/// Maximum number of distinct peer candidate routes retained in memory.
const MAX_PEER_CANDIDATES: usize = 64;

/// Maximum entries cached in the RTT measurement map.
const MAX_RTT_CACHE_ENTRIES: usize = 128;

/// In-memory cache lifetime for TCP RTT probe measurements.
const RTT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Maximum tracked remote devices in the anti-replay cache.
const MAX_REPLAY_DEVICES: usize = 128;

/// Maximum simultaneous IP paths tracked per remote device in the anti-replay cache.
const MAX_REPLAY_IPS_PER_DEVICE: usize = 8;

/// Expiration lifetime for anti-replay cache entries.
const REPLAY_WINDOW_TTL: Duration = Duration::from_secs(130);

/// Maximum permissible clock skew (in milliseconds) across multi-homed interface bursts.
const MAX_REPLAY_CROSS_IP_SKEW_MS: u64 = 3_000;

/// Maximum user-configured manual peer IP addresses allowed in persistent storage.
const MAX_MANUAL_IPS: usize = 32;

/// Ring buffer capacity for deduplicating recent peer IP history writes.
const MAX_RECENT_SEEN: usize = 64;

/// Upper limit on concurrent background TCP RTT probe tasks.
const MAX_CONCURRENT_RTT_PROBES: usize = 8;

/// Sentinel RTT value (in milliseconds) assigned to candidates without a measured latency
/// so unmeasured paths sort strictly behind measured routes during peer selection.
const UNMEASURED_RTT_SENTINEL_MS: f64 = 9999.0;

/// Maximum timeout duration for an asynchronous TCP three-way handshake RTT probe.
const TCP_RTT_PROBE_TIMEOUT: Duration = Duration::from_millis(450);

/// Global file lock ensuring serialized access to `peer_history.json`.
static HISTORY_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Monotonic atomic counter for generating unique temporary history filenames.
static HISTORY_TMP_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Returns the static mutex guarding peer history file writes.
fn history_file_lock() -> &'static Mutex<()> {
    HISTORY_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

/// Tracks replay detection state for a single remote device identity.
#[derive(Debug)]
struct DeviceReplayState {
    /// Highest timestamp seen across all network interfaces for this device.
    max_ts_ms: u64,
    /// Local monotonic instant when this device record was last refreshed.
    last_updated: Instant,
    /// Per-source-IP timestamp history: maps IP address to `(last_timestamp_ms, recorded_instant)`.
    per_ip: HashMap<IpAddr, (u64, Instant)>,
}

/// In-memory sliding window cache mitigating discovery beacon replay attacks.
#[derive(Debug, Default)]
struct BeaconReplayCache {
    /// Maps remote device ID hex strings to their replay tracking states.
    devices: HashMap<String, DeviceReplayState>,
}

impl BeaconReplayCache {
    /// Evaluates whether an incoming beacon should be accepted or rejected as a replay.
    ///
    /// # Replay Rules:
    /// 1. Prunes records older than `REPLAY_WINDOW_TTL` (130 seconds).
    /// 2. Enforces LRU eviction if device capacity (`MAX_REPLAY_DEVICES`) is exceeded.
    /// 3. Rejects beacons whose timestamp is older than `max_ts_ms - 3000ms`, preventing
    ///    attackers from re-broadcasting older beacons captured on another interface.
    /// 4. Rejects non-strictly-increasing timestamps arriving from the same source IP.
    ///
    /// # Arguments
    /// * `device_id` - Identifier of the transmitting device.
    /// * `ip` - Source IP address where the packet arrived.
    /// * `timestamp_ms` - POSIX timestamp in milliseconds from the beacon payload.
    /// * `now` - Monotonic instant of receipt.
    ///
    /// # Return Value
    /// Returns `true` if the beacon is fresh and valid; `false` if replayed or stale.
    fn accept(&mut self, device_id: &str, ip: IpAddr, timestamp_ms: u64, now: Instant) -> bool {
        // Prune expired IP entries and stale devices first
        self.devices.retain(|_, state| {
            state
                .per_ip
                .retain(|_, (_, seen_at)| now.saturating_duration_since(*seen_at) <= REPLAY_WINDOW_TTL);
            !state.per_ip.is_empty()
                && now.saturating_duration_since(state.last_updated) <= REPLAY_WINDOW_TTL
        });

        // Enforce maximum device capacity via LRU eviction
        if !self.devices.contains_key(device_id) && self.devices.len() >= MAX_REPLAY_DEVICES {
            if let Some(oldest_key) = self
                .devices
                .iter()
                .min_by_key(|(_, s)| s.last_updated)
                .map(|(k, _)| k.clone())
            {
                self.devices.remove(&oldest_key);
            }
        }

        let state = self
            .devices
            .entry(device_id.to_string())
            .or_insert_with(|| DeviceReplayState {
                max_ts_ms: 0,
                last_updated: now,
                per_ip: HashMap::new(),
            });

        // Reject replayed older beacons routed through a spoofed source IP
        if state.max_ts_ms > timestamp_ms.saturating_add(MAX_REPLAY_CROSS_IP_SKEW_MS) {
            return false;
        }

        // Reject duplicate or backwards timestamps arriving on the same source IP
        if let Some((last_ip_ts, _)) = state.per_ip.get(&ip) {
            if timestamp_ms <= *last_ip_ts {
                return false;
            }
        } else if state.per_ip.len() >= MAX_REPLAY_IPS_PER_DEVICE {
            // Evict oldest IP if device has too many simultaneous active interfaces
            if let Some(oldest_ip) = state
                .per_ip
                .iter()
                .min_by_key(|(_, (_, seen_at))| *seen_at)
                .map(|(k, _)| *k)
            {
                state.per_ip.remove(&oldest_ip);
            }
        }

        // Record fresh timestamp and advance state
        state.per_ip.insert(ip, (timestamp_ms, now));
        state.max_ts_ms = state.max_ts_ms.max(timestamp_ms);
        state.last_updated = now;
        true
    }
}

/// Identifies whether a Unicode character represents a bidirectional formatting override.
///
/// Detects characters like Left-to-Right Embedding, Right-to-Left Override, and directional isolates
/// used in visual spoofing / Trojan Source attacks.
fn is_bidi_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Returns `true` if the input text contains control characters or bidirectional format overrides.
fn contains_unsafe_text_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_bidi_format_char(c))
}

/// Sanitizes display strings received over the wire by stripping control characters and BiDi overrides,
/// trimming whitespace, and bounding maximum character length.
fn sanitize_display_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|&c| !c.is_control() && !is_bidi_format_char(c))
        .collect::<String>()
        .trim()
        .chars()
        .take(max_chars)
        .collect()
}

/// Wire schema for UDP discovery beacon packets broadcast across network interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    /// Wire protocol version number (negotiated at `DISCOVERY_PROTOCOL_VERSION = 2`).
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    /// Unique 32-character hexadecimal identifier derived from the sender's Ed25519 public key.
    #[serde(default)]
    pub device_id: String,
    /// Hex-encoded 32-byte Ed25519 public key of the transmitting device.
    #[serde(default)]
    pub ed25519_pubkey: String,
    /// User-friendly hostname or machine name of the transmitting device.
    pub sender_name: String,
    /// Operating system platform name (`"macos"`, `"windows"`).
    pub os: String,
    /// Hardware product model name (e.g. `"MacBookPro18,1"`, `"Mac14,12"`, or `"Dell XPS 15 9520"`).
    #[serde(default)]
    pub hardware_model: String,
    /// Detected chassis form factor (`"laptop"`, `"desktop"`, or `"unknown"`).
    #[serde(default)]
    pub form_factor: String,
    /// TCP service port for control handshakes and SPAKE2+ key exchange.
    pub control_port: u16,
    /// TCP service port for clipboard synchronization streams.
    pub clipboard_port: u16,
    /// Width of primary display in physical pixels.
    #[serde(default)]
    pub display_width: u32,
    /// Height of primary display in physical pixels.
    #[serde(default)]
    pub display_height: u32,
    /// Primary display refresh rate in frames per second (FPS).
    #[serde(default)]
    pub display_fps: u32,
    /// Optional default SMB file share name published by this device.
    #[serde(default)]
    pub share_name: Option<String>,
    /// Optional Sunshine game-streaming service host name.
    #[serde(default)]
    pub sunshine_name: Option<String>,
    /// Optional Sunshine Web UI / RTSP control port.
    #[serde(default)]
    pub sunshine_port: u16,
    /// List of detected GPU adapter model names.
    #[serde(default)]
    pub gpus: Vec<String>,
    /// POSIX timestamp in milliseconds when the beacon was generated and signed.
    pub timestamp_ms: u64,
    /// Hex-encoded 64-byte Ed25519 cryptographic signature over the canonical beacon metadata.
    #[serde(default)]
    pub beacon_sig: String,
}

/// Serde default helper providing the default protocol version constant.
fn default_protocol_version() -> u16 {
    DISCOVERY_PROTOCOL_VERSION
}

/// Active discovery transport combination selectable via `INTEGRATOR_DISCOVERY_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// Hybrid mode (default): UDP `:58280` + Bonjour `_integrator._tcp.local.` + BLE magic packets.
    All,
    /// Only signed UDP `:58280` beacons.
    UdpOnly,
    /// Only standard Bonjour / mDNS (`_integrator._tcp.local.`) discovery + `TransportSessionV2` auth.
    BonjourOnly,
    /// Only Bluetooth LE magic-packet discovery + `TransportSessionV2` auth.
    BleOnly,
}

impl DiscoveryMode {
    /// Reads `INTEGRATOR_DISCOVERY_MODE` from the process environment (defaults to [`DiscoveryMode::All`]).
    pub fn from_env() -> Self {
        match std::env::var("INTEGRATOR_DISCOVERY_MODE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "udp" | "udp_only" | "udp-only" => Self::UdpOnly,
            "bonjour" | "bonjour_only" | "bonjour-only" | "mdns" => Self::BonjourOnly,
            "ble" | "ble_only" | "ble-only" | "bluetooth" => Self::BleOnly,
            _ => Self::All,
        }
    }

    /// Returns the wire/diagnostic label for this discovery mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::UdpOnly => "udp_only",
            Self::BonjourOnly => "bonjour_only",
            Self::BleOnly => "ble_only",
        }
    }

    /// Returns `true` if UDP `:58280` beacons should run in this mode.
    pub const fn udp_enabled(self) -> bool {
        matches!(self, Self::All | Self::UdpOnly)
    }

    /// Returns `true` if Bonjour / mDNS (`_integrator._tcp.local.`) should run in this mode.
    pub const fn bonjour_enabled(self) -> bool {
        matches!(self, Self::All | Self::BonjourOnly)
    }

    /// Returns `true` if Bluetooth LE magic-packet discovery should run in this mode.
    pub const fn ble_enabled(self) -> bool {
        matches!(self, Self::All | Self::BleOnly)
    }
}

/// Cryptographic proof object returned by isolated BLE-only or Bonjour-only authentication tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDiscoveryProof {
    /// Discovery transport under test (`"ble"` or `"bonjour"`).
    pub transport: String,
    /// Raw transport-specific discovery hint summary (BLE format + RSSI, or Bonjour service fullname).
    pub hint_detail: String,
    /// Peer IPv4 address resolved exclusively from the tested discovery transport.
    pub discovered_ip: String,
    /// Peer control RPC port resolved from the discovery hint.
    pub discovered_port: u16,
    /// `true` once full mutual Ed25519 + X25519 + ChaCha20-Poly1305 `TransportSessionV2` auth succeeded.
    pub authenticated: bool,
    /// Cryptographically authenticated peer `device_id` from `TransportSessionV2`.
    pub peer_device_id: String,
    /// Verified remote hostname returned inside the encrypted `GetHardwareProfile` RPC response.
    pub peer_hostname: String,
    /// Verified remote OS string returned inside the encrypted `GetHardwareProfile` RPC response.
    pub peer_os: String,
    /// Verified remote form factor returned inside the encrypted `GetHardwareProfile` RPC response.
    pub peer_form_factor: String,
    /// End-to-end encrypted handshake + RPC round-trip time in milliseconds.
    pub rtt_ms: f64,
}

/// Discovered peer candidate route representing an active reachability path to a remote machine.
#[derive(Debug, Clone)]
pub struct PeerCandidate {
    /// Resolved socket address (IP and control port) of the peer service.
    pub addr: SocketAddr,
    /// Local monotonic instant when the most recent beacon was received from this candidate.
    pub last_seen: Instant,
    /// Remote operating system name.
    pub os: String,
    /// Remote device ID hex string.
    pub device_id: String,
    /// Remote user-friendly computer name.
    pub device_name: String,
    /// Remote hardware model identifier.
    pub hardware_model: String,
    /// Remote hardware chassis form factor (`"laptop"`, `"desktop"`, or `"unknown"`).
    pub form_factor: String,
    /// Width of remote display in physical pixels.
    pub display_width: u32,
    /// Height of remote display in physical pixels.
    pub display_height: u32,
    /// Remote display refresh rate in Hz/FPS.
    pub display_fps: u32,
    /// Remote SMB share name, if available.
    pub share_name: Option<String>,
    /// Remote Sunshine streamer service name, if active.
    pub sunshine_name: Option<String>,
    /// Remote Sunshine service port.
    pub sunshine_port: u16,
    /// Remote GPU adapter descriptions.
    pub gpus: Vec<String>,
    /// Physical link classification (Thunderbolt, USB CDC-NCM, Ethernet, Wi-Fi).
    pub transport: LinkTransport,
    /// Link physical speed in Megabits per second (e.g. 40000 for Thunderbolt 4).
    pub link_speed_mbps: Option<u32>,
    /// Human-readable description of physical route interface.
    pub link_description: String,
    /// Local IPv4 interface address used to reach this peer.
    pub local_ip_used: Option<String>,
    /// Indicates whether the peer resides on the exact same CIDR subnet as the local interface.
    pub same_subnet: bool,
    /// Measured round-trip connection latency in milliseconds.
    pub rtt_ms: Option<f64>,
    /// Cryptographic trust status: `true` if peer's Ed25519 key is paired in local keystore.
    pub trusted: bool,
    /// Discovery mechanism(s) through which this candidate was observed (`"udp"`, `"bonjour"`, `"ble"`).
    pub discovery_source: String,
}

/// Persistent schema stored in `peer_history.json` tracking known peer IPs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PeerHistoryFile {
    /// Recently observed verified peer IP addresses.
    recent_ips: Vec<String>,
    /// User-configured manual unicast peer IP addresses.
    manual_ips: Vec<String>,
}

/// Central peer discovery manager coordinating broadcast tasks, listener sockets, and route selection.
#[derive(Clone)]
pub struct DiscoveryManager {
    /// Local device ID derived from Ed25519 public key.
    local_device_id: String,
    /// Local user-friendly device hostname.
    local_name: String,
    /// In-memory table of active peer candidate routes.
    candidates: Arc<RwLock<Vec<PeerCandidate>>>,
    /// Currently elected active peer IP address string.
    active_peer_ip: Arc<RwLock<Option<String>>>,
    /// Cache of measured TCP round-trip times per destination IP.
    rtt_cache: Arc<RwLock<HashMap<String, (Instant, f64)>>>,
    /// User-defined manual peer IP addresses.
    manual_ips: Arc<RwLock<Vec<String>>>,
}

impl DiscoveryManager {
    /// Initializes a new `DiscoveryManager` instance and loads stored peer IP history.
    pub fn new(my_device_name: &str) -> Self {
        let history = load_peer_history();
        Self {
            local_device_id: system_info::get_or_create_device_id(),
            local_name: my_device_name.to_string(),
            candidates: Arc::new(RwLock::new(Vec::new())),
            active_peer_ip: Arc::new(RwLock::new(None)),
            rtt_cache: Arc::new(RwLock::new(HashMap::new())),
            manual_ips: Arc::new(RwLock::new(history.manual_ips)),
        }
    }

    /// Returns the IP address string of the highest-ranking active peer candidate.
    pub async fn get_peer_ip(&self) -> Option<String> {
        self.best_candidate_inner()
            .await
            .map(|c| c.addr.ip().to_string())
    }

    /// Returns the complete `PeerCandidate` record for the highest-ranking candidate.
    pub async fn get_best_peer(&self) -> Option<PeerCandidate> {
        self.best_candidate_inner().await
    }

    /// Returns a list of all active peer candidate routes observed within `PEER_CANDIDATE_TTL`.
    pub async fn get_all_peers(&self) -> Vec<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        // Prune expired candidate entries
        guard.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);
        guard.clone()
    }

    /// Adds a user-specified manual IPv4 address to the unicast discovery list and persists it to disk.
    ///
    /// # Errors
    /// Returns an error if `ip` is not a valid IPv4 address or if `MAX_MANUAL_IPS` is exceeded.
    pub async fn add_manual_peer_ip(&self, ip: &str) -> Result<()> {
        let trimmed = ip.trim().to_string();
        if !system_info::is_valid_ipv4(&trimmed) {
            anyhow::bail!("Invalid IPv4 address: {}", ip);
        }
        {
            let mut m = self.manual_ips.write().await;
            if !m.contains(&trimmed) {
                if m.len() >= MAX_MANUAL_IPS {
                    anyhow::bail!("Manual peer IP limit reached (max {})", MAX_MANUAL_IPS);
                }
                m.push(trimmed.clone());
            }
        }
        let ip_for_disk = trimmed;
        let _ = tokio::task::spawn_blocking(move || {
            let mut hist = load_peer_history();
            if !hist.manual_ips.contains(&ip_for_disk) {
                hist.manual_ips.push(ip_for_disk);
                hist.manual_ips.truncate(MAX_MANUAL_IPS);
                save_peer_history(&hist);
            }
        })
        .await;
        Ok(())
    }

    /// Removes a user-specified manual IP address from the unicast list and persists the update.
    pub async fn remove_manual_peer_ip(&self, ip: &str) {
        let trimmed = ip.trim().to_string();
        {
            let mut m = self.manual_ips.write().await;
            m.retain(|x| x != &trimmed);
        }
        let ip_for_disk = trimmed;
        let _ = tokio::task::spawn_blocking(move || {
            let mut hist = load_peer_history();
            hist.manual_ips.retain(|x| x != &ip_for_disk);
            save_peer_history(&hist);
        })
        .await;
    }

    /// Returns a list of currently registered manual peer IP strings.
    pub async fn get_manual_peer_ips(&self) -> Vec<String> {
        self.manual_ips.read().await.clone()
    }

    /// Internal helper evaluating candidate list, pruning stale candidates, and ranking the best candidate.
    async fn best_candidate_inner(&self) -> Option<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        guard.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);

        let mut active = self.active_peer_ip.write().await;
        let selected = select_best_peer(&guard);
        *active = selected.as_ref().map(|c| c.addr.ip().to_string());
        selected
    }

    /// Starts the background discovery tasks governed by [`DiscoveryMode::from_env`]:
    /// 1. **UDP Listener & Broadcaster (`:58280`)** when `mode.udp_enabled()`.
    /// 2. **Bonjour / mDNS (`_integrator._tcp.local.`)** when `mode.bonjour_enabled()`.
    /// 3. **BLE Magic-Packet Advertising & Scanning** when `mode.ble_enabled()`.
    pub async fn start(&self) -> Result<()> {
        let mode = DiscoveryMode::from_env();
        tracing::info!("🔎 Starting discovery engine (mode={})", mode.as_str());

        let socket = if mode.udp_enabled() {
            let bind_addr = format!("0.0.0.0:{}", DISCOVERY_PORT);
            let sock = UdpSocket::bind(&bind_addr).await?;
            sock.set_broadcast(true)?;
            Some(Arc::new(sock))
        } else {
            None
        };

        // --------------------------------------------------------------------
        // Task 1: UDP Discovery Listener Task (when UDP mode is active)
        // --------------------------------------------------------------------
        if let Some(ref udp_sock) = socket {
        let listener_socket = Arc::clone(udp_sock);
        let candidates = Arc::clone(&self.candidates);
        let active_peer_ip = Arc::clone(&self.active_peer_ip);
        let rtt_cache = Arc::clone(&self.rtt_cache);
        let my_device_id = self.local_device_id.clone();
        let my_trust_device_id = trust::local_device_id_hex();
        let my_name = sanitize_display_text(&self.local_name, 128);
        let replay_cache = Arc::new(Mutex::new(BeaconReplayCache::default()));
        let rtt_probe_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_RTT_PROBES));

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match listener_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        // Deserialize JSON beacon payload
                        if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..len]) {
                            // Verify protocol version
                            if beacon.protocol_version != DISCOVERY_PROTOCOL_VERSION {
                                continue;
                            }
                            let peer_ip = addr.ip().to_string();
                            let dev_id = if beacon.device_id.trim().is_empty() {
                                continue;
                            } else {
                                beacon.device_id.trim().to_ascii_lowercase()
                            };

                            // Ignore loopback reflections and own device beacons
                            if dev_id == my_device_id
                                || dev_id == my_trust_device_id
                                || addr.ip().is_loopback()
                            {
                                continue;
                            }

                            // Reject privileged/invalid port numbers (< 1024)
                            if beacon.control_port < 1024 || beacon.clipboard_port < 1024 {
                                tracing::debug!(
                                    "Dropped discovery beacon with privileged/invalid ports from {}",
                                    peer_ip
                                );
                                continue;
                            }

                            // Reject beacons containing control characters or Unicode BiDi formatting markers
                            if contains_unsafe_text_chars(&beacon.sender_name)
                                || contains_unsafe_text_chars(&beacon.os)
                                || contains_unsafe_text_chars(&beacon.hardware_model)
                                || beacon
                                    .share_name
                                    .as_deref()
                                    .is_some_and(contains_unsafe_text_chars)
                                || beacon
                                    .sunshine_name
                                    .as_deref()
                                    .is_some_and(contains_unsafe_text_chars)
                                || beacon.gpus.iter().any(|g| contains_unsafe_text_chars(g))
                            {
                                tracing::debug!(
                                    "Dropped discovery beacon containing control/bidi characters from {}",
                                    peer_ip
                                );
                                continue;
                            }

                            // Construct canonical metadata structure for Ed25519 signature verification
                            let signed_meta = trust::DiscoveryBeaconSignedMeta {
                                protocol_version: beacon.protocol_version,
                                sender_name: &beacon.sender_name,
                                os: &beacon.os,
                                hardware_model: &beacon.hardware_model,
                                display_width: beacon.display_width,
                                display_height: beacon.display_height,
                                display_fps: beacon.display_fps,
                                share_name: beacon.share_name.as_deref(),
                                sunshine_name: beacon.sunshine_name.as_deref(),
                                sunshine_port: beacon.sunshine_port,
                                gpus: &beacon.gpus,
                            };

                            // Verify Ed25519 signature and timestamp freshness (±60 seconds)
                            if !trust::verify_discovery_beacon_v2_full(
                                &dev_id,
                                &beacon.ed25519_pubkey,
                                beacon.timestamp_ms,
                                beacon.control_port,
                                beacon.clipboard_port,
                                Some(addr.ip()),
                                &signed_meta,
                                &beacon.beacon_sig,
                            ) {
                                tracing::debug!(
                                    "Dropped invalid, blocked, or stale discovery beacon from {}",
                                    peer_ip
                                );
                                continue;
                            }

                            // Enforce anti-replay sliding window checks
                            let replay_ok = {
                                let mut rc = replay_cache
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                rc.accept(&dev_id, addr.ip(), beacon.timestamp_ms, Instant::now())
                            };
                            if !replay_ok {
                                tracing::debug!(
                                    "Dropped replayed discovery beacon for device {} from {}",
                                    dev_id,
                                    peer_ip
                                );
                                continue;
                            }

                            let valid_control_port = beacon.control_port;
                            let peer_ip_for_route = peer_ip.clone();
                            let my_name_clone = my_name.clone();
                            let sender_name_clean =
                                sanitize_display_text(&beacon.sender_name, 128);
                            if sender_name_clean.is_empty() {
                                continue;
                            }
                            let sender_name_clone = sender_name_clean.clone();
                            let dev_id_clone = dev_id.clone();

                            // Offload blocking OS routing table query to blocking pool
                            let Ok((
                                is_self_ip,
                                transport,
                                speed_mbps,
                                link_desc,
                                local_ip,
                                same_subnet,
                                trusted,
                            )) = tokio::task::spawn_blocking(move || {
                                let is_self = sender_name_clone == my_name_clone
                                    && is_own_local_ip(&peer_ip_for_route);
                                if is_self {
                                    return (
                                        true,
                                        LinkTransport::Unknown,
                                        None,
                                        String::new(),
                                        None,
                                        false,
                                        false,
                                    );
                                }
                                let (transport, speed_mbps, link_desc, local_ip) =
                                    system_info::describe_route_to_peer(&peer_ip_for_route);
                                let same_subnet = system_info::is_same_subnet_as_peer(
                                    local_ip.as_deref(),
                                    &peer_ip_for_route,
                                );
                                let trusted = trust::observe_discovered_peer(
                                    &dev_id_clone,
                                    &sender_name_clone,
                                    &peer_ip_for_route,
                                    transport.is_direct_cable(),
                                );
                                // Persist verified paired peer IPs only, preventing spoofed LAN history pollution
                                if trusted {
                                    record_recent_peer_ip(&peer_ip_for_route);
                                }
                                (
                                    false,
                                    transport,
                                    speed_mbps,
                                    link_desc,
                                    local_ip,
                                    same_subnet,
                                    trusted,
                                )
                            })
                            .await
                            else {
                                continue;
                            };

                            if is_self_ip {
                                continue;
                            }

                            // Refresh TCP RTT in background at most once every 4 seconds per IP
                            let cached_rtt = {
                                let cache_guard = rtt_cache.read().await;
                                cache_guard.get(&peer_ip).map(|(t, r)| (t.elapsed(), *r))
                            };
                            let rtt_ms = match cached_rtt {
                                Some((age, r)) if age < Duration::from_secs(4) => Some(r),
                                _ => {
                                    if let Ok(permit) = Arc::clone(&rtt_probe_limiter).try_acquire_owned() {
                                        let probe_ip = peer_ip.clone();
                                        let probe_port = valid_control_port;
                                        let rtt_map = Arc::clone(&rtt_cache);
                                        let cands_ref = Arc::clone(&candidates);
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            if let Some(measured) =
                                                measure_tcp_connect_rtt(&probe_ip, probe_port).await
                                            {
                                                {
                                                    let mut cache = rtt_map.write().await;
                                                    let now = Instant::now();
                                                    cache.retain(|_, (ts, _)| {
                                                        now.saturating_duration_since(*ts) < RTT_CACHE_TTL
                                                    });
                                                    if !cache.contains_key(&probe_ip)
                                                        && cache.len() >= MAX_RTT_CACHE_ENTRIES
                                                    {
                                                        if let Some(oldest_ip) = cache
                                                            .iter()
                                                            .min_by_key(|(_, (ts, _))| *ts)
                                                            .map(|(k, _)| k.clone())
                                                        {
                                                            cache.remove(&oldest_ip);
                                                        }
                                                    }
                                                    cache.insert(probe_ip.clone(), (now, measured));
                                                }
                                                let mut list = cands_ref.write().await;
                                                for c in list.iter_mut() {
                                                    if c.addr.ip().to_string() == probe_ip {
                                                        c.rtt_ms = Some(measured);
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    cached_rtt.map(|(_, r)| r)
                                }
                            };

                            let sanitized_share = beacon
                                .share_name
                                .as_deref()
                                .and_then(|s| crate::storage::validate_smb_share_name(s).ok());
                            let sanitized_gpus: Vec<String> = beacon
                                .gpus
                                .into_iter()
                                .take(8)
                                .map(|g| sanitize_display_text(&g, 128))
                                .filter(|g| !g.is_empty())
                                .collect();

                            let mut list = candidates.write().await;
                            let now = Instant::now();

                            let os_clean = sanitize_display_text(&beacon.os, 64);
                            let hw_model_clean = sanitize_display_text(&beacon.hardware_model, 128);
                            let raw_ff = sanitize_display_text(&beacon.form_factor, 32);
                            let form_factor = system_info::infer_peer_form_factor(
                                &os_clean,
                                &hw_model_clean,
                                (!raw_ff.is_empty()).then_some(raw_ff.as_str()),
                            )
                            .as_str()
                            .to_string();

                            let candidate = PeerCandidate {
                                addr: SocketAddr::new(addr.ip(), valid_control_port),
                                last_seen: now,
                                os: os_clean,
                                device_id: dev_id,
                                device_name: sender_name_clean,
                                hardware_model: hw_model_clean,
                                form_factor,
                                display_width: beacon.display_width.clamp(0, MAX_DISPLAY_WIDTH),
                                display_height: beacon.display_height.clamp(0, MAX_DISPLAY_HEIGHT),
                                display_fps: beacon.display_fps.clamp(0, MAX_DISPLAY_FPS),
                                share_name: sanitized_share,
                                sunshine_name: beacon
                                    .sunshine_name
                                    .map(|s| sanitize_display_text(&s, 128))
                                    .filter(|s| !s.is_empty()),
                                sunshine_port: if beacon.sunshine_port >= 1024 {
                                    beacon.sunshine_port
                                } else {
                                    SUNSHINE_DEFAULT_PORT
                                },
                                gpus: sanitized_gpus,
                                transport,
                                link_speed_mbps: speed_mbps,
                                link_description: link_desc,
                                local_ip_used: local_ip,
                                same_subnet,
                                rtt_ms,
                                trusted,
                                discovery_source: "udp".to_string(),
                            };

                            upsert_peer_candidate(&mut list, candidate, now);

                            // Re-evaluate best candidate route
                            let best = select_best_peer(&list).map(|c| c.addr.ip().to_string());
                            let mut active = active_peer_ip.write().await;
                            if *active != best {
                                *active = best.clone();
                                if let Some(ref b) = best {
                                    tracing::info!(
                                        "📡 Selected active peer route: {} ({})",
                                        b,
                                        transport.label()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Discovery recv error: {}", e);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        });

        // --------------------------------------------------------------------
        // Task 2: UDP Beacon Broadcaster Task
        // --------------------------------------------------------------------
        let broadcaster_socket = Arc::clone(udp_sock);
        let manual_ips_ref = Arc::clone(&self.manual_ips);
        let candidates_for_unicast = Arc::clone(&self.candidates);
        let fallback_name = self.local_name.clone();

        tokio::spawn(async move {
            loop {
                let manual_snapshot = manual_ips_ref.read().await.clone();
                let active_candidate_ips: Vec<String> = {
                    let guard = candidates_for_unicast.read().await;
                    let now = Instant::now();
                    guard
                        .iter()
                        .filter(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL)
                        .take(16)
                        .map(|c| c.addr.ip().to_string())
                        .collect()
                };
                let fallback_clone = fallback_name.clone();

                // Offload profile collection, beacon signing, and interface broadcast to blocking pool
                if let Ok((bytes, no_endpoints, unicast_targets)) =
                    tokio::task::spawn_blocking(move || {
                    let profile = system_info::collect_local_profile();
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let sender_name = sanitize_display_text(
                        if profile.hostname.is_empty() {
                            &fallback_clone
                        } else {
                            &profile.hostname
                        },
                        128,
                    );
                    let os = sanitize_display_text(&profile.os, 64);
                    let hardware_model = sanitize_display_text(&profile.hardware_model, 128);
                    let share_name = profile
                        .default_share_names
                        .first()
                        .and_then(|s| crate::storage::validate_smb_share_name(s).ok());
                    let sunshine_name = profile
                        .sunshine_name
                        .as_deref()
                        .map(|s| sanitize_display_text(s, 128))
                        .filter(|s| !s.is_empty());
                    let gpus: Vec<String> = profile
                        .gpus
                        .iter()
                        .take(8)
                        .map(|g| sanitize_display_text(&g.name, 128))
                        .filter(|g| !g.is_empty())
                        .collect();

                    let signed_meta = trust::DiscoveryBeaconSignedMeta {
                        protocol_version: DISCOVERY_PROTOCOL_VERSION,
                        sender_name: &sender_name,
                        os: &os,
                        hardware_model: &hardware_model,
                        display_width: profile.primary_display.width,
                        display_height: profile.primary_display.height,
                        display_fps: profile.primary_display.fps,
                        share_name: share_name.as_deref(),
                        sunshine_name: sunshine_name.as_deref(),
                        sunshine_port: profile.sunshine_port,
                        gpus: &gpus,
                    };

                    // Cryptographically sign discovery beacon with local Ed25519 identity key
                    let (signed_dev_id, ed25519_pubkey, sig) =
                        trust::sign_discovery_beacon_v2_full(
                            ts,
                            CONTROL_PORT,
                            CLIPBOARD_PORT,
                            &signed_meta,
                        );

                    let beacon = DiscoveryBeacon {
                        protocol_version: DISCOVERY_PROTOCOL_VERSION,
                        device_id: signed_dev_id,
                        ed25519_pubkey,
                        sender_name,
                        os,
                        hardware_model,
                        form_factor: profile.form_factor.as_str().to_string(),
                        control_port: CONTROL_PORT,
                        clipboard_port: CLIPBOARD_PORT,
                        display_width: profile.primary_display.width,
                        display_height: profile.primary_display.height,
                        display_fps: profile.primary_display.fps,
                        share_name,
                        sunshine_name,
                        sunshine_port: profile.sunshine_port,
                        gpus,
                        timestamp_ms: ts,
                        beacon_sig: sig,
                    };

                    let bytes = serde_json::to_vec(&beacon).unwrap_or_default();
                    let endpoints = system_info::discovery_interface_endpoints();
                    let mut unicast_targets: Vec<String> = Vec::new();
                    let mut seen: HashSet<String> = HashSet::new();
                    let hist = load_peer_history();

                    // Accumulate manual IP overrides, active verified candidate IPs (for bidirectional
                    // discovery on broadcast-isolated APs), and recent peer history for unicast delivery
                    for ip in manual_snapshot
                        .iter()
                        .chain(active_candidate_ips.iter())
                        .chain(hist.recent_ips.iter())
                    {
                        if seen.insert(ip.clone()) {
                            unicast_targets.push(ip.clone());
                        }
                    }

                    // Transmit beacon onto each physical interface broadcast endpoint
                    if !bytes.is_empty() {
                        for (iface_name, ip_str, bcast_str, _transport) in &endpoints {
                            broadcast_beacon_on_interface(
                                iface_name,
                                ip_str,
                                bcast_str,
                                DISCOVERY_PORT,
                                &bytes,
                            );
                        }
                    }
                    (bytes, endpoints.is_empty(), unicast_targets)
                })
                .await
                {
                    if !bytes.is_empty() {
                        // Fallback to global broadcast if no discrete interface endpoints were enumerated
                        if no_endpoints {
                            let global_bcast = SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::BROADCAST),
                                DISCOVERY_PORT,
                            );
                            let _ = broadcaster_socket.send_to(&bytes, global_bcast).await;
                        }
                        // Send direct unicast datagrams to manual and recent peer endpoints
                        for ip in unicast_targets {
                            if let Ok(parsed) = ip.parse::<IpAddr>() {
                                let target = SocketAddr::new(parsed, DISCOVERY_PORT);
                                let _ = broadcaster_socket.send_to(&bytes, target).await;
                            }
                        }
                    }
                }

                // Sleep for 2 seconds between discovery broadcast cycles
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        } // end if let Some(ref udp_sock) = socket

        // --------------------------------------------------------------------
        // Task 3: Bonjour / mDNS (`_integrator._tcp.local.`) Discovery Task
        // --------------------------------------------------------------------
        let hint_probe_times: Arc<Mutex<HashMap<(Ipv4Addr, &'static str), Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let my_trust_id = trust::local_device_id_hex();
        let my_trust_prefix: String = my_trust_id.chars().take(8).collect();

        if mode.bonjour_enabled() {
            if let Some(mut bonjour_rx) =
                crate::bonjour_discovery::start_bonjour_discovery(my_trust_id.clone(), true, true)
            {
                let cands_ref = Arc::clone(&self.candidates);
                let active_ref = Arc::clone(&self.active_peer_ip);
                let probe_times = Arc::clone(&hint_probe_times);
                let own_id = my_trust_id.clone();

                tokio::spawn(async move {
                    while let Some(hint) = bonjour_rx.recv().await {
                        if hint.device_id.as_deref() == Some(own_id.as_str()) {
                            continue;
                        }
                        if !allow_hint_probe(&probe_times, hint.ip, "bonjour") {
                            continue;
                        }
                        let cands = Arc::clone(&cands_ref);
                        let active = Arc::clone(&active_ref);
                        let expected_id = hint.device_id.clone();
                        tokio::spawn(async move {
                            ingest_authenticated_hint(
                                &cands,
                                &active,
                                hint.ip,
                                hint.port,
                                expected_id.as_deref(),
                                None,
                                "bonjour",
                            )
                            .await;
                        });
                    }
                });
            }
        }

        // --------------------------------------------------------------------
        // Task 4: BLE Magic-Packet Proximity Discovery Task
        // --------------------------------------------------------------------
        if mode.ble_enabled() {
            if let Some(mut ble_rx) =
                crate::ble_discovery::start_ble_discovery(my_trust_id.clone(), true, true)
            {
                let cands_ref = Arc::clone(&self.candidates);
                let active_ref = Arc::clone(&self.active_peer_ip);
                let probe_times = Arc::clone(&hint_probe_times);
                let own_prefix = my_trust_prefix.clone();

                tokio::spawn(async move {
                    while let Some(hint) = ble_rx.recv().await {
                        if hint.device_id_prefix == own_prefix {
                            continue;
                        }
                        if !allow_hint_probe(&probe_times, hint.ip, "ble") {
                            continue;
                        }
                        let cands = Arc::clone(&cands_ref);
                        let active = Arc::clone(&active_ref);
                        let prefix = hint.device_id_prefix.clone();
                        tokio::spawn(async move {
                            ingest_authenticated_hint(
                                &cands,
                                &active,
                                hint.ip,
                                hint.port,
                                None,
                                Some(prefix.as_str()),
                                "ble",
                            )
                            .await;
                        });
                    }
                });
            }
        }

        Ok(())
    }
}

/// Rate-limits repeated Bonjour/BLE authentication probes to the same IPv4 address (at most once every 3s).
fn allow_hint_probe(
    probe_times: &Mutex<HashMap<(Ipv4Addr, &'static str), Instant>>,
    ip: Ipv4Addr,
    source: &'static str,
) -> bool {
    const HINT_PROBE_COOLDOWN: Duration = Duration::from_secs(3);
    let mut guard = probe_times.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    guard.retain(|_, ts| now.saturating_duration_since(*ts) < Duration::from_secs(60));
    if let Some(prev) = guard.get(&(ip, source)) {
        if now.saturating_duration_since(*prev) < HINT_PROBE_COOLDOWN {
            return false;
        }
    }
    guard.insert((ip, source), now);
    true
}

/// Performs a full mutually authenticated `TransportSessionV2` (`ServiceId::DisplayRpc`)
/// `GetHardwareProfile` handshake against a Bonjour- or BLE-hinted `(peer_ip, port)`.
///
/// # Security Invariant
/// Neither Bonjour nor BLE grants any trust. Authentication succeeds ONLY when the remote
/// peer proves possession of a paired Ed25519 identity key via `TransportSessionV2` AEAD.
async fn authenticate_hint_via_transport_v2(
    peer_ip: Ipv4Addr,
    port: u16,
    expected_device_id: Option<&str>,
    expected_prefix: Option<&str>,
) -> Result<(String, Option<system_info::LocalHardwareProfile>, f64)> {
    use crate::display::protocol::{DisplayRpcRequest, DisplayRpcResponse};
    use crate::security::transport::ServiceId;

    if peer_ip.is_loopback() || peer_ip.is_unspecified() || peer_ip.is_broadcast() || port < 1024 {
        anyhow::bail!("Invalid hinted peer endpoint {}:{}", peer_ip, port);
    }

    let ip_str = peer_ip.to_string();
    let start = Instant::now();
    let mut session = trust::connect_transport_to_hinted_ip(
        &ip_str,
        port,
        ServiceId::DisplayRpc,
        Duration::from_secs(4),
        expected_device_id,
        expected_prefix,
    )
    .await
    .map_err(|e| anyhow::anyhow!("TransportV2 authentication to {}:{} failed: {}", ip_str, port, e))?;

    let verified_device_id = session.peer_device_id_hex().to_ascii_lowercase();
    let req_bytes = serde_json::to_vec(&DisplayRpcRequest::GetHardwareProfile)?;
    tokio::time::timeout(Duration::from_secs(4), session.send_message(&req_bytes))
        .await
        .map_err(|_| anyhow::anyhow!("Timed out sending GetHardwareProfile to {}", ip_str))?
        .map_err(|e| anyhow::anyhow!("TransportV2 send error to {}: {}", ip_str, e))?;

    let resp_bytes = tokio::time::timeout(Duration::from_secs(5), session.recv_message())
        .await
        .map_err(|_| anyhow::anyhow!("Timed out receiving GetHardwareProfile from {}", ip_str))?
        .map_err(|e| anyhow::anyhow!("TransportV2 recv error from {}: {}", ip_str, e))?;

    let rtt_ms = ((start.elapsed().as_secs_f64() * 1000.0) * 100.0).round() / 100.0;
    let resp: DisplayRpcResponse = serde_json::from_slice(&resp_bytes)?;
    if !resp.success {
        anyhow::bail!(
            "Remote GetHardwareProfile RPC rejected by {}: {}",
            ip_str,
            resp.message
        );
    }
    Ok((verified_device_id, resp.hardware_profile, rtt_ms))
}

/// Authenticates a Bonjour or BLE discovery hint via `TransportSessionV2` and upserts the
/// verified peer into `DiscoveryManager`'s active candidate table.
async fn ingest_authenticated_hint(
    candidates: &Arc<RwLock<Vec<PeerCandidate>>>,
    active_peer_ip: &Arc<RwLock<Option<String>>>,
    peer_ip: Ipv4Addr,
    port: u16,
    expected_device_id: Option<&str>,
    expected_prefix: Option<&str>,
    source: &'static str,
) {
    let ip_str = peer_ip.to_string();
    let is_self = tokio::task::spawn_blocking({
        let s = ip_str.clone();
        move || is_own_local_ip(&s)
    })
    .await
    .unwrap_or(false);
    if is_self {
        return;
    }

    let Ok((verified_dev_id, prof_opt, rtt_ms)) = authenticate_hint_via_transport_v2(
        peer_ip,
        port,
        expected_device_id,
        expected_prefix,
    )
    .await
    else {
        return;
    };

    if let Some(exp) = expected_device_id {
        if !verified_dev_id.eq_ignore_ascii_case(exp) {
            tracing::warn!(
                "Rejected {} hint from {}: authenticated device_id {} != hinted {}",
                source,
                ip_str,
                verified_dev_id,
                exp
            );
            return;
        }
    }
    if let Some(pfx) = expected_prefix {
        if !verified_dev_id.starts_with(&pfx.to_ascii_lowercase()) {
            tracing::warn!(
                "Rejected {} hint from {}: authenticated device_id {} does not match prefix {}",
                source,
                ip_str,
                verified_dev_id,
                pfx
            );
            return;
        }
    }

    let prof = match prof_opt {
        Some(p) => p,
        None => return,
    };
    let hostname = sanitize_display_text(&prof.hostname, 128);
    if hostname.is_empty() {
        return;
    }

    let ip_for_route = ip_str.clone();
    let dev_for_obs = verified_dev_id.clone();
    let host_for_obs = hostname.clone();
    let Ok((transport, speed_mbps, link_desc, local_ip, same_subnet, trusted)) =
        tokio::task::spawn_blocking(move || {
            let (transport, speed_mbps, link_desc, local_ip) =
                system_info::describe_route_to_peer(&ip_for_route);
            let same_subnet =
                system_info::is_same_subnet_as_peer(local_ip.as_deref(), &ip_for_route);
            let trusted = trust::observe_discovered_peer(
                &dev_for_obs,
                &host_for_obs,
                &ip_for_route,
                transport.is_direct_cable(),
            );
            if trusted {
                record_recent_peer_ip(&ip_for_route);
            }
            (transport, speed_mbps, link_desc, local_ip, same_subnet, trusted)
        })
        .await
    else {
        return;
    };

    let os_clean = sanitize_display_text(&prof.os, 64);
    let hw_clean = sanitize_display_text(&prof.hardware_model, 128);
    let form_factor = system_info::infer_peer_form_factor(
        &os_clean,
        &hw_clean,
        Some(prof.form_factor.as_str()),
    )
    .as_str()
    .to_string();

    let candidate = PeerCandidate {
        addr: SocketAddr::new(IpAddr::V4(peer_ip), port),
        last_seen: Instant::now(),
        os: os_clean,
        device_id: verified_dev_id,
        device_name: hostname.clone(),
        hardware_model: hw_clean,
        form_factor,
        display_width: prof.primary_display.width.clamp(0, MAX_DISPLAY_WIDTH),
        display_height: prof.primary_display.height.clamp(0, MAX_DISPLAY_HEIGHT),
        display_fps: prof.primary_display.fps.clamp(0, MAX_DISPLAY_FPS),
        share_name: prof
            .default_share_names
            .first()
            .and_then(|s| crate::storage::validate_smb_share_name(s).ok()),
        sunshine_name: prof
            .sunshine_name
            .map(|s| sanitize_display_text(&s, 128))
            .filter(|s| !s.is_empty()),
        sunshine_port: if prof.sunshine_port >= 1024 {
            prof.sunshine_port
        } else {
            SUNSHINE_DEFAULT_PORT
        },
        gpus: prof
            .gpus
            .into_iter()
            .take(8)
            .map(|g| sanitize_display_text(&g.name, 128))
            .filter(|g| !g.is_empty())
            .collect(),
        transport,
        link_speed_mbps: speed_mbps,
        link_description: link_desc,
        local_ip_used: local_ip,
        same_subnet,
        rtt_ms: Some(rtt_ms),
        trusted,
        discovery_source: source.to_string(),
    };

    let mut list = candidates.write().await;
    let now = Instant::now();
    upsert_peer_candidate(&mut list, candidate, now);
    let best = select_best_peer(&list).map(|c| c.addr.ip().to_string());
    let mut active = active_peer_ip.write().await;
    if *active != best {
        *active = best.clone();
        if let Some(ref b) = best {
            tracing::info!(
                "📡 Selected active peer route via {}: {} ({}, {:.2} ms)",
                source,
                b,
                transport.label(),
                rtt_ms
            );
        }
    }
}

/// Executes an isolated, end-to-end **BLE-only** discovery + cryptographic `TransportSessionV2`
/// authentication verification (zero UDP `:58280`, zero Bonjour mDNS, zero cached IPs).
pub async fn authenticate_peer_via_ble(timeout: Duration) -> Result<AuthDiscoveryProof> {
    let own_id = trust::local_device_id_hex();
    let hint = crate::ble_discovery::scan_once_for_ble_hint(&own_id, timeout).await?;

    let (verified_dev_id, prof_opt, rtt_ms) = authenticate_hint_via_transport_v2(
        hint.ip,
        hint.port,
        None,
        Some(hint.device_id_prefix.as_str()),
    )
    .await?;

    if !verified_dev_id.starts_with(&hint.device_id_prefix) {
        anyhow::bail!(
            "BLE prefix mismatch: BLE packet advertised prefix '{}' at {}:{}, but TransportV2 authenticated '{}'",
            hint.device_id_prefix,
            hint.ip,
            hint.port,
            verified_dev_id
        );
    }

    let (peer_hostname, peer_os, peer_form_factor) = match prof_opt {
        Some(p) => (p.hostname, p.os, p.form_factor.as_str().to_string()),
        None => ("Unknown".to_string(), "unknown".to_string(), "unknown".to_string()),
    };

    Ok(AuthDiscoveryProof {
        transport: "ble".to_string(),
        hint_detail: format!(
            "format={} prefix={} rssi={}dBm",
            hint.format, hint.device_id_prefix, hint.rssi
        ),
        discovered_ip: hint.ip.to_string(),
        discovered_port: hint.port,
        authenticated: true,
        peer_device_id: verified_dev_id,
        peer_hostname,
        peer_os,
        peer_form_factor,
        rtt_ms,
    })
}

/// Executes an isolated, end-to-end **Bonjour-only** (`_integrator._tcp.local.`) discovery +
/// cryptographic `TransportSessionV2` authentication verification (zero UDP `:58280`, zero BLE, zero cached IPs).
pub async fn authenticate_peer_via_bonjour(timeout: Duration) -> Result<AuthDiscoveryProof> {
    let own_id = trust::local_device_id_hex();
    let hint = crate::bonjour_discovery::browse_once_for_bonjour_hint(&own_id, timeout).await?;

    let (verified_dev_id, prof_opt, rtt_ms) = authenticate_hint_via_transport_v2(
        hint.ip,
        hint.port,
        hint.device_id.as_deref(),
        None,
    )
    .await?;

    if let Some(ref txt_id) = hint.device_id {
        if !verified_dev_id.eq_ignore_ascii_case(txt_id) {
            anyhow::bail!(
                "Bonjour TXT device_id mismatch: mDNS advertised '{}' at {}:{}, but TransportV2 authenticated '{}'",
                txt_id,
                hint.ip,
                hint.port,
                verified_dev_id
            );
        }
    }

    let (peer_hostname, peer_os, peer_form_factor) = match prof_opt {
        Some(p) => (p.hostname, p.os, p.form_factor.as_str().to_string()),
        None => (
            hint.hostname,
            hint.os.unwrap_or_else(|| "unknown".to_string()),
            hint.form_factor.unwrap_or_else(|| "unknown".to_string()),
        ),
    };

    Ok(AuthDiscoveryProof {
        transport: "bonjour".to_string(),
        hint_detail: hint.fullname,
        discovered_ip: hint.ip.to_string(),
        discovered_port: hint.port,
        authenticated: true,
        peer_device_id: verified_dev_id,
        peer_hostname,
        peer_os,
        peer_form_factor,
        rtt_ms,
    })
}

/// Transmits a UDP discovery beacon packet out of a specific physical network interface.
///
/// # Platform Behavior:
/// - On macOS: Uses `setsockopt(..., IPPROTO_IP, IP_BOUND_IF, ...)` to strictly bind the socket
///   to the interface index corresponding to `iface_name`. This ensures that packets meant for a
///   direct Thunderbolt or USB4 bridge do not leak across Wi-Fi or primary Ethernet.
/// - Transmits to both the subnet-directed broadcast address (`bcast_ip_str`) and the global
///   broadcast address (`255.255.255.255`).
fn broadcast_beacon_on_interface(
    iface_name: &str,
    local_ip_str: &str,
    bcast_ip_str: &str,
    port: u16,
    bytes: &[u8],
) {
    let Ok(local_v4) = local_ip_str.parse::<Ipv4Addr>() else {
        return;
    };
    let bind_addr = SocketAddr::new(IpAddr::V4(local_v4), 0);
    let Ok(sock) = std::net::UdpSocket::bind(bind_addr) else {
        return;
    };
    if sock.set_broadcast(true).is_err() {
        return;
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        if let Ok(c_name) = CString::new(iface_name) {
            // SAFETY: c_name is NUL-terminated; if_nametoindex returns 0 if not found.
            let if_idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if if_idx != 0 {
                // SAFETY: valid open IPv4 socket fd and u32 interface index for IP_BOUND_IF.
                unsafe {
                    let idx_u32 = if_idx as u32;
                    let _ = libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_BOUND_IF,
                        &idx_u32 as *const u32 as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    );
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = iface_name;

    // Transmit to directed subnet broadcast
    if let Ok(bcast_v4) = bcast_ip_str.parse::<Ipv4Addr>() {
        let _ = sock.send_to(bytes, SocketAddr::new(IpAddr::V4(bcast_v4), port));
    }
    // Transmit to global subnet broadcast
    let _ = sock.send_to(bytes, SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port));
}

/// Inserts or refreshes a verified `PeerCandidate` in the active candidate table.
///
/// # Multi-Homed & DHCP Lease Failover Rules
/// 1. Prunes candidates older than [`PEER_CANDIDATE_TTL`].
/// 2. If the same `device_id` was previously seen on the **exact same local interface** (`local_ip_used`)
///    at a different source IP (e.g. DHCP lease change on hotspot reconnect `172.20.10.15` -> `172.20.10.7`),
///    immediately replaces the stale candidate on that interface while preserving simultaneous routes
///    on other interfaces (e.g. USB-C `10.99.99.2` + Wi-Fi/Hotspot `172.20.10.2`).
/// 3. Enforces [`MAX_PEER_CANDIDATES`] capacity bounds.
fn upsert_peer_candidate(list: &mut Vec<PeerCandidate>, candidate: PeerCandidate, now: Instant) {
    list.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);

    // Evict stale DHCP address for the same device on the same local interface
    if !candidate.device_id.is_empty() && candidate.local_ip_used.is_some() {
        list.retain(|c| {
            !(c.device_id == candidate.device_id
                && c.local_ip_used == candidate.local_ip_used
                && c.addr.ip() != candidate.addr.ip())
        });
    }

    if let Some(existing) = list.iter_mut().find(|c| c.addr.ip() == candidate.addr.ip()) {
        // Merge discovery_source tags cleanly (e.g. "udp+bonjour+ble")
        let merged_source = merge_discovery_sources(&existing.discovery_source, &candidate.discovery_source);
        *existing = candidate;
        existing.discovery_source = merged_source;
    } else {
        if list.len() >= MAX_PEER_CANDIDATES {
            if let Some(evict_idx) = list
                .iter()
                .enumerate()
                .filter(|(_, c)| !c.trusted)
                .min_by_key(|(_, c)| c.last_seen)
                .or_else(|| list.iter().enumerate().min_by_key(|(_, c)| c.last_seen))
                .map(|(i, _)| i)
            {
                list.swap_remove(evict_idx);
            }
        }
        list.push(candidate);
    }
}

/// Merges discovery transport source tags (e.g. `"udp"` + `"bonjour"` -> `"udp+bonjour"`) without duplicates.
fn merge_discovery_sources(existing: &str, incoming: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for tag in existing.split('+').chain(incoming.split('+')) {
        let t = tag.trim();
        if !t.is_empty() && !parts.contains(&t) {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        "udp".to_string()
    } else {
        parts.join("+")
    }
}

/// Evaluates a collection of active peer candidates and selects the single best candidate route.
///
/// # Priority Hierarchy:
/// 1. **Trust Status**: Trusted (cryptographically paired) peers strictly take precedence over untrusted peers.
/// 2. **Subnet Alignment**: Direct matching interface subnet beats routed or alien alias IPs.
/// 3. **Physical Transport Medium**: Thunderbolt 4 / USB4 (`Thunderbolt`) > USB-C NCM (`DirectUsb`) > Wired Ethernet > Wi-Fi LAN > Mobile Hotspot > Unknown.
/// 4. **Measured Latency**: Lower measured round-trip time (RTT in ms).
/// 5. **Recency**: Most recently observed beacon timestamp.
fn select_best_peer(candidates: &[PeerCandidate]) -> Option<PeerCandidate> {
    candidates
        .iter()
        .min_by(|a, b| {
            // 1. Trusted peers strictly first
            b.trusted
                .cmp(&a.trusted)
                // 2. Directly on a matching local interface subnet (beats routed alias IPs)
                .then_with(|| b.same_subnet.cmp(&a.same_subnet))
                // 3. Physical / wired / faster transport first
                .then_with(|| a.transport.route_priority().cmp(&b.transport.route_priority()))
                // 4. Lower measured RTT if available
                .then_with(|| {
                    let ar = a.rtt_ms.unwrap_or(UNMEASURED_RTT_SENTINEL_MS);
                    let br = b.rtt_ms.unwrap_or(UNMEASURED_RTT_SENTINEL_MS);
                    ar.partial_cmp(&br).unwrap_or(std::cmp::Ordering::Equal)
                })
                // 5. More recently seen
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        })
        .cloned()
}

/// Checks whether the given IP address matches one of the local machine's network interface addresses.
fn is_own_local_ip(ip: &str) -> bool {
    system_info::list_local_ipv4_interfaces()
        .iter()
        .any(|iface| iface.ip == ip)
}

/// Measures TCP connection round-trip latency to `ip:port` with a bounded probe timeout.
///
/// Drops the TCP stream immediately upon completing the 3-way handshake.
async fn measure_tcp_connect_rtt(ip: &str, port: u16) -> Option<f64> {
    let Ok(parsed) = ip.parse::<IpAddr>() else {
        return None;
    };
    let target = SocketAddr::new(parsed, port);
    let start = Instant::now();
    if let Ok(Ok(stream)) =
        tokio::time::timeout(TCP_RTT_PROBE_TIMEOUT, TcpStream::connect(target)).await
    {
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        drop(stream);
        return Some((ms * 100.0).round() / 100.0);
    }
    None
}

/// Resolves the filesystem path to `peer_history.json` in the user's application data directory.
fn history_path() -> std::path::PathBuf {
    system_info::app_data_dir().join("peer_history.json")
}

/// Loads peer IP history from `peer_history.json` with file locking and schema sanitization.
fn load_peer_history() -> PeerHistoryFile {
    let _guard = history_file_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut parsed: PeerHistoryFile = std::fs::read_to_string(history_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    parsed
        .recent_ips
        .retain(|ip| system_info::is_valid_ipv4(ip));
    parsed.recent_ips.truncate(8);
    parsed
        .manual_ips
        .retain(|ip| system_info::is_valid_ipv4(ip));
    parsed.manual_ips.truncate(MAX_MANUAL_IPS);
    parsed
}

/// Persists peer IP history atomically to disk using a unique temporary file and atomic rename.
fn save_peer_history(hist: &PeerHistoryFile) {
    let _guard = history_file_lock().lock().unwrap_or_else(|e| e.into_inner());
    let Ok(json) = serde_json::to_string_pretty(hist) else {
        return;
    };
    let path = history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let seq = HISTORY_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.{}.{}.tmp", std::process::id(), seq));
    if std::fs::write(&tmp, json.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    if std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Adds a verified, authenticated peer IP address to the recent peers list.
///
/// Uses an in-memory ring buffer (`RECENT_SEEN`) to debounce duplicate writes.
fn record_recent_peer_ip(ip: &str) {
    static RECENT_SEEN: OnceLock<Mutex<(VecDeque<String>, HashSet<String>)>> = OnceLock::new();
    let seen = RECENT_SEEN.get_or_init(|| Mutex::new((VecDeque::new(), HashSet::new())));
    {
        let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
        if guard.1.contains(ip) {
            return;
        }
        if guard.0.len() >= MAX_RECENT_SEEN {
            if let Some(evicted) = guard.0.pop_front() {
                guard.1.remove(&evicted);
            }
        }
        guard.0.push_back(ip.to_string());
        guard.1.insert(ip.to_string());
    }
    let mut hist = load_peer_history();
    if !hist.recent_ips.iter().any(|x| x == ip) {
        hist.recent_ips.insert(0, ip.to_string());
        hist.recent_ips.truncate(8);
        save_peer_history(&hist);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicate_and_stale_but_allows_dual_interface_burst() {
        let mut cache = BeaconReplayCache::default();
        let usb_ip: IpAddr = "169.254.10.2".parse().unwrap();
        let wifi_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let spoof_ip: IpAddr = "10.0.0.99".parse().unwrap();
        let now = Instant::now();

        assert!(cache.accept("dev1", usb_ip, 100_000, now));
        // Duplicate exact beacon from same IP rejected
        assert!(!cache.accept("dev1", usb_ip, 100_000, now));
        // Older beacon on same IP rejected
        assert!(!cache.accept("dev1", usb_ip, 99_500, now));
        // Same timestamp burst arriving on second interface (Wi-Fi) accepted
        assert!(cache.accept("dev1", wifi_ip, 100_000, now));

        // Newer beacon advances max_ts_ms
        assert!(cache.accept("dev1", usb_ip, 110_000, now));
        // Stale beacon (>3s older than max_ts_ms) replayed on spoofed IP rejected
        assert!(!cache.accept("dev1", spoof_ip, 105_000, now));
    }

    #[test]
    fn sanitize_strips_control_and_bidi_chars() {
        assert!(contains_unsafe_text_chars("evil\u{202E}name"));
        assert!(contains_unsafe_text_chars("bad\nline"));
        assert_eq!(sanitize_display_text("  Mac\u{202E}Book\x07Pro  ", 64), "MacBookPro");
    }

    #[test]
    fn select_best_peer_prefers_trusted_same_subnet_and_wired_transports() {
        let now = Instant::now();
        let make = |ip: &str, transport: LinkTransport, same_subnet: bool, rtt: f64| PeerCandidate {
            addr: SocketAddr::new(ip.parse().unwrap(), CONTROL_PORT),
            last_seen: now,
            os: "windows".into(),
            device_id: "peer1".into(),
            device_name: "PC".into(),
            hardware_model: "Laptop".into(),
            form_factor: "laptop".into(),
            display_width: 1920,
            display_height: 1200,
            display_fps: 165,
            share_name: None,
            sunshine_name: None,
            sunshine_port: SUNSHINE_DEFAULT_PORT,
            gpus: vec![],
            transport,
            link_speed_mbps: None,
            link_description: transport.label().into(),
            local_ip_used: None,
            same_subnet,
            rtt_ms: Some(rtt),
            trusted: true,
            discovery_source: "udp".into(),
        };

        let stale_alias = make("192.168.2.2", LinkTransport::DirectUsb, false, 0.5);
        let wifi = make("192.168.137.1", LinkTransport::Wifi, true, 1.2);
        let eth = make("169.254.20.5", LinkTransport::Ethernet, true, 0.6);
        let tb = make("169.254.10.5", LinkTransport::Thunderbolt, true, 0.3);

        let chosen_tb = select_best_peer(&[wifi.clone(), stale_alias.clone(), eth.clone(), tb.clone()]).unwrap();
        assert_eq!(chosen_tb.addr.ip().to_string(), "169.254.10.5");

        let chosen_eth = select_best_peer(&[wifi, stale_alias, eth]).unwrap();
        assert_eq!(chosen_eth.addr.ip().to_string(), "169.254.20.5");
    }

    #[test]
    fn multi_topology_route_election_and_dhcp_lease_failover() {
        let now = Instant::now();
        let make_with_lip = |ip: &str,
                             lip: &str,
                             transport: LinkTransport,
                             same_subnet: bool,
                             rtt: f64| PeerCandidate {
            addr: SocketAddr::new(ip.parse().unwrap(), CONTROL_PORT),
            last_seen: now,
            os: "windows".into(),
            device_id: "peer-uuid-1".into(),
            device_name: "Studio-PC".into(),
            hardware_model: "Desktop".into(),
            form_factor: "desktop".into(),
            display_width: 2560,
            display_height: 1440,
            display_fps: 144,
            share_name: Some("Shared".into()),
            sunshine_name: Some("Studio-PC".into()),
            sunshine_port: SUNSHINE_DEFAULT_PORT,
            gpus: vec![],
            transport,
            link_speed_mbps: None,
            link_description: transport.label().into(),
            local_ip_used: Some(lip.into()),
            same_subnet,
            rtt_ms: Some(rtt),
            trusted: true,
            discovery_source: "udp".into(),
        };

        // 1. Multi-homed peer reachable simultaneously over USB-C Direct (10.99.99.1) and iPhone /28 Hotspot (172.20.10.15)
        let mut table = Vec::new();
        let hotspot_old = make_with_lip(
            "172.20.10.15",
            "172.20.10.2",
            LinkTransport::Hotspot,
            true,
            4.5,
        );
        let usbc = make_with_lip(
            "10.99.99.1",
            "10.99.99.2",
            LinkTransport::DirectUsb,
            true,
            0.4,
        );
        upsert_peer_candidate(&mut table, hotspot_old, now);
        upsert_peer_candidate(&mut table, usbc, now);
        assert_eq!(table.len(), 2, "both simultaneous links across distinct local interfaces must be kept");

        // Direct USB-C cable strictly beats Mobile Hotspot
        let best = select_best_peer(&table).unwrap();
        assert_eq!(best.addr.ip().to_string(), "10.99.99.1");
        assert_eq!(best.transport, LinkTransport::DirectUsb);

        // 2. USB-C cable is unplugged (removed/expired) and peer reconnects to iPhone Hotspot with new DHCP lease 172.20.10.7
        table.retain(|c| c.transport != LinkTransport::DirectUsb);
        let hotspot_new = make_with_lip(
            "172.20.10.7",
            "172.20.10.2",
            LinkTransport::Hotspot,
            true,
            3.8,
        );
        upsert_peer_candidate(&mut table, hotspot_new, now);

        // Stale DHCP lease 172.20.10.15 on the same local interface (172.20.10.2) is replaced immediately
        assert_eq!(table.len(), 1);
        let failed_over = select_best_peer(&table).unwrap();
        assert_eq!(failed_over.addr.ip().to_string(), "172.20.10.7");
        assert_eq!(failed_over.transport, LinkTransport::Hotspot);
        assert!(!failed_over.transport.is_direct_cable());
    }
}
