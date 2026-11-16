//! Dynamic UDP Peer Discovery over any active interface (USB-C CDC-NCM,
//! Thunderbolt Bridge, Wired Ethernet, Wi-Fi, or user-configured peer IP).
//!
//! Validates incoming beacons for protocol version, timestamp freshness (±60s),
//! HMAC integrity, port bounds, and field lengths, and runs synchronous OS queries
//! on the blocking thread pool so Tokio async worker threads are never stalled.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore};

use crate::config::{CLIPBOARD_PORT, CONTROL_PORT, DISCOVERY_PORT};
use crate::system_info::{self, LinkTransport};
use crate::trust;

pub const DISCOVERY_PROTOCOL_VERSION: u16 = 2;
const PEER_CANDIDATE_TTL: Duration = Duration::from_secs(10);
const MAX_PEER_CANDIDATES: usize = 64;
const MAX_RTT_CACHE_ENTRIES: usize = 128;
const RTT_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_REPLAY_DEVICES: usize = 128;
const MAX_REPLAY_IPS_PER_DEVICE: usize = 8;
const REPLAY_WINDOW_TTL: Duration = Duration::from_secs(130);
const MAX_REPLAY_CROSS_IP_SKEW_MS: u64 = 3_000;
const MAX_MANUAL_IPS: usize = 32;
const MAX_RECENT_SEEN: usize = 64;
const MAX_CONCURRENT_RTT_PROBES: usize = 8;

static HISTORY_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static HISTORY_TMP_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

fn history_file_lock() -> &'static Mutex<()> {
    HISTORY_FILE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug)]
struct DeviceReplayState {
    max_ts_ms: u64,
    last_updated: Instant,
    per_ip: HashMap<IpAddr, (u64, Instant)>,
}

#[derive(Debug, Default)]
struct BeaconReplayCache {
    devices: HashMap<String, DeviceReplayState>,
}

impl BeaconReplayCache {
    fn accept(&mut self, device_id: &str, ip: IpAddr, timestamp_ms: u64, now: Instant) -> bool {
        // Prune expired IP entries and stale devices first.
        self.devices.retain(|_, state| {
            state
                .per_ip
                .retain(|_, (_, seen_at)| now.saturating_duration_since(*seen_at) <= REPLAY_WINDOW_TTL);
            !state.per_ip.is_empty()
                && now.saturating_duration_since(state.last_updated) <= REPLAY_WINDOW_TTL
        });

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

        // Reject replayed older beacons routed through a spoofed source IP.
        if state.max_ts_ms > timestamp_ms.saturating_add(MAX_REPLAY_CROSS_IP_SKEW_MS) {
            return false;
        }

        // Reject duplicate or backwards timestamps arriving on the same source IP.
        if let Some((last_ip_ts, _)) = state.per_ip.get(&ip) {
            if timestamp_ms <= *last_ip_ts {
                return false;
            }
        } else if state.per_ip.len() >= MAX_REPLAY_IPS_PER_DEVICE {
            if let Some(oldest_ip) = state
                .per_ip
                .iter()
                .min_by_key(|(_, (_, seen_at))| *seen_at)
                .map(|(k, _)| *k)
            {
                state.per_ip.remove(&oldest_ip);
            }
        }

        state.per_ip.insert(ip, (timestamp_ms, now));
        state.max_ts_ms = state.max_ts_ms.max(timestamp_ms);
        state.last_updated = now;
        true
    }
}

fn is_bidi_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

fn contains_unsafe_text_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_bidi_format_char(c))
}

fn sanitize_display_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|&c| !c.is_control() && !is_bidi_format_char(c))
        .collect::<String>()
        .trim()
        .chars()
        .take(max_chars)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub ed25519_pubkey: String,
    pub sender_name: String,
    pub os: String,
    #[serde(default)]
    pub hardware_model: String,
    pub control_port: u16,
    pub clipboard_port: u16,
    #[serde(default)]
    pub display_width: u32,
    #[serde(default)]
    pub display_height: u32,
    #[serde(default)]
    pub display_fps: u32,
    #[serde(default)]
    pub share_name: Option<String>,
    #[serde(default)]
    pub sunshine_name: Option<String>,
    #[serde(default)]
    pub sunshine_port: u16,
    #[serde(default)]
    pub gpus: Vec<String>,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub beacon_sig: String,
}

fn default_protocol_version() -> u16 {
    DISCOVERY_PROTOCOL_VERSION
}

#[derive(Debug, Clone)]
pub struct PeerCandidate {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub os: String,
    pub device_id: String,
    pub device_name: String,
    pub hardware_model: String,
    pub display_width: u32,
    pub display_height: u32,
    pub display_fps: u32,
    pub share_name: Option<String>,
    pub sunshine_name: Option<String>,
    pub sunshine_port: u16,
    pub gpus: Vec<String>,
    pub transport: LinkTransport,
    pub link_speed_mbps: Option<u32>,
    pub link_description: String,
    pub local_ip_used: Option<String>,
    pub same_subnet: bool,
    pub rtt_ms: Option<f64>,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PeerHistoryFile {
    recent_ips: Vec<String>,
    manual_ips: Vec<String>,
}

#[derive(Clone)]
pub struct DiscoveryManager {
    local_device_id: String,
    local_name: String,
    candidates: Arc<RwLock<Vec<PeerCandidate>>>,
    active_peer_ip: Arc<RwLock<Option<String>>>,
    rtt_cache: Arc<RwLock<HashMap<String, (Instant, f64)>>>,
    manual_ips: Arc<RwLock<Vec<String>>>,
}

impl DiscoveryManager {
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

    pub async fn get_peer_ip(&self) -> Option<String> {
        self.best_candidate_inner()
            .await
            .map(|c| c.addr.ip().to_string())
    }

    pub async fn get_best_peer(&self) -> Option<PeerCandidate> {
        self.best_candidate_inner().await
    }

    pub async fn get_all_peers(&self) -> Vec<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        guard.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);
        guard.clone()
    }

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

    pub async fn get_manual_peer_ips(&self) -> Vec<String> {
        self.manual_ips.read().await.clone()
    }

    async fn best_candidate_inner(&self) -> Option<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        guard.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);

        let mut active = self.active_peer_ip.write().await;
        let selected = select_best_peer(&guard);
        *active = selected.as_ref().map(|c| c.addr.ip().to_string());
        selected
    }

    pub async fn start(&self) -> Result<()> {
        let bind_addr = format!("0.0.0.0:{}", DISCOVERY_PORT);
        let socket = UdpSocket::bind(&bind_addr).await?;
        socket.set_broadcast(true)?;
        let socket = Arc::new(socket);

        // Task 1: UDP listener
        let listener_socket = Arc::clone(&socket);
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
                        if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..len]) {
                            if beacon.protocol_version != DISCOVERY_PROTOCOL_VERSION {
                                continue;
                            }
                            let peer_ip = addr.ip().to_string();
                            let dev_id = if beacon.device_id.trim().is_empty() {
                                continue;
                            } else {
                                beacon.device_id.trim().to_ascii_lowercase()
                            };

                            if dev_id == my_device_id
                                || dev_id == my_trust_device_id
                                || addr.ip().is_loopback()
                            {
                                continue;
                            }

                            if beacon.control_port < 1024 || beacon.clipboard_port < 1024 {
                                tracing::debug!(
                                    "Dropped discovery beacon with privileged/invalid ports from {}",
                                    peer_ip
                                );
                                continue;
                            }

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
                                // Persist verified paired peer IPs only, preventing spoofed LAN history pollution.
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

                            // Refresh real TCP RTT in background at most once every 4s per IP (bounded probes & cache)
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
                            list.retain(|c| now.saturating_duration_since(c.last_seen) < PEER_CANDIDATE_TTL);

                            let candidate = PeerCandidate {
                                addr: SocketAddr::new(addr.ip(), valid_control_port),
                                last_seen: now,
                                os: sanitize_display_text(&beacon.os, 64),
                                device_id: dev_id,
                                device_name: sender_name_clean,
                                hardware_model: sanitize_display_text(&beacon.hardware_model, 128),
                                display_width: beacon.display_width.clamp(0, 7680),
                                display_height: beacon.display_height.clamp(0, 4320),
                                display_fps: beacon.display_fps.clamp(0, 240),
                                share_name: sanitized_share,
                                sunshine_name: beacon
                                    .sunshine_name
                                    .map(|s| sanitize_display_text(&s, 128))
                                    .filter(|s| !s.is_empty()),
                                sunshine_port: if beacon.sunshine_port >= 1024 {
                                    beacon.sunshine_port
                                } else {
                                    47989
                                },
                                gpus: sanitized_gpus,
                                transport,
                                link_speed_mbps: speed_mbps,
                                link_description: link_desc,
                                local_ip_used: local_ip,
                                same_subnet,
                                rtt_ms,
                                trusted,
                            };

                            if let Some(existing) =
                                list.iter_mut().find(|c| c.addr.ip() == addr.ip())
                            {
                                *existing = candidate;
                            } else {
                                if list.len() >= MAX_PEER_CANDIDATES {
                                    if let Some(evict_idx) = list
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, c)| !c.trusted)
                                        .min_by_key(|(_, c)| c.last_seen)
                                        .or_else(|| {
                                            list.iter().enumerate().min_by_key(|(_, c)| c.last_seen)
                                        })
                                        .map(|(i, _)| i)
                                    {
                                        list.swap_remove(evict_idx);
                                    }
                                }
                                list.push(candidate);
                            }

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

        // Task 2: UDP beacon broadcaster across dynamic OS interface broadcasts & unicast hints
        let broadcaster_socket = Arc::clone(&socket);
        let manual_ips_ref = Arc::clone(&self.manual_ips);
        let fallback_name = self.local_name.clone();

        tokio::spawn(async move {
            loop {
                let manual_snapshot = manual_ips_ref.read().await.clone();
                let fallback_clone = fallback_name.clone();

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
                    for ip in manual_snapshot.iter().chain(hist.recent_ips.iter()) {
                        if seen.insert(ip.clone()) {
                            unicast_targets.push(ip.clone());
                        }
                    }
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
                        if no_endpoints {
                            let global_bcast = SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::BROADCAST),
                                DISCOVERY_PORT,
                            );
                            let _ = broadcaster_socket.send_to(&bytes, global_bcast).await;
                        }
                        for ip in unicast_targets {
                            if let Ok(parsed) = ip.parse::<IpAddr>() {
                                let target = SocketAddr::new(parsed, DISCOVERY_PORT);
                                let _ = broadcaster_socket.send_to(&bytes, target).await;
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        Ok(())
    }
}

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

    if let Ok(bcast_v4) = bcast_ip_str.parse::<Ipv4Addr>() {
        let _ = sock.send_to(bytes, SocketAddr::new(IpAddr::V4(bcast_v4), port));
    }
    let _ = sock.send_to(bytes, SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port));
}

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
                .then_with(|| a.transport.cmp(&b.transport))
                // 4. Lower measured RTT if available
                .then_with(|| {
                    let ar = a.rtt_ms.unwrap_or(9999.0);
                    let br = b.rtt_ms.unwrap_or(9999.0);
                    ar.partial_cmp(&br).unwrap_or(std::cmp::Ordering::Equal)
                })
                // 5. More recently seen
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        })
        .cloned()
}

fn is_own_local_ip(ip: &str) -> bool {
    system_info::list_local_ipv4_interfaces()
        .iter()
        .any(|iface| iface.ip == ip)
}

async fn measure_tcp_connect_rtt(ip: &str, port: u16) -> Option<f64> {
    let Ok(parsed) = ip.parse::<IpAddr>() else {
        return None;
    };
    let target = SocketAddr::new(parsed, port);
    let start = Instant::now();
    if let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_millis(450), TcpStream::connect(target)).await
    {
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        drop(stream);
        return Some((ms * 100.0).round() / 100.0);
    }
    None
}

fn history_path() -> std::path::PathBuf {
    system_info::app_data_dir().join("peer_history.json")
}

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
            display_width: 1920,
            display_height: 1200,
            display_fps: 165,
            share_name: None,
            sunshine_name: None,
            sunshine_port: 47989,
            gpus: vec![],
            transport,
            link_speed_mbps: None,
            link_description: transport.label().into(),
            local_ip_used: None,
            same_subnet,
            rtt_ms: Some(rtt),
            trusted: true,
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
}
