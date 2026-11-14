//! Dynamic UDP Peer Discovery over any active interface (USB-C CDC-NCM,
//! Thunderbolt Bridge, Wired Ethernet, Wi-Fi, or user-configured peer IP).
//!
//! Zero hardcoded IPs or subnets: broadcast targets come directly from the OS
//! interface table and routes are classified dynamically via the routing table.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::config::{CLIPBOARD_PORT, CONTROL_PORT, DISCOVERY_PORT};
use crate::system_info::{self, LinkTransport};
use crate::trust;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    #[serde(default)]
    pub device_id: String,
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
        self.best_candidate_inner().await.map(|c| c.addr.ip().to_string())
    }

    pub async fn get_best_peer(&self) -> Option<PeerCandidate> {
        self.best_candidate_inner().await
    }

    pub async fn get_all_peers(&self) -> Vec<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        guard.retain(|c| now.duration_since(c.last_seen) < Duration::from_secs(10));
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
                m.push(trimmed.clone());
            }
        }
        let mut hist = load_peer_history();
        if !hist.manual_ips.contains(&trimmed) {
            hist.manual_ips.push(trimmed);
            save_peer_history(&hist);
        }
        Ok(())
    }

    pub async fn remove_manual_peer_ip(&self, ip: &str) {
        let trimmed = ip.trim().to_string();
        let mut m = self.manual_ips.write().await;
        m.retain(|x| x != &trimmed);
        let mut hist = load_peer_history();
        hist.manual_ips.retain(|x| x != &trimmed);
        save_peer_history(&hist);
    }

    pub async fn get_manual_peer_ips(&self) -> Vec<String> {
        self.manual_ips.read().await.clone()
    }

    async fn best_candidate_inner(&self) -> Option<PeerCandidate> {
        let mut guard = self.candidates.write().await;
        let now = Instant::now();
        guard.retain(|c| now.duration_since(c.last_seen) < Duration::from_secs(8));

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
        let my_name = self.local_name.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match listener_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..len]) {
                            let peer_ip = addr.ip().to_string();
                            let is_self_id =
                                !beacon.device_id.is_empty() && beacon.device_id == my_device_id;
                            let is_self_name_and_ip = beacon.device_id.is_empty()
                                && beacon.sender_name == my_name
                                && is_own_local_ip(&peer_ip);
                            if is_self_id || is_self_name_and_ip || addr.ip().is_loopback() {
                                continue;
                            }

                            let (transport, speed_mbps, link_desc, local_ip) =
                                system_info::describe_route_to_peer(&peer_ip);
                            let dev_id = if beacon.device_id.is_empty() {
                                format!("legacy-{}", peer_ip)
                            } else {
                                beacon.device_id.clone()
                            };

                            let trusted = trust::observe_discovered_peer(
                                &dev_id,
                                &beacon.sender_name,
                                &peer_ip,
                                transport.is_direct_cable(),
                            );

                            // Refresh real TCP RTT in background at most once every 3s per IP
                            let cached_rtt = {
                                let cache_guard = rtt_cache.read().await;
                                cache_guard.get(&peer_ip).map(|(t, r)| (t.elapsed(), *r))
                            };
                            let rtt_ms = match cached_rtt {
                                Some((age, r)) if age < Duration::from_secs(4) => Some(r),
                                _ => {
                                    let probe_ip = peer_ip.clone();
                                    let probe_port = beacon.control_port.max(1);
                                    let rtt_map = Arc::clone(&rtt_cache);
                                    let cands_ref = Arc::clone(&candidates);
                                    tokio::spawn(async move {
                                        if let Some(measured) =
                                            measure_tcp_connect_rtt(&probe_ip, probe_port).await
                                        {
                                            rtt_map
                                                .write()
                                                .await
                                                .insert(probe_ip.clone(), (Instant::now(), measured));
                                            let mut list = cands_ref.write().await;
                                            for c in list.iter_mut() {
                                                if c.addr.ip().to_string() == probe_ip {
                                                    c.rtt_ms = Some(measured);
                                                }
                                            }
                                        }
                                    });
                                    cached_rtt.map(|(_, r)| r)
                                }
                            };

                            record_recent_peer_ip(&peer_ip);

                            let mut list = candidates.write().await;
                            let now = Instant::now();
                            list.retain(|c| now.duration_since(c.last_seen) < Duration::from_secs(8));

                            let candidate = PeerCandidate {
                                addr: SocketAddr::new(addr.ip(), beacon.control_port),
                                last_seen: now,
                                os: beacon.os.clone(),
                                device_id: dev_id,
                                device_name: beacon.sender_name.clone(),
                                hardware_model: beacon.hardware_model.clone(),
                                display_width: beacon.display_width,
                                display_height: beacon.display_height,
                                display_fps: beacon.display_fps,
                                share_name: beacon.share_name.clone(),
                                sunshine_name: beacon.sunshine_name.clone(),
                                sunshine_port: if beacon.sunshine_port > 0 {
                                    beacon.sunshine_port
                                } else {
                                    47989
                                },
                                gpus: beacon.gpus.clone(),
                                transport,
                                link_speed_mbps: speed_mbps,
                                link_description: link_desc,
                                local_ip_used: local_ip,
                                rtt_ms,
                                trusted,
                            };

                            if let Some(existing) = list.iter_mut().find(|c| c.addr.ip() == addr.ip())
                            {
                                *existing = candidate;
                            } else {
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
        let dev_id = self.local_device_id.clone();

        tokio::spawn(async move {
            loop {
                let profile = system_info::collect_local_profile();
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let beacon = DiscoveryBeacon {
                    device_id: dev_id.clone(),
                    sender_name: if profile.hostname.is_empty() {
                        fallback_name.clone()
                    } else {
                        profile.hostname.clone()
                    },
                    os: profile.os.clone(),
                    hardware_model: profile.hardware_model.clone(),
                    control_port: CONTROL_PORT,
                    clipboard_port: CLIPBOARD_PORT,
                    display_width: profile.primary_display.width,
                    display_height: profile.primary_display.height,
                    display_fps: profile.primary_display.fps,
                    share_name: profile.default_share_names.first().cloned(),
                    sunshine_name: profile.sunshine_name.clone(),
                    sunshine_port: profile.sunshine_port,
                    gpus: profile.gpus.iter().map(|g| g.name.clone()).collect(),
                    timestamp_ms: ts,
                };

                if let Ok(bytes) = serde_json::to_vec(&beacon) {
                    let mut targets: Vec<String> = system_info::discovery_broadcast_targets();
                    let hist = load_peer_history();
                    let manual = manual_ips_ref.read().await;
                    let mut seen: HashSet<String> = targets.iter().cloned().collect();
                    for ip in manual.iter().chain(hist.recent_ips.iter()) {
                        if seen.insert(ip.clone()) {
                            targets.push(ip.clone());
                        }
                    }

                    for ip in targets {
                        let target = format!("{}:{}", ip, DISCOVERY_PORT);
                        let _ = broadcaster_socket.send_to(&bytes, &target).await;
                    }
                }

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        Ok(())
    }
}

fn select_best_peer(candidates: &[PeerCandidate]) -> Option<PeerCandidate> {
    candidates
        .iter()
        .min_by(|a, b| {
            // 1. Trusted peers strictly first
            b.trusted
                .cmp(&a.trusted)
                // 2. Physical / wired / faster transport first (DirectUsb < Thunderbolt < Ethernet < Wifi < Unknown)
                .then_with(|| a.transport.cmp(&b.transport))
                // 3. Lower measured RTT if available
                .then_with(|| {
                    let ar = a.rtt_ms.unwrap_or(9999.0);
                    let br = b.rtt_ms.unwrap_or(9999.0);
                    ar.partial_cmp(&br).unwrap_or(std::cmp::Ordering::Equal)
                })
                // 4. More recently seen
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
    let target = format!("{}:{}", ip, port);
    let start = Instant::now();
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_millis(450), TcpStream::connect(&target)).await
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let payload = b"\"Ping\"";
        if stream.write_u32(payload.len() as u32).await.is_ok()
            && stream.write_all(payload).await.is_ok()
        {
            let mut hdr = [0u8; 4];
            if let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_millis(300), stream.read_exact(&mut hdr)).await
            {
                let len = u32::from_be_bytes(hdr) as usize;
                if len > 0 && len <= 65_536 {
                    let mut resp = vec![0u8; len];
                    let _ = tokio::time::timeout(
                        Duration::from_millis(300),
                        stream.read_exact(&mut resp),
                    )
                    .await;
                }
            }
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        return Some((ms * 100.0).round() / 100.0);
    }
    None
}

fn history_path() -> std::path::PathBuf {
    system_info::app_data_dir().join("peer_history.json")
}

fn load_peer_history() -> PeerHistoryFile {
    std::fs::read_to_string(history_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_peer_history(hist: &PeerHistoryFile) {
    if let Ok(json) = serde_json::to_string_pretty(hist) {
        let _ = std::fs::write(history_path(), json);
    }
}

fn record_recent_peer_ip(ip: &str) {
    static RECENT_SEEN: std::sync::OnceLock<std::sync::Mutex<HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = RECENT_SEEN.get_or_init(|| std::sync::Mutex::new(HashSet::new()));
    if let Ok(mut guard) = seen.lock() {
        if !guard.insert(ip.to_string()) {
            return;
        }
    }
    let mut hist = load_peer_history();
    if !hist.recent_ips.iter().any(|x| x == ip) {
        hist.recent_ips.insert(0, ip.to_string());
        hist.recent_ips.truncate(8);
        save_peer_history(&hist);
    }
}
