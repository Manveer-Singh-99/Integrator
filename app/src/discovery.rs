//! Dynamic Peer Discovery across USB-C, Mac Sharing, Windows Hotspot, and Wi-Fi.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, debug};
use crate::config::{DISCOVERY_PORT, CANDIDATE_PEER_IPS};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    pub sender_name: String,
    pub os: String,
    pub control_port: u16,
    pub clipboard_port: u16,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PeerCandidate {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    #[allow(dead_code)]
    pub device_name: String,
}

#[derive(Clone)]
pub struct DiscoveryManager {
    candidates: Arc<RwLock<Vec<PeerCandidate>>>,
    active_peer_ip: Arc<RwLock<Option<String>>>,
    my_device_name: String,
}

impl DiscoveryManager {
    pub fn new(my_device_name: &str) -> Self {
        Self {
            candidates: Arc::new(RwLock::new(Vec::new())),
            active_peer_ip: Arc::new(RwLock::new(None)),
            my_device_name: my_device_name.to_string(),
        }
    }

    /// Returns the best currently active peer IP.
    /// Priority: 10.99.99.x (USB-C 0.7ms) > 192.168.2.x (Mac Sharing) > 192.168.137.x (Hotspot) > Other Wi-Fi.
    pub async fn get_peer_ip(&self) -> Option<String> {
        self.active_peer_ip.read().await.clone()
    }

    pub async fn start(&self) -> Result<()> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await?;
        socket.set_broadcast(true)?;
        let socket = Arc::new(socket);

        let listener_socket = Arc::clone(&socket);
        let candidates = Arc::clone(&self.candidates);
        let active_peer_ip = Arc::clone(&self.active_peer_ip);
        let my_name = self.my_device_name.clone();

        // 1. Background Listener
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, src_addr)) = listener_socket.recv_from(&mut buf).await {
                    if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..len]) {
                        if beacon.sender_name == my_name {
                            continue;
                        }

                        let now = Instant::now();
                        let mut cand_lock = candidates.write().await;
                        
                        // Update or add candidate
                        if let Some(existing) = cand_lock.iter_mut().find(|c| c.addr.ip() == src_addr.ip()) {
                            existing.last_seen = now;
                        } else {
                            cand_lock.push(PeerCandidate {
                                addr: src_addr,
                                last_seen: now,
                                device_name: beacon.sender_name.clone(),
                            });
                        }

                        // Remove stale candidates (>6 seconds old)
                        cand_lock.retain(|c| now.duration_since(c.last_seen).as_secs() < 6);

                        // Select best link based on hardware hierarchy
                        let best_ip = Self::select_best_ip(&cand_lock);
                        let mut active_lock = active_peer_ip.write().await;
                        if *active_lock != best_ip {
                            if let Some(ref new_ip) = best_ip {
                                info!("🟢 Link locked to peer [{}] at {} via optimal route", beacon.sender_name, new_ip);
                            } else {
                                info!("🔴 Peer connection lost across all routes");
                            }
                            *active_lock = best_ip;
                        }
                    }
                }
            }
        });

        // 2. Background Broadcaster
        let broadcaster_socket = Arc::clone(&socket);
        let my_name_broadcast = self.my_device_name.clone();

        tokio::spawn(async move {
            let beacon = DiscoveryBeacon {
                sender_name: my_name_broadcast,
                os: std::env::consts::OS.to_string(),
                control_port: crate::config::CONTROL_PORT,
                clipboard_port: crate::config::CLIPBOARD_PORT,
                timestamp_ms: 0,
            };

            let payload = serde_json::to_vec(&beacon).unwrap_or_default();

            let broadcast_addrs = [
                format!("255.255.255.255:{}", DISCOVERY_PORT),
                format!("10.99.99.255:{}", DISCOVERY_PORT),
                format!("192.168.2.255:{}", DISCOVERY_PORT),
                format!("192.168.137.255:{}", DISCOVERY_PORT),
            ];

            loop {
                for addr in &broadcast_addrs {
                    let _ = broadcaster_socket.send_to(&payload, addr).await;
                }
                for ip in CANDIDATE_PEER_IPS {
                    let unicast_addr = format!("{}:{}", ip, DISCOVERY_PORT);
                    let _ = broadcaster_socket.send_to(&payload, &unicast_addr).await;
                }
                debug!("Broadcasted discovery beacons");
                sleep(Duration::from_millis(1500)).await;
            }
        });

        Ok(())
    }

    /// Selects the best active IP address based on priority:
    /// 1. 10.99.99.x (USB-C cable: <0.7ms latency)
    /// 2. 192.168.2.x (USB-C Mac Internet Sharing: <0.8ms)
    /// 3. 192.168.137.x (Windows Wi-Fi Hotspot: ~3-5ms)
    /// 4. Any other candidate
    fn select_best_ip(candidates: &[PeerCandidate]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }

        // Tier 1: USB-C 10.99.99.x
        if let Some(c) = candidates.iter().find(|c| c.addr.ip().to_string().starts_with("10.99.99.")) {
            return Some(c.addr.ip().to_string());
        }

        // Tier 2: Mac Sharing 192.168.2.x
        if let Some(c) = candidates.iter().find(|c| c.addr.ip().to_string().starts_with("192.168.2.")) {
            return Some(c.addr.ip().to_string());
        }

        // Tier 3: Hotspot 192.168.137.x
        if let Some(c) = candidates.iter().find(|c| c.addr.ip().to_string().starts_with("192.168.137.")) {
            return Some(c.addr.ip().to_string());
        }

        // Tier 4: Fallback to first available
        candidates.first().map(|c| c.addr.ip().to_string())
    }
}
