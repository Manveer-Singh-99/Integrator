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
pub struct PeerState {
    pub addr: SocketAddr,
    pub rtt_ms: f32,
    pub last_seen: Instant,
    pub device_name: String,
}

#[derive(Clone)]
pub struct DiscoveryManager {
    pub active_peer: Arc<RwLock<Option<PeerState>>>,
    pub my_device_name: String,
}

impl DiscoveryManager {
    pub fn new(my_device_name: &str) -> Self {
        Self {
            active_peer: Arc::new(RwLock::new(None)),
            my_device_name: my_device_name.to_string(),
        }
    }

    pub async fn get_peer_ip(&self) -> Option<String> {
        self.active_peer.read().await.as_ref().map(|p| p.addr.ip().to_string())
    }

    /// Spawns the discovery engine: both broadcaster and listener.
    pub async fn start(&self) -> Result<()> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await?;
        socket.set_broadcast(true)?;
        let socket = Arc::new(socket);

        let listener_socket = Arc::clone(&socket);
        let active_peer = Arc::clone(&self.active_peer);
        let my_name = self.my_device_name.clone();

        // Background Listener
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, src_addr)) = listener_socket.recv_from(&mut buf).await {
                    if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..len]) {
                        // Ignore our own beacons
                        if beacon.sender_name == my_name {
                            continue;
                        }

                        let now = Instant::now();
                        let mut peer_lock = active_peer.write().await;
                        let is_new = peer_lock.is_none() || peer_lock.as_ref().map(|p| p.addr != src_addr).unwrap_or(false);

                        *peer_lock = Some(PeerState {
                            addr: src_addr,
                            rtt_ms: 0.8, // updated via TCP ping
                            last_seen: now,
                            device_name: beacon.sender_name.clone(),
                        });

                        if is_new {
                            info!("🟢 Connected to peer [{}] at {} (Discovered via UDP)", beacon.sender_name, src_addr);
                        }
                    }
                }
            }
        });

        // Background Broadcaster
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

            // Broadcast endpoints across all candidate networks
            let broadcast_addrs = [
                format!("255.255.255.255:{}", DISCOVERY_PORT),
                format!("10.99.99.255:{}", DISCOVERY_PORT),
                format!("192.168.2.255:{}", DISCOVERY_PORT),
                format!("192.168.137.255:{}", DISCOVERY_PORT),
            ];

            loop {
                // Send broadcast to all subnets
                for addr in &broadcast_addrs {
                    let _ = broadcaster_socket.send_to(&payload, addr).await;
                }

                // Also unicast directly to known candidate IPs in case broadcast is filtered
                for ip in CANDIDATE_PEER_IPS {
                    let unicast_addr = format!("{}:{}", ip, DISCOVERY_PORT);
                    let _ = broadcaster_socket.send_to(&payload, &unicast_addr).await;
                }

                debug!("Sent multi-subnet discovery beacons");
                sleep(Duration::from_millis(1500)).await;
            }
        });

        Ok(())
    }
}
