//! Link health and latency measurement over the USB-C CDC-NCM point-to-point tunnel.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use anyhow::Result;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{info, warn};

pub struct LinkMonitor {
    peer_addr: SocketAddr,
    check_interval: Duration,
}

impl LinkMonitor {
    pub fn new(peer_ip: &str, port: u16) -> Result<Self> {
        let addr_str = format!("{}:{}", peer_ip, port);
        let peer_addr: SocketAddr = addr_str.parse()?;
        Ok(Self {
            peer_addr,
            check_interval: Duration::from_millis(1000),
        })
    }

    /// Measures TCP connect round-trip time (RTT) to the peer daemon.
    pub async fn measure_rtt(&self, timeout_dur: Duration) -> Option<Duration> {
        let start = Instant::now();
        match tokio::time::timeout(timeout_dur, TcpStream::connect(self.peer_addr)).await {
            Ok(Ok(_stream)) => Some(start.elapsed()),
            _ => None,
        }
    }

    /// Background loop monitoring link health and logging latency transitions.
    pub async fn run_watchdog(&self) {
        info!("Starting USB-C Link Monitor targeting {}", self.peer_addr);
        let mut is_connected = false;

        loop {
            match self.measure_rtt(Duration::from_millis(800)).await {
                Some(rtt) => {
                    if !is_connected {
                        info!("🟢 USB-C Link ESTABLISHED to {} (RTT: {:.2}ms)", self.peer_addr, rtt.as_secs_f64() * 1000.0);
                        is_connected = true;
                    }
                }
                None => {
                    if is_connected {
                        warn!("🔴 USB-C Link LOST to {} (Peer unreachable)", self.peer_addr);
                        is_connected = false;
                    }
                }
            }
            sleep(self.check_interval).await;
        }
    }
}
