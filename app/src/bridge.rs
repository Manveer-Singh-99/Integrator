//! Transport-agnostic link health and latency (RTT) measurement across active peer routes.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::system_info;

#[allow(dead_code)]
pub struct LinkMonitor {
    peer_addr: SocketAddr,
    check_interval: Duration,
}

#[allow(dead_code)]
impl LinkMonitor {
    pub fn new(peer_ip: &str, port: u16) -> Result<Self> {
        ensure!(port > 0, "Peer port must be non-zero");
        let ip: IpAddr = peer_ip
            .trim()
            .parse()
            .with_context(|| format!("Invalid peer IP address: {}", peer_ip))?;
        Ok(Self {
            peer_addr: SocketAddr::new(ip, port),
            check_interval: Duration::from_millis(1000),
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval.max(Duration::from_millis(100));
        self
    }

    /// Measures TCP round-trip time (RTT) to the peer endpoint.
    ///
    /// Performs a clean TCP connect and immediate socket close (which `DisplayServer`
    /// recognizes as a probe via clean EOF on the 4-byte magic read).
    pub async fn measure_rtt(&self, timeout_dur: Duration) -> Option<Duration> {
        let start = Instant::now();
        let Ok(Ok(stream)) =
            tokio::time::timeout(timeout_dur, TcpStream::connect(self.peer_addr)).await
        else {
            return None;
        };
        let connect_elapsed = start.elapsed();
        drop(stream);
        Some(connect_elapsed)
    }

    /// One-shot convenience helper returning measured RTT in milliseconds
    /// (rounded to 2 decimal places) for `peer_ip:port`.
    pub async fn measure_peer_rtt_ms(
        peer_ip: &str,
        port: u16,
        timeout_dur: Duration,
    ) -> Option<f64> {
        let monitor = Self::new(peer_ip, port).ok()?;
        let rtt = monitor.measure_rtt(timeout_dur).await?;
        let ms = rtt.as_secs_f64() * 1000.0;
        Some((ms * 100.0).round() / 100.0)
    }

    /// Background loop monitoring link health and logging dynamic route transitions
    /// until cancelled cleanly via `shutdown`.
    pub async fn run_watchdog_until(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let peer_ip = self.peer_addr.ip().to_string();
        let (transport, link_desc) = describe_route_async(peer_ip.clone()).await;
        info!(
            "Starting Link Monitor targeting {} ({} — {})",
            self.peer_addr,
            transport.label(),
            link_desc
        );
        let mut is_connected = false;

        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                rtt_res = self.measure_rtt(Duration::from_millis(800)) => {
                    match rtt_res {
                        Some(rtt) => {
                            if !is_connected {
                                let (transport, _) = describe_route_async(peer_ip.clone()).await;
                                info!(
                                    "🟢 {} link ESTABLISHED to {} (RTT: {:.2}ms)",
                                    transport.label(),
                                    self.peer_addr,
                                    rtt.as_secs_f64() * 1000.0
                                );
                                is_connected = true;
                            }
                        }
                        None => {
                            if is_connected {
                                let (transport, _) = describe_route_async(peer_ip.clone()).await;
                                warn!(
                                    "🔴 {} link LOST to {} (Peer unreachable)",
                                    transport.label(),
                                    self.peer_addr
                                );
                                is_connected = false;
                            }
                        }
                    }
                }
            }
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = sleep(self.check_interval) => {}
            }
        }
    }

    /// Background loop monitoring link health and logging dynamic route transitions.
    pub async fn run_watchdog(&self) {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        self.run_watchdog_until(rx).await;
    }
}

async fn describe_route_async(peer_ip: String) -> (system_info::LinkTransport, String) {
    tokio::task::spawn_blocking(move || {
        let (transport, _, desc, _) = system_info::describe_route_to_peer(&peer_ip);
        (transport, desc)
    })
    .await
    .unwrap_or((
        system_info::LinkTransport::Unknown,
        "Network Link".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn rejects_invalid_ip_or_zero_port_and_accepts_ipv4_ipv6() {
        assert!(LinkMonitor::new("not-an-ip", 58281).is_err());
        assert!(LinkMonitor::new("127.0.0.1", 0).is_err());

        let v4 = LinkMonitor::new("127.0.0.1", 58281).unwrap();
        assert_eq!(v4.peer_addr(), "127.0.0.1:58281".parse::<SocketAddr>().unwrap());

        let v6 = LinkMonitor::new("::1", 58281).unwrap();
        assert_eq!(v6.peer_addr(), "[::1]:58281".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn measures_real_loopback_rtt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let rtt = LinkMonitor::measure_peer_rtt_ms("127.0.0.1", port, Duration::from_millis(500))
            .await;
        assert!(rtt.is_some());
        let _ = accept_task.await;
    }

    #[tokio::test]
    async fn watchdog_exits_cleanly_on_shutdown() {
        let monitor = LinkMonitor::new("127.0.0.1", 58281).unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            monitor.run_watchdog_until(rx).await;
        });
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("watchdog should exit cleanly on shutdown")
            .unwrap();
    }
}
