//! # Transport-Agnostic Link Health & Latency (RTT) Monitor (`bridge.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `bridge.rs` provides real-time link health monitoring, round-trip time (RTT) measurement,
//! and network route characterization across active peer communication pathways.
//!
//! When connecting macOS and Windows 11 machines, multiple network links may coexist simultaneously
//! (e.g., high-speed Thunderbolt 4 / USB4 direct bridges, multi-gigabit Ethernet, and 5GHz/6GHz Wi-Fi).
//! `LinkMonitor` continuously probes connectivity over the active socket address, tracks link
//! latency transitions, and logs human-readable route classifications (e.g., identifying when traffic
//! switches from Thunderbolt to Wi-Fi).
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core.rs`: Spawns watchdog monitoring tasks during peer session connection to keep tabs
//!   on link degradation or physical cable disconnects.
//! - UI View Models (via `ffi.rs` / `core.rs`): Call `measure_peer_rtt_ms` on demand to populate
//!   connection diagnostic widgets and status overlays.
//!
//! ### Downstream Callees:
//! - `system_info::describe_route_to_peer`: Resolves the OS routing table and network interface
//!   hardware model to determine physical link transport medium (Thunderbolt, Ethernet, Wi-Fi).
//! - `tokio::net::TcpStream`: Establishes lightweight TCP handshakes to compute physical round-trip times.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Probing is conducted against the peer's `CONTROL_PORT` (58281). The peer's `TcpListener` accepts
//! the connection; when `LinkMonitor` closes the socket immediately upon successful TCP handshake,
//! the peer's control server recognizes the clean 0-byte EOF as an intentional health probe and drops
//! the connection without logging spurious disconnect errors.
//!
//! ## 3. Threading & Concurrency Model
//! - Asynchronous Tokio runtime: Probing and watchdog loops run inside non-blocking Tokio green threads.
//! - Blocking OS routing table lookups (`describe_route_to_peer`) are offloaded to `tokio::task::spawn_blocking`
//!   to avoid stalling the Tokio asynchronous worker pool.
//! - Lifecycle control uses `tokio::sync::watch` broadcast channels for instant, cancel-safe teardown.
//!
//! ## 4. Security & Safety Invariants
//! - Probes do not send or receive unencrypted application data.
//! - All socket connections are wrapped in strict millisecond-level timeouts (default 800ms) to prevent
//!   deadlocks or file descriptor exhaustion in case of silent packet blackholes.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::system_info;

/// Default bounded timeout duration for each periodic watchdog TCP RTT probe.
#[allow(dead_code)]
const DEFAULT_WATCHDOG_PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// Network link health monitor and latency prober targeting a specific peer endpoint.
#[allow(dead_code)]
pub struct LinkMonitor {
    /// Target socket address (IPv4 or IPv6) of the peer service.
    peer_addr: SocketAddr,
    /// Time to wait between successive watchdog link probes.
    check_interval: Duration,
}

#[allow(dead_code)]
impl LinkMonitor {
    /// Creates a new `LinkMonitor` instance for the specified IP address string and port.
    ///
    /// # Arguments
    /// * `peer_ip` - String representation of the target IPv4 or IPv6 address (e.g. `"192.168.1.50"` or `"::1"`).
    /// * `port` - Target TCP service port (must be non-zero, typically `config::CONTROL_PORT`).
    ///
    /// # Errors
    /// Returns an error if `port` is 0 or if `peer_ip` cannot be parsed into a valid `IpAddr`.
    pub fn new(peer_ip: &str, port: u16) -> Result<Self> {
        // Enforce non-zero port constraint to prevent invalid socket binding attempts
        ensure!(port > 0, "Peer port must be non-zero");

        // Parse IPv4/IPv6 string after trimming leading and trailing whitespace
        let ip: IpAddr = peer_ip
            .trim()
            .parse()
            .with_context(|| format!("Invalid peer IP address: {}", peer_ip))?;

        // Initialize with default 1000ms polling interval
        Ok(Self {
            peer_addr: SocketAddr::new(ip, port),
            check_interval: Duration::from_millis(1000),
        })
    }

    /// Returns the resolved socket address of the monitored peer.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Builder method to configure the watchdog polling interval.
    ///
    /// Clamps the minimum polling interval to 100 milliseconds to avoid socket starvation.
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        // Enforce lower bound of 100ms to prevent CPU spinning and socket descriptor churn
        self.check_interval = interval.max(Duration::from_millis(100));
        self
    }

    /// Measures TCP round-trip time (RTT) to the peer endpoint.
    ///
    /// # Algorithm
    /// 1. Records high-precision monotonic start timestamp using `Instant::now()`.
    /// 2. Initiates asynchronous TCP three-way handshake (`SYN` -> `SYN-ACK` -> `ACK`).
    /// 3. Drops the resulting `TcpStream` immediately upon completion, sending a `FIN`.
    /// 4. Computes elapsed time between connection request and handshake completion.
    ///
    /// # Arguments
    /// * `timeout_dur` - Maximum duration to wait before aborting the probe attempt.
    ///
    /// # Return Value
    /// Returns `Some(Duration)` representing handshake round-trip latency, or `None` if
    /// connection timed out, was refused, or network route was unreachable.
    pub async fn measure_rtt(&self, timeout_dur: Duration) -> Option<Duration> {
        let start = Instant::now();

        // Enforce timeout guard over asynchronous TCP connection handshake
        let Ok(Ok(stream)) =
            tokio::time::timeout(timeout_dur, TcpStream::connect(self.peer_addr)).await
        else {
            return None;
        };

        // Handshake succeeded; calculate total elapsed round-trip duration
        let connect_elapsed = start.elapsed();

        // Immediately drop stream to send FIN packet. Peer recognizes this as probe.
        drop(stream);

        Some(connect_elapsed)
    }

    /// One-shot convenience helper returning measured RTT in milliseconds
    /// (rounded to 2 decimal places) for `peer_ip:port`.
    ///
    /// # Arguments
    /// * `peer_ip` - Destination IP address string.
    /// * `port` - Destination port number.
    /// * `timeout_dur` - Maximum timeout window for the probe.
    ///
    /// # Return Value
    /// Returns `Some(f64)` in milliseconds (e.g. `1.45`), or `None` if unreachable.
    pub async fn measure_peer_rtt_ms(
        peer_ip: &str,
        port: u16,
        timeout_dur: Duration,
    ) -> Option<f64> {
        let monitor = Self::new(peer_ip, port).ok()?;
        let rtt = monitor.measure_rtt(timeout_dur).await?;
        let ms = rtt.as_secs_f64() * 1000.0;
        // Round to 2 decimal places for clean UI presentation and metric logging
        Some((ms * 100.0).round() / 100.0)
    }

    /// Background loop monitoring link health and logging dynamic route transitions
    /// until cancelled cleanly via the provided `shutdown` watch receiver.
    ///
    /// Emits structured `info!` logs when connection is established or re-established,
    /// and `warn!` logs when link connectivity is severed.
    pub async fn run_watchdog_until(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let peer_ip = self.peer_addr.ip().to_string();

        // Perform initial route discovery to classify interface medium (e.g. Thunderbolt vs Wi-Fi)
        let (transport, link_desc) = describe_route_async(peer_ip.clone()).await;
        info!(
            "Starting Link Monitor targeting {} ({} — {})",
            self.peer_addr,
            transport.label(),
            link_desc
        );
        let mut is_connected = false;

        loop {
            // Check shutdown channel before starting next probe cycle
            if *shutdown.borrow() {
                break;
            }

            tokio::select! {
                // Wake immediately on shutdown notification
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                // Execute latency probe with bounded watchdog timeout
                rtt_res = self.measure_rtt(DEFAULT_WATCHDOG_PROBE_TIMEOUT) => {
                    match rtt_res {
                        Some(rtt) => {
                            if !is_connected {
                                // Transition from disconnected to connected: refresh route description
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
                                // Transition from connected to disconnected: warn and update state
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

            // Delay for configured check interval, while listening for shutdown signals
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

    /// Background loop monitoring link health indefinitely until program termination.
    pub async fn run_watchdog(&self) {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        self.run_watchdog_until(rx).await;
    }
}

/// Helper function to asynchronously query the OS routing table and interface description.
///
/// Offloads synchronous system socket / routing table lookups to `tokio::task::spawn_blocking`
/// to protect async executor worker threads from I/O pauses.
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
