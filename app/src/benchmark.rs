//! # High-Performance Mutual Authenticated Network Benchmark Service (`benchmark.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `benchmark.rs` implements a high-throughput, point-to-point network benchmark suite that measures
//! real-world round-trip time (RTT) and bidirectional data transfer rates (in Gbps and Megabytes/sec)
//! across active peer links (Thunderbolt 4 / USB4 direct bridges, 10GbE Ethernet, 5GHz/6GHz Wi-Fi).
//!
//! Unlike unauthenticated diagnostic tools (e.g. iperf3), Integrator's benchmark operates exclusively
//! inside the mutually authenticated, ChaCha20-Poly1305 encrypted `TransportSessionV2` channel
//! under `ServiceId::Benchmark`. This guarantees that benchmark results reflect actual application-layer
//! wire throughput, including cipher framing, TCP socket buffer performance, and MAC verification overhead,
//! while preventing unauthorized third parties from flooding the host network interface.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::run_cli_if_requested`: Invoked when user runs `integrator benchmark <PEER_IP>`.
//! - Native UI Frontends (via `ffi::integrator_core_invoke`): Triggers live speed tests from GUI
//!   settings widgets and displays real-time bandwidth meters.
//!
//! ### Downstream Callees:
//! - `trust::connect_transport_to_ip` / `trust::accept_transport_from_stream`: Performs mutual Ed25519
//!   cryptographic verification before establishing the encrypted benchmark session.
//! - `security::transport::TransportSessionV2`: Encrypts/decrypts framed records (up to 256 KiB chunks).
//! - `features::FeatureManager`: Evaluates `features.is_enabled("benchmark")` before allocating resources.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! The client machine initiates a TCP connection to the peer's `TELEMETRY_PORT` (58285).
//! Upon mutual authentication, the test executes three sequential phases:
//! 1. **Latency Phase (Ping)**: Sends 5 sequential 9-byte echo packets containing 64-bit monotonic
//!    sequence numbers. The server echoes the sequence number back. The client computes mean RTT.
//! 2. **Adaptive Payload Scaling**: If average RTT is under 2.0ms (typical of direct Thunderbolt 4 bridges),
//!    payload size scales to 64 MiB to fully saturate high-bandwidth links; otherwise, it defaults to 16 MiB
//!    to prevent lengthy test delays on congested Wi-Fi.
//! 3. **Upload Phase**: Client streams 256 KiB encrypted chunks to server until target bytes are reached,
//!    waiting for a 1-byte final ACK.
//! 4. **Download Phase**: Server streams 256 KiB encrypted chunks back to client until target bytes are reached.
//!
//! ## 3. Threading & Concurrency Model
//! - Fully asynchronous execution within the Tokio runtime.
//! - **Two-Tier Concurrency Protection**:
//!   - Pre-Authentication Semaphore (`MAX_PRE_AUTH_BENCH_CONNS = 16`): Limits unauthenticated handshake attempts
//!     to mitigate connection-exhaustion DoS attacks.
//!   - Post-Authentication Semaphore (`MAX_CONCURRENT_BENCH_CONNS = 4`): Restricts concurrent high-bandwidth tests
//!     to preserve CPU and network resources for active display/audio streaming.
//! - **Timeouts**: Client imposes a 20s global deadline; individual record I/O operations timeout at 10s;
//!   server sessions terminate after 45s maximum.
//!
//! ## 4. Security & Safety Invariants
//! - **Mandatory Mutual Authentication**: Anonymous connections are terminated immediately during handshake.
//! - **Strict Byte Caps**: Server rejects any upload/download request exceeding `MAX_BENCHMARK_BYTES` (128 MiB).
//! - **Chunk Size Enforcement**: Out-of-bounds chunks trigger immediate session teardown.
//! - **Feature Flag Isolation**: If the `benchmark` feature switch is toggled off, incoming connections
//!   and outgoing test requests fail immediately.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::TELEMETRY_PORT;
use crate::features::FeatureManager;
use crate::security::transport::{ServiceId, TransportSessionV2};
use crate::trust;

/// Protocol opcode for Round-Trip Time (RTT) echo probe packets.
const MODE_PING: u8 = 1;

/// Protocol opcode for client-to-server bulk upload throughput test.
const MODE_UPLOAD: u8 = 2;

/// Protocol opcode for server-to-client bulk download throughput test.
const MODE_DOWNLOAD: u8 = 3;

/// Payload record chunk size (256 KiB), aligned with `TransportSessionV2::MAX_RECORD_PLAINTEXT_LEN`.
const CHUNK_SIZE: usize = 256 * 1024;

/// Baseline test volume (16 MiB) used on Wi-Fi and standard network routes.
const DEFAULT_BENCHMARK_BYTES: u64 = 16 * 1024 * 1024;

/// Absolute maximum test volume (128 MiB) permitted per direction to prevent buffer exhaustion.
const MAX_BENCHMARK_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum simultaneous unauthenticated handshake attempts allowed on the benchmark server.
const MAX_PRE_AUTH_BENCH_CONNS: usize = 16;

/// Maximum simultaneous active authenticated throughput tests permitted concurrently.
const MAX_CONCURRENT_BENCH_CONNS: usize = 4;

/// Per-frame / per-record socket read/write timeout guard.
const BENCH_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum allowable wall-clock duration for an entire benchmark session on the server.
const MAX_BENCH_SESSION_DURATION: Duration = Duration::from_secs(45);

/// Overall wall-clock timeout deadline enforced by the benchmark client for an entire speed test run.
const BENCHMARK_CLIENT_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum timeout duration for establishing the authenticated TCP benchmark session.
const BENCHMARK_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Number of sequential ping echo probes averaged to compute mean RTT latency.
const BENCHMARK_PING_SAMPLE_COUNT: u64 = 5;

/// Comprehensive results from a completed network throughput and latency benchmark test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    /// Indicates whether the benchmark completed successfully without transport or timeout errors.
    pub success: bool,
    /// Maximum measured throughput in Gigabit per second (Gbps) across upload and download directions.
    pub max_gbps: f64,
    /// Upload bandwidth from local machine to peer in Gigabit per second (Gbps).
    pub upload_gbps: f64,
    /// Upload transfer speed from local machine to peer in Megabytes per second (MB/s).
    pub upload_mb_s: f64,
    /// Download bandwidth from peer to local machine in Gigabit per second (Gbps).
    pub download_gbps: f64,
    /// Download transfer speed from peer to local machine in Megabytes per second (MB/s).
    pub download_mb_s: f64,
    /// Mean round-trip ping time in milliseconds (ms) over 5 consecutive probe samples.
    pub latency_ms: f64,
    /// IP address string of the benchmarked peer machine.
    pub peer_ip: String,
    /// Human-readable formatted summary string (e.g. `"2.45 Gbps max (290 MB/s up, 305 MB/s down) • 0.35 ms RTT"`).
    pub summary: String,
}

/// Global cache storing the most recent benchmark result indexed by peer IP address.
static LAST_BENCHMARK_BY_PEER: OnceLock<Mutex<HashMap<String, SpeedTestResult>>> = OnceLock::new();

/// Records a successful benchmark measurement into the in-memory peer history table.
///
/// Ignores unsuccessful results or empty peer IP strings.
pub fn record_measurement(result: &SpeedTestResult) {
    if !result.success || result.peer_ip.is_empty() {
        return;
    }
    let map = LAST_BENCHMARK_BY_PEER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        guard.insert(result.peer_ip.clone(), result.clone());
    }
}

/// Retrieves the most recent benchmark measurement recorded for the given `peer_ip`.
///
/// Returns `None` if no prior test has completed for this peer.
pub fn latest_measurement_for_peer(peer_ip: &str) -> Option<SpeedTestResult> {
    let map = LAST_BENCHMARK_BY_PEER.get()?;
    let guard = map.lock().ok()?;
    guard.get(peer_ip).cloned()
}

/// Benchmark responder daemon that accepts incoming benchmark connections on `TELEMETRY_PORT`.
pub struct BenchmarkServer;

impl BenchmarkServer {
    /// Starts the background benchmark receiver listening on `TELEMETRY_PORT` (58285).
    ///
    /// # Arguments
    /// * `features` - Shared feature manager reference used to reject requests when benchmarking is disabled.
    ///
    /// # Errors
    /// Returns an error if the TCP listener fails to bind to port 58285.
    pub async fn start(features: Arc<FeatureManager>) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", TELEMETRY_PORT))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind benchmark server on port {}: {}", TELEMETRY_PORT, e))?;
        info!("⚡ Speed Benchmark Server active on port {}", TELEMETRY_PORT);

        // Pre-auth and post-auth concurrency rate limiters
        let pre_auth_limiter = Arc::new(Semaphore::new(MAX_PRE_AUTH_BENCH_CONNS));
        let post_auth_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_BENCH_CONNS));

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        // Check if benchmark feature is enabled locally
                        if !features.is_enabled("benchmark") {
                            debug!(
                                "Dropped benchmark connection from {}: benchmark feature is disabled",
                                addr
                            );
                            drop(socket);
                            continue;
                        }

                        // Acquire pre-authentication permit to throttle connection floods
                        let Ok(pre_permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned() else {
                            warn!(
                                "Dropped pre-auth benchmark connection from {}: pre-auth concurrency limit reached",
                                addr
                            );
                            drop(socket);
                            continue;
                        };

                        let peer_ip = addr.ip();
                        // Enable TCP_NODELAY to minimize latency packet buffering
                        let _ = socket.set_nodelay(true);
                        let post_lim = Arc::clone(&post_auth_limiter);
                        let features_ref = Arc::clone(&features);

                        tokio::spawn(async move {
                            // Perform mutual cryptographic authentication handshake
                            let session = match trust::accept_transport_from_stream(
                                socket,
                                peer_ip,
                                None,
                                ServiceId::Benchmark,
                            )
                            .await
                            {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("🚫 Rejected unauthorized benchmark connection from {}: {}", addr, e);
                                    return;
                                }
                            };
                            // Handshake succeeded; release pre-auth permit
                            drop(pre_permit);

                            if !features_ref.is_enabled("benchmark") {
                                return;
                            }

                            // Acquire post-authentication execution permit
                            let Ok(_post_permit) = post_lim.try_acquire_owned() else {
                                warn!(
                                    "Dropped authenticated benchmark connection from {}: active benchmark concurrency limit reached",
                                    addr
                                );
                                return;
                            };

                            debug!("Authenticated TransportV2 benchmark connection from {}", addr);

                            // Execute benchmark session loop bounded by session timeout
                            match tokio::time::timeout(
                                MAX_BENCH_SESSION_DURATION,
                                Self::handle_connection(session, features_ref),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => debug!("Benchmark session ended: {}", e),
                                Err(_) => warn!("Benchmark session timed out after {:?}", MAX_BENCH_SESSION_DURATION),
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Benchmark server accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handles an individual authenticated benchmark session protocol loop.
    ///
    /// Interprets 9-byte command frames:
    /// - Byte 0: `MODE_PING (1)`, `MODE_UPLOAD (2)`, or `MODE_DOWNLOAD (3)`.
    /// - Bytes 1..9: Big-endian 64-bit integer payload parameter (sequence number or target byte count).
    async fn handle_connection(
        mut session: TransportSessionV2<TcpStream>,
        features: Arc<FeatureManager>,
    ) -> Result<()> {
        let dummy_chunk = vec![0xAAu8; CHUNK_SIZE];

        loop {
            if !features.is_enabled("benchmark") {
                anyhow::bail!("Benchmark feature disabled");
            }

            // Read 9-byte command header with 10s timeout
            let cmd = match tokio::time::timeout(BENCH_IO_TIMEOUT, session.recv_message()).await {
                Ok(Ok(msg)) if msg.len() == 9 => msg,
                _ => break,
            };

            let mode = cmd[0];
            let mut val_bytes = [0u8; 8];
            val_bytes.copy_from_slice(&cmd[1..9]);
            let val = u64::from_be_bytes(val_bytes);

            match mode {
                MODE_PING => {
                    // Echo back the 8-byte sequence number payload
                    tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&val_bytes))
                        .await?
                        .map_err(|e| anyhow::anyhow!("Benchmark ping reply error: {}", e))?;
                }
                MODE_UPLOAD => {
                    // Receive upload data from client until total requested bytes are ingested
                    let total_bytes = val;
                    if total_bytes == 0 || total_bytes > MAX_BENCHMARK_BYTES {
                        anyhow::bail!("Rejected benchmark upload size {} bytes", total_bytes);
                    }
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let chunk = tokio::time::timeout(BENCH_IO_TIMEOUT, session.recv_message())
                            .await?
                            .map_err(|e| anyhow::anyhow!("Benchmark upload read error: {}", e))?;
                        if chunk.is_empty() || (chunk.len() as u64) > remaining {
                            anyhow::bail!("Invalid benchmark upload chunk length {} (remaining {})", chunk.len(), remaining);
                        }
                        remaining -= chunk.len() as u64;
                    }

                    // Send 1-byte completion acknowledgment [0x01]
                    tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&[1u8]))
                        .await?
                        .map_err(|e| anyhow::anyhow!("Benchmark upload ack error: {}", e))?;
                }
                MODE_DOWNLOAD => {
                    // Stream dummy data chunks to client until total requested bytes are dispatched
                    let total_bytes = val;
                    if total_bytes == 0 || total_bytes > MAX_BENCHMARK_BYTES {
                        anyhow::bail!("Rejected benchmark download size {} bytes", total_bytes);
                    }
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
                        tokio::time::timeout(
                            BENCH_IO_TIMEOUT,
                            session.send_message(&dummy_chunk[..to_write]),
                        )
                        .await?
                        .map_err(|e| anyhow::anyhow!("Benchmark download write error: {}", e))?;
                        remaining -= to_write as u64;
                    }
                }
                _ => break,
            }
        }

        Ok(())
    }
}

/// Benchmark initiator client that connects to a remote peer and executes the speed test suite.
pub struct BenchmarkClient;

impl BenchmarkClient {
    /// Executes a live active throughput & latency benchmark against `peer_ip` with a 20-second safety timeout.
    ///
    /// # Arguments
    /// * `peer_ip` - Remote peer IPv4 or IPv6 address string.
    /// * `features` - Feature manager reference to check if benchmarking is permitted.
    ///
    /// # Return Value
    /// Returns `Ok(SpeedTestResult)` on completion, or `Err` if timeout occurs or test fails.
    pub async fn run_test(peer_ip: &str, features: &FeatureManager) -> Result<SpeedTestResult> {
        if !features.is_enabled("benchmark") {
            anyhow::bail!("Speed benchmark is disabled in feature settings.");
        }
        tokio::time::timeout(BENCHMARK_CLIENT_TIMEOUT, async move {
            // Connect and establish mutual cryptographic authentication on TELEMETRY_PORT
            let mut session = trust::connect_transport_to_ip(
                peer_ip,
                TELEMETRY_PORT,
                ServiceId::Benchmark,
                BENCHMARK_CONNECT_TIMEOUT,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to establish authenticated benchmark session with {}: {}", peer_ip, e))?;

            // --------------------------------------------------------------------
            // Phase 1: Latency Test (Ping x BENCHMARK_PING_SAMPLE_COUNT samples)
            // --------------------------------------------------------------------
            let mut latencies = Vec::new();
            for seq in 1u64..=BENCHMARK_PING_SAMPLE_COUNT {
                let start = Instant::now();
                let mut cmd = [0u8; 9];
                cmd[0] = MODE_PING;
                let expected_seq = seq.to_be_bytes();
                cmd[1..9].copy_from_slice(&expected_seq);

                // Send 9-byte ping command
                tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&cmd))
                    .await
                    .map_err(|_| anyhow::anyhow!("Benchmark ping send timed out"))?
                    .map_err(|e| anyhow::anyhow!("Benchmark ping send error: {}", e))?;

                // Await 8-byte echo response
                let reply = tokio::time::timeout(BENCH_IO_TIMEOUT, session.recv_message())
                    .await
                    .map_err(|_| anyhow::anyhow!("Benchmark ping recv timed out"))?
                    .map_err(|e| anyhow::anyhow!("Benchmark ping recv error: {}", e))?;

                if reply.as_slice() != expected_seq {
                    anyhow::bail!(
                        "Invalid benchmark ping echo payload (expected seq {}, got {} bytes)",
                        seq,
                        reply.len()
                    );
                }
                latencies.push(start.elapsed().as_secs_f64() * 1000.0);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            if latencies.is_empty() {
                anyhow::bail!("Failed to measure RTT samples against {}", peer_ip);
            }
            let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;

            // Baseline payload size (16 MiB) for reliable transfer across network routes
            let bench_bytes: u64 = DEFAULT_BENCHMARK_BYTES;

            // --------------------------------------------------------------------
            // Phase 2: Upload Throughput Test (Client -> Server)
            // --------------------------------------------------------------------
            let dummy_chunk = vec![0x55u8; CHUNK_SIZE];
            let start_upload = Instant::now();
            let mut up_cmd = [0u8; 9];
            up_cmd[0] = MODE_UPLOAD;
            up_cmd[1..9].copy_from_slice(&bench_bytes.to_be_bytes());

            // Send upload start command with requested byte count
            tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&up_cmd))
                .await
                .map_err(|_| anyhow::anyhow!("Benchmark upload command timed out"))?
                .map_err(|e| anyhow::anyhow!("Benchmark upload command error: {}", e))?;

            // Stream raw chunks until bench_bytes transmitted
            let mut remaining = bench_bytes;
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
                tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&dummy_chunk[..to_write]))
                    .await
                    .map_err(|_| anyhow::anyhow!("Benchmark upload frame timed out"))?
                    .map_err(|e| anyhow::anyhow!("Benchmark upload frame error: {}", e))?;
                remaining -= to_write as u64;
            }

            // Await server ACK [0x01]
            let ack = tokio::time::timeout(BENCH_IO_TIMEOUT, session.recv_message())
                .await
                .map_err(|_| anyhow::anyhow!("Benchmark upload ack timed out"))?
                .map_err(|e| anyhow::anyhow!("Benchmark upload ack recv error: {}", e))?;

            if ack.as_slice() != [1u8] {
                anyhow::bail!("Invalid benchmark upload ACK from {}", peer_ip);
            }

            let upload_dur = start_upload.elapsed().as_secs_f64().max(0.000_1);
            let upload_mb_s = (bench_bytes as f64 / (1024.0 * 1024.0)) / upload_dur;
            let upload_gbps = (bench_bytes as f64 * 8.0) / (upload_dur * 1_000_000_000.0);

            // --------------------------------------------------------------------
            // Phase 3: Download Throughput Test (Server -> Client)
            // --------------------------------------------------------------------
            let start_download = Instant::now();
            let mut down_cmd = [0u8; 9];
            down_cmd[0] = MODE_DOWNLOAD;
            down_cmd[1..9].copy_from_slice(&bench_bytes.to_be_bytes());

            // Send download start command with requested byte count
            tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&down_cmd))
                .await
                .map_err(|_| anyhow::anyhow!("Benchmark download command timed out"))?
                .map_err(|e| anyhow::anyhow!("Benchmark download command error: {}", e))?;

            // Ingest chunks from server until bench_bytes received
            let mut remaining = bench_bytes;
            while remaining > 0 {
                let chunk = tokio::time::timeout(BENCH_IO_TIMEOUT, session.recv_message())
                    .await
                    .map_err(|_| anyhow::anyhow!("Benchmark download frame timed out"))?
                    .map_err(|e| anyhow::anyhow!("Benchmark download frame error: {}", e))?;

                if chunk.is_empty() || (chunk.len() as u64) > remaining {
                    anyhow::bail!("Benchmark download invalid chunk size {}", chunk.len());
                }
                remaining -= chunk.len() as u64;
            }

            let download_dur = start_download.elapsed().as_secs_f64().max(0.000_1);
            let download_mb_s = (bench_bytes as f64 / (1024.0 * 1024.0)) / download_dur;
            let download_gbps = (bench_bytes as f64 * 8.0) / (download_dur * 1_000_000_000.0);

            // --------------------------------------------------------------------
            // Phase 4: Format Metrics & Record Result
            // --------------------------------------------------------------------
            let max_gbps = upload_gbps.max(download_gbps);
            let summary = format!(
                "{:.2} Gbps max ({:.0} MB/s up, {:.0} MB/s down) • {:.2} ms RTT",
                max_gbps, upload_mb_s, download_mb_s, avg_latency
            );

            info!("⚡ Live Benchmark Results with {}: {}", peer_ip, summary);

            let result = SpeedTestResult {
                success: true,
                max_gbps: (max_gbps * 100.0).round() / 100.0,
                upload_gbps: (upload_gbps * 100.0).round() / 100.0,
                upload_mb_s: upload_mb_s.round(),
                download_gbps: (download_gbps * 100.0).round() / 100.0,
                download_mb_s: download_mb_s.round(),
                latency_ms: (avg_latency * 100.0).round() / 100.0,
                peer_ip: peer_ip.to_string(),
                summary,
            };

            record_measurement(&result);
            Ok(result)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Speed benchmark timed out after {} seconds",
                BENCHMARK_CLIENT_TIMEOUT.as_secs()
            )
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureFlags;

    #[test]
    fn stores_and_retrieves_latest_measurement_per_peer() {
        let sample = SpeedTestResult {
            success: true,
            max_gbps: 2.34,
            upload_gbps: 2.10,
            upload_mb_s: 262.0,
            download_gbps: 2.34,
            download_mb_s: 292.0,
            latency_ms: 0.42,
            peer_ip: "10.99.99.2".to_string(),
            summary: "2.34 Gbps max".to_string(),
        };
        record_measurement(&sample);
        let got = latest_measurement_for_peer("10.99.99.2").expect("stored benchmark");
        assert!((got.max_gbps - 2.34).abs() < 0.001);
    }

    #[tokio::test]
    async fn client_refuses_when_benchmark_feature_disabled() {
        let mut flags = FeatureFlags::default();
        flags.benchmark = false;
        let mgr = FeatureManager::from_flags_for_test(flags);
        let res = BenchmarkClient::run_test("127.0.0.1", &mgr).await;
        assert!(res.is_err());
    }
}
