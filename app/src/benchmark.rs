//! High-performance point-to-point network benchmark service.
//! Measures active link latency (RTT) and maximum live throughput (Gbps / MB/s)
//! bidirectionally over mutually authenticated `TransportSessionV2` (`ServiceId::Benchmark`).

use std::sync::Arc;
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

const MODE_PING: u8 = 1;
const MODE_UPLOAD: u8 = 2;
const MODE_DOWNLOAD: u8 = 3;

const CHUNK_SIZE: usize = 256 * 1024; // 256 KiB (matches TransportV2 MAX_RECORD_PLAINTEXT_LEN)
const DEFAULT_BENCHMARK_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB adaptive baseline
const MAX_BENCHMARK_BYTES: u64 = 128 * 1024 * 1024; // Hard 128 MiB cap per direction
const MAX_PRE_AUTH_BENCH_CONNS: usize = 16;
const MAX_CONCURRENT_BENCH_CONNS: usize = 4;
const BENCH_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BENCH_SESSION_DURATION: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub success: bool,
    pub max_gbps: f64,
    pub upload_gbps: f64,
    pub upload_mb_s: f64,
    pub download_gbps: f64,
    pub download_mb_s: f64,
    pub latency_ms: f64,
    pub peer_ip: String,
    pub summary: String,
}

pub struct BenchmarkServer;

impl BenchmarkServer {
    /// Starts the background benchmark receiver listening on TELEMETRY_PORT (58285).
    pub async fn start(features: Arc<FeatureManager>) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", TELEMETRY_PORT))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind benchmark server on port {}: {}", TELEMETRY_PORT, e))?;
        info!("⚡ Speed Benchmark Server active on port {}", TELEMETRY_PORT);

        let pre_auth_limiter = Arc::new(Semaphore::new(MAX_PRE_AUTH_BENCH_CONNS));
        let post_auth_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_BENCH_CONNS));

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        if !features.is_enabled("benchmark") {
                            debug!(
                                "Dropped benchmark connection from {}: benchmark feature is disabled",
                                addr
                            );
                            drop(socket);
                            continue;
                        }
                        let Ok(pre_permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned() else {
                            warn!(
                                "Dropped pre-auth benchmark connection from {}: pre-auth concurrency limit reached",
                                addr
                            );
                            drop(socket);
                            continue;
                        };
                        let peer_ip = addr.ip();
                        let _ = socket.set_nodelay(true);
                        let post_lim = Arc::clone(&post_auth_limiter);
                        let features_ref = Arc::clone(&features);
                        tokio::spawn(async move {
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
                            drop(pre_permit);

                            if !features_ref.is_enabled("benchmark") {
                                return;
                            }
                            let Ok(_post_permit) = post_lim.try_acquire_owned() else {
                                warn!(
                                    "Dropped authenticated benchmark connection from {}: active benchmark concurrency limit reached",
                                    addr
                                );
                                return;
                            };

                            debug!("Authenticated TransportV2 benchmark connection from {}", addr);
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

    async fn handle_connection(
        mut session: TransportSessionV2<TcpStream>,
        features: Arc<FeatureManager>,
    ) -> Result<()> {
        let dummy_chunk = vec![0xAAu8; CHUNK_SIZE];

        loop {
            if !features.is_enabled("benchmark") {
                anyhow::bail!("Benchmark feature disabled");
            }
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
                    tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&val_bytes))
                        .await?
                        .map_err(|e| anyhow::anyhow!("Benchmark ping reply error: {}", e))?;
                }
                MODE_UPLOAD => {
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

                    tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&[1u8]))
                        .await?
                        .map_err(|e| anyhow::anyhow!("Benchmark upload ack error: {}", e))?;
                }
                MODE_DOWNLOAD => {
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

pub struct BenchmarkClient;

impl BenchmarkClient {
    /// Executes a live active throughput & latency benchmark against peer_ip with a 20-second safety timeout.
    pub async fn run_test(peer_ip: &str, features: &FeatureManager) -> Result<SpeedTestResult> {
        if !features.is_enabled("benchmark") {
            anyhow::bail!("Speed benchmark is disabled in feature settings.");
        }
        tokio::time::timeout(Duration::from_secs(20), Self::run_test_internal(peer_ip))
            .await
            .map_err(|_| anyhow::anyhow!("Speed benchmark timed out after 20 seconds"))?
    }

    async fn run_test_internal(peer_ip: &str) -> Result<SpeedTestResult> {
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            TELEMETRY_PORT,
            ServiceId::Benchmark,
            Duration::from_secs(4),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish authenticated benchmark session with {}: {}", peer_ip, e))?;

        // 1. Latency Test (Ping x 5)
        let mut latencies = Vec::new();
        for seq in 1u64..=5 {
            let start = Instant::now();
            let mut cmd = [0u8; 9];
            cmd[0] = MODE_PING;
            let expected_seq = seq.to_be_bytes();
            cmd[1..9].copy_from_slice(&expected_seq);
            tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&cmd))
                .await
                .map_err(|_| anyhow::anyhow!("Benchmark ping send timed out"))?
                .map_err(|e| anyhow::anyhow!("Benchmark ping send error: {}", e))?;

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

        // Scale payload size based on RTT so high-speed links saturate while slow Wi-Fi doesn't time out
        let bench_bytes: u64 = if avg_latency < 2.0 {
            64 * 1024 * 1024
        } else {
            DEFAULT_BENCHMARK_BYTES
        };

        // 2. Upload Throughput Test
        let dummy_chunk = vec![0x55u8; CHUNK_SIZE];
        let start_upload = Instant::now();
        let mut up_cmd = [0u8; 9];
        up_cmd[0] = MODE_UPLOAD;
        up_cmd[1..9].copy_from_slice(&bench_bytes.to_be_bytes());
        tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&up_cmd))
            .await
            .map_err(|_| anyhow::anyhow!("Benchmark upload command timed out"))?
            .map_err(|e| anyhow::anyhow!("Benchmark upload command error: {}", e))?;

        let mut remaining = bench_bytes;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
            tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&dummy_chunk[..to_write]))
                .await
                .map_err(|_| anyhow::anyhow!("Benchmark upload frame timed out"))?
                .map_err(|e| anyhow::anyhow!("Benchmark upload frame error: {}", e))?;
            remaining -= to_write as u64;
        }

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

        // 3. Download Throughput Test
        let start_download = Instant::now();
        let mut down_cmd = [0u8; 9];
        down_cmd[0] = MODE_DOWNLOAD;
        down_cmd[1..9].copy_from_slice(&bench_bytes.to_be_bytes());
        tokio::time::timeout(BENCH_IO_TIMEOUT, session.send_message(&down_cmd))
            .await
            .map_err(|_| anyhow::anyhow!("Benchmark download command timed out"))?
            .map_err(|e| anyhow::anyhow!("Benchmark download command error: {}", e))?;

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

        let max_gbps = upload_gbps.max(download_gbps);
        let summary = format!(
            "{:.2} Gbps max ({:.0} MB/s up, {:.0} MB/s down) • {:.2} ms RTT",
            max_gbps, upload_mb_s, download_mb_s, avg_latency
        );

        info!("⚡ Live Benchmark Results with {}: {}", peer_ip, summary);

        Ok(SpeedTestResult {
            success: true,
            max_gbps: (max_gbps * 100.0).round() / 100.0,
            upload_gbps: (upload_gbps * 100.0).round() / 100.0,
            upload_mb_s: upload_mb_s.round(),
            download_gbps: (download_gbps * 100.0).round() / 100.0,
            download_mb_s: download_mb_s.round(),
            latency_ms: (avg_latency * 100.0).round() / 100.0,
            peer_ip: peer_ip.to_string(),
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureFlags;

    #[tokio::test]
    async fn client_refuses_when_benchmark_feature_disabled() {
        let mut flags = FeatureFlags::default();
        flags.benchmark = false;
        let mgr = FeatureManager::from_flags_for_test(flags);
        let res = BenchmarkClient::run_test("127.0.0.1", &mgr).await;
        assert!(res.is_err());
    }
}
