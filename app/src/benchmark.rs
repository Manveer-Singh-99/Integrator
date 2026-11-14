//! High-performance point-to-point network benchmark service.
//! Measures active link latency (RTT) and maximum live throughput (Gbps / MB/s)
//! bidirectionally over TCP with peer authorization, connection limits, and I/O timeouts.

use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::TELEMETRY_PORT;
use crate::trust;

const MODE_PING: u8 = 1;
const MODE_UPLOAD: u8 = 2;
const MODE_DOWNLOAD: u8 = 3;

const CHUNK_SIZE: usize = 128 * 1024; // 128 KiB
const DEFAULT_BENCHMARK_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB adaptive baseline
const MAX_BENCHMARK_BYTES: u64 = 128 * 1024 * 1024; // Hard 128 MiB cap per direction
const MAX_CONCURRENT_BENCH_CONNS: usize = 4;
const BENCH_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
    pub async fn start() -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", TELEMETRY_PORT))
            .await
            .with_context(|| format!("Failed to bind benchmark server on port {}", TELEMETRY_PORT))?;
        info!("⚡ Speed Benchmark Server active on port {}", TELEMETRY_PORT);

        let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_BENCH_CONNS));

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let Ok(permit) = Arc::clone(&conn_limiter).try_acquire_owned() else {
                            warn!("Dropped benchmark connection from {}: concurrency limit reached", addr);
                            drop(socket);
                            continue;
                        };
                        let peer_ip = addr.ip();
                        let _ = socket.set_nodelay(true);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let authorized = tokio::task::spawn_blocking(move || {
                                trust::is_remote_addr_authorized(peer_ip)
                            })
                            .await
                            .unwrap_or(false);
                            if !authorized {
                                warn!("🚫 Rejected unauthorized benchmark connection from {}", addr);
                                return;
                            }
                            debug!("Benchmark connection from {}", addr);
                            if let Err(e) = Self::handle_connection(socket).await {
                                debug!("Benchmark session ended: {}", e);
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

    async fn handle_connection(mut socket: TcpStream) -> Result<()> {
        let dummy_chunk = vec![0xAAu8; CHUNK_SIZE];
        let mut recv_buf = vec![0u8; CHUNK_SIZE];

        loop {
            let mode = match tokio::time::timeout(BENCH_IO_TIMEOUT, socket.read_u8()).await {
                Ok(Ok(m)) => m,
                _ => break,
            };

            match mode {
                MODE_PING => {
                    let timestamp = tokio::time::timeout(BENCH_IO_TIMEOUT, socket.read_u64()).await??;
                    tokio::time::timeout(BENCH_IO_TIMEOUT, async {
                        socket.write_u64(timestamp).await?;
                        socket.flush().await
                    })
                    .await??;
                }
                MODE_UPLOAD => {
                    let total_bytes = tokio::time::timeout(BENCH_IO_TIMEOUT, socket.read_u64()).await??;
                    if total_bytes == 0 || total_bytes > MAX_BENCHMARK_BYTES {
                        anyhow::bail!("Rejected benchmark upload size {} bytes", total_bytes);
                    }
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let to_read = std::cmp::min(remaining, recv_buf.len() as u64) as usize;
                        let n = tokio::time::timeout(
                            BENCH_IO_TIMEOUT,
                            socket.read(&mut recv_buf[..to_read]),
                        )
                        .await??;
                        if n == 0 {
                            break;
                        }
                        remaining -= n as u64;
                    }

                    tokio::time::timeout(BENCH_IO_TIMEOUT, async {
                        socket.write_u8(1).await?;
                        socket.flush().await
                    })
                    .await??;
                }
                MODE_DOWNLOAD => {
                    let total_bytes = tokio::time::timeout(BENCH_IO_TIMEOUT, socket.read_u64()).await??;
                    if total_bytes == 0 || total_bytes > MAX_BENCHMARK_BYTES {
                        anyhow::bail!("Rejected benchmark download size {} bytes", total_bytes);
                    }
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
                        tokio::time::timeout(
                            BENCH_IO_TIMEOUT,
                            socket.write_all(&dummy_chunk[..to_write]),
                        )
                        .await??;
                        remaining -= to_write as u64;
                    }

                    tokio::time::timeout(BENCH_IO_TIMEOUT, socket.flush()).await??;
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
    pub async fn run_test(peer_ip: &str) -> Result<SpeedTestResult> {
        tokio::time::timeout(Duration::from_secs(20), Self::run_test_internal(peer_ip))
            .await
            .map_err(|_| anyhow::anyhow!("Speed benchmark timed out after 20 seconds"))?
    }

    async fn run_test_internal(peer_ip: &str) -> Result<SpeedTestResult> {
        let addr = format!("{}:{}", peer_ip, TELEMETRY_PORT);
        let mut stream = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&addr))
            .await
            .with_context(|| format!("Timed out connecting to benchmark server at {}", addr))?
            .with_context(|| format!("Failed to connect to benchmark server at {}", addr))?;
        stream.set_nodelay(true)?;

        // 1. Latency Test (Ping x 5)
        let mut latencies = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            stream.write_u8(MODE_PING).await?;
            stream.write_u64(1).await?;
            stream.flush().await?;

            let _ = stream.read_u64().await?;
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
        stream.write_u8(MODE_UPLOAD).await?;
        stream.write_u64(bench_bytes).await?;

        let mut remaining = bench_bytes;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
            stream.write_all(&dummy_chunk[..to_write]).await?;
            remaining -= to_write as u64;
        }
        stream.flush().await?;

        let _ack = stream.read_u8().await?;
        let upload_dur = start_upload.elapsed().as_secs_f64().max(0.000_1);
        let upload_mb_s = (bench_bytes as f64 / (1024.0 * 1024.0)) / upload_dur;
        let upload_gbps = (bench_bytes as f64 * 8.0) / (upload_dur * 1_000_000_000.0);

        // 3. Download Throughput Test
        let mut recv_buf = vec![0u8; CHUNK_SIZE];
        let start_download = Instant::now();
        stream.write_u8(MODE_DOWNLOAD).await?;
        stream.write_u64(bench_bytes).await?;
        stream.flush().await?;

        let mut remaining = bench_bytes;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, recv_buf.len() as u64) as usize;
            let n = stream.read(&mut recv_buf[..to_read]).await?;
            if n == 0 {
                anyhow::bail!("Benchmark download stream closed prematurely");
            }
            remaining -= n as u64;
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
