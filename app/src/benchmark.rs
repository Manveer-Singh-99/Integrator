//! High-performance point-to-point network benchmark service.
//! Measures active link latency (RTT) and maximum live throughput (Gbps / MB/s)
//! bidirectionally over TCP using large zero-copy streaming buffers.

use std::time::{Duration, Instant};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn, debug};

use crate::config::TELEMETRY_PORT;

const MODE_PING: u8 = 1;
const MODE_UPLOAD: u8 = 2;
const MODE_DOWNLOAD: u8 = 3;

const CHUNK_SIZE: usize = 128 * 1024; // 128 KB
const BENCHMARK_BYTES: u64 = 64 * 1024 * 1024; // 64 MB per direction

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
        let listener = TcpListener::bind(format!("0.0.0.0:{}", TELEMETRY_PORT)).await
            .with_context(|| format!("Failed to bind benchmark server on port {}", TELEMETRY_PORT))?;
        info!("⚡ Speed Benchmark Server active on port {}", TELEMETRY_PORT);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        debug!("Benchmark connection from {}", addr);
                        let _ = socket.set_nodelay(true);
                        tokio::spawn(async move {
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
            let mode = match socket.read_u8().await {
                Ok(m) => m,
                Err(_) => break, // normal client disconnect
            };

            match mode {
                MODE_PING => {
                    let timestamp = socket.read_u64().await?;
                    socket.write_u64(timestamp).await?;
                    socket.flush().await?;
                }
                MODE_UPLOAD => {
                    // Client is streaming data to us. We read and discard.
                    let total_bytes = socket.read_u64().await?;
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let to_read = std::cmp::min(remaining, recv_buf.len() as u64) as usize;
                        let n = socket.read(&mut recv_buf[..to_read]).await?;
                        if n == 0 {
                            break;
                        }
                        remaining -= n as u64;
                    }

                    // Send ACK back
                    socket.write_u8(1).await?;
                    socket.flush().await?;
                }
                MODE_DOWNLOAD => {
                    // Client wants us to stream data to them.
                    let total_bytes = socket.read_u64().await?;
                    let mut remaining = total_bytes;

                    while remaining > 0 {
                        let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
                        socket.write_all(&dummy_chunk[..to_write]).await?;
                        remaining -= to_write as u64;
                    }

                    socket.flush().await?;
                }
                _ => break,
            }
        }

        Ok(())
    }
}

pub struct BenchmarkClient;

impl BenchmarkClient {
    /// Executes a live active throughput & latency benchmark against peer_ip with a 15-second safety timeout.
    pub async fn run_test(peer_ip: &str) -> Result<SpeedTestResult> {
        tokio::time::timeout(Duration::from_secs(15), Self::run_test_internal(peer_ip))
            .await
            .map_err(|_| anyhow::anyhow!("Speed benchmark timed out after 15 seconds"))?
    }

    async fn run_test_internal(peer_ip: &str) -> Result<SpeedTestResult> {
        let addr = format!("{}:{}", peer_ip, TELEMETRY_PORT);
        let mut stream = TcpStream::connect(&addr).await
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
        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        } else {
            0.5
        };

        // 2. Upload Throughput Test (Send BENCHMARK_BYTES to peer)
        let dummy_chunk = vec![0x55u8; CHUNK_SIZE];
        let start_upload = Instant::now();
        stream.write_u8(MODE_UPLOAD).await?;
        stream.write_u64(BENCHMARK_BYTES).await?;

        let mut remaining = BENCHMARK_BYTES;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, dummy_chunk.len() as u64) as usize;
            stream.write_all(&dummy_chunk[..to_write]).await?;
            remaining -= to_write as u64;
        }
        stream.flush().await?;

        // Wait for server ACK
        let _ack = stream.read_u8().await?;
        let upload_dur = start_upload.elapsed().as_secs_f64();
        let upload_mb_s = (BENCHMARK_BYTES as f64 / (1024.0 * 1024.0)) / upload_dur;
        let upload_gbps = (BENCHMARK_BYTES as f64 * 8.0) / (upload_dur * 1_000_000_000.0);

        // 3. Download Throughput Test (Receive BENCHMARK_BYTES from peer)
        let mut recv_buf = vec![0u8; CHUNK_SIZE];
        let start_download = Instant::now();
        stream.write_u8(MODE_DOWNLOAD).await?;
        stream.write_u64(BENCHMARK_BYTES).await?;
        stream.flush().await?;

        let mut remaining = BENCHMARK_BYTES;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, recv_buf.len() as u64) as usize;
            let n = stream.read(&mut recv_buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            remaining -= n as u64;
        }

        let download_dur = start_download.elapsed().as_secs_f64();
        let download_mb_s = (BENCHMARK_BYTES as f64 / (1024.0 * 1024.0)) / download_dur;
        let download_gbps = (BENCHMARK_BYTES as f64 * 8.0) / (download_dur * 1_000_000_000.0);

        let max_gbps = upload_gbps.max(download_gbps);
        let summary = format!(
            "{:.2} Gbps max ({:.0} MB/s up, {:.0} MB/s down) • {:.2} ms RTT",
            max_gbps, upload_mb_s, download_mb_s, avg_latency
        );

        info!("⚡ Live Benchmark Results with {}: {}", peer_ip, summary);

        Ok(SpeedTestResult {
            success: true,
            max_gbps,
            upload_gbps,
            upload_mb_s,
            download_gbps,
            download_mb_s,
            latency_ms: avg_latency,
            peer_ip: peer_ip.to_string(),
            summary,
        })
    }
}
