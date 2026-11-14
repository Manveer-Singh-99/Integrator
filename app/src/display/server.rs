use anyhow::{Context, Result};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::CONTROL_PORT;
use crate::security::pairing::PAIRING_WIRE_MAGIC;
use crate::security::transport::{ServiceId, TRANSPORT_WIRE_MAGIC};
use crate::trust;

use super::controller::DisplayController;
use super::protocol::DisplayRpcRequest;

const MAX_RPC_BYTES: usize = 65_536;
const MAX_CONCURRENT_RPC_CONNS: usize = 32;
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DisplayServer {
    controller: DisplayController,
}

impl DisplayServer {
    pub fn new(controller: DisplayController) -> Self {
        Self { controller }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", CONTROL_PORT)).await?;
        info!("🖥️ Display Control RPC Server active on port {}", CONTROL_PORT);

        let ctrl = self.controller.clone();
        let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_RPC_CONNS));

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let peer_ip = addr.ip();
                        let Ok(permit) = Arc::clone(&conn_limiter).try_acquire_owned() else {
                            warn!(
                                "🚫 Dropped Display RPC connection from {}: concurrency limit ({}) reached",
                                peer_ip, MAX_CONCURRENT_RPC_CONNS
                            );
                            drop(socket);
                            continue;
                        };
                        let c = ctrl.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = Self::handle_connection(socket, peer_ip, c).await {
                                error!("Display RPC connection error from {}: {}", peer_ip, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Display control TCP listener error: {}", e);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(
        mut socket: TcpStream,
        peer_ip: IpAddr,
        controller: DisplayController,
    ) -> Result<()> {
        let _ = socket.set_nodelay(true);

        let mut magic = [0u8; 4];
        match tokio::time::timeout(RPC_IO_TIMEOUT, socket.read_exact(&mut magic)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Clean TCP connect probe (e.g. discovery RTT measurement)
                return Ok(());
            }
            Ok(Err(e)) => {
                return Err(e).context("Failed reading wire magic on Display RPC port");
            }
            Err(_) => {
                anyhow::bail!("Timed out reading wire magic from {}", peer_ip);
            }
        }

        if magic == PAIRING_WIRE_MAGIC {
            let (creds, sas_6) =
                trust::handle_incoming_pairing_stream_v2(&mut socket, peer_ip, Some(magic))
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
            info!(
                "🔐 Completed IPR2 pairing with '{}' ({}) at {} [SAS: {}]",
                creds.hostname, creds.device_id_hex, peer_ip, sas_6
            );
            return Ok(());
        }

        if magic != TRANSPORT_WIRE_MAGIC {
            warn!(
                "🚫 Rejected unknown or legacy v1 wire magic {:02x?} from {}",
                magic, peer_ip
            );
            anyhow::bail!("Rejected unsupported wire protocol magic from {}", peer_ip);
        }

        let mut session = trust::accept_transport_from_stream(
            socket,
            peer_ip,
            Some(magic),
            ServiceId::DisplayRpc,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

        let plaintext = tokio::time::timeout(RPC_IO_TIMEOUT, session.recv_message())
            .await
            .context("Timed out reading Display RPC message over TransportV2")?
            .map_err(|e| anyhow::anyhow!("Display RPC TransportV2 read error: {}", e))?;

        if plaintext.is_empty() || plaintext.len() > MAX_RPC_BYTES {
            anyhow::bail!(
                "Rejected Display RPC payload size {} bytes from {}",
                plaintext.len(),
                peer_ip
            );
        }

        let req: DisplayRpcRequest = serde_json::from_slice(&plaintext)?;
        let resp = controller.handle_rpc(req, Some(peer_ip)).await;
        let resp_json = serde_json::to_vec(&resp)?;

        tokio::time::timeout(RPC_IO_TIMEOUT, session.send_message(&resp_json))
            .await
            .context("Timed out writing Display RPC response over TransportV2")?
            .map_err(|e| anyhow::anyhow!("Display RPC TransportV2 write error: {}", e))?;

        Ok(())
    }
}
