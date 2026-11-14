use anyhow::{Context, Result};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::CONTROL_PORT;
use crate::trust;

use super::controller::DisplayController;
use super::protocol::{DisplayRpcRequest, DisplayRpcResponse};

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

        let req_len = tokio::time::timeout(RPC_IO_TIMEOUT, socket.read_u32())
            .await
            .context("Timed out reading Display RPC frame length")?? as usize;

        if req_len == 0 || req_len > MAX_RPC_BYTES {
            anyhow::bail!("Rejected RPC frame size {} bytes from {}", req_len, peer_ip);
        }

        let mut buf = vec![0u8; req_len];
        tokio::time::timeout(RPC_IO_TIMEOUT, socket.read_exact(&mut buf))
            .await
            .context("Timed out reading Display RPC frame body")??;

        let is_raw_loopback =
            peer_ip.is_loopback() && serde_json::from_slice::<DisplayRpcRequest>(&buf).is_ok();

        let (authenticated_dev_id, plaintext) = match trust::open_envelope_from_ip(peer_ip, &buf) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("🚫 Rejected Display RPC envelope from {}: {}", peer_ip, e);
                anyhow::bail!("{}", e);
            }
        };

        let req: DisplayRpcRequest = serde_json::from_slice(&plaintext)?;

        let requires_trust = !matches!(
            req,
            DisplayRpcRequest::Ping
                | DisplayRpcRequest::GetHardwareProfile
                | DisplayRpcRequest::PairRequest { .. }
        );

        let is_trusted = authenticated_dev_id.is_some() || trust::is_remote_addr_authorized(peer_ip);

        let resp = if requires_trust && !is_trusted {
            warn!("🚫 Rejected untrusted Display RPC {:?} from {}", req, peer_ip);
            DisplayRpcResponse {
                success: false,
                message: "Peer is not trusted/paired on this host. Pair using the 6-digit PIN in the Integrator UI.".to_string(),
                ..Default::default()
            }
        } else {
            controller.handle_rpc(req, Some(peer_ip)).await
        };

        let resp_json = serde_json::to_vec(&resp)?;
        let wire_bytes = if is_raw_loopback {
            resp_json
        } else {
            trust::seal_envelope_for_ip(&peer_ip.to_string(), &resp_json)
                .map_err(|e| anyhow::anyhow!(e))?
        };

        tokio::time::timeout(RPC_IO_TIMEOUT, async {
            socket.write_u32(wire_bytes.len() as u32).await?;
            socket.write_all(&wire_bytes).await?;
            socket.flush().await
        })
        .await
        .context("Timed out writing Display RPC response")??;

        Ok(())
    }
}
