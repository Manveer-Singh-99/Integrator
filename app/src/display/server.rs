use anyhow::Result;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::CONTROL_PORT;
use crate::trust;

use super::controller::DisplayController;
use super::protocol::{DisplayRpcRequest, DisplayRpcResponse};

const MAX_RPC_BYTES: usize = 65_536;

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
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let c = ctrl.clone();
                        let peer_ip = addr.ip();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(socket, peer_ip, c).await {
                                error!("Display RPC connection error from {}: {}", peer_ip, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Display control TCP listener error: {}", e);
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
        let req_len = socket.read_u32().await? as usize;
        if req_len == 0 || req_len > MAX_RPC_BYTES {
            anyhow::bail!("Rejected RPC frame size {} bytes from {}", req_len, peer_ip);
        }

        let mut buf = vec![0u8; req_len];
        socket.read_exact(&mut buf).await?;

        let req: DisplayRpcRequest = serde_json::from_slice(&buf)?;

        let requires_trust = !matches!(
            req,
            DisplayRpcRequest::Ping
                | DisplayRpcRequest::GetHardwareProfile
                | DisplayRpcRequest::PairRequest { .. }
        );

        let resp = if requires_trust && !trust::is_remote_addr_authorized(peer_ip) {
            warn!("🚫 Rejected untrusted Display RPC {:?} from {}", req, peer_ip);
            DisplayRpcResponse {
                success: false,
                message: "Peer is not trusted/paired on this host. Approve pairing in Integrator UI or use a direct USB-C/Thunderbolt cable.".to_string(),
                ..Default::default()
            }
        } else {
            controller.handle_rpc(req, Some(peer_ip)).await
        };

        let resp_bytes = serde_json::to_vec(&resp)?;
        socket.write_u32(resp_bytes.len() as u32).await?;
        socket.write_all(&resp_bytes).await?;

        Ok(())
    }
}
