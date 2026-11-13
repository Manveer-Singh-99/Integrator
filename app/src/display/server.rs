//! TCP server for display control RPC requests.

use std::time::Duration;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tracing::{info, debug, warn, error};

use crate::config::CONTROL_PORT;
use super::controller::DisplayController;
use super::protocol::DisplayRpcRequest;

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

        let controller = self.controller.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        debug!("Incoming display control RPC connection from {}", addr);
                        let ctrl = controller.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(socket, ctrl).await {
                                warn!("Error handling display control RPC from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Display control TCP listener error: {}", e);
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(mut socket: TcpStream, controller: DisplayController) -> Result<()> {
        let req_len = socket.read_u32().await? as usize;
        let mut buf = vec![0u8; req_len];
        socket.read_exact(&mut buf).await?;

        let req: DisplayRpcRequest = serde_json::from_slice(&buf)?;
        let resp = controller.handle_rpc(req).await;

        let resp_bytes = serde_json::to_vec(&resp)?;
        socket.write_u32(resp_bytes.len() as u32).await?;
        socket.write_all(&resp_bytes).await?;
        socket.flush().await?;

        Ok(())
    }
}
