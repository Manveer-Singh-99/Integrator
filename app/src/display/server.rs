use anyhow::{Context, Result};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, info, warn};

use crate::config::CONTROL_PORT;
use crate::features::FeatureManager;
use crate::security::pairing::PAIRING_WIRE_MAGIC;
use crate::security::transport::{ServiceId, TRANSPORT_WIRE_MAGIC};
use crate::trust;

use super::controller::DisplayController;
use super::protocol::{required_feature_for_rpc, DisplayRpcRequest, DisplayRpcResponse};

const MAX_RPC_BYTES: usize = 65_536;
const MAX_PRE_AUTH_CONNS: usize = 32;
const MAX_POST_AUTH_CONNS: usize = 16;
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const PAIRING_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DisplayServer {
    controller: DisplayController,
    features: Arc<FeatureManager>,
}

impl DisplayServer {
    pub fn new(controller: DisplayController, features: Arc<FeatureManager>) -> Self {
        Self {
            controller,
            features,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", CONTROL_PORT)).await?;
        info!("🖥️ Display Control RPC Server active on port {}", CONTROL_PORT);

        let ctrl = self.controller.clone();
        let features = Arc::clone(&self.features);
        let pre_auth_limiter = Arc::new(Semaphore::new(MAX_PRE_AUTH_CONNS));
        let post_auth_limiter = Arc::new(Semaphore::new(MAX_POST_AUTH_CONNS));

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let peer_ip = addr.ip();
                        let Ok(pre_permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned() else {
                            warn!(
                                "🚫 Dropped Display RPC connection from {}: pre-auth concurrency limit ({}) reached",
                                peer_ip, MAX_PRE_AUTH_CONNS
                            );
                            drop(socket);
                            continue;
                        };
                        let c = ctrl.clone();
                        let f = Arc::clone(&features);
                        let post_lim = Arc::clone(&post_auth_limiter);
                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_connection(socket, peer_ip, c, f, pre_permit, post_lim)
                                    .await
                            {
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
        features: Arc<FeatureManager>,
        pre_auth_permit: OwnedSemaphorePermit,
        post_auth_limiter: Arc<Semaphore>,
    ) -> Result<()> {
        let _pre_auth_guard = Some(pre_auth_permit);
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
            let (creds, sas_6) = tokio::time::timeout(
                PAIRING_HANDSHAKE_TIMEOUT,
                trust::handle_incoming_pairing_stream_v2(&mut socket, peer_ip, Some(magic)),
            )
            .await
            .with_context(|| format!("Timed out during pairing handshake with {}", peer_ip))?
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

        let mut session = tokio::time::timeout(
            RPC_HANDSHAKE_TIMEOUT,
            trust::accept_transport_from_stream(
                socket,
                peer_ip,
                Some(magic),
                ServiceId::DisplayRpc,
            ),
        )
        .await
        .with_context(|| format!("Timed out during TransportV2 handshake from {}", peer_ip))?
        .map_err(|e| anyhow::anyhow!(e))?;

        let post_auth_permit = post_auth_limiter.try_acquire_owned().map_err(|_| {
            anyhow::anyhow!(
                "Dropped Display RPC connection from {}: authenticated concurrency limit ({}) reached",
                peer_ip,
                MAX_POST_AUTH_CONNS
            )
        })?;
        // Authentication succeeded and post-auth permit is held; release pre-auth slot immediately.
        drop(_pre_auth_guard);
        let _post_auth_guard = post_auth_permit;

        let peer_device_id = session.peer_device_id_hex().to_string();

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

        let req: DisplayRpcRequest = match serde_json::from_slice(&plaintext) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = DisplayRpcResponse {
                    success: false,
                    message: format!("Invalid Display RPC request payload: {}", e),
                    ..Default::default()
                };
                if let Ok(err_json) = serde_json::to_vec(&err_resp) {
                    let _ = tokio::time::timeout(RPC_IO_TIMEOUT, session.send_message(&err_json))
                        .await;
                }
                return Err(e.into());
            }
        };

        let resp = if let Some(feature) = required_feature_for_rpc(&req) {
            if !features.is_enabled(feature) && !peer_ip.is_loopback() {
                warn!(
                    "🚫 Rejected remote Display RPC {:?} from {} ({}): feature '{}' disabled",
                    req, peer_ip, peer_device_id, feature
                );
                DisplayRpcResponse {
                    success: false,
                    message: format!("Rejected: feature '{}' is disabled on this device", feature),
                    ..Default::default()
                }
            } else {
                controller
                    .handle_rpc(req, Some(peer_ip), Some(peer_device_id.as_str()))
                    .await
            }
        } else {
            controller
                .handle_rpc(req, Some(peer_ip), Some(peer_device_id.as_str()))
                .await
        };

        let resp_json = serde_json::to_vec(&resp)?;

        tokio::time::timeout(RPC_IO_TIMEOUT, session.send_message(&resp_json))
            .await
            .context("Timed out writing Display RPC response over TransportV2")?
            .map_err(|e| anyhow::anyhow!("Display RPC TransportV2 write error: {}", e))?;

        Ok(())
    }
}
