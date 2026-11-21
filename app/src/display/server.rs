//! # Display Control RPC Server & Demultiplexer
//!
//! ## 1. Module Purpose & Scope
//! This module implements [`DisplayServer`], the primary incoming TCP listener and protocol
//! demultiplexer for Integrator control traffic on [`CONTROL_PORT`] (`58281`).
//!
//! It serves as the primary ingress gateway for all cross-device control requests, including:
//! - **SPAKE2 Mutual Pairing**: Handled when connection starts with wire magic `PAIRING_WIRE_MAGIC` (`"IPR2"`).
//! - **Display Control RPC**: Handled when connection starts with wire magic `TRANSPORT_WIRE_MAGIC` (`"ITR2"`),
//!   initiating an authenticated `TransportSessionV2` session with [`ServiceId::DisplayRpc`].
//! - **Discovery RTT Probes**: Zero-byte TCP connections used by peer discovery to measure round-trip latency
//!   are closed cleanly without logging spurious error alerts.
//!
//! ## 2. Cross-Subsystem Architectural Flow
//!
//! ### Extended Display Streaming Pipeline
//! When a display session is initiated (Mac -> PC or PC -> Mac), the initiator transmits
//! [`DisplayRpcRequest::StartMoonlight`] over this server's connection. The server validates
//! caller authentication, checks feature flag enablement, verifies that `host_ip` matches the
//! peer's authenticated IP address to prevent redirect attacks, and invokes [`DisplayController::handle_rpc`],
//! which launches Moonlight with hardware-accelerated decoding (D3D11 on Windows, VideoToolbox on Mac).
//!
//! ### Shared Camera Control Routing
//! Incoming camera control requests ([`DisplayRpcRequest::StartCamera`], [`DisplayRpcRequest::ToggleCamera`],
//! [`DisplayRpcRequest::StopCamera`], [`DisplayRpcRequest::GetCameraStatus`]) are demultiplexed through this
//! server and handed to [`DisplayController`]. These trigger local activation of the Shared Camera pipeline:
//! - On Mac: Starts AVFoundation 720p30 NV12 capture (`camera_macos.swift`) and opens streaming port 58287.
//! - On Windows: Registers and starts the standalone Media Foundation Virtual Camera COM DLL (`integrator_vcam.dll`),
//!   mapping shared memory (`Global\IntegratorVCamShm_v1`) to receive remote frames without requiring physical
//!   webcam hardware or wrapper attributes (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Multi-Threaded Accept Loop**: The TCP listener runs on an asynchronous task, spawning an
//!   independent task per accepted socket.
//! - **Two-Tiered Semaphore Concurrency Limiting**:
//!   1. Pre-Authentication Semaphore ([`MAX_PRE_AUTH_CONNS`] = 32): Prevents TCP connection exhaustion
//!      or SYN flood attacks from unauthenticated clients.
//!   2. Post-Authentication Semaphore ([`MAX_POST_AUTH_CONNS`] = 16): Caps simultaneous authenticated
//!      RPC operations.
//!   As soon as a connection successfully authenticates and acquires a post-auth permit, its pre-auth permit
//!   is immediately released to keep the ingress pipeline responsive.
//! - **Strict Timeout Protection**:
//!   - Handshake Timeout ([`RPC_HANDSHAKE_TIMEOUT`] = 12s).
//!   - Pairing Timeout ([`PAIRING_HANDSHAKE_TIMEOUT`] = 30s).
//!   - I/O Read/Write Timeout ([`RPC_IO_TIMEOUT`] = 10s).
//!
//! ## 4. Security & Safety Invariants
//! - **Bounded Payloads**: Inbound JSON RPC datagrams are strictly bounded to [`MAX_RPC_BYTES`] (64 KiB).
//! - **Mutual Authentication**: Connections failing the Ed25519 authenticated key exchange are aborted.
//! - **Feature Flag Filtering**: Requests associated with disabled features are blocked unless originating
//!   from local loopback for emergency teardown (`StopAll` / `StopMoonlight`).

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Maximum allowed size for an incoming RPC JSON payload in bytes (64 KiB).
const MAX_RPC_BYTES: usize = 65_536;

/// Maximum number of concurrent unauthenticated connections allowed on the control port.
const MAX_PRE_AUTH_CONNS: usize = 32;

/// Maximum number of concurrent authenticated sessions allowed.
const MAX_POST_AUTH_CONNS: usize = 16;

/// Timeout applied to individual RPC socket read and write operations.
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout allowed for completing the `TransportSessionV2` cryptographic handshake.
const RPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);

/// Timeout allowed for interactive SPAKE2 mutual pairing handshakes.
const PAIRING_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Backoff delay after a transient TCP `accept` error to prevent tight CPU spin loops.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(200);

/// Display Control RPC server managing incoming TCP sockets on port [`CONTROL_PORT`].
pub struct DisplayServer {
    /// Reference to the central [`DisplayController`] executing parsed RPC actions.
    controller: DisplayController,
    /// Dynamic feature flag manager.
    features: Arc<FeatureManager>,
}

impl DisplayServer {
    /// Creates a new [`DisplayServer`] with associated controller and feature managers.
    pub fn new(controller: DisplayController, features: Arc<FeatureManager>) -> Self {
        Self {
            controller,
            features,
        }
    }

    /// Binds the TCP listener to `0.0.0.0:CONTROL_PORT` and spawns the connection accept loop.
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, CONTROL_PORT))).await?;
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
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handles a single incoming TCP connection: demuxes magic, performs crypto handshake, and routes RPC.
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

        // Read 4-byte wire magic with I/O timeout
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

        // 1. Demux SPAKE2 Mutual Pairing Handshake ("IPR2")
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

        // 2. Reject unsupported or legacy wire magic
        if magic != TRANSPORT_WIRE_MAGIC {
            warn!(
                "🚫 Rejected unknown or legacy v1 wire magic {:02x?} from {}",
                magic, peer_ip
            );
            anyhow::bail!("Rejected unsupported wire protocol magic from {}", peer_ip);
        }

        // 3. Establish mutually authenticated TransportSessionV2 ("ITR2")
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

        // 4. Acquire post-auth permit and release pre-auth slot
        let post_auth_permit = post_auth_limiter.try_acquire_owned().map_err(|_| {
            anyhow::anyhow!(
                "Dropped Display RPC connection from {}: authenticated concurrency limit ({}) reached",
                peer_ip,
                MAX_POST_AUTH_CONNS
            )
        })?;
        drop(_pre_auth_guard);
        let _post_auth_guard = post_auth_permit;

        let peer_device_id = session.peer_device_id_hex().to_string();

        // 5. Read plaintext RPC message
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

        // 6. Deserialize and validate JSON request
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

        // 7. Check feature flag requirements
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

        // 8. Serialize and return response
        let resp_json = serde_json::to_vec(&resp)?;

        tokio::time::timeout(RPC_IO_TIMEOUT, session.send_message(&resp_json))
            .await
            .context("Timed out writing Display RPC response over TransportV2")?
            .map_err(|e| anyhow::anyhow!("Display RPC TransportV2 write error: {}", e))?;

        Ok(())
    }
}
