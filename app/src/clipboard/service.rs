//! Universal Clipboard Service for Text, Images, and Files with Deskflow-inspired sequence tracking and Zero-RAM streaming.

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, Context};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, debug, warn, error};

use crate::config::CLIPBOARD_PORT;
use crate::discovery::DiscoveryManager;
use super::protocol::{ClipboardMessage, ClipboardPayload, FileMetadata};
use super::file_helper::FileClipboardHelper;
use super::os_seq;

fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub struct ClipboardService {
    discovery: DiscoveryManager,
    last_hash: Arc<RwLock<String>>,
    last_seq: Arc<RwLock<i64>>,
    file_helper: Arc<FileClipboardHelper>,
}

impl ClipboardService {
    pub fn new(discovery: DiscoveryManager) -> Result<Self> {
        let file_helper = Arc::new(FileClipboardHelper::new()?);
        let initial_seq = os_seq::get_clipboard_sequence();
        Ok(Self {
            discovery,
            last_hash: Arc::new(RwLock::new(String::new())),
            last_seq: Arc::new(RwLock::new(initial_seq)),
            file_helper,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", CLIPBOARD_PORT)).await?;
        info!("📋 Universal Clipboard Service active on port {}", CLIPBOARD_PORT);

        // 1. Spawn TCP Receiver for incoming remote clipboard items
        let receiver_hash = Arc::clone(&self.last_hash);
        let receiver_seq = Arc::clone(&self.last_seq);
        let receiver_file_helper = Arc::clone(&self.file_helper);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        debug!("Incoming clipboard connection from {}", addr);
                        let hash_clone = Arc::clone(&receiver_hash);
                        let seq_clone = Arc::clone(&receiver_seq);
                        let file_helper_clone = Arc::clone(&receiver_file_helper);
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_incoming(socket, hash_clone, seq_clone, file_helper_clone).await {
                                warn!("Error handling clipboard transfer: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Clipboard TCP listener accept error: {}", e);
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });

        // 2. Spawn Clipboard Monitor Loop (checking sequence number)
        let monitor_discovery = self.discovery.clone();
        let monitor_hash = Arc::clone(&self.last_hash);
        let monitor_seq = Arc::clone(&self.last_seq);
        let monitor_file_helper = Arc::clone(&self.file_helper);
        tokio::spawn(async move {
            Self::monitor_loop(monitor_discovery, monitor_hash, monitor_seq, monitor_file_helper).await;
        });

        Ok(())
    }

    /// Handles incoming clipboard payloads from peer.
    async fn handle_incoming(
        mut socket: TcpStream,
        last_hash: Arc<RwLock<String>>,
        last_seq: Arc<RwLock<i64>>,
        file_helper: Arc<FileClipboardHelper>,
    ) -> Result<()> {
        let header_len = socket.read_u32().await? as usize;
        let mut header_buf = vec![0u8; header_len];
        socket.read_exact(&mut header_buf).await?;

        let msg: ClipboardMessage = serde_json::from_slice(&header_buf)?;

        // Update last seen hash so monitor doesn't echo it
        {
            let mut lock = last_hash.write().await;
            *lock = msg.hash.clone();
        }

        match msg.payload {
            ClipboardPayload::Text(text) => {
                info!("📋 Received remote text ({} chars)", text.len());
                if let Ok(mut cb) = Clipboard::new() {
                    let _ = cb.set_text(text);
                }
                // Record the sequence number immediately after setting clipboard
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = last_seq.write().await;
                *seq_lock = new_seq;
            }
            ClipboardPayload::Image { width, height, rgba } => {
                info!("🖼️ Received remote image ({}x{} px)", width, height);
                if let Ok(mut cb) = Clipboard::new() {
                    let img_data = ImageData {
                        width,
                        height,
                        bytes: rgba.into(),
                    };
                    let _ = cb.set_image(img_data);
                }
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = last_seq.write().await;
                *seq_lock = new_seq;
            }
            ClipboardPayload::Files { files } => {
                info!("📂 Receiving {} remote file(s)...", files.len());
                let cache_dir = file_helper.get_cache_dir();
                let mut staged_paths = Vec::new();

                for meta in files {
                    let dest_path = cache_dir.join(&meta.name);
                    let mut file = File::create(&dest_path)?;

                    let mut remaining = meta.size;
                    let mut chunk_buf = vec![0u8; 64 * 1024];

                    while remaining > 0 {
                        let to_read = std::cmp::min(remaining, chunk_buf.len() as u64) as usize;
                        socket.read_exact(&mut chunk_buf[..to_read]).await?;
                        file.write_all(&chunk_buf[..to_read])?;
                        remaining -= to_read as u64;
                    }

                    staged_paths.push(dest_path);
                }

                file_helper.write_copied_files(&staged_paths)?;
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = last_seq.write().await;
                *seq_lock = new_seq;
                info!("✅ Staged {} file(s) into clipboard cache and set native pasteboard", staged_paths.len());
            }
        }

        Ok(())
    }

    /// Continuous lightweight loop checking for clipboard sequence changes.
    async fn monitor_loop(
        discovery: DiscoveryManager,
        last_hash: Arc<RwLock<String>>,
        last_seq: Arc<RwLock<i64>>,
        file_helper: Arc<FileClipboardHelper>,
    ) {
        loop {
            sleep(Duration::from_millis(100)).await;

            let current_seq = os_seq::get_clipboard_sequence();
            {
                let read_lock = last_seq.read().await;
                if *read_lock == current_seq {
                    // ZERO overhead - OS clipboard has not been modified
                    continue;
                }
            }

            // Sequence changed! Update last_seq immediately
            {
                let mut write_lock = last_seq.write().await;
                *write_lock = current_seq;
            }

            debug!("Clipboard sequence updated: {}", current_seq);

            // 1. Check for Copied Files
            let copied_files = file_helper.read_copied_files();
            if !copied_files.is_empty() {
                let mut hasher = Sha256::new();
                let mut meta_list = Vec::new();

                for p in &copied_files {
                    if let Ok(meta) = std::fs::metadata(p) {
                        hasher.update(p.to_string_lossy().as_bytes());
                        hasher.update(&meta.len().to_le_bytes());
                        if let Some(name) = p.file_name() {
                            meta_list.push(FileMetadata {
                                name: name.to_string_lossy().to_string(),
                                size: meta.len(),
                            });
                        }
                    }
                }

                let hash_hex = to_hex_string(&hasher.finalize());
                let mut hash_lock = last_hash.write().await;
                if *hash_lock != hash_hex {
                    *hash_lock = hash_hex.clone();
                    drop(hash_lock);

                    info!("📤 Detected local copied files ({} files). Sending to peer...", copied_files.len());
                    if let Some(peer_ip) = discovery.get_peer_ip().await {
                        let _ = Self::send_files(&peer_ip, hash_hex, meta_list, copied_files).await;
                    }
                }
                continue;
            }

            // 2. Check for Image / Text via arboard
            if let Ok(mut cb) = Clipboard::new() {
                // Check Image first
                if let Ok(img) = cb.get_image() {
                    let mut hasher = Sha256::new();
                    hasher.update(&(img.width as u64).to_le_bytes());
                    hasher.update(&(img.height as u64).to_le_bytes());
                    hasher.update(&(img.bytes.len() as u64).to_le_bytes());
                    if !img.bytes.is_empty() {
                        let sample_len = std::cmp::min(1024, img.bytes.len());
                        hasher.update(&img.bytes[..sample_len]);
                    }
                    let hash_hex = to_hex_string(&hasher.finalize());

                    let mut hash_lock = last_hash.write().await;
                    if *hash_lock != hash_hex {
                        *hash_lock = hash_hex.clone();
                        drop(hash_lock);

                        info!("📤 Detected local copied image ({}x{} px). Sending to peer...", img.width, img.height);
                        if let Some(peer_ip) = discovery.get_peer_ip().await {
                            let _ = Self::send_payload(&peer_ip, ClipboardMessage {
                                hash: hash_hex,
                                payload: ClipboardPayload::Image {
                                    width: img.width,
                                    height: img.height,
                                    rgba: img.bytes.into_owned(),
                                },
                            }).await;
                        }
                    }
                    continue;
                }

                // Check Text
                if let Ok(text) = cb.get_text() {
                    if !text.is_empty() {
                        let mut hasher = Sha256::new();
                        hasher.update(text.as_bytes());
                        let hash_hex = to_hex_string(&hasher.finalize());

                        let mut hash_lock = last_hash.write().await;
                        if *hash_lock != hash_hex {
                            *hash_lock = hash_hex.clone();
                            drop(hash_lock);

                            info!("📤 Detected local copied text ({} chars). Sending to peer...", text.len());
                            if let Some(peer_ip) = discovery.get_peer_ip().await {
                                let _ = Self::send_payload(&peer_ip, ClipboardMessage {
                                    hash: hash_hex,
                                    payload: ClipboardPayload::Text(text),
                                }).await;
                            }
                        }
                        continue;
                    }
                }
            }
        }
    }

    /// Sends text or image payload over TCP.
    async fn send_payload(peer_ip: &str, msg: ClipboardMessage) -> Result<()> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut stream = TcpStream::connect(&addr).await
            .with_context(|| format!("Failed to connect to peer at {}", addr))?;

        let serialized = serde_json::to_vec(&msg)?;
        stream.write_u32(serialized.len() as u32).await?;
        stream.write_all(&serialized).await?;
        stream.flush().await?;

        debug!("Sent clipboard payload to {}", addr);
        Ok(())
    }

    /// Streams files over TCP using fixed 64 KB ring buffers (Zero-RAM streaming).
    async fn send_files(
        peer_ip: &str,
        hash: String,
        metadata: Vec<FileMetadata>,
        file_paths: Vec<PathBuf>,
    ) -> Result<()> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut stream = TcpStream::connect(&addr).await
            .with_context(|| format!("Failed to connect to peer at {}", addr))?;

        let header_msg = ClipboardMessage {
            hash,
            payload: ClipboardPayload::Files { files: metadata },
        };

        let serialized = serde_json::to_vec(&header_msg)?;
        stream.write_u32(serialized.len() as u32).await?;
        stream.write_all(&serialized).await?;

        // Stream each file directly from disk
        let mut chunk_buf = vec![0u8; 64 * 1024];
        for path in file_paths {
            let mut file = File::open(&path)?;
            loop {
                let n = file.read(&mut chunk_buf)?;
                if n == 0 {
                    break;
                }
                stream.write_all(&chunk_buf[..n]).await?;
            }
        }

        stream.flush().await?;
        info!("✅ Finished streaming files to {}", addr);
        Ok(())
    }
}
