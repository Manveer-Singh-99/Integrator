//! Universal Clipboard Service for Text, Images, and Files with Deskflow-inspired sequence tracking and Zero-RAM streaming.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
use super::protocol::{ClipboardMessage, ClipboardPayload, FileEntry};
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
            ClipboardPayload::Files { root_names, entries } => {
                info!("📂 Receiving remote files/folders ({} root items, {} total entries)...", root_names.len(), entries.len());
                let cache_dir = file_helper.get_cache_dir();

                // 1. Clean existing root items in cache_dir so we start fresh
                for root in &root_names {
                    let target = cache_dir.join(root);
                    if target.is_dir() {
                        let _ = std::fs::remove_dir_all(&target);
                    } else if target.exists() {
                        let _ = std::fs::remove_file(&target);
                    }
                }

                // 2. Iterate through entries and recreate folder structure & stream files
                for entry in entries {
                    let mut dest_path = cache_dir.to_path_buf();
                    for component in entry.rel_path.split('/') {
                        if !component.is_empty() && component != "." && component != ".." {
                            dest_path.push(component);
                        }
                    }

                    if entry.is_dir {
                        std::fs::create_dir_all(&dest_path)?;
                    } else {
                        if let Some(parent) = dest_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        let mut file = File::create(&dest_path)?;
                        let mut remaining = entry.size;
                        let mut chunk_buf = vec![0u8; 64 * 1024];

                        while remaining > 0 {
                            let to_read = std::cmp::min(remaining, chunk_buf.len() as u64) as usize;
                            socket.read_exact(&mut chunk_buf[..to_read]).await?;
                            file.write_all(&chunk_buf[..to_read])?;
                            remaining -= to_read as u64;
                        }
                    }
                }

                // 3. Register root paths on native OS clipboard
                let mut staged_roots = Vec::new();
                for root in &root_names {
                    let p = cache_dir.join(root);
                    if p.exists() {
                        staged_roots.push(p);
                    }
                }

                file_helper.write_copied_files(&staged_roots)?;
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = last_seq.write().await;
                *seq_lock = new_seq;
                info!("✅ Staged {} root file/folder(s) into clipboard cache and set native pasteboard", staged_roots.len());
            }
        }

        Ok(())
    }

    /// Recursively collects all files and subdirectories inside a directory.
    fn collect_dir_entries(
        _root: &Path,
        current: &Path,
        rel_prefix: &str,
        entries: &mut Vec<FileEntry>,
        files_to_stream: &mut Vec<PathBuf>,
    ) {
        if let Ok(read_dir) = std::fs::read_dir(current) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let rel = format!("{}/{}", rel_prefix, name);

                if path.is_dir() {
                    entries.push(FileEntry {
                        rel_path: rel.clone(),
                        size: 0,
                        is_dir: true,
                    });
                    Self::collect_dir_entries(_root, &path, &rel, entries, files_to_stream);
                } else if path.is_file() {
                    let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    entries.push(FileEntry {
                        rel_path: rel,
                        size: len,
                        is_dir: false,
                    });
                    files_to_stream.push(path);
                }
            }
        }
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

            // 1. Check for Copied Files and Folders
            let copied_paths = file_helper.read_copied_files();
            if !copied_paths.is_empty() {
                let mut hasher = Sha256::new();
                for root in &copied_paths {
                    hasher.update(root.to_string_lossy().as_bytes());
                    if let Ok(meta) = std::fs::metadata(root) {
                        hasher.update(&meta.len().to_le_bytes());
                        if let Ok(mtime) = meta.modified() {
                            if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                                hasher.update(&dur.as_millis().to_le_bytes());
                            }
                        }
                    }
                }

                let hash_hex = to_hex_string(&hasher.finalize());
                let mut hash_lock = last_hash.write().await;
                if *hash_lock != hash_hex {
                    *hash_lock = hash_hex.clone();
                    drop(hash_lock);

                    // Collect all entries and files to stream
                    let mut root_names = Vec::new();
                    let mut entries = Vec::new();
                    let mut files_to_stream = Vec::new();

                    for root in &copied_paths {
                        if let Some(file_name) = root.file_name() {
                            let name_str = file_name.to_string_lossy().to_string();
                            root_names.push(name_str.clone());

                            if root.is_dir() {
                                entries.push(FileEntry {
                                    rel_path: name_str.clone(),
                                    size: 0,
                                    is_dir: true,
                                });
                                Self::collect_dir_entries(root, root, &name_str, &mut entries, &mut files_to_stream);
                            } else if root.is_file() {
                                let len = std::fs::metadata(root).map(|m| m.len()).unwrap_or(0);
                                entries.push(FileEntry {
                                    rel_path: name_str,
                                    size: len,
                                    is_dir: false,
                                });
                                files_to_stream.push(root.clone());
                            }
                        }
                    }

                    info!(
                        "📤 Detected local copied file/folder(s) ({} root item(s), {} total entries). Sending to peer...",
                        root_names.len(),
                        entries.len()
                    );
                    if let Some(peer_ip) = discovery.get_peer_ip().await {
                        if let Err(e) = Self::send_files(&peer_ip, hash_hex, root_names, entries, files_to_stream).await {
                            warn!("Failed to send files/folders to {}: {}", peer_ip, e);
                        }
                    } else {
                        warn!("No peer IP available to send files/folders");
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
                            if let Err(e) = Self::send_payload(&peer_ip, ClipboardMessage {
                                hash: hash_hex,
                                payload: ClipboardPayload::Image {
                                    width: img.width,
                                    height: img.height,
                                    rgba: img.bytes.into_owned(),
                                },
                            }).await {
                                warn!("Failed to send image to {}: {}", peer_ip, e);
                            }
                        } else {
                            warn!("No peer IP available to send image");
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
                                if let Err(e) = Self::send_payload(&peer_ip, ClipboardMessage {
                                    hash: hash_hex,
                                    payload: ClipboardPayload::Text(text),
                                }).await {
                                    warn!("Failed to send text to {}: {}", peer_ip, e);
                                }
                            } else {
                                warn!("No peer IP available to send text");
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

        info!("✅ Successfully sent clipboard payload to {}", addr);
        Ok(())
    }

    /// Streams files over TCP using fixed 64 KB ring buffers (Zero-RAM streaming).
    async fn send_files(
        peer_ip: &str,
        hash: String,
        root_names: Vec<String>,
        entries: Vec<FileEntry>,
        files_to_stream: Vec<PathBuf>,
    ) -> Result<()> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut stream = TcpStream::connect(&addr).await
            .with_context(|| format!("Failed to connect to peer at {}", addr))?;

        let header_msg = ClipboardMessage {
            hash,
            payload: ClipboardPayload::Files { root_names, entries },
        };

        let serialized = serde_json::to_vec(&header_msg)?;
        stream.write_u32(serialized.len() as u32).await?;
        stream.write_all(&serialized).await?;

        // Stream each file directly from disk using 64 KB ring buffer
        let mut chunk_buf = vec![0u8; 64 * 1024];
        for path in files_to_stream {
            if let Ok(mut file) = File::open(&path) {
                loop {
                    let n = file.read(&mut chunk_buf)?;
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&chunk_buf[..n]).await?;
                }
            } else {
                warn!("Could not open file {:?} for streaming", path);
            }
        }

        stream.flush().await?;
        info!("✅ Finished streaming files/folders to {}", addr);
        Ok(())
    }
}
