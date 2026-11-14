//! Universal Clipboard Service with Universal Control-Style On-Demand Streaming.
//! Transfers metadata (<1ms, <1KB) on copy. Streams directly to target folder on paste with ZERO temp cache.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
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
use super::protocol::{
    ClipboardMessage, ClipboardPayload, LazyAnnouncement, StreamRequest,
    FRAME_DIR, FRAME_FILE, FRAME_END,
    MAX_TEXT_CHARS, MAX_IMAGE_BYTES,
};
use super::file_helper::FileClipboardHelper;
use super::os_seq;

const STREAM_CHUNK_SIZE: usize = 256 * 1024; // 256 KB high-throughput buffer for line-rate NVMe transfer

#[cfg(target_os = "macos")]
extern "C" {
    pub fn init_shortcut_interceptor();
    pub fn set_has_pending_remote_file(pending: bool);
    pub fn clear_pasteboard_in_app();
    fn notify_touchbar_remote_file(name: *const std::os::raw::c_char, total_bytes: u64);
    fn update_touchbar_paste_progress(percent: f32, mb_per_sec: f32);
    fn reset_touchbar_paste_progress();
}

pub static CLIPBOARD_INSTANCE: std::sync::OnceLock<ClipboardService> = std::sync::OnceLock::new();
pub static TOKIO_HANDLE: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

#[no_mangle]
pub extern "C" fn trigger_rust_remote_paste() {
    if let (Some(service), Some(handle)) = (CLIPBOARD_INSTANCE.get(), TOKIO_HANDLE.get()) {
        let service = service.clone();
        handle.spawn(async move {
            if let Err(e) = service.paste_remote(None).await {
                warn!("On-demand remote paste error: {}", e);
            }
        });
    } else {
        warn!("trigger_rust_remote_paste called but CLIPBOARD_INSTANCE or TOKIO_HANDLE not ready");
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn safe_root_entry_name(raw: &str) -> String {
    let cleaned = raw
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .last()
        .unwrap_or("clipboard_item");
    if cleaned.contains(':') || cleaned.is_empty() {
        "clipboard_item".to_string()
    } else {
        cleaned.to_string()
    }
}

fn join_safe_rel_path(base: &Path, rel_path: &str) -> PathBuf {
    let mut dest = base.to_path_buf();
    for comp in rel_path.split(['/', '\\']) {
        if !comp.is_empty() && comp != "." && comp != ".." && !comp.contains(':') {
            dest.push(comp);
        }
    }
    dest
}

#[derive(Clone, Debug)]
pub struct LocalPendingCopy {
    pub session_id: String,
    pub root_name: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub directories: Vec<String>,
    pub files: Vec<(String, PathBuf)>,
}

#[derive(Clone)]
pub struct ClipboardService {
    discovery: DiscoveryManager,
    last_hash: Arc<RwLock<String>>,
    last_seq: Arc<RwLock<i64>>,
    file_helper: Arc<FileClipboardHelper>,
    pending_local: Arc<RwLock<Option<LocalPendingCopy>>>,
    pending_remote: Arc<RwLock<Option<LazyAnnouncement>>>,
    last_remote_ip: Arc<RwLock<Option<IpAddr>>>,
    is_pasting: Arc<std::sync::atomic::AtomicBool>,
}

impl ClipboardService {
    pub fn new(discovery: DiscoveryManager) -> Result<Self> {
        let file_helper = Arc::new(FileClipboardHelper::new()?);
        let initial_seq = os_seq::get_clipboard_sequence();
        let service = Self {
            discovery,
            last_hash: Arc::new(RwLock::new(String::new())),
            last_seq: Arc::new(RwLock::new(initial_seq)),
            file_helper,
            pending_local: Arc::new(RwLock::new(None)),
            pending_remote: Arc::new(RwLock::new(None)),
            last_remote_ip: Arc::new(RwLock::new(None)),
            is_pasting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = TOKIO_HANDLE.set(handle);
        }

        let _ = CLIPBOARD_INSTANCE.set(service.clone());
        Ok(service)
    }

    pub fn get_pending_remote(&self) -> Arc<RwLock<Option<LazyAnnouncement>>> {
        Arc::clone(&self.pending_remote)
    }

    async fn is_ip_authorized(ip: IpAddr) -> bool {
        tokio::task::spawn_blocking(move || crate::trust::is_remote_addr_authorized(ip))
            .await
            .unwrap_or(false)
    }

    /// Returns an authorized peer IP (preferring the discovery-selected best peer).
    async fn get_authorized_peer_ip(&self) -> Option<String> {
        if let Some(best) = self.discovery.get_best_peer().await {
            if Self::is_ip_authorized(best.addr.ip()).await {
                return Some(best.addr.ip().to_string());
            }
        }
        for peer in self.discovery.get_all_peers().await {
            if Self::is_ip_authorized(peer.addr.ip()).await {
                return Some(peer.addr.ip().to_string());
            }
        }
        None
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", CLIPBOARD_PORT)).await?;
        info!("📋 Universal Clipboard Service active on port {}", CLIPBOARD_PORT);

        // 1. Spawn TCP Receiver
        let s_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let handler = s_clone.clone();
                        tokio::spawn(async move {
                            if !Self::is_ip_authorized(addr.ip()).await {
                                warn!("🚫 Rejected untrusted clipboard connection from {}", addr);
                                drop(socket);
                                return;
                            }
                            debug!("Incoming clipboard connection from {}", addr);
                            if let Err(e) = handler.handle_incoming(socket, addr).await {
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

        // 2. Spawn Clipboard Monitor Loop
        let monitor_service = self.clone();
        tokio::spawn(async move {
            monitor_service.monitor_loop().await;
        });

        #[cfg(target_os = "macos")]
        unsafe {
            init_shortcut_interceptor();
        }

        Ok(())
    }

    /// Handles incoming clipboard payloads and stream requests from peer.
    async fn handle_incoming(&self, mut socket: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        let header_len = tokio::time::timeout(Duration::from_secs(10), socket.read_u32())
            .await
            .context("Timed out reading header length")?? as usize;

        if header_len == 0 || header_len > MAX_IMAGE_BYTES * 5 {
            anyhow::bail!("Invalid clipboard header length {} bytes from {}", header_len, peer_addr);
        }

        let mut header_buf = vec![0u8; header_len];
        tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut header_buf))
            .await
            .context("Timed out reading header body")??;

        let msg: ClipboardMessage = serde_json::from_slice(&header_buf)?;

        if !msg.hash.is_empty() {
            let mut lock = self.last_hash.write().await;
            *lock = msg.hash.clone();
        }

        match msg.payload {
            ClipboardPayload::Text(text) => {
                if text.len() > MAX_TEXT_CHARS {
                    warn!("Received text exceeds limit ({} chars)", text.len());
                    return Ok(());
                }
                info!("📋 Received remote text ({} chars)", text.len());
                #[cfg(target_os = "macos")]
                unsafe {
                    set_has_pending_remote_file(false);
                }
                if let Ok(mut cb) = Clipboard::new() {
                    let _ = cb.set_text(text);
                }
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = self.last_seq.write().await;
                *seq_lock = new_seq;
            }
            ClipboardPayload::Image { width, height, rgba } => {
                if rgba.len() > MAX_IMAGE_BYTES {
                    warn!("Received image exceeds limit ({} bytes)", rgba.len());
                    return Ok(());
                }
                info!("🖼️ Received remote image ({}x{} px)", width, height);
                #[cfg(target_os = "macos")]
                unsafe {
                    set_has_pending_remote_file(false);
                }
                if let Ok(mut cb) = Clipboard::new() {
                    let img_data = ImageData {
                        width,
                        height,
                        bytes: rgba.into(),
                    };
                    let _ = cb.set_image(img_data);
                }
                let new_seq = os_seq::get_clipboard_sequence();
                let mut seq_lock = self.last_seq.write().await;
                *seq_lock = new_seq;
            }
            ClipboardPayload::LazyAnnouncement(ann) => {
                info!(
                    "📥 Peer announced file/folder '{}' ({} files, {:.1} MB). Ready for on-demand paste.",
                    ann.root_name, ann.total_files, ann.total_bytes as f64 / (1024.0 * 1024.0)
                );
                {
                    let mut lock = self.pending_remote.write().await;
                    *lock = Some(ann.clone());
                }
                {
                    let mut ip_lock = self.last_remote_ip.write().await;
                    *ip_lock = Some(peer_addr.ip());
                }

                // Immediately clear OS clipboard so stale text/images are completely eradicated!
                if let Ok(mut cb) = Clipboard::new() {
                    let _ = cb.clear();
                }
                let _ = self.file_helper.clear_clipboard();
                #[cfg(target_os = "macos")]
                unsafe {
                    clear_pasteboard_in_app();
                }

                let new_seq = os_seq::get_clipboard_sequence();
                {
                    let mut seq_lock = self.last_seq.write().await;
                    *seq_lock = new_seq;
                }

                #[cfg(target_os = "macos")]
                {
                    let name_c = std::ffi::CString::new(ann.root_name.clone()).unwrap_or_default();
                    unsafe {
                        notify_touchbar_remote_file(name_c.as_ptr(), ann.total_bytes);
                        set_has_pending_remote_file(true);
                    }
                }

                // Immediately stream announced files/folder across high-speed link into staging cache
                // so that native Cmd+V in Finder (and Ctrl+V in Explorer) works IMMEDIATELY!
                let service_clone = self.clone();
                let ann_clone = ann.clone();
                let source_ip = peer_addr.ip();
                tokio::spawn(async move {
                    if let Err(e) = service_clone.stream_to_cache_from(ann_clone, Some(source_ip)).await {
                        warn!("Background stream to cache error: {}", e);
                    }
                });
            }
            ClipboardPayload::RequestStream(req) => {
                let local_copy = {
                    let lock = self.pending_local.read().await;
                    lock.clone()
                };

                if let Some(copy) = local_copy {
                    if copy.session_id == req.session_id {
                        info!(
                            "🚀 Peer requested on-demand stream for '{}' ({} files, {:.1} MB). Streaming directly from disk...",
                            copy.root_name, copy.total_files, copy.total_bytes as f64 / (1024.0 * 1024.0)
                        );
                        Self::stream_files_to_socket(&mut socket, copy.directories, copy.files).await?;
                    } else {
                        warn!("Stream request session_id does not match active local copy");
                    }
                } else {
                    warn!("No local copy pending to stream");
                }
            }
        }

        Ok(())
    }

    /// Recursively collects all files and subdirectories for on-demand streaming.
    fn collect_dir_entries(
        _root: &Path,
        current: &Path,
        rel_prefix: &str,
        directories: &mut Vec<String>,
        files: &mut Vec<(String, PathBuf)>,
        total_bytes: &mut u64,
        total_files: &mut usize,
    ) {
        if let Ok(read_dir) = std::fs::read_dir(current) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let rel = format!("{}/{}", rel_prefix, name);

                if path.is_dir() {
                    directories.push(rel.clone());
                    Self::collect_dir_entries(
                        _root,
                        &path,
                        &rel,
                        directories,
                        files,
                        total_bytes,
                        total_files,
                    );
                } else if path.is_file() {
                    let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    *total_bytes += len;
                    *total_files += 1;
                    files.push((rel, path));
                }
            }
        }
    }

    /// Continuous lightweight loop checking for clipboard sequence changes.
    async fn monitor_loop(&self) {
        loop {
            sleep(Duration::from_millis(100)).await;

            let current_seq = os_seq::get_clipboard_sequence();
            {
                let read_lock = self.last_seq.read().await;
                if *read_lock == current_seq {
                    continue;
                }
            }

            {
                let mut write_lock = self.last_seq.write().await;
                *write_lock = current_seq;
            }

            debug!("Clipboard sequence updated: {}", current_seq);

            // 1. Check for Copied Files and Folders
            let copied_paths = self.file_helper.read_copied_files();
            if !copied_paths.is_empty() {
                let cache_dir = self.file_helper.get_cache_dir();
                let external_paths: Vec<PathBuf> = copied_paths
                    .into_iter()
                    .filter(|p| !p.starts_with(cache_dir))
                    .collect();

                if external_paths.is_empty() {
                    continue;
                }

                // Compute unified hash based on root base name and metadata
                let mut hasher = Sha256::new();
                for root in &external_paths {
                    if let Some(name) = root.file_name() {
                        hasher.update(name.to_string_lossy().as_bytes());
                    }
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
                let mut hash_lock = self.last_hash.write().await;
                if *hash_lock != hash_hex {
                    *hash_lock = hash_hex.clone();
                    drop(hash_lock);

                    // Clear pending remote announcement on local file copy
                    {
                        let mut remote_lock = self.pending_remote.write().await;
                        *remote_lock = None;
                    }
                    {
                        let mut ip_lock = self.last_remote_ip.write().await;
                        *ip_lock = None;
                    }
                    #[cfg(target_os = "macos")]
                    unsafe {
                        reset_touchbar_paste_progress();
                        set_has_pending_remote_file(false);
                    }

                    // Collect directory structure and file paths (< 5ms)
                    let mut root_name = String::new();
                    let mut directories = Vec::new();
                    let mut files = Vec::new();
                    let mut total_bytes: u64 = 0;
                    let mut total_files: usize = 0;

                    for root in &external_paths {
                        if let Some(file_name) = root.file_name() {
                            let name_str = file_name.to_string_lossy().to_string();
                            if root_name.is_empty() {
                                root_name = name_str.clone();
                            }
                            if root.is_dir() {
                                directories.push(name_str.clone());
                                Self::collect_dir_entries(
                                    root,
                                    root,
                                    &name_str,
                                    &mut directories,
                                    &mut files,
                                    &mut total_bytes,
                                    &mut total_files,
                                );
                            } else if root.is_file() {
                                let len = std::fs::metadata(root).map(|m| m.len()).unwrap_or(0);
                                total_bytes += len;
                                total_files += 1;
                                files.push((name_str, root.clone()));
                            }
                        }
                    }

                    if external_paths.len() > 1 {
                        root_name = format!("{} (+{} items)", root_name, external_paths.len() - 1);
                    }

                    let session_id = format!(
                        "{:x}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );

                    // Store locally for on-demand streaming
                    {
                        let mut local_lock = self.pending_local.write().await;
                        *local_lock = Some(LocalPendingCopy {
                            session_id: session_id.clone(),
                            root_name: root_name.clone(),
                            total_files,
                            total_bytes,
                            directories,
                            files,
                        });
                    }

                    if let Some(peer_ip) = self.get_authorized_peer_ip().await {
                        info!(
                            "📢 Local copy detected: '{}' ({} files, {:.1} MB). Broadcasting lazy announcement to {} (0 file bytes transferred)...",
                            root_name, total_files, total_bytes as f64 / (1024.0 * 1024.0), peer_ip
                        );
                        let ann = LazyAnnouncement {
                            session_id,
                            root_name,
                            total_files,
                            total_bytes,
                        };
                        tokio::spawn(async move {
                            if let Err(e) = Self::send_payload(&peer_ip, ClipboardMessage {
                                hash: hash_hex,
                                payload: ClipboardPayload::LazyAnnouncement(ann),
                            }).await {
                                warn!("Failed to send lazy announcement to {}: {}", peer_ip, e);
                            }
                        });
                    } else {
                        debug!(
                            "Local copy detected: '{}' ({} files), but no trusted peer is connected; skipping lazy announcement",
                            root_name, total_files
                        );
                    }
                }
                continue;
            }

            // 2. Check for Image / Text via arboard
            if let Ok(mut cb) = Clipboard::new() {
                if let Ok(img) = cb.get_image() {
                    let img_bytes_len = img.bytes.len();
                    if img_bytes_len <= MAX_IMAGE_BYTES {
                        let mut hasher = Sha256::new();
                        hasher.update(&(img.width as u64).to_le_bytes());
                        hasher.update(&(img.height as u64).to_le_bytes());
                        hasher.update(&(img_bytes_len as u64).to_le_bytes());
                        if !img.bytes.is_empty() {
                            let sample_len = std::cmp::min(1024, img.bytes.len());
                            hasher.update(&img.bytes[..sample_len]);
                        }
                        let hash_hex = to_hex_string(&hasher.finalize());

                        let mut hash_lock = self.last_hash.write().await;
                        if *hash_lock != hash_hex {
                            *hash_lock = hash_hex.clone();
                            drop(hash_lock);

                            // Clear pending remote announcement on local image copy
                            {
                                let mut remote_lock = self.pending_remote.write().await;
                                *remote_lock = None;
                            }
                            {
                                let mut ip_lock = self.last_remote_ip.write().await;
                                *ip_lock = None;
                            }
                            #[cfg(target_os = "macos")]
                            unsafe {
                                reset_touchbar_paste_progress();
                                set_has_pending_remote_file(false);
                            }

                            if let Some(peer_ip) = self.get_authorized_peer_ip().await {
                                info!("📤 Detected local copied image ({}x{} px). Sending to {}...", img.width, img.height, peer_ip);
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
                                debug!("Local image copied ({}x{} px), but no trusted peer is connected; skipping sync", img.width, img.height);
                            }
                        }
                        continue;
                    }
                }

                if let Ok(text) = cb.get_text() {
                    if !text.is_empty() && text.len() <= MAX_TEXT_CHARS {
                        let mut hasher = Sha256::new();
                        hasher.update(text.as_bytes());
                        let hash_hex = to_hex_string(&hasher.finalize());

                        let mut hash_lock = self.last_hash.write().await;
                        if *hash_lock != hash_hex {
                            *hash_lock = hash_hex.clone();
                            drop(hash_lock);

                            // Clear pending remote announcement on local text copy
                            {
                                let mut remote_lock = self.pending_remote.write().await;
                                *remote_lock = None;
                            }
                            {
                                let mut ip_lock = self.last_remote_ip.write().await;
                                *ip_lock = None;
                            }
                            #[cfg(target_os = "macos")]
                            unsafe {
                                reset_touchbar_paste_progress();
                                set_has_pending_remote_file(false);
                            }

                            if let Some(peer_ip) = self.get_authorized_peer_ip().await {
                                info!("📤 Detected local copied text ({} chars). Sending to {}...", text.len(), peer_ip);
                                if let Err(e) = Self::send_payload(&peer_ip, ClipboardMessage {
                                    hash: hash_hex,
                                    payload: ClipboardPayload::Text(text),
                                }).await {
                                    warn!("Failed to send text to {}: {}", peer_ip, e);
                                }
                            } else {
                                debug!("Local text copied ({} chars), but no trusted peer is connected; skipping sync", text.len());
                            }
                        }
                        continue;
                    }
                }
            }
        }
    }

    /// Sends lightweight JSON payload over TCP.
    async fn send_payload(peer_ip: &str, msg: ClipboardMessage) -> Result<()> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut stream = TcpStream::connect(&addr).await
            .with_context(|| format!("Failed to connect to peer at {}", addr))?;

        let serialized = serde_json::to_vec(&msg)?;
        stream.write_u32(serialized.len() as u32).await?;
        stream.write_all(&serialized).await?;
        stream.flush().await?;

        info!("✅ Sent clipboard message to {}", addr);
        Ok(())
    }

    /// Streams directory structure and file contents directly from disk over socket.
    async fn stream_files_to_socket(
        stream: &mut TcpStream,
        directories: Vec<String>,
        files: Vec<(String, PathBuf)>,
    ) -> Result<()> {
        let _ = stream.set_nodelay(true);

        // 1. Directory frames
        for dir_rel in &directories {
            let rel_bytes = dir_rel.as_bytes();
            if rel_bytes.len() > u16::MAX as usize { continue; }
            stream.write_u8(FRAME_DIR).await?;
            stream.write_u16(rel_bytes.len() as u16).await?;
            stream.write_all(rel_bytes).await?;
        }

        // 2. File frames
        let mut chunk_buf = vec![0u8; STREAM_CHUNK_SIZE];
        for (rel_path, abs_path) in files {
            let rel_bytes = rel_path.as_bytes();
            if rel_bytes.len() > u16::MAX as usize { continue; }

            match File::open(&abs_path) {
                Ok(mut file) => {
                    let actual_len = match file.metadata() {
                        Ok(m) => m.len(),
                        Err(_) => 0,
                    };

                    stream.write_u8(FRAME_FILE).await?;
                    stream.write_u16(rel_bytes.len() as u16).await?;
                    stream.write_all(rel_bytes).await?;
                    stream.write_u64(actual_len).await?;

                    let mut remaining = actual_len;
                    while remaining > 0 {
                        let to_read = std::cmp::min(remaining, chunk_buf.len() as u64) as usize;
                        let n = file.read(&mut chunk_buf[..to_read])?;
                        if n == 0 {
                            chunk_buf.fill(0);
                            while remaining > 0 {
                                let pad = std::cmp::min(remaining, chunk_buf.len() as u64) as usize;
                                stream.write_all(&chunk_buf[..pad]).await?;
                                remaining -= pad as u64;
                            }
                            break;
                        }
                        stream.write_all(&chunk_buf[..n]).await?;
                        remaining -= n as u64;
                    }
                }
                Err(e) => {
                    warn!("Could not open file {:?} for streaming, skipping: {}", abs_path, e);
                }
            }
        }

        stream.write_u8(FRAME_END).await?;
        stream.flush().await?;
        info!("✅ Finished on-demand streaming to peer");
        Ok(())
    }

    /// Resolves the frontmost active folder (Finder insertion location on macOS, Desktop/Downloads on Windows).
    pub fn resolve_active_destination_folder() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            let script = r#"
            tell application "Finder"
                try
                    set targetFolder to (insertion location as alias)
                    return POSIX path of targetFolder
                on error
                    return POSIX path of (path to desktop)
                end try
            end tell
            "#;
            if let Ok(output) = std::process::Command::new("osascript").arg("-e").arg(script).output() {
                if output.status.success() {
                    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !s.is_empty() {
                        let p = PathBuf::from(s);
                        if p.is_dir() {
                            return p;
                        }
                    }
                }
            }
            crate::system_info::user_desktop_or_downloads_dir()
        }

        #[cfg(not(target_os = "macos"))]
        {
            crate::system_info::user_desktop_or_downloads_dir()
        }
    }

    /// Reveals the pasted file or folder in Finder or File Explorer.
    pub fn reveal_in_file_manager(path: &Path) {
        #[cfg(target_os = "macos")]
        {
            let escaped = path
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('\"', "\\\"");
            let script = format!(
                "tell application \"Finder\" to reveal POSIX file \"{}\"",
                escaped
            );
            let _ = std::process::Command::new("osascript").arg("-e").arg(&script).spawn();
        }

        #[cfg(target_os = "windows")]
        {
            let arg = format!("/select,\"{}\"", path.to_string_lossy());
            let _ = std::process::Command::new("explorer.exe").arg(arg).spawn();
        }
    }

    fn copy_entry_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        if src.is_dir() {
            std::fs::create_dir_all(dst)?;
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let path = entry.path();
                let dest_child = dst.join(entry.file_name());
                Self::copy_entry_all(&path, &dest_child)?;
            }
        } else if src.is_file() {
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::copy(src, dst)?;
        }
        Ok(())
    }

    async fn resolve_stream_peer_ip(&self, source_ip: Option<IpAddr>) -> Result<String> {
        if let Some(ip) = self.get_authorized_peer_ip().await {
            return Ok(ip);
        }
        if let Some(ip) = source_ip {
            if Self::is_ip_authorized(ip).await {
                return Ok(ip.to_string());
            }
        }
        anyhow::bail!("No trusted peer connected for clipboard stream")
    }

    async fn connect_and_request_stream(peer_ip: &str, session_id: &str) -> Result<TcpStream> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut socket = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Failed to connect to peer at {}", addr))?;
        let _ = socket.set_nodelay(true);

        let req_msg = ClipboardMessage {
            hash: String::new(),
            payload: ClipboardPayload::RequestStream(StreamRequest {
                session_id: session_id.to_string(),
            }),
        };

        let serialized = serde_json::to_vec(&req_msg)?;
        socket.write_u32(serialized.len() as u32).await?;
        socket.write_all(&serialized).await?;
        socket.flush().await?;
        Ok(socket)
    }

    async fn receive_stream_frames(
        socket: &mut TcpStream,
        dest_base: &Path,
        total_bytes: u64,
    ) -> Result<(u64, std::time::Instant)> {
        let mut transferred_bytes: u64 = 0;
        let start_time = std::time::Instant::now();
        let mut last_progress_report = std::time::Instant::now();
        let mut chunk_buf = vec![0u8; STREAM_CHUNK_SIZE];

        loop {
            let tag = match tokio::time::timeout(Duration::from_secs(30), socket.read_u8()).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    debug!("Stream ended or socket closed: {}", e);
                    break;
                }
                Err(_) => {
                    warn!("Timed out waiting for next frame tag from peer");
                    break;
                }
            };

            if tag == FRAME_END {
                debug!("Received FRAME_END from peer");
                break;
            } else if tag == FRAME_DIR {
                let path_len = socket.read_u16().await? as usize;
                let mut path_bytes = vec![0u8; path_len];
                socket.read_exact(&mut path_bytes).await?;
                let rel_path = String::from_utf8_lossy(&path_bytes);
                let dest_path = join_safe_rel_path(dest_base, &rel_path);
                let _ = std::fs::create_dir_all(&dest_path);
            } else if tag == FRAME_FILE {
                let path_len = socket.read_u16().await? as usize;
                let mut path_bytes = vec![0u8; path_len];
                socket.read_exact(&mut path_bytes).await?;
                let rel_path = String::from_utf8_lossy(&path_bytes);
                let file_size = socket.read_u64().await?;

                let dest_path = join_safe_rel_path(dest_base, &rel_path);
                if let Some(parent) = dest_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                let mut file = File::create(&dest_path)?;
                let mut remaining = file_size;
                while remaining > 0 {
                    let to_read = std::cmp::min(remaining, chunk_buf.len() as u64) as usize;
                    socket.read_exact(&mut chunk_buf[..to_read]).await?;
                    file.write_all(&chunk_buf[..to_read])?;
                    remaining -= to_read as u64;
                    transferred_bytes += to_read as u64;

                    if last_progress_report.elapsed() >= Duration::from_millis(100) {
                        last_progress_report = std::time::Instant::now();
                        let elapsed = start_time.elapsed().as_secs_f64();
                        #[allow(unused_variables)]
                        let mb_s = (transferred_bytes as f64 / (1024.0 * 1024.0)) / elapsed.max(0.001);
                        #[allow(unused_variables)]
                        let pct = if total_bytes > 0 {
                            (transferred_bytes as f64 / total_bytes as f64 * 100.0).min(100.0)
                        } else {
                            100.0
                        };

                        #[cfg(target_os = "macos")]
                        unsafe {
                            update_touchbar_paste_progress(pct as f32, mb_s as f32);
                        }
                    }
                }
            } else {
                warn!("Unexpected frame tag: 0x{:02x}, closing stream read", tag);
                break;
            }
        }

        Ok((transferred_bytes, start_time))
    }

    /// Automatically streams the peer's announced files into the local staging cache,
    /// and registers them onto the native OS clipboard (NSPasteboard / Win32 Clipboard)
    /// so the user can immediately paste with Cmd+V / Ctrl+V natively!
    pub async fn stream_to_cache(&self, ann: LazyAnnouncement) -> Result<()> {
        self.stream_to_cache_from(ann, None).await
    }

    async fn stream_to_cache_from(
        &self,
        ann: LazyAnnouncement,
        source_ip: Option<IpAddr>,
    ) -> Result<()> {
        let peer_ip = self.resolve_stream_peer_ip(source_ip).await?;
        let cache_dir = self.file_helper.get_cache_dir().to_path_buf();
        let safe_name = safe_root_entry_name(&ann.root_name);
        let dest_root = cache_dir.join(&safe_name);

        info!(
            "📥 Streaming announced item '{}' ({:.1} MB) from {} into staging cache...",
            ann.root_name,
            ann.total_bytes as f64 / (1024.0 * 1024.0),
            peer_ip
        );

        let mut socket = Self::connect_and_request_stream(&peer_ip, &ann.session_id).await?;
        let (transferred_bytes, start_time) =
            Self::receive_stream_frames(&mut socket, &cache_dir, ann.total_bytes).await?;

        // Register the file on native OS clipboard for IMMEDIATE native Cmd+V / Ctrl+V!
        if dest_root.exists() {
            self.file_helper.write_copied_files(&[dest_root.clone()])?;
            let new_seq = os_seq::get_clipboard_sequence();
            let mut seq_lock = self.last_seq.write().await;
            *seq_lock = new_seq;
            info!("📋 Registered '{}' on native clipboard. Ready for instant Cmd+V / Ctrl+V in file manager!", ann.root_name);
        }

        #[cfg(target_os = "macos")]
        unsafe {
            reset_touchbar_paste_progress();
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let avg_mb_s = (transferred_bytes as f64 / (1024.0 * 1024.0)) / elapsed.max(0.001);
        info!(
            "✅ Cached '{}' ({:.1} MB at {:.0} MB/s). Ready for native paste.",
            ann.root_name,
            transferred_bytes as f64 / (1024.0 * 1024.0),
            avg_mb_s
        );
        Ok(())
    }

    /// Executes On-Demand Remote Paste:
    /// Pulls the announced files from the peer directly into the target folder with live progress.
    pub async fn paste_remote(&self, custom_target: Option<PathBuf>) -> Result<String> {
        let ann = {
            let lock = self.pending_remote.read().await;
            lock.clone()
        }.context("No remote file announcement pending to paste")?;

        let target_dir = custom_target.unwrap_or_else(Self::resolve_active_destination_folder);
        let safe_name = safe_root_entry_name(&ann.root_name);

        // If the item is already present in the staging cache, copy or reveal it directly!
        let cache_dir = self.file_helper.get_cache_dir().to_path_buf();
        let cached_item = cache_dir.join(&safe_name);
        if cached_item.exists() && target_dir != cache_dir {
            info!("📋 Item '{}' already present in staging cache. Copying to destination {:?}...", ann.root_name, target_dir);
            let dest_root = target_dir.join(&safe_name);
            Self::copy_entry_all(&cached_item, &dest_root)?;
            Self::reveal_in_file_manager(&dest_root);
            #[cfg(target_os = "macos")]
            unsafe {
                reset_touchbar_paste_progress();
            }
            return Ok(format!("✅ Pasted '{}' directly into {:?}", ann.root_name, target_dir));
        }

        if self.is_pasting.swap(true, std::sync::atomic::Ordering::SeqCst) {
            warn!("Remote paste is already in progress, ignoring duplicate trigger");
            return Ok("Paste already in progress".to_string());
        }

        struct PasteGuard<'a> {
            service: &'a ClipboardService,
        }
        impl<'a> Drop for PasteGuard<'a> {
            fn drop(&mut self) {
                self.service.is_pasting.store(false, std::sync::atomic::Ordering::SeqCst);
                #[cfg(target_os = "macos")]
                unsafe {
                    set_has_pending_remote_file(false);
                    reset_touchbar_paste_progress();
                }
            }
        }
        let _guard = PasteGuard { service: self };

        let last_ip = *self.last_remote_ip.read().await;
        let peer_ip = self.resolve_stream_peer_ip(last_ip).await?;

        info!(
            "📥 Initiating on-demand stream of '{}' from {} directly into {:?}",
            ann.root_name, peer_ip, target_dir
        );

        let mut socket = Self::connect_and_request_stream(&peer_ip, &ann.session_id).await?;
        let dest_root = target_dir.join(&safe_name);
        let (transferred_bytes, start_time) =
            Self::receive_stream_frames(&mut socket, &target_dir, ann.total_bytes).await?;

        // Clear pending remote announcement
        {
            let mut lock = self.pending_remote.write().await;
            *lock = None;
        }
        {
            let mut ip_lock = self.last_remote_ip.write().await;
            *ip_lock = None;
        }

        #[cfg(target_os = "macos")]
        unsafe {
            reset_touchbar_paste_progress();
        }

        Self::reveal_in_file_manager(&dest_root);

        let elapsed = start_time.elapsed().as_secs_f64();
        let avg_mb_s = (transferred_bytes as f64 / (1024.0 * 1024.0)) / elapsed.max(0.001);
        let msg = format!(
            "✅ Successfully pasted '{}' ({:.1} MB at {:.0} MB/s) directly into {:?}",
            ann.root_name,
            transferred_bytes as f64 / (1024.0 * 1024.0),
            avg_mb_s,
            target_dir
        );
        info!("{}", msg);
        Ok(msg)
    }
}
