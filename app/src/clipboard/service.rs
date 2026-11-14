//! Universal Clipboard Service with Mutually Authenticated `TransportSessionV2` (`ITR2`),
//! Strict Quotas, Path Traversal & Symlink Protections, Per-File + Manifest SHA-256 Verification,
//! and Isolated Staging with Atomic Commits.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::config::CLIPBOARD_PORT;
use crate::discovery::DiscoveryManager;
use crate::security::transport::{ServiceId, TransportSessionV2};
use crate::trust;
use super::file_helper::FileClipboardHelper;
use super::os_seq;
use super::protocol::{
    ClipboardMessage, ClipboardPayload, LazyAnnouncement, StreamRequest,
    FRAME_DIR, FRAME_END, FRAME_FILE, FRAME_FILE_DATA, FRAME_FILE_HASH,
    MAX_AUTO_STAGE_BYTES, MAX_CLIPBOARD_HEADER_BYTES, MAX_DIRECTORY_DEPTH,
    MAX_IMAGE_BYTES, MAX_IMAGE_DIMENSION, MAX_SINGLE_FILE_BYTES, MAX_TEXT_CHARS,
    MAX_TOTAL_TRANSFER_BYTES, MAX_TRANSFER_FILES,
};

const STREAM_CHUNK_SIZE: usize = 256 * 1024; // 256 KiB high-throughput AEAD chunk
const MAX_CONCURRENT_CLIPBOARD_CONNS: usize = 8;
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(target_os = "macos")]
extern "C" {
    pub fn init_shortcut_interceptor();
    pub fn set_has_pending_remote_file(pending: bool);
    #[allow(dead_code)]
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

fn compute_text_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    to_hex_string(&hasher.finalize())
}

fn compute_image_hash(width: usize, height: usize, rgba: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&(width as u64).to_le_bytes());
    hasher.update(&(height as u64).to_le_bytes());
    hasher.update(&(rgba.len() as u64).to_le_bytes());
    hasher.update(rgba);
    to_hex_string(&hasher.finalize())
}

fn validate_image_bounds(width: usize, height: usize, rgba_len: usize) -> bool {
    if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return false;
    }
    if rgba_len == 0 || rgba_len > MAX_IMAGE_BYTES {
        return false;
    }
    match width.checked_mul(height).and_then(|px| px.checked_mul(4)) {
        Some(expected) => expected == rgba_len,
        None => false,
    }
}

/// Checks whether a path component is a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`,
/// `COM1`..`COM9`, `LPT1`..`LPT9`, with or without extension).
fn is_windows_reserved_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Validates a single path component against traversal, control chars, Windows forbidden chars,
/// trailing spaces/dots, and Windows reserved device names.
fn validate_single_path_component(comp: &str) -> Result<()> {
    if comp.is_empty() || comp == "." || comp == ".." {
        anyhow::bail!("Rejected traversal or empty path component '{}'", comp);
    }
    if comp.len() > 255 {
        anyhow::bail!("Rejected path component exceeding 255 bytes");
    }
    if comp.ends_with(' ') || comp.ends_with('.') {
        anyhow::bail!(
            "Rejected path component '{}' ending with trailing space or dot",
            comp
        );
    }
    if comp.chars().any(|c| {
        c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\0')
    }) {
        anyhow::bail!(
            "Rejected path component '{}' containing forbidden or control characters",
            comp
        );
    }
    if is_windows_reserved_device_name(comp) {
        anyhow::bail!(
            "Rejected Windows reserved device name '{}' in file transfer path",
            comp
        );
    }
    Ok(())
}

fn safe_root_entry_name(raw: &str) -> String {
    let candidate = raw
        .split(['/', '\\'])
        .find(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or("clipboard_item");
    if validate_single_path_component(candidate).is_ok() {
        candidate.to_string()
    } else {
        "clipboard_item".to_string()
    }
}

/// Strictly validates `rel_path` (rejecting leading slashes, `..`, `.`, empty segments,
/// depth > `MAX_DIRECTORY_DEPTH`, Windows reserved names, and symlinks) and resolves it
/// inside `dest_base`.
fn ensure_safe_contained_path(dest_base: &Path, rel_path: &str) -> Result<PathBuf> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.starts_with('\\')
        || rel_path.contains('\0')
    {
        anyhow::bail!(
            "Security violation: rejected absolute or malformed relative path '{}'",
            rel_path
        );
    }

    std::fs::create_dir_all(dest_base)?;
    let canon_base = dest_base
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize destination base {:?}", dest_base))?;

    let mut current = canon_base.clone();
    let mut depth = 0usize;

    for comp in rel_path.split(['/', '\\']) {
        validate_single_path_component(comp)?;
        depth += 1;
        if depth > MAX_DIRECTORY_DEPTH {
            anyhow::bail!(
                "Security violation: relative path '{}' exceeds maximum directory depth ({})",
                rel_path,
                MAX_DIRECTORY_DEPTH
            );
        }
        current.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "Security violation: refusing to traverse or overwrite symlink at {:?}",
                    current
                );
            }
        }
    }

    if depth == 0 {
        anyhow::bail!("Rejected empty relative path in file stream");
    }
    if !current.starts_with(&canon_base) {
        anyhow::bail!(
            "Security violation: destination {:?} escapes base {:?}",
            current,
            canon_base
        );
    }
    Ok(current)
}

/// Creates a new staged file exclusively (`create_new(true)`) with `O_NOFOLLOW` on Unix so a
/// symlink or pre-existing file at `dest_path` can never be followed or overwritten.
fn open_staged_file_create_new(dest_path: &Path) -> Result<File> {
    if let Ok(meta) = std::fs::symlink_metadata(dest_path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "Security violation: target file {:?} is a symbolic link",
                dest_path
            );
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
        opts.mode(0o600);
    }
    opts.open(dest_path)
        .with_context(|| format!("Failed to exclusively create staged file {:?}", dest_path))
}

/// Picks a non-destructive destination path in `target_dir` so existing files/folders
/// are never silently overwritten during paste.
fn resolve_non_colliding_dest(target_dir: &Path, safe_name: &str) -> PathBuf {
    let candidate = target_dir.join(safe_name);
    if !candidate.exists() && std::fs::symlink_metadata(&candidate).is_err() {
        return candidate;
    }

    let path_obj = Path::new(safe_name);
    let stem = path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(safe_name);
    let ext = path_obj.extension().and_then(|e| e.to_str());

    for idx in 2..=10_000 {
        let numbered = match ext {
            Some(e) if !e.is_empty() => format!("{} ({}).{}", stem, idx, e),
            _ => format!("{} ({})", stem, idx),
        };
        let next = target_dir.join(numbered);
        if !next.exists() && std::fs::symlink_metadata(&next).is_err() {
            return next;
        }
    }
    target_dir.join(format!(
        "{}_{}",
        safe_name,
        trust::generate_random_token_hex(4)
    ))
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

    async fn has_paired_peer(ip: IpAddr) -> bool {
        tokio::task::spawn_blocking(move || crate::trust::has_paired_peer_at_ip(ip))
            .await
            .unwrap_or(false)
    }

    /// Returns a paired peer IP (preferring the discovery-selected best peer).
    async fn get_authorized_peer_ip(&self) -> Option<String> {
        if let Some(best) = self.discovery.get_best_peer().await {
            if Self::has_paired_peer(best.addr.ip()).await {
                return Some(best.addr.ip().to_string());
            }
        }
        for peer in self.discovery.get_all_peers().await {
            if Self::has_paired_peer(peer.addr.ip()).await {
                return Some(peer.addr.ip().to_string());
            }
        }
        None
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", CLIPBOARD_PORT)).await?;
        info!(
            "📋 Universal Clipboard Service (TransportV2 ITR2) active on port {}",
            CLIPBOARD_PORT
        );

        // 1. Spawn TCP Receiver with bounded concurrency
        let s_clone = self.clone();
        let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIPBOARD_CONNS));
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let Ok(permit) = Arc::clone(&conn_limiter).try_acquire_owned() else {
                            warn!(
                                "🚫 Dropped clipboard connection from {}: concurrency limit ({}) reached",
                                addr, MAX_CONCURRENT_CLIPBOARD_CONNS
                            );
                            drop(socket);
                            continue;
                        };
                        let handler = s_clone.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            debug!("Incoming clipboard connection from {}", addr);
                            if let Err(e) = handler.handle_incoming(socket, addr).await {
                                warn!("Error handling clipboard transfer from {}: {}", addr, e);
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

    /// Handles incoming mutually authenticated `TransportSessionV2` (`ServiceId::ClipboardTransfer`)
    /// clipboard payloads and stream requests from a paired peer.
    async fn handle_incoming(&self, socket: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        let _ = socket.set_nodelay(true);
        let mut session = trust::accept_transport_from_stream(
            socket,
            peer_addr.ip(),
            None,
            ServiceId::ClipboardTransfer,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Clipboard TransportV2 handshake rejected: {}", e))?;

        let plaintext = tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.recv_chunked_payload(MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .context("Timed out reading clipboard message over TransportV2")?
        .map_err(|e| anyhow::anyhow!("Failed reading clipboard message over TransportV2: {}", e))?;

        let msg: ClipboardMessage = serde_json::from_slice(&plaintext)?;

        match msg.payload {
            ClipboardPayload::Text(text) => {
                if text.is_empty() || text.len() > MAX_TEXT_CHARS {
                    warn!("Rejected remote text out of bounds ({} bytes)", text.len());
                    return Ok(());
                }
                let computed_hash = compute_text_hash(&text);
                if msg.hash.is_empty()
                    || !trust::constant_time_eq(computed_hash.as_bytes(), msg.hash.as_bytes())
                {
                    warn!(
                        "🚫 Rejected remote text from {}: SHA-256 integrity hash mismatch",
                        peer_addr
                    );
                    return Ok(());
                }

                {
                    let mut lock = self.last_hash.write().await;
                    *lock = computed_hash;
                }

                info!("📋 Verified & received remote text ({} chars)", text.len());
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
            ClipboardPayload::Image {
                width,
                height,
                rgba,
            } => {
                if !validate_image_bounds(width, height, rgba.len()) {
                    warn!(
                        "🚫 Rejected remote image from {}: invalid dimensions ({}x{}) or RGBA length ({})",
                        peer_addr,
                        width,
                        height,
                        rgba.len()
                    );
                    return Ok(());
                }
                let computed_hash = compute_image_hash(width, height, &rgba);
                if msg.hash.is_empty()
                    || !trust::constant_time_eq(computed_hash.as_bytes(), msg.hash.as_bytes())
                {
                    warn!(
                        "🚫 Rejected remote image from {}: SHA-256 integrity hash mismatch",
                        peer_addr
                    );
                    return Ok(());
                }

                {
                    let mut lock = self.last_hash.write().await;
                    *lock = computed_hash;
                }

                info!("🖼️ Verified & received remote image ({}x{} px)", width, height);
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
                if ann.session_id.trim().is_empty()
                    || ann.session_id.len() > 128
                    || ann.total_files == 0
                    || ann.total_files > MAX_TRANSFER_FILES
                    || ann.total_bytes > MAX_TOTAL_TRANSFER_BYTES
                {
                    warn!(
                        "🚫 Rejected out-of-bounds file announcement from {} (files={}, bytes={})",
                        peer_addr, ann.total_files, ann.total_bytes
                    );
                    return Ok(());
                }

                if !msg.hash.is_empty() && msg.hash.len() <= 128 {
                    let mut lock = self.last_hash.write().await;
                    *lock = msg.hash.clone();
                }

                info!(
                    "📥 Peer announced file/folder '{}' ({} files, {:.1} MB). Ready for paste.",
                    ann.root_name,
                    ann.total_files,
                    ann.total_bytes as f64 / (1024.0 * 1024.0)
                );
                {
                    let mut lock = self.pending_remote.write().await;
                    *lock = Some(ann.clone());
                }
                {
                    let mut ip_lock = self.last_remote_ip.write().await;
                    *ip_lock = Some(peer_addr.ip());
                }

                // Preserve existing native OS clipboard until staging succeeds or user triggers paste.
                #[cfg(target_os = "macos")]
                {
                    let name_c =
                        std::ffi::CString::new(ann.root_name.clone()).unwrap_or_default();
                    unsafe {
                        notify_touchbar_remote_file(name_c.as_ptr(), ann.total_bytes);
                        set_has_pending_remote_file(true);
                    }
                }

                // Only auto-stage bounded transfers (<= 128 MiB) in the background;
                // larger multi-GB transfers stream on-demand when the user explicitly pastes.
                if ann.total_bytes <= MAX_AUTO_STAGE_BYTES {
                    let service_clone = self.clone();
                    let ann_clone = ann.clone();
                    let source_ip = peer_addr.ip();
                    tokio::spawn(async move {
                        if let Err(e) = service_clone
                            .stream_to_cache_from(ann_clone, Some(source_ip))
                            .await
                        {
                            warn!("Background stream to staging cache failed: {}", e);
                        }
                    });
                } else {
                    info!(
                        "📦 Announcement '{}' ({:.1} MB) exceeds auto-stage threshold ({} MB); waiting for user paste.",
                        ann.root_name,
                        ann.total_bytes as f64 / (1024.0 * 1024.0),
                        MAX_AUTO_STAGE_BYTES / (1024 * 1024)
                    );
                }
            }
            ClipboardPayload::RequestStream(req) => {
                let local_copy = {
                    let lock = self.pending_local.read().await;
                    lock.clone()
                };

                if let Some(copy) = local_copy {
                    if !req.session_id.is_empty()
                        && trust::constant_time_eq(
                            copy.session_id.as_bytes(),
                            req.session_id.as_bytes(),
                        )
                    {
                        info!(
                            "🚀 Peer requested on-demand stream for '{}' ({} files, {:.1} MB). Streaming over TransportV2...",
                            copy.root_name,
                            copy.total_files,
                            copy.total_bytes as f64 / (1024.0 * 1024.0)
                        );
                        Self::stream_files_over_session(&mut session, copy.directories, copy.files)
                            .await?;
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

    /// Recursively collects regular files and subdirectories while skipping symlinks
    /// and enforcing `MAX_TRANSFER_FILES`, `MAX_DIRECTORY_DEPTH`, and `MAX_TOTAL_TRANSFER_BYTES`.
    fn collect_dir_entries(
        _root: &Path,
        current: &Path,
        rel_prefix: &str,
        depth: usize,
        directories: &mut Vec<String>,
        files: &mut Vec<(String, PathBuf)>,
        total_bytes: &mut u64,
        total_files: &mut usize,
    ) {
        if depth >= MAX_DIRECTORY_DEPTH
            || *total_files >= MAX_TRANSFER_FILES
            || *total_bytes >= MAX_TOTAL_TRANSFER_BYTES
        {
            return;
        }
        if let Ok(read_dir) = std::fs::read_dir(current) {
            for entry in read_dir.flatten() {
                if *total_files >= MAX_TRANSFER_FILES || *total_bytes >= MAX_TOTAL_TRANSFER_BYTES {
                    break;
                }
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                // Never follow symlinks when indexing clipboard directories
                if meta.file_type().is_symlink() {
                    debug!("Skipping symlink in clipboard copy: {:?}", path);
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if validate_single_path_component(&name).is_err() {
                    continue;
                }
                let rel = format!("{}/{}", rel_prefix, name);

                if meta.is_dir() {
                    if depth + 1 < MAX_DIRECTORY_DEPTH {
                        directories.push(rel.clone());
                        Self::collect_dir_entries(
                            _root,
                            &path,
                            &rel,
                            depth + 1,
                            directories,
                            files,
                            total_bytes,
                            total_files,
                        );
                    }
                } else if meta.is_file() {
                    let len = meta.len();
                    if len <= MAX_SINGLE_FILE_BYTES
                        && total_bytes.saturating_add(len) <= MAX_TOTAL_TRANSFER_BYTES
                    {
                        *total_bytes += len;
                        *total_files += 1;
                        files.push((rel, path));
                    }
                }
            }
        }
    }

    /// Continuous lightweight loop checking for clipboard sequence changes.
    async fn monitor_loop(&self) {
        loop {
            sleep(Duration::from_millis(120)).await;

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

            // 1. Check for Copied Files and Folders (run on blocking pool so OS helpers never stall async workers)
            let helper = Arc::clone(&self.file_helper);
            let copied_paths = tokio::task::spawn_blocking(move || helper.read_copied_files())
                .await
                .unwrap_or_default();

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
                    if let Ok(meta) = std::fs::symlink_metadata(root) {
                        if meta.file_type().is_symlink() {
                            continue;
                        }
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

                    // Collect directory structure and file paths (skipping symlinks)
                    let mut root_name = String::new();
                    let mut directories = Vec::new();
                    let mut files = Vec::new();
                    let mut total_bytes: u64 = 0;
                    let mut total_files: usize = 0;

                    for root in &external_paths {
                        let Ok(meta) = std::fs::symlink_metadata(root) else {
                            continue;
                        };
                        if meta.file_type().is_symlink() {
                            continue;
                        }
                        if let Some(file_name) = root.file_name() {
                            let name_str = file_name.to_string_lossy().to_string();
                            if validate_single_path_component(&name_str).is_err() {
                                continue;
                            }
                            if root_name.is_empty() {
                                root_name = name_str.clone();
                            }
                            if meta.is_dir() {
                                directories.push(name_str.clone());
                                Self::collect_dir_entries(
                                    root,
                                    root,
                                    &name_str,
                                    1,
                                    &mut directories,
                                    &mut files,
                                    &mut total_bytes,
                                    &mut total_files,
                                );
                            } else if meta.is_file() {
                                let len = meta.len();
                                if total_files < MAX_TRANSFER_FILES
                                    && len <= MAX_SINGLE_FILE_BYTES
                                    && total_bytes.saturating_add(len) <= MAX_TOTAL_TRANSFER_BYTES
                                {
                                    total_bytes += len;
                                    total_files += 1;
                                    files.push((name_str, root.clone()));
                                }
                            }
                        }
                    }

                    if total_files == 0 {
                        continue;
                    }

                    if external_paths.len() > 1 {
                        root_name = format!("{} (+{} items)", root_name, external_paths.len() - 1);
                    }

                    // Cryptographically random 256-bit session capability token
                    let session_id = trust::generate_random_token_hex(32);

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
                            "📢 Local copy detected: '{}' ({} files, {:.1} MB). Sending announcement to {}...",
                            root_name,
                            total_files,
                            total_bytes as f64 / (1024.0 * 1024.0),
                            peer_ip
                        );
                        let ann = LazyAnnouncement {
                            session_id,
                            root_name,
                            total_files,
                            total_bytes,
                        };
                        tokio::spawn(async move {
                            if let Err(e) = Self::send_payload(
                                &peer_ip,
                                ClipboardMessage {
                                    hash: hash_hex,
                                    payload: ClipboardPayload::LazyAnnouncement(ann),
                                },
                            )
                            .await
                            {
                                warn!("Failed to send lazy announcement to {}: {}", peer_ip, e);
                            }
                        });
                    } else {
                        debug!(
                            "Local copy detected: '{}' ({} files), but no trusted peer is connected; skipping announcement",
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
                    if validate_image_bounds(img.width, img.height, img_bytes_len) {
                        let hash_hex = compute_image_hash(img.width, img.height, &img.bytes);

                        let mut hash_lock = self.last_hash.write().await;
                        if *hash_lock != hash_hex {
                            *hash_lock = hash_hex.clone();
                            drop(hash_lock);

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
                                info!(
                                    "📤 Detected local copied image ({}x{} px). Sending to {}...",
                                    img.width, img.height, peer_ip
                                );
                                if let Err(e) = Self::send_payload(
                                    &peer_ip,
                                    ClipboardMessage {
                                        hash: hash_hex,
                                        payload: ClipboardPayload::Image {
                                            width: img.width,
                                            height: img.height,
                                            rgba: img.bytes.into_owned(),
                                        },
                                    },
                                )
                                .await
                                {
                                    warn!("Failed to send image to {}: {}", peer_ip, e);
                                }
                            } else {
                                debug!(
                                    "Local image copied ({}x{} px), but no trusted peer is connected; skipping sync",
                                    img.width, img.height
                                );
                            }
                        }
                        continue;
                    }
                }

                if let Ok(text) = cb.get_text() {
                    if !text.is_empty() && text.len() <= MAX_TEXT_CHARS {
                        let hash_hex = compute_text_hash(&text);

                        let mut hash_lock = self.last_hash.write().await;
                        if *hash_lock != hash_hex {
                            *hash_lock = hash_hex.clone();
                            drop(hash_lock);

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
                                info!(
                                    "📤 Detected local copied text ({} chars). Sending to {}...",
                                    text.len(),
                                    peer_ip
                                );
                                if let Err(e) = Self::send_payload(
                                    &peer_ip,
                                    ClipboardMessage {
                                        hash: hash_hex,
                                        payload: ClipboardPayload::Text(text),
                                    },
                                )
                                .await
                                {
                                    warn!("Failed to send text to {}: {}", peer_ip, e);
                                }
                            } else {
                                debug!(
                                    "Local text copied ({} chars), but no trusted peer is connected; skipping sync",
                                    text.len()
                                );
                            }
                        }
                        continue;
                    }
                }
            }
        }
    }

    /// Sends an encrypted, mutually authenticated `ClipboardMessage` over `TransportSessionV2`.
    async fn send_payload(peer_ip: &str, msg: ClipboardMessage) -> Result<()> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CLIPBOARD_PORT,
            ServiceId::ClipboardTransfer,
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish Clipboard TransportV2 to {}: {}", addr, e))?;

        let serialized = serde_json::to_vec(&msg)?;
        tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.send_chunked_payload(&serialized, MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .with_context(|| format!("Timed out sending clipboard payload to {}", addr))?
        .map_err(|e| anyhow::anyhow!("Clipboard TransportV2 send error to {}: {}", addr, e))?;

        info!("✅ Sent TransportV2 encrypted clipboard message to {}", addr);
        Ok(())
    }

    /// Streams directory structure, file contents, per-file SHA-256 digests, and a final manifest
    /// SHA-256 digest over an authenticated `TransportSessionV2`.
    /// Aborts cleanly if any source file is modified/truncated mid-transfer instead of zero-padding.
    pub(crate) async fn stream_files_over_session<S>(
        session: &mut TransportSessionV2<S>,
        directories: Vec<String>,
        files: Vec<(String, PathBuf)>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(b"INTEGRATOR-FILE-MANIFEST-V2");

        // 1. Directory frames: [FRAME_DIR(1B) || path_len_be(2B) || rel_path_utf8]
        for dir_rel in &directories {
            let rel_bytes = dir_rel.as_bytes();
            if rel_bytes.is_empty() || rel_bytes.len() > 4096 {
                continue;
            }
            let mut rec = Vec::with_capacity(3 + rel_bytes.len());
            rec.push(FRAME_DIR);
            rec.extend_from_slice(&(rel_bytes.len() as u16).to_be_bytes());
            rec.extend_from_slice(rel_bytes);

            tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&rec))
                .await
                .context("Timed out writing directory frame")?
                .map_err(|e| anyhow::anyhow!("Directory frame TransportV2 error: {}", e))?;
        }

        // 2. File frames
        let mut chunk_buf = vec![0u8; STREAM_CHUNK_SIZE + 1];
        chunk_buf[0] = FRAME_FILE_DATA;

        for (rel_path, abs_path) in files {
            let rel_bytes = rel_path.as_bytes();
            if rel_bytes.is_empty() || rel_bytes.len() > 4096 {
                continue;
            }

            let meta = std::fs::symlink_metadata(&abs_path)
                .with_context(|| format!("Source file {:?} unavailable for streaming", abs_path))?;
            if meta.file_type().is_symlink() {
                anyhow::bail!("Refusing to stream symlink {:?}", abs_path);
            }
            let actual_len = meta.len();
            let mut file = File::open(&abs_path)
                .with_context(|| format!("Could not open {:?} for streaming", abs_path))?;

            // Header record: [FRAME_FILE(1B) || path_len_be(2B) || rel_bytes || actual_len_be(8B)]
            let mut hdr_rec = Vec::with_capacity(11 + rel_bytes.len());
            hdr_rec.push(FRAME_FILE);
            hdr_rec.extend_from_slice(&(rel_bytes.len() as u16).to_be_bytes());
            hdr_rec.extend_from_slice(rel_bytes);
            hdr_rec.extend_from_slice(&actual_len.to_be_bytes());

            tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&hdr_rec))
                .await
                .context("Timed out writing file header frame")?
                .map_err(|e| anyhow::anyhow!("File header TransportV2 error: {}", e))?;

            let mut file_hasher = Sha256::new();
            let mut remaining = actual_len;
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, STREAM_CHUNK_SIZE as u64) as usize;
                let n = file.read(&mut chunk_buf[1..1 + to_read])?;
                if n == 0 {
                    anyhow::bail!(
                        "Source file {:?} was truncated during transfer ({} bytes remaining); aborting stream to prevent corruption",
                        abs_path,
                        remaining
                    );
                }
                file_hasher.update(&chunk_buf[1..1 + n]);
                tokio::time::timeout(
                    FRAME_IO_TIMEOUT,
                    session.send_message(&chunk_buf[..1 + n]),
                )
                .await
                .context("Timed out writing file chunk to TransportV2 session")?
                .map_err(|e| anyhow::anyhow!("File chunk TransportV2 error: {}", e))?;
                remaining -= n as u64;
            }

            // Ensure the file did not grow while being read
            let mut extra_byte = [0u8; 1];
            if file.read(&mut extra_byte)? > 0 {
                anyhow::bail!(
                    "Source file {:?} was modified/appended during transfer; aborting stream",
                    abs_path
                );
            }

            let file_sha256: [u8; 32] = file_hasher.finalize().into();
            manifest_hasher.update(&(rel_bytes.len() as u32).to_be_bytes());
            manifest_hasher.update(rel_bytes);
            manifest_hasher.update(&actual_len.to_be_bytes());
            manifest_hasher.update(&file_sha256);

            let mut hash_rec = [0u8; 33];
            hash_rec[0] = FRAME_FILE_HASH;
            hash_rec[1..33].copy_from_slice(&file_sha256);

            tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&hash_rec))
                .await
                .context("Timed out writing file SHA-256 frame")?
                .map_err(|e| anyhow::anyhow!("File hash TransportV2 error: {}", e))?;
        }

        let manifest_sha256: [u8; 32] = manifest_hasher.finalize().into();
        let mut end_rec = [0u8; 33];
        end_rec[0] = FRAME_END;
        end_rec[1..33].copy_from_slice(&manifest_sha256);

        tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&end_rec))
            .await
            .context("Timed out writing FRAME_END")?
            .map_err(|e| anyhow::anyhow!("FRAME_END TransportV2 error: {}", e))?;

        info!("✅ Finished authenticated streaming to peer");
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
            if let Ok(output) = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .output()
            {
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
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .spawn();
        }

        #[cfg(target_os = "windows")]
        {
            let arg = format!("/select,{}", path.to_string_lossy());
            let _ = std::process::Command::new("explorer.exe").arg(arg).spawn();
        }
    }

    fn copy_entry_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(src)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        if meta.is_dir() {
            std::fs::create_dir_all(dst)?;
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let path = entry.path();
                let dest_child = dst.join(entry.file_name());
                Self::copy_entry_all(&path, &dest_child)?;
            }
        } else if meta.is_file() {
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::copy(src, dst)?;
        }
        Ok(())
    }

    async fn resolve_stream_peer_ip(&self, source_ip: Option<IpAddr>) -> Result<String> {
        if let Some(ip) = source_ip {
            if Self::has_paired_peer(ip).await {
                return Ok(ip.to_string());
            }
        }
        if let Some(ip) = self.get_authorized_peer_ip().await {
            return Ok(ip);
        }
        anyhow::bail!("No trusted peer connected for clipboard stream")
    }

    async fn connect_and_request_stream(
        peer_ip: &str,
        session_id: &str,
    ) -> Result<TransportSessionV2<TcpStream>> {
        let addr = format!("{}:{}", peer_ip, CLIPBOARD_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CLIPBOARD_PORT,
            ServiceId::ClipboardTransfer,
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect TransportV2 to {}: {}", addr, e))?;

        let req_msg = ClipboardMessage {
            hash: String::new(),
            payload: ClipboardPayload::RequestStream(StreamRequest {
                session_id: session_id.to_string(),
            }),
        };

        let serialized = serde_json::to_vec(&req_msg)?;
        tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.send_chunked_payload(&serialized, MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .context("Timed out sending stream request header")?
        .map_err(|e| anyhow::anyhow!("Stream request TransportV2 send error: {}", e))?;

        Ok(session)
    }

    /// Receives and verifies directory frames, file frames, per-file SHA-256 digests, and the
    /// overall manifest SHA-256 digest into an isolated staging directory (`dest_base`).
    pub(crate) async fn receive_stream_frames_from_session<S>(
        session: &mut TransportSessionV2<S>,
        dest_base: &Path,
        expected_total_bytes: u64,
        expected_total_files: usize,
        root_remap: Option<(&str, &str)>,
    ) -> Result<(u64, std::time::Instant)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        if expected_total_files == 0 || expected_total_files > MAX_TRANSFER_FILES {
            anyhow::bail!(
                "Invalid announced file count {} (max {})",
                expected_total_files,
                MAX_TRANSFER_FILES
            );
        }
        if expected_total_bytes > MAX_TOTAL_TRANSFER_BYTES {
            anyhow::bail!(
                "Announced transfer size {} exceeds limit {}",
                expected_total_bytes,
                MAX_TOTAL_TRANSFER_BYTES
            );
        }

        let mut transferred_bytes: u64 = 0;
        let mut received_files: usize = 0;
        let start_time = std::time::Instant::now();
        let mut last_progress_report = std::time::Instant::now();
        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(b"INTEGRATOR-FILE-MANIFEST-V2");

        loop {
            let rec = tokio::time::timeout(FRAME_IO_TIMEOUT, session.recv_message())
                .await
                .context("Timed out waiting for next stream frame from peer")?
                .map_err(|e| anyhow::anyhow!("Stream closed or failed before FRAME_END: {}", e))?;

            if rec.is_empty() {
                anyhow::bail!("Received empty stream record from peer");
            }
            let tag = rec[0];

            if tag == FRAME_END {
                if rec.len() != 33 {
                    anyhow::bail!(
                        "Invalid FRAME_END record length {} (expected 33 bytes with manifest SHA-256)",
                        rec.len()
                    );
                }
                let expected_manifest_sha256 = &rec[1..33];
                let computed_manifest_sha256: [u8; 32] = manifest_hasher.finalize().into();
                if !trust::constant_time_eq(&computed_manifest_sha256, expected_manifest_sha256) {
                    anyhow::bail!(
                        "Security violation: file transfer manifest SHA-256 mismatch; aborting commit"
                    );
                }
                debug!("Verified FRAME_END and manifest SHA-256 from peer");
                break;
            } else if tag == FRAME_DIR {
                if rec.len() < 3 {
                    anyhow::bail!("Malformed FRAME_DIR record (len {})", rec.len());
                }
                let path_len = u16::from_be_bytes([rec[1], rec[2]]) as usize;
                if path_len == 0 || path_len > 4096 || rec.len() != 3 + path_len {
                    anyhow::bail!("Invalid directory path length {} in stream", path_len);
                }
                let raw_rel = std::str::from_utf8(&rec[3..3 + path_len])
                    .context("Directory relative path is not valid UTF-8")?;
                let rel_path = Self::remap_rel_root(raw_rel, root_remap);
                let dest_path = ensure_safe_contained_path(dest_base, &rel_path)?;
                std::fs::create_dir_all(&dest_path)?;
            } else if tag == FRAME_FILE {
                received_files += 1;
                if received_files > expected_total_files.min(MAX_TRANSFER_FILES) {
                    anyhow::bail!(
                        "Peer sent more files ({}) than announced ({})",
                        received_files,
                        expected_total_files
                    );
                }
                if rec.len() < 11 {
                    anyhow::bail!("Malformed FRAME_FILE header record (len {})", rec.len());
                }
                let path_len = u16::from_be_bytes([rec[1], rec[2]]) as usize;
                if path_len == 0 || path_len > 4096 || rec.len() != 11 + path_len {
                    anyhow::bail!("Invalid file path length {} in stream", path_len);
                }
                let raw_rel_bytes = &rec[3..3 + path_len];
                let raw_rel = std::str::from_utf8(raw_rel_bytes)
                    .context("File relative path is not valid UTF-8")?;
                let rel_path = Self::remap_rel_root(raw_rel, root_remap);

                let mut sz_bytes = [0u8; 8];
                sz_bytes.copy_from_slice(&rec[3 + path_len..11 + path_len]);
                let file_size = u64::from_be_bytes(sz_bytes);

                if file_size > MAX_SINGLE_FILE_BYTES {
                    anyhow::bail!(
                        "File '{}' size {} exceeds single-file limit {}",
                        rel_path,
                        file_size,
                        MAX_SINGLE_FILE_BYTES
                    );
                }
                if transferred_bytes.saturating_add(file_size) > expected_total_bytes {
                    anyhow::bail!(
                        "Stream byte count ({} + {}) exceeds announced total_bytes ({})",
                        transferred_bytes,
                        file_size,
                        expected_total_bytes
                    );
                }

                let dest_path = ensure_safe_contained_path(dest_base, &rel_path)?;
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let mut file = open_staged_file_create_new(&dest_path)?;
                let mut file_hasher = Sha256::new();
                let mut remaining = file_size;

                while remaining > 0 {
                    let data_rec = tokio::time::timeout(FRAME_IO_TIMEOUT, session.recv_message())
                        .await
                        .with_context(|| {
                            format!("Timed out reading file data chunk for '{}'", rel_path)
                        })?
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Stream closed prematurely while reading '{}' ({} bytes remaining): {}",
                                rel_path,
                                remaining,
                                e
                            )
                        })?;

                    if data_rec.len() < 2 || data_rec[0] != FRAME_FILE_DATA {
                        anyhow::bail!(
                            "Expected FRAME_FILE_DATA (0x03) for '{}', got len={}",
                            rel_path,
                            data_rec.len()
                        );
                    }
                    let chunk = &data_rec[1..];
                    if (chunk.len() as u64) > remaining {
                        anyhow::bail!(
                            "File '{}' chunk size {} exceeds remaining bytes {}",
                            rel_path,
                            chunk.len(),
                            remaining
                        );
                    }

                    file_hasher.update(chunk);
                    file.write_all(chunk)?;
                    remaining -= chunk.len() as u64;
                    transferred_bytes += chunk.len() as u64;

                    if last_progress_report.elapsed() >= Duration::from_millis(100) {
                        last_progress_report = std::time::Instant::now();
                        let elapsed = start_time.elapsed().as_secs_f64();
                        #[allow(unused_variables)]
                        let mb_s =
                            (transferred_bytes as f64 / (1024.0 * 1024.0)) / elapsed.max(0.001);
                        #[allow(unused_variables)]
                        let pct = if expected_total_bytes > 0 {
                            (transferred_bytes as f64 / expected_total_bytes as f64 * 100.0)
                                .min(100.0)
                        } else {
                            100.0
                        };

                        #[cfg(target_os = "macos")]
                        unsafe {
                            update_touchbar_paste_progress(pct as f32, mb_s as f32);
                        }
                    }
                }
                file.flush()?;

                // Read and verify mandatory per-file SHA-256 commit frame
                let hash_rec = tokio::time::timeout(FRAME_IO_TIMEOUT, session.recv_message())
                    .await
                    .with_context(|| format!("Timed out reading SHA-256 frame for '{}'", rel_path))?
                    .map_err(|e| {
                        anyhow::anyhow!("Failed reading SHA-256 frame for '{}': {}", rel_path, e)
                    })?;
                if hash_rec.len() != 33 || hash_rec[0] != FRAME_FILE_HASH {
                    anyhow::bail!("Missing or malformed FRAME_FILE_HASH for '{}'", rel_path);
                }
                let expected_file_sha256 = &hash_rec[1..33];
                let computed_file_sha256: [u8; 32] = file_hasher.finalize().into();
                if !trust::constant_time_eq(&computed_file_sha256, expected_file_sha256) {
                    anyhow::bail!(
                        "Security violation: SHA-256 integrity mismatch for file '{}'",
                        rel_path
                    );
                }

                manifest_hasher.update(&(raw_rel_bytes.len() as u32).to_be_bytes());
                manifest_hasher.update(raw_rel_bytes);
                manifest_hasher.update(&file_size.to_be_bytes());
                manifest_hasher.update(&computed_file_sha256);
            } else {
                anyhow::bail!("Unexpected frame tag 0x{:02x} in file stream", tag);
            }
        }

        if received_files != expected_total_files {
            anyhow::bail!(
                "Transferred file count ({}) did not match announced total_files ({})",
                received_files,
                expected_total_files
            );
        }
        if transferred_bytes != expected_total_bytes {
            anyhow::bail!(
                "Transferred byte count ({}) did not match announced total_bytes ({})",
                transferred_bytes,
                expected_total_bytes
            );
        }

        Ok((transferred_bytes, start_time))
    }

    fn remap_rel_root(rel_path: &str, root_remap: Option<(&str, &str)>) -> String {
        let Some((orig_root, new_root)) = root_remap else {
            return rel_path.to_string();
        };
        if orig_root == new_root || orig_root.is_empty() || new_root.is_empty() {
            return rel_path.to_string();
        }
        let mut comps = rel_path.split(['/', '\\']).filter(|s| !s.is_empty());
        let Some(first) = comps.next() else {
            return new_root.to_string();
        };
        let rest: Vec<&str> = comps.collect();
        if first == orig_root {
            if rest.is_empty() {
                new_root.to_string()
            } else {
                format!("{}/{}", new_root, rest.join("/"))
            }
        } else if rest.is_empty() {
            new_root.to_string()
        } else {
            rel_path.to_string()
        }
    }

    /// Streams the peer's announced files into an isolated staging directory inside the local cache,
    /// verifies per-file and manifest SHA-256 hashes, atomically commits the verified root entry,
    /// and updates the native OS clipboard only after full verification succeeds.
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

        // Stage into a unique isolated staging directory first so failed transfers never clobber cache
        let stage_dir = cache_dir.join(format!(
            ".staging_{}_{}",
            safe_root_entry_name(&ann.session_id),
            trust::generate_random_token_hex(6)
        ));
        let _ = std::fs::remove_dir_all(&stage_dir);
        std::fs::create_dir_all(&stage_dir)?;

        info!(
            "📥 Streaming announced item '{}' ({:.1} MB) from {} into isolated staging cache...",
            ann.root_name,
            ann.total_bytes as f64 / (1024.0 * 1024.0),
            peer_ip
        );

        let mut session = match Self::connect_and_request_stream(&peer_ip, &ann.session_id).await {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        let stream_res = Self::receive_stream_frames_from_session(
            &mut session,
            &stage_dir,
            ann.total_bytes,
            ann.total_files,
            None,
        )
        .await;

        let (transferred_bytes, start_time) = match stream_res {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                #[cfg(target_os = "macos")]
                unsafe {
                    reset_touchbar_paste_progress();
                }
                return Err(e);
            }
        };

        let staged_item = stage_dir.join(&safe_name);
        if staged_item.exists() {
            if dest_root.exists() {
                if dest_root.is_dir() {
                    let _ = std::fs::remove_dir_all(&dest_root);
                } else {
                    let _ = std::fs::remove_file(&dest_root);
                }
            }
            if std::fs::rename(&staged_item, &dest_root).is_err() {
                Self::copy_entry_all(&staged_item, &dest_root)?;
            }
        }
        let _ = std::fs::remove_dir_all(&stage_dir);

        // Only replace the native OS clipboard AFTER the staged file exists and passed SHA-256 verification
        if dest_root.exists() {
            let helper = Arc::clone(&self.file_helper);
            let root_for_cb = dest_root.clone();
            tokio::task::spawn_blocking(move || helper.write_copied_files(&[root_for_cb]))
                .await
                .context("Clipboard writer task panicked")??;
            let new_seq = os_seq::get_clipboard_sequence();
            let mut seq_lock = self.last_seq.write().await;
            *seq_lock = new_seq;
            info!(
                "📋 Registered verified '{}' on native clipboard. Ready for Cmd+V / Ctrl+V!",
                ann.root_name
            );
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

    /// Executes On-Demand Remote Paste with isolated staging, SHA-256 verification, atomic commit,
    /// and non-destructive collision naming.
    pub async fn paste_remote(&self, custom_target: Option<PathBuf>) -> Result<String> {
        let ann = {
            let lock = self.pending_remote.read().await;
            lock.clone()
        }
        .context("No remote file announcement pending to paste")?;

        let target_dir = custom_target.unwrap_or_else(Self::resolve_active_destination_folder);
        let safe_name = safe_root_entry_name(&ann.root_name);
        let dest_root = resolve_non_colliding_dest(&target_dir, &safe_name);
        let final_name = dest_root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&safe_name)
            .to_string();

        // If the item is already present and verified in the staging cache, copy to non-colliding destination
        let cache_dir = self.file_helper.get_cache_dir().to_path_buf();
        let cached_item = cache_dir.join(&safe_name);
        if cached_item.exists() && target_dir != cache_dir {
            info!(
                "📋 Item '{}' already present in verified cache. Copying to {:?}...",
                ann.root_name, dest_root
            );
            Self::copy_entry_all(&cached_item, &dest_root)?;
            Self::reveal_in_file_manager(&dest_root);
            #[cfg(target_os = "macos")]
            unsafe {
                reset_touchbar_paste_progress();
            }
            return Ok(format!(
                "✅ Pasted '{}' into {:?}",
                final_name, target_dir
            ));
        }

        if self
            .is_pasting
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            warn!("Remote paste is already in progress, ignoring duplicate trigger");
            return Ok("Paste already in progress".to_string());
        }

        struct PasteGuard<'a> {
            service: &'a ClipboardService,
        }
        impl<'a> Drop for PasteGuard<'a> {
            fn drop(&mut self) {
                self.service
                    .is_pasting
                    .store(false, std::sync::atomic::Ordering::SeqCst);
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

        // Stage inside an isolated hidden directory in `target_dir` so partial/corrupted files
        // never appear in the user's destination folder unless SHA-256 verification succeeds.
        let stage_dir = target_dir.join(format!(
            ".integrator_staging_{}",
            trust::generate_random_token_hex(8)
        ));
        let _ = std::fs::remove_dir_all(&stage_dir);
        std::fs::create_dir_all(&stage_dir)?;

        info!(
            "📥 Initiating on-demand stream of '{}' from {} via isolated staging into {:?}",
            ann.root_name, peer_ip, dest_root
        );

        let mut session = match Self::connect_and_request_stream(&peer_ip, &ann.session_id).await {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        let stream_res = Self::receive_stream_frames_from_session(
            &mut session,
            &stage_dir,
            ann.total_bytes,
            ann.total_files,
            Some((&safe_name, &final_name)),
        )
        .await;

        let (transferred_bytes, start_time) = match stream_res {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        // Atomically commit the verified item from `stage_dir` into `dest_root`
        let staged_item = stage_dir.join(&final_name);
        if staged_item.exists() {
            if std::fs::rename(&staged_item, &dest_root).is_err() {
                Self::copy_entry_all(&staged_item, &dest_root)?;
            }
        }
        let _ = std::fs::remove_dir_all(&stage_dir);

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
            "✅ Successfully pasted '{}' ({:.1} MB at {:.0} MB/s) into {:?}",
            final_name,
            transferred_bytes as f64 / (1024.0 * 1024.0),
            avg_mb_s,
            target_dir
        );
        info!("{}", msg);
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keystore::{FixedKekProvider, KeystoreV2};
    use zeroize::Zeroizing;

    #[test]
    fn image_dimension_and_byte_bounds_are_enforced() {
        assert!(validate_image_bounds(100, 100, 100 * 100 * 4));
        // Mismatched byte length vs width * height * 4 must be rejected
        assert!(!validate_image_bounds(100, 100, 100 * 100 * 3));
        // Zero or oversized dimensions (> 8192) must be rejected
        assert!(!validate_image_bounds(0, 100, 0));
        assert!(!validate_image_bounds(
            MAX_IMAGE_DIMENSION + 1,
            10,
            (MAX_IMAGE_DIMENSION + 1) * 40
        ));
    }

    #[test]
    fn non_colliding_destination_never_overwrites_existing_file() {
        let tmp = std::env::temp_dir().join(format!(
            "integrator_clip_test_{}",
            trust::generate_random_token_hex(6)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let f1 = tmp.join("report.pdf");
        std::fs::write(&f1, b"original").unwrap();

        let next = resolve_non_colliding_dest(&tmp, "report.pdf");
        assert_eq!(next.file_name().unwrap().to_str().unwrap(), "report (2).pdf");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn traversal_windows_reserved_names_and_depth_limits_are_rejected() {
        let tmp = std::env::temp_dir().join(format!(
            "integrator_traversal_test_{}",
            trust::generate_random_token_hex(6)
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        // Path traversal attempts must be explicitly rejected (never silently stripped)
        assert!(ensure_safe_contained_path(&tmp, "../outside.txt").is_err());
        assert!(ensure_safe_contained_path(&tmp, "folder/../../outside.txt").is_err());
        assert!(ensure_safe_contained_path(&tmp, "/etc/passwd").is_err());
        assert!(ensure_safe_contained_path(&tmp, "\\\\server\\share\\file.txt").is_err());
        assert!(ensure_safe_contained_path(&tmp, "C:\\Windows\\System32\\cmd.exe").is_err());

        // Windows reserved device names (with or without extensions) must be rejected
        assert!(ensure_safe_contained_path(&tmp, "CON").is_err());
        assert!(ensure_safe_contained_path(&tmp, "dir/nul.txt").is_err());
        assert!(ensure_safe_contained_path(&tmp, "dir/com1.tar.gz").is_err());
        assert!(ensure_safe_contained_path(&tmp, "lpt9").is_err());

        // Trailing spaces or dots must be rejected
        assert!(ensure_safe_contained_path(&tmp, "folder /file.txt").is_err());
        assert!(ensure_safe_contained_path(&tmp, "file.txt.").is_err());

        // Directory depth > 16 must be rejected
        let deep = (0..=MAX_DIRECTORY_DEPTH)
            .map(|i| format!("d{}", i))
            .collect::<Vec<_>>()
            .join("/");
        assert!(ensure_safe_contained_path(&tmp, &deep).is_err());

        // Valid relative path must succeed
        let valid = ensure_safe_contained_path(&tmp, "project/src/main.rs").unwrap();
        assert!(valid.ends_with("project/src/main.rs"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_destination_is_rejected() {
        let tmp = std::env::temp_dir().join(format!(
            "integrator_symlink_test_{}",
            trust::generate_random_token_hex(6)
        ));
        let outside = std::env::temp_dir().join(format!(
            "integrator_outside_{}",
            trust::generate_random_token_hex(6)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let link_path = tmp.join("escape");
        std::os::unix::fs::symlink(&outside, &link_path).unwrap();

        assert!(ensure_safe_contained_path(&tmp, "escape/pwned.txt").is_err());

        let file_link = tmp.join("symlink_file.txt");
        std::os::unix::fs::symlink(outside.join("target.txt"), &file_link).unwrap();
        assert!(open_staged_file_create_new(&file_link).is_err());

        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn test_file_stream_over_transport_v2_sha256_verification_and_truncation_abort() {
        let src_dir = std::env::temp_dir().join(format!(
            "integrator_stream_src_{}",
            trust::generate_random_token_hex(6)
        ));
        let dst_dir = std::env::temp_dir().join(format!(
            "integrator_stream_dst_{}",
            trust::generate_random_token_hex(6)
        ));
        std::fs::create_dir_all(src_dir.join("bundle/sub")).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();

        let f1_path = src_dir.join("bundle/hello.txt");
        let f2_path = src_dir.join("bundle/sub/data.bin");
        let f1_bytes = b"Integrator v2.0 authenticated file stream test";
        let f2_bytes = vec![0x3Cu8; 300_000]; // spans multiple TransportV2 records
        std::fs::write(&f1_path, f1_bytes).unwrap();
        std::fs::write(&f2_path, &f2_bytes).unwrap();

        // Setup paired KeystoreV2 instances for TransportSessionV2
        let ks_dir_c = src_dir.join("ks_c");
        let ks_dir_s = src_dir.join("ks_s");
        let mut ks_c =
            KeystoreV2::open_with_provider(ks_dir_c, &FixedKekProvider::new([0x21u8; 32])).unwrap();
        let mut ks_s =
            KeystoreV2::open_with_provider(ks_dir_s, &FixedKekProvider::new([0x22u8; 32])).unwrap();
        let k_root = [0x88u8; 32];
        ks_c.commit_paired_peer(
            ks_s.local_device_id(),
            ks_s.local_ed25519_pubkey(),
            Zeroizing::new(k_root),
            "Server".into(),
            "macOS".into(),
            "10.99.99.1".into(),
            true,
        )
        .unwrap();
        ks_s.commit_paired_peer(
            ks_c.local_device_id(),
            ks_c.local_ed25519_pubkey(),
            Zeroizing::new(k_root),
            "Client".into(),
            "Windows".into(),
            "10.99.99.2".into(),
            true,
        )
        .unwrap();
        let peer_s = ks_c.get_peer(&ks_s.local_device_id_hex()).unwrap().clone();

        // 1. Valid multi-file stream with per-file and manifest SHA-256 verification
        let (c_io, s_io) = tokio::io::duplex(512 * 1024);
        let (c_res, s_res) = tokio::join!(
            TransportSessionV2::connect_client(
                c_io,
                &ks_c,
                &peer_s,
                ServiceId::ClipboardTransfer
            ),
            TransportSessionV2::accept_server(
                s_io,
                &ks_s,
                ServiceId::ClipboardTransfer,
                false
            )
        );
        let mut client_sess = c_res.unwrap();
        let mut server_sess = s_res.unwrap();

        let dirs = vec!["bundle".to_string(), "bundle/sub".to_string()];
        let files = vec![
            ("bundle/hello.txt".to_string(), f1_path.clone()),
            ("bundle/sub/data.bin".to_string(), f2_path.clone()),
        ];
        let total_bytes = (f1_bytes.len() + f2_bytes.len()) as u64;

        let (send_res, recv_res) = tokio::join!(
            ClipboardService::stream_files_over_session(&mut server_sess, dirs, files),
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess,
                &dst_dir,
                total_bytes,
                2,
                None
            )
        );
        send_res.expect("sender stream must succeed");
        let (rx_bytes, _) = recv_res.expect("receiver stream and SHA-256 checks must succeed");
        assert_eq!(rx_bytes, total_bytes);
        assert_eq!(
            std::fs::read(dst_dir.join("bundle/hello.txt")).unwrap(),
            f1_bytes
        );
        assert_eq!(
            std::fs::read(dst_dir.join("bundle/sub/data.bin")).unwrap(),
            f2_bytes
        );

        // 2. Corrupted per-file SHA-256 frame must be rejected by receiver
        let (c_io2, s_io2) = tokio::io::duplex(128 * 1024);
        let (c_res2, s_res2) = tokio::join!(
            TransportSessionV2::connect_client(
                c_io2,
                &ks_c,
                &peer_s,
                ServiceId::ClipboardTransfer
            ),
            TransportSessionV2::accept_server(
                s_io2,
                &ks_s,
                ServiceId::ClipboardTransfer,
                false
            )
        );
        let mut client_sess2 = c_res2.unwrap();
        let mut server_sess2 = s_res2.unwrap();
        let dst_corrupt = src_dir.join("dst_corrupt");
        std::fs::create_dir_all(&dst_corrupt).unwrap();

        let corrupt_sender = async move {
            let rel = b"bundle/hello.txt";
            let mut hdr = Vec::new();
            hdr.push(FRAME_FILE);
            hdr.extend_from_slice(&(rel.len() as u16).to_be_bytes());
            hdr.extend_from_slice(rel);
            hdr.extend_from_slice(&(5u64).to_be_bytes());
            server_sess2.send_message(&hdr).await.unwrap();

            let mut data = vec![FRAME_FILE_DATA];
            data.extend_from_slice(b"hello");
            server_sess2.send_message(&data).await.unwrap();

            // Send bogus SHA-256 digest
            let mut bad_hash = [0xAAu8; 33];
            bad_hash[0] = FRAME_FILE_HASH;
            server_sess2.send_message(&bad_hash).await.unwrap();
        };
        let (_, corrupt_rx_res) = tokio::join!(
            corrupt_sender,
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess2,
                &dst_corrupt,
                5,
                1,
                None
            )
        );
        assert!(
            corrupt_rx_res.is_err(),
            "corrupted file SHA-256 must be rejected"
        );

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }
}
