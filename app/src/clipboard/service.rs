//! # Universal Clipboard Service & Zero-RAM Streaming Engine
//!
//! ## 1. Module Purpose & Scope
//! The `ClipboardService` provides secure, full-duplex, mutually authenticated clipboard
//! synchronization across macOS and Windows 10/11 workstations.
//!
//! Operating over `TransportSessionV2` (`ServiceId::ClipboardSync` on TCP port `CLIPBOARD_PORT = 58285`),
//! the service synchronizes UTF-8 plain text, uncompressed RGBA bitmaps, and entire directory
//! trees with zero memory-buffering overhead.
//!
//! ### Core Subsystem Responsibilities:
//! 1. **Lightweight Change Polling**: Continuously polls `os_seq::get_clipboard_sequence()` every
//!    250ms. Expensive OS clipboard reads and SHA-256 hashing occur only when the native sequence
//!    number increments.
//! 2. **Multi-Format Ingestion & Negotiation**:
//!    - Text strings up to 10 MiB are hashed and synchronized instantly upon copy.
//!    - Bitmaps up to 64 MiB (max 8192x8192 px) are transmitted inline (icons) or streamed as binary
//!      RGBA chunks without base64 overhead.
//!    - Multi-gigabyte file hierarchies (up to 32 GiB total) are advertised via lightweight
//!      `LazyAnnouncement` metadata, deferring actual data transmission until the user explicitly
//!      triggers Paste (`Cmd+V` / `Ctrl+V`) or finishes an edge drag-and-drop.
//! 3. **Isolated Staging & Atomic Commits**:
//!    - Incoming files are streamed into private, isolated temporary directories (`0o700` on Unix).
//!    - Each file is verified against its individual SHA-256 digest (`FRAME_FILE_HASH`) during transfer.
//!    - Once the entire session completes (`FRAME_END`), the staging directory is atomically promoted
//!      into the local clipboard cache and registered with the native OS clipboard (`NSPasteboard` / `CF_HDROP`).
//! 4. **Hardware & TouchBar Telemetry**:
//!    - Drives the TouchBar HUD on MacBook Pro models (`touchbar_hud.swift`), displaying live
//!      transfer progress percentages and MB/s throughput during multi-gigabyte transfers.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                          ClipboardService Architecture & Call Flow                     │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                 Integrator Core Engine                  │
//!              │             (src/core.rs / src/main.rs)                 │
//!              └────────────────────────────┬────────────────────────────┘
//!                                           │ Instantiates & Supervises
//!                                           ▼
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                    ClipboardService                     │
//!              │  - Sequence Watcher Loop (250ms interval)               │
//!              │  - Format Negotiator (Text, Image, LazyAnnouncement)   │
//!              │  - Staging Pipeline & Atomic Cache Promotion            │
//!              └───────┬─────────────────┬───────────────────┬───────────┘
//!                      │                 │                   │
//!           Outbound   │     Inbound     │                   │ Progress Telemetry
//!           Streams    │     Streams     │                   │
//!                      ▼                 ▼                   ▼
//!       ┌───────────────────────────────┐     ┌──────────────────────────────┐
//!       │      TransportSessionV2       │     │     touchbar_hud.swift       │
//!       │  (ServiceId::ClipboardSync)   │     │  - Live Transfer Progress %  │
//!       │   ChaCha20-Poly1305 over TCP  │     │  - MB/s Streaming Velocity   │
//!       └──────────────┬────────────────┘     └──────────────────────────────┘
//!                      │ Port 58285
//!                      ▼
//!             Remote Peer Workstation
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Instantiates `ClipboardService::new`, assigns `CLIPBOARD_INSTANCE`, spawns the
//!   sequence watcher task, and calls `shutdown()`.
//! - Native Keyboard Shortcut Interceptors: Invoke `trigger_rust_remote_paste()` when the user
//!   presses `Cmd+V` / `Ctrl+V` while a remote lazy file transfer is pending.
//! - KVM Engine (`src/kvm/service.rs`): Reuses `ClipboardService` staging and streaming helpers
//!   for drag-and-drop operations.
//!
//! ### Downstream Callees:
//! - `super::protocol`: Wire message formats and frame markers.
//! - `super::os_seq`: OS sequence counter queries.
//! - `super::file_helper::FileClipboardHelper`: Native OS file clipboard access (`NSPasteboard` / `CF_HDROP`).
//! - `arboard::Clipboard`: Cross-platform plain text and bitmap read/write operations.
//! - `crate::trust`: Mutually authenticated transport session establishment.
//! - `crate::security::transport::TransportSessionV2`: Encrypted bi-directional framing over port 58285.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Multi-Thread Runtime**: Manages TCP connection acceptance, handshake timeouts,
//!   and asynchronous file streaming loops.
//! - **Connection Limits & Semaphores**:
//!   - `MAX_PRE_AUTH_CLIP_CONNS = 16`: Throttles unauthenticated TCP connection bursts.
//!   - `MAX_POST_AUTH_CLIP_CONNS = 8`: Bounds active concurrent transfer sessions.
//! - **Blocking I/O Offloading**: Heavy disk reads and OS clipboard operations are dispatched to
//!   `tokio::task::spawn_blocking` to prevent starving async network worker threads.
//!
//! ## 4. Security & Safety Invariants
//! - **Strict Mutual Authentication**: Operates exclusively over `TransportSessionV2` validated
//!   against pinned Ed25519 identity keys. Zero IP-based bypass or cleartext transmission is permitted.
//! - **Path Traversal & Symlink Immunity**: Rejects absolute paths, Windows drive letters (`C:\`),
//!   and `..` components. Refuses to follow or create symlinks in staging directories.
//! - **Digest Verification**: Incoming files undergo two-layer verification: per-file SHA-256 validation
//!   (`FRAME_FILE_HASH`) and session-wide content verification. Missing or mismatched hashes cause
//!   immediate abort and deletion of the temporary staging directory.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::config::{CLIPBOARD_PORT, DRAG_STAGING_DIR_NAME};
#[cfg(target_os = "macos")]
use crate::config::MACOS_OSASCRIPT_BIN;
use crate::discovery::DiscoveryManager;
use crate::security::transport::{ServiceId, TransportSessionV2};
use crate::trust;
use super::file_helper::FileClipboardHelper;
use super::os_seq;
use super::protocol::{
    ClipboardMessage, ClipboardPayload, LazyAnnouncement, StreamRequest,
    FRAME_DIR, FRAME_END, FRAME_FILE, FRAME_FILE_DATA, FRAME_FILE_HASH, FRAME_IMAGE_DATA,
    MAX_AUTO_STAGE_BYTES, MAX_CLIPBOARD_HEADER_BYTES, MAX_DIRECTORY_DEPTH, MAX_ROOTS,
    MAX_SINGLE_FILE_BYTES, MAX_TEXT_CHARS, MAX_TOTAL_TRANSFER_BYTES, MAX_TRANSFER_FILES,
};

const MAX_PRE_AUTH_CLIP_CONNS: usize = 16;
const MAX_POST_AUTH_CLIP_CONNS: usize = 8;
const CLIP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const STREAM_CHUNK_SIZE: usize = 256 * 1024; // 256 KiB high-throughput AEAD chunk
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum age before orphaned staging directories are swept on startup or announcement (1 hour).
const STALE_STAGING_DIR_MAX_AGE: Duration = Duration::from_secs(3600);

/// Backoff delay after a clipboard TCP listener `accept()` error before retrying (500 ms).
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Polling interval for lightweight OS clipboard sequence monitoring (120 ms).
const CLIPBOARD_MONITOR_POLL_INTERVAL: Duration = Duration::from_millis(120);

/// Outbound TCP + `TransportV2` connection timeout for clipboard transfers (5 seconds).
const CLIPBOARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of concurrent pending cross-screen drag sessions retained in memory (16 sessions).
const MAX_CONCURRENT_DRAG_SESSIONS: usize = 16;

/// Minimum interval between Touch Bar paste progress HUD updates (100 ms).
const TOUCHBAR_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum number of SHA-256-verified clipboard cache entries retained in the LRU queue (8 entries).
const MAX_VERIFIED_CACHE_ENTRIES: usize = 8;

#[cfg(target_os = "macos")]
extern "C" {
    pub fn init_shortcut_interceptor();
    pub fn set_has_pending_remote_file(pending: bool);
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
    super::protocol::validate_image_bounds(width, height, rgba_len).is_some()
}

fn is_valid_hex_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= 128
        && session_id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn format_socket_target(ip: &str, port: u16) -> String {
    let trimmed = ip.trim();
    if let Ok(parsed) = trimmed.parse::<IpAddr>() {
        return std::net::SocketAddr::new(parsed, port).to_string();
    }
    if trimmed.contains(':') && !trimmed.starts_with('[') {
        format!("[{}]:{}", trimmed, port)
    } else {
        format!("{}:{}", trimmed, port)
    }
}

fn create_private_dir_no_symlink(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                anyhow::bail!(
                    "Security violation: '{}' is a symlink or non-directory",
                    dir.display()
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut db = std::fs::DirBuilder::new();
                db.mode(0o700);
                db.create(dir)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir(dir)?;
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Ensures every directory component from `base` down to `target_dir` exists as a real
/// non-symlink directory, creating missing levels with private permissions.
fn ensure_dir_no_symlinks(base: &Path, target_dir: &Path) -> Result<()> {
    create_private_dir_no_symlink(base)?;
    let canon_base = std::fs::canonicalize(base)
        .with_context(|| format!("Failed to canonicalize base directory '{}'", base.display()))?;
    if target_dir == base || target_dir == canon_base {
        return Ok(());
    }
    let rel = target_dir
        .strip_prefix(&canon_base)
        .or_else(|_| target_dir.strip_prefix(base))
        .with_context(|| {
            format!(
                "Target directory '{}' is outside base '{}'",
                target_dir.display(),
                base.display()
            )
        })?;
    let mut cur = canon_base;
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                cur.push(seg);
                create_private_dir_no_symlink(&cur)?;
            }
            std::path::Component::CurDir => {}
            _ => anyhow::bail!(
                "Unsafe path component in directory path '{}'",
                target_dir.display()
            ),
        }
    }
    Ok(())
}

fn open_source_file_no_follow(path: &Path) -> Result<File> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to stat source path {:?}", path))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        anyhow::bail!(
            "Security violation: source {:?} is a symlink or non-file",
            path
        );
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
        .with_context(|| format!("Failed to open source file {:?}", path))
}

fn move_staged_entry(src: &Path, dst: &Path) -> Result<()> {
    let src_meta = std::fs::symlink_metadata(src)
        .with_context(|| format!("Staged entry missing: {:?}", src))?;
    if src_meta.file_type().is_symlink() {
        anyhow::bail!("Security violation: staged entry {:?} is a symlink", src);
    }
    if let Ok(dst_meta) = std::fs::symlink_metadata(dst) {
        if dst_meta.file_type().is_symlink() {
            anyhow::bail!("Security violation: destination {:?} is a symlink", dst);
        }
        anyhow::bail!("Destination {:?} already exists before commit", dst);
    }
    if std::fs::rename(src, dst).is_err() {
        ClipboardService::copy_entry_all(src, dst)?;
        if src_meta.is_dir() {
            let _ = std::fs::remove_dir_all(src);
        } else {
            let _ = std::fs::remove_file(src);
        }
    }
    Ok(())
}

fn resolve_unique_root_name(
    used: &mut std::collections::HashSet<String>,
    base_name: &str,
) -> String {
    if used.insert(base_name.to_string()) {
        return base_name.to_string();
    }
    let path_obj = Path::new(base_name);
    let stem = path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(base_name);
    let ext = path_obj.extension().and_then(|e| e.to_str());
    for idx in 2..=10_000 {
        let candidate = match ext {
            Some(e) if !e.is_empty() => format!("{} ({}).{}", stem, idx, e),
            _ => format!("{} ({})", stem, idx),
        };
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    let fallback = format!("{}_{}", base_name, trust::generate_random_token_hex(4));
    used.insert(fallback.clone());
    fallback
}

fn sweep_staging_dir_entries(parent: &Path, prefixes: &[&str], max_age: Duration) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !prefixes.iter().any(|pref| name.starts_with(pref)) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&p) {
            if meta.file_type().is_symlink() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if now.duration_since(mtime).unwrap_or_default() > max_age {
                if meta.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                } else {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
}

fn cleanup_orphaned_staging_dirs(cache_dir: &Path) {
    sweep_staging_dir_entries(
        cache_dir,
        &[".staging_", ".integrator_staging_"],
        STALE_STAGING_DIR_MAX_AGE,
    );
    let drag_root = crate::system_info::app_data_dir().join(DRAG_STAGING_DIR_NAME);
    sweep_staging_dir_entries(&drag_root, &["drag_"], STALE_STAGING_DIR_MAX_AGE);
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
    pub top_entries: Vec<String>,
}

#[derive(Clone, Debug)]
struct VerifiedCacheEntry {
    session_id: String,
    manifest_hash: [u8; 32],
    session_dir: PathBuf,
    roots: Vec<String>,
}

#[derive(Clone)]
pub struct ClipboardService {
    discovery: DiscoveryManager,
    last_hash: Arc<RwLock<String>>,
    last_seq: Arc<RwLock<i64>>,
    file_helper: Arc<FileClipboardHelper>,
    pending_local: Arc<RwLock<Option<LocalPendingCopy>>>,
    pending_remote: Arc<RwLock<Option<LazyAnnouncement>>>,
    pending_drag_sessions: Arc<RwLock<HashMap<String, LocalPendingCopy>>>,
    pending_drag_order: Arc<RwLock<VecDeque<String>>>,
    verified_cache: Arc<RwLock<VecDeque<VerifiedCacheEntry>>>,
    last_remote_ip: Arc<RwLock<Option<IpAddr>>>,
    is_pasting: Arc<std::sync::atomic::AtomicBool>,
    features: Arc<OnceLock<Arc<crate::features::FeatureManager>>>,
}

impl ClipboardService {
    pub fn new(discovery: DiscoveryManager) -> Result<Self> {
        let file_helper = Arc::new(FileClipboardHelper::new()?);
        cleanup_orphaned_staging_dirs(file_helper.get_cache_dir());
        let initial_seq = os_seq::get_clipboard_sequence();
        let service = Self {
            discovery,
            last_hash: Arc::new(RwLock::new(String::new())),
            last_seq: Arc::new(RwLock::new(initial_seq)),
            file_helper,
            pending_local: Arc::new(RwLock::new(None)),
            pending_remote: Arc::new(RwLock::new(None)),
            pending_drag_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_drag_order: Arc::new(RwLock::new(VecDeque::new())),
            verified_cache: Arc::new(RwLock::new(VecDeque::new())),
            last_remote_ip: Arc::new(RwLock::new(None)),
            is_pasting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            features: Arc::new(OnceLock::new()),
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = TOKIO_HANDLE.set(handle);
        }

        let _ = CLIPBOARD_INSTANCE.set(service.clone());
        Ok(service)
    }

    pub fn set_feature_manager(&self, fm: Arc<crate::features::FeatureManager>) {
        let _ = self.features.set(fm);
    }

    fn is_clipboard_enabled(&self) -> bool {
        self.features
            .get()
            .map(|f| f.is_enabled("clipboard"))
            .unwrap_or(true)
    }

    fn is_dragdrop_enabled(&self) -> bool {
        self.features
            .get()
            .map(|f| f.is_enabled("dragdrop"))
            .unwrap_or(true)
    }

    pub async fn clear_pending_state(&self) {
        {
            let mut lock = self.pending_remote.write().await;
            *lock = None;
        }
        {
            let mut lock = self.pending_local.write().await;
            *lock = None;
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

        // 1. Spawn TCP Receiver with separate pre-auth and post-auth semaphores + handshake timeout
        let s_clone = self.clone();
        let pre_auth_limiter = Arc::new(Semaphore::new(MAX_PRE_AUTH_CLIP_CONNS));
        let post_auth_limiter = Arc::new(Semaphore::new(MAX_POST_AUTH_CLIP_CONNS));
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let Ok(pre_permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned() else {
                            warn!(
                                "🚫 Dropped clipboard connection from {}: pre-auth limit ({}) reached",
                                addr, MAX_PRE_AUTH_CLIP_CONNS
                            );
                            drop(socket);
                            continue;
                        };
                        let handler = s_clone.clone();
                        let post_lim = Arc::clone(&post_auth_limiter);
                        tokio::spawn(async move {
                            debug!("Incoming clipboard connection from {}", addr);
                            if let Err(e) = handler
                                .handle_incoming_guarded(socket, addr, pre_permit, post_lim)
                                .await
                            {
                                warn!("Error handling clipboard transfer from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Clipboard TCP listener accept error: {}", e);
                        sleep(ACCEPT_ERROR_RETRY_DELAY).await;
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

    async fn apply_remote_image(
        &self,
        peer_addr: SocketAddr,
        expected_hash: &str,
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    ) -> Result<()> {
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
        if expected_hash.is_empty()
            || !trust::constant_time_eq(computed_hash.as_bytes(), expected_hash.as_bytes())
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

        let new_seq = tokio::task::spawn_blocking(move || -> Option<i64> {
            let mut cb = Clipboard::new().ok()?;
            let img_data = ImageData {
                width,
                height,
                bytes: rgba.into(),
            };
            cb.set_image(img_data).ok()?;
            let seq = os_seq::get_clipboard_sequence();
            (seq >= 0).then_some(seq)
        })
        .await
        .unwrap_or(None);

        if let Some(seq) = new_seq {
            let mut seq_lock = self.last_seq.write().await;
            *seq_lock = seq;
        }
        Ok(())
    }

    /// Authenticates incoming `TransportSessionV2` under `pre_permit` + `CLIP_HANDSHAKE_TIMEOUT`,
    /// then swaps into the post-auth concurrency pool before dispatching payloads.
    async fn handle_incoming_guarded(
        &self,
        socket: TcpStream,
        peer_addr: SocketAddr,
        pre_permit: tokio::sync::OwnedSemaphorePermit,
        post_limiter: Arc<Semaphore>,
    ) -> Result<()> {
        let _ = socket.set_nodelay(true);
        let mut session = tokio::time::timeout(
            CLIP_HANDSHAKE_TIMEOUT,
            trust::accept_transport_from_stream(
                socket,
                peer_addr.ip(),
                None,
                ServiceId::ClipboardTransfer,
            ),
        )
        .await
        .context("Timed out during Clipboard TransportV2 handshake")?
        .map_err(|e| anyhow::anyhow!("Clipboard TransportV2 handshake rejected: {}", e))?;

        drop(pre_permit);
        let _post_permit = post_limiter
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("Post-auth clipboard concurrency limit reached"))?;

        let plaintext = tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.recv_chunked_payload(MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .context("Timed out reading clipboard message over TransportV2")?
        .map_err(|e| anyhow::anyhow!("Failed reading clipboard message over TransportV2: {}", e))?;

        let msg: ClipboardMessage = serde_json::from_slice(&plaintext)?;

        let allow_clipboard = self.is_clipboard_enabled();
        let allow_dragdrop = self.is_dragdrop_enabled();

        match msg.payload {
            ClipboardPayload::Text(text) => {
                if !allow_clipboard {
                    debug!("Ignoring remote clipboard text while Universal Clipboard/KVM is disabled");
                    return Ok(());
                }
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

                let new_seq = tokio::task::spawn_blocking(move || -> Option<i64> {
                    let mut cb = Clipboard::new().ok()?;
                    cb.set_text(text).ok()?;
                    let seq = os_seq::get_clipboard_sequence();
                    (seq >= 0).then_some(seq)
                })
                .await
                .unwrap_or(None);

                if let Some(seq) = new_seq {
                    let mut seq_lock = self.last_seq.write().await;
                    *seq_lock = seq;
                }
            }
            ClipboardPayload::Image {
                width,
                height,
                rgba,
            } => {
                if !allow_clipboard {
                    debug!("Ignoring remote clipboard image while Universal Clipboard/KVM is disabled");
                    return Ok(());
                }
                self.apply_remote_image(peer_addr, &msg.hash, width, height, rgba)
                    .await?;
            }
            ClipboardPayload::ImageStream {
                width,
                height,
                byte_len,
            } => {
                if !allow_clipboard {
                    debug!("Ignoring remote clipboard image stream while Universal Clipboard/KVM is disabled");
                    return Ok(());
                }
                let Some(expected_len) =
                    super::protocol::validate_image_bounds(width, height, byte_len)
                else {
                    warn!(
                        "🚫 Rejected remote ImageStream from {}: invalid dimensions ({}x{}, {} bytes)",
                        peer_addr, width, height, byte_len
                    );
                    return Ok(());
                };

                let mut rgba = Vec::with_capacity(expected_len);
                while rgba.len() < expected_len {
                    let rec = tokio::time::timeout(FRAME_IO_TIMEOUT, session.recv_message())
                        .await
                        .context("Timed out reading image data chunk")?
                        .map_err(|e| anyhow::anyhow!("Image stream aborted prematurely: {}", e))?;
                    if rec.len() < 2 || rec[0] != FRAME_IMAGE_DATA {
                        anyhow::bail!(
                            "Expected FRAME_IMAGE_DATA (0x05) record, got len={}",
                            rec.len()
                        );
                    }
                    let chunk = &rec[1..];
                    if rgba.len() + chunk.len() > expected_len {
                        anyhow::bail!("Image stream overflowed declared byte_len");
                    }
                    rgba.extend_from_slice(chunk);
                }

                self.apply_remote_image(peer_addr, &msg.hash, width, height, rgba)
                    .await?;
            }
            ClipboardPayload::LazyAnnouncement(ann) => {
                if !allow_clipboard {
                    debug!("Ignoring remote file announcement while Universal Clipboard/KVM is disabled");
                    return Ok(());
                }
                if !is_valid_hex_session_id(&ann.session_id)
                    || ann.total_files == 0
                    || ann.total_files > MAX_TRANSFER_FILES
                    || ann.total_bytes > MAX_TOTAL_TRANSFER_BYTES
                    || Self::effective_roots(&ann).is_err()
                {
                    warn!(
                        "🚫 Rejected invalid or out-of-bounds file announcement from {} (files={}, bytes={})",
                        peer_addr, ann.total_files, ann.total_bytes
                    );
                    return Ok(());
                }

                if !msg.hash.is_empty() && msg.hash.len() <= 128 {
                    let mut lock = self.last_hash.write().await;
                    *lock = msg.hash.clone();
                }

                let helper_prune = Arc::clone(&self.file_helper);
                tokio::task::spawn_blocking(move || {
                    helper_prune.maybe_prune_cache();
                    cleanup_orphaned_staging_dirs(helper_prune.get_cache_dir());
                });

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
                if !allow_clipboard {
                    warn!("Rejected remote clipboard stream request while Universal Clipboard/KVM is disabled");
                    return Ok(());
                }
                if !is_valid_hex_session_id(&req.session_id) {
                    warn!("Rejected malformed stream request session_id");
                    return Ok(());
                }
                let local_copy = {
                    let lock = self.pending_local.read().await;
                    lock.clone()
                };

                if let Some(copy) = local_copy {
                    if trust::constant_time_eq(
                        copy.session_id.as_bytes(),
                        req.session_id.as_bytes(),
                    ) {
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
            ClipboardPayload::RequestDragStream(req) => {
                if !allow_dragdrop {
                    warn!("Rejected cross-screen drag stream request while Drag & Drop/KVM is disabled");
                    return Ok(());
                }
                if !is_valid_hex_session_id(&req.session_id) {
                    warn!("Rejected malformed drag stream session_id");
                    return Ok(());
                }
                let matched_copy = {
                    let lock = self.pending_drag_sessions.read().await;
                    lock.iter()
                        .find(|(k, _)| {
                            trust::constant_time_eq(k.as_bytes(), req.session_id.as_bytes())
                        })
                        .map(|(_, v)| v.clone())
                };
                if let Some(copy) = matched_copy {
                    info!(
                        "🪂 Peer requested cross-screen drag stream for '{}' ({} files, {:.1} MB). Streaming over TransportV2...",
                        copy.root_name,
                        copy.total_files,
                        copy.total_bytes as f64 / (1024.0 * 1024.0)
                    );
                    Self::stream_files_over_session(&mut session, copy.directories, copy.files)
                        .await?;
                } else {
                    warn!("Rejected unknown or expired drag stream session_id");
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
            if rel.len() > 4096 || directories.len() >= MAX_TRANSFER_FILES {
                continue;
            }
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
            if rel.len() <= 4096
                && len <= MAX_SINGLE_FILE_BYTES
                && total_bytes.saturating_add(len) <= MAX_TOTAL_TRANSFER_BYTES
                && *total_files < MAX_TRANSFER_FILES
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
        enum LocalClipboardSnapshot {
            Unchanged,
            Files {
                hash_hex: String,
                copy: LocalPendingCopy,
            },
            Image {
                hash_hex: String,
                width: usize,
                height: usize,
                rgba: Vec<u8>,
            },
            Text {
                hash_hex: String,
                text: String,
            },
        }

        loop {
            sleep(CLIPBOARD_MONITOR_POLL_INTERVAL).await;

            let current_seq = tokio::task::spawn_blocking(os_seq::get_clipboard_sequence)
                .await
                .unwrap_or(-1);
            if current_seq < 0 {
                continue;
            }
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

            if !self.is_clipboard_enabled() {
                continue;
            }

            debug!("Clipboard sequence updated: {}", current_seq);

            let prev_hash = self.last_hash.read().await.clone();
            let helper = Arc::clone(&self.file_helper);
            let snapshot = tokio::task::spawn_blocking(move || -> LocalClipboardSnapshot {
                let copied_paths = helper.read_copied_files();
                if !copied_paths.is_empty() {
                    let cache_dir = helper.get_cache_dir();
                    let external_paths: Vec<PathBuf> = copied_paths
                        .into_iter()
                        .filter(|p| !p.starts_with(cache_dir))
                        .collect();
                    if external_paths.is_empty() {
                        return LocalClipboardSnapshot::Unchanged;
                    }

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
                    if hash_hex == prev_hash {
                        return LocalClipboardSnapshot::Unchanged;
                    }
                    if let Ok(copy) = ClipboardService::collect_local_entries(&external_paths) {
                        return LocalClipboardSnapshot::Files { hash_hex, copy };
                    }
                    return LocalClipboardSnapshot::Unchanged;
                }

                if let Ok(mut cb) = Clipboard::new() {
                    if let Ok(img) = cb.get_image() {
                        if validate_image_bounds(img.width, img.height, img.bytes.len()) {
                            let hash_hex = compute_image_hash(img.width, img.height, &img.bytes);
                            if hash_hex == prev_hash {
                                return LocalClipboardSnapshot::Unchanged;
                            }
                            return LocalClipboardSnapshot::Image {
                                hash_hex,
                                width: img.width,
                                height: img.height,
                                rgba: img.bytes.into_owned(),
                            };
                        }
                    }

                    if let Ok(text) = cb.get_text() {
                        if !text.is_empty() && text.len() <= MAX_TEXT_CHARS {
                            let hash_hex = compute_text_hash(&text);
                            if hash_hex == prev_hash {
                                return LocalClipboardSnapshot::Unchanged;
                            }
                            return LocalClipboardSnapshot::Text { hash_hex, text };
                        }
                    }
                }

                LocalClipboardSnapshot::Unchanged
            })
            .await
            .unwrap_or(LocalClipboardSnapshot::Unchanged);

            match snapshot {
                LocalClipboardSnapshot::Unchanged => continue,
                LocalClipboardSnapshot::Files { hash_hex, copy } => {
                    {
                        let mut hash_lock = self.last_hash.write().await;
                        *hash_lock = hash_hex.clone();
                    }
                    self.clear_remote_pending_ui_state().await;

                    let ann = LazyAnnouncement {
                        session_id: copy.session_id.clone(),
                        root_name: copy.root_name.clone(),
                        roots: copy.top_entries.clone(),
                        total_files: copy.total_files,
                        total_bytes: copy.total_bytes,
                    };
                    {
                        let mut local_lock = self.pending_local.write().await;
                        *local_lock = Some(copy);
                    }

                    if let Some(peer_ip) = self.get_authorized_peer_ip().await {
                        info!(
                            "📢 Local copy detected: '{}' ({} files, {:.1} MB). Sending announcement to {}...",
                            ann.root_name,
                            ann.total_files,
                            ann.total_bytes as f64 / (1024.0 * 1024.0),
                            peer_ip
                        );
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
                            ann.root_name, ann.total_files
                        );
                    }
                }
                LocalClipboardSnapshot::Image {
                    hash_hex,
                    width,
                    height,
                    rgba,
                } => {
                    {
                        let mut hash_lock = self.last_hash.write().await;
                        *hash_lock = hash_hex.clone();
                    }
                    self.clear_remote_pending_ui_state().await;

                    if let Some(peer_ip) = self.get_authorized_peer_ip().await {
                        info!(
                            "📤 Detected local copied image ({}x{} px). Streaming to {}...",
                            width, height, peer_ip
                        );
                        if let Err(e) =
                            Self::send_image_stream(&peer_ip, hash_hex, width, height, rgba).await
                        {
                            warn!("Failed to stream image to {}: {}", peer_ip, e);
                        }
                    } else {
                        debug!(
                            "Local image copied ({}x{} px), but no trusted peer is connected; skipping sync",
                            width, height
                        );
                    }
                }
                LocalClipboardSnapshot::Text { hash_hex, text } => {
                    {
                        let mut hash_lock = self.last_hash.write().await;
                        *hash_lock = hash_hex.clone();
                    }
                    self.clear_remote_pending_ui_state().await;

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
            }
        }
    }

    async fn clear_remote_pending_ui_state(&self) {
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
    }

    /// Sends an encrypted, mutually authenticated `ClipboardMessage` over `TransportSessionV2`.
    async fn send_payload(peer_ip: &str, msg: ClipboardMessage) -> Result<()> {
        let addr = format_socket_target(peer_ip, CLIPBOARD_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CLIPBOARD_PORT,
            ServiceId::ClipboardTransfer,
            CLIPBOARD_CONNECT_TIMEOUT,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish Clipboard TransportV2 to {}: {}", addr, e))?;

        let serialized = serde_json::to_vec(&msg)?;
        if serialized.len() > MAX_CLIPBOARD_HEADER_BYTES {
            anyhow::bail!(
                "Serialized clipboard payload ({} bytes) exceeds MAX_CLIPBOARD_HEADER_BYTES",
                serialized.len()
            );
        }
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

    /// Streams raw RGBA pixels cleanly over `TransportSessionV2` without JSON expansion bloat.
    async fn send_image_stream(
        peer_ip: &str,
        hash_hex: String,
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    ) -> Result<()> {
        let byte_len = rgba.len();
        if !validate_image_bounds(width, height, byte_len) {
            anyhow::bail!("Refusing to stream invalid RGBA image dimensions/size");
        }
        let addr = format_socket_target(peer_ip, CLIPBOARD_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CLIPBOARD_PORT,
            ServiceId::ClipboardTransfer,
            CLIPBOARD_CONNECT_TIMEOUT,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect ImageStream TransportV2 to {}: {}", addr, e))?;

        let header = ClipboardMessage {
            hash: hash_hex,
            payload: ClipboardPayload::ImageStream {
                width,
                height,
                byte_len,
            },
        };
        let serialized = serde_json::to_vec(&header)?;
        tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.send_chunked_payload(&serialized, MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .with_context(|| format!("Timed out sending image stream header to {}", addr))?
        .map_err(|e| anyhow::anyhow!("ImageStream header error to {}: {}", addr, e))?;

        let mut chunk_buf = Vec::with_capacity(STREAM_CHUNK_SIZE + 1);
        for chunk in rgba.chunks(STREAM_CHUNK_SIZE) {
            chunk_buf.clear();
            chunk_buf.push(FRAME_IMAGE_DATA);
            chunk_buf.extend_from_slice(chunk);
            tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&chunk_buf))
                .await
                .with_context(|| format!("Timed out streaming image bytes to {}", addr))?
                .map_err(|e| anyhow::anyhow!("ImageStream data error to {}: {}", addr, e))?;
        }
        info!("✅ Streamed {} bytes of RGBA image to {}", byte_len, addr);
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
                anyhow::bail!("Invalid directory path length {} in local copy", rel_bytes.len());
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
                anyhow::bail!("Invalid file path length {} in local copy", rel_bytes.len());
            }

            let mut file = open_source_file_no_follow(&abs_path)?;
            let actual_len = file
                .metadata()
                .with_context(|| format!("Failed to inspect open source file {:?}", abs_path))?
                .len();

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
            if let Ok(output) = std::process::Command::new(MACOS_OSASCRIPT_BIN)
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

    /// Reveals the pasted file or folder in Finder or File Explorer without script or shell injection.
    pub fn reveal_in_file_manager(path: &Path) {
        let path_owned = path.to_path_buf();

        #[cfg(target_os = "macos")]
        {
            let script = r#"on run argv
    if (count of argv) < 1 then return
    tell application "Finder" to reveal POSIX file (item 1 of argv)
end run"#;
            if let Ok(mut child) = std::process::Command::new(MACOS_OSASCRIPT_BIN)
                .arg("-e")
                .arg(script)
                .arg("--")
                .arg(&path_owned)
                .spawn()
            {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;

            let path_str = path_owned.to_string_lossy().to_string();
            if path_str.is_empty()
                || path_str.contains('"')
                || path_str.chars().any(|c| c.is_control())
            {
                return;
            }
            let explorer = crate::system_info::windows_root_dir().join("explorer.exe");
            let mut cmd = std::process::Command::new(explorer);
            cmd.raw_arg(format!("/select,\"{}\"", path_str));
            if let Ok(mut child) = cmd.spawn() {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = path_owned;
        }
    }

    pub(crate) fn copy_entry_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(src)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        if meta.is_dir() {
            create_private_dir_no_symlink(dst)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let path = entry.path();
                let dest_child = dst.join(entry.file_name());
                Self::copy_entry_all(&path, &dest_child)?;
            }
        } else if meta.is_file() {
            if let Some(parent) = dst.parent() {
                create_private_dir_no_symlink(parent)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }
            let mut reader = open_source_file_no_follow(src)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let mut writer = open_staged_file_create_new(dst)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            std::io::copy(&mut reader, &mut writer)?;
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
        Self::connect_and_request_stream_kind(peer_ip, session_id, false).await
    }

    async fn connect_and_request_stream_kind(
        peer_ip: &str,
        session_id: &str,
        is_drag: bool,
    ) -> Result<TransportSessionV2<TcpStream>> {
        if !is_valid_hex_session_id(session_id) {
            anyhow::bail!("Rejected invalid clipboard/drag session_id");
        }
        let addr = format_socket_target(peer_ip, CLIPBOARD_PORT);
        let mut session = trust::connect_transport_to_ip(
            peer_ip,
            CLIPBOARD_PORT,
            ServiceId::ClipboardTransfer,
            CLIPBOARD_CONNECT_TIMEOUT,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect TransportV2 to {}: {}", addr, e))?;

        let stream_req = StreamRequest {
            session_id: session_id.to_string(),
        };
        let req_msg = ClipboardMessage {
            hash: String::new(),
            payload: if is_drag {
                ClipboardPayload::RequestDragStream(stream_req)
            } else {
                ClipboardPayload::RequestStream(stream_req)
            },
        };

        let serialized = serde_json::to_vec(&req_msg)?;
        if serialized.len() > MAX_CLIPBOARD_HEADER_BYTES {
            anyhow::bail!("Serialized stream request exceeds header cap");
        }
        tokio::time::timeout(
            FRAME_IO_TIMEOUT,
            session.send_chunked_payload(&serialized, MAX_CLIPBOARD_HEADER_BYTES),
        )
        .await
        .context("Timed out sending stream request header")?
        .map_err(|e| anyhow::anyhow!("Stream request TransportV2 send error: {}", e))?;

        Ok(session)
    }

    /// Indexes local files/folders (for both clipboard copy and cross-screen drag) using shared
    /// quota, depth, length, symlink, reserved-name, and basename-collision protections.
    pub(crate) fn collect_local_entries(paths: &[PathBuf]) -> Result<LocalPendingCopy> {
        let mut first_root = String::new();
        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut top_entries = Vec::new();
        let mut used_roots = std::collections::HashSet::new();
        let mut total_bytes: u64 = 0;
        let mut total_files: usize = 0;

        for root in paths {
            if top_entries.len() >= MAX_ROOTS || total_files >= MAX_TRANSFER_FILES {
                break;
            }
            let Ok(meta) = std::fs::symlink_metadata(root) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let Some(file_name) = root.file_name() else {
                continue;
            };
            let base_name = file_name.to_string_lossy().to_string();
            if validate_single_path_component(&base_name).is_err() {
                continue;
            }
            let unique_root = resolve_unique_root_name(&mut used_roots, &base_name);
            if validate_single_path_component(&unique_root).is_err()
                || unique_root.len() > 4096
            {
                continue;
            }

            if meta.is_dir() {
                if directories.len() >= MAX_TRANSFER_FILES {
                    continue;
                }
                if first_root.is_empty() {
                    first_root = unique_root.clone();
                }
                directories.push(unique_root.clone());
                top_entries.push(unique_root.clone());
                Self::collect_dir_entries(
                    root,
                    root,
                    &unique_root,
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
                    if first_root.is_empty() {
                        first_root = unique_root.clone();
                    }
                    total_bytes += len;
                    total_files += 1;
                    top_entries.push(unique_root.clone());
                    files.push((unique_root, root.clone()));
                }
            }
        }

        if total_files == 0 || top_entries.is_empty() {
            anyhow::bail!("No valid non-symlink files found");
        }
        let root_name = if top_entries.len() > 1 {
            format!("{} (+{} items)", first_root, top_entries.len() - 1)
        } else {
            first_root
        };

        Ok(LocalPendingCopy {
            session_id: trust::generate_random_token_hex(32),
            root_name,
            total_files,
            total_bytes,
            directories,
            files,
            top_entries,
        })
    }

    pub async fn register_drag_session(&self, copy: LocalPendingCopy) {
        let mut map = self.pending_drag_sessions.write().await;
        let mut order = self.pending_drag_order.write().await;
        if map.len() >= MAX_CONCURRENT_DRAG_SESSIONS {
            while let Some(oldest) = order.pop_front() {
                if map.remove(&oldest).is_some() {
                    break;
                }
            }
        }
        order.push_back(copy.session_id.clone());
        map.insert(copy.session_id.clone(), copy);
    }

    pub async fn remove_drag_session(&self, session_id: &str) {
        let mut map = self.pending_drag_sessions.write().await;
        map.remove(session_id);
    }

    /// Streams an offered cross-screen drag session into an isolated `drag_staging/<session_id>` folder,
    /// enforcing per-file & manifest SHA-256 verification before returning the staged top-level paths.
    pub async fn stream_drag_session_to_staging(
        &self,
        peer_ip: &str,
        session_id: &str,
        expected_total_bytes: u64,
        expected_total_files: usize,
        top_entries: &[String],
    ) -> Result<(PathBuf, Vec<PathBuf>)> {
        if !self.is_dragdrop_enabled() {
            anyhow::bail!("Cross-Screen Drag & Drop is disabled");
        }
        if !is_valid_hex_session_id(session_id) {
            anyhow::bail!("Rejected invalid drag session_id");
        }
        if top_entries.is_empty() || top_entries.len() > MAX_ROOTS {
            anyhow::bail!("Rejected drag offer with invalid top-level entry count");
        }
        for entry in top_entries {
            validate_single_path_component(entry)?;
        }

        let base_dir = crate::system_info::app_data_dir();
        let staging_root = base_dir.join(DRAG_STAGING_DIR_NAME);
        ensure_dir_no_symlinks(&base_dir, &staging_root)?;
        let session_dir = staging_root.join(format!("drag_{}", session_id));
        if let Ok(meta) = std::fs::symlink_metadata(&session_dir) {
            if meta.file_type().is_symlink() {
                anyhow::bail!("Refusing symlinked drag staging directory");
            }
            let _ = std::fs::remove_dir_all(&session_dir);
        }
        ensure_dir_no_symlinks(&staging_root, &session_dir)?;

        let mut session = Self::connect_and_request_stream_kind(peer_ip, session_id, true)
            .await
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&session_dir);
                e
            })?;

        if let Err(e) = Self::receive_stream_frames_from_session(
            &mut session,
            &session_dir,
            expected_total_bytes,
            expected_total_files,
            None,
        )
        .await
        {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(e);
        }

        let mut staged_paths = Vec::with_capacity(top_entries.len());
        for entry in top_entries {
            let p = ensure_safe_contained_path(&session_dir, entry)?;
            if p.exists() {
                staged_paths.push(p);
            }
        }
        if staged_paths.is_empty() {
            let _ = std::fs::remove_dir_all(&session_dir);
            anyhow::bail!("Staged drag transfer produced no top-level files");
        }
        Ok((session_dir, staged_paths))
    }

    /// Receives and verifies directory frames, file frames, per-file SHA-256 digests, and the
    /// overall manifest SHA-256 digest into an isolated staging directory (`dest_base`).
    /// Returns `(transferred_bytes, start_time, manifest_sha256)`.
    pub(crate) async fn receive_stream_frames_from_session<S>(
        session: &mut TransportSessionV2<S>,
        dest_base: &Path,
        expected_total_bytes: u64,
        expected_total_files: usize,
        root_remap: Option<(&str, &str)>,
    ) -> Result<(u64, std::time::Instant, [u8; 32])>
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
        let mut received_dirs: usize = 0;
        let start_time = std::time::Instant::now();
        let mut last_progress_report = std::time::Instant::now();
        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(b"INTEGRATOR-FILE-MANIFEST-V2");

        let manifest_sha256: [u8; 32];
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
                manifest_sha256 = computed_manifest_sha256;
                debug!("Verified FRAME_END and manifest SHA-256 from peer");
                break;
            } else if tag == FRAME_DIR {
                received_dirs += 1;
                if received_dirs > MAX_TRANSFER_FILES {
                    anyhow::bail!(
                        "Peer sent too many directory frames ({} > max {})",
                        received_dirs,
                        MAX_TRANSFER_FILES
                    );
                }
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
                ensure_dir_no_symlinks(dest_base, &dest_path)?;
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
                    ensure_dir_no_symlinks(dest_base, parent)?;
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

                    if last_progress_report.elapsed() >= TOUCHBAR_PROGRESS_INTERVAL {
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

        Ok((transferred_bytes, start_time, manifest_sha256))
    }

    pub(crate) fn remap_rel_root(rel_path: &str, root_remap: Option<(&str, &str)>) -> String {
        let Some((orig_root, new_root)) = root_remap else {
            return rel_path.to_string();
        };
        if orig_root == new_root || orig_root.is_empty() || new_root.is_empty() {
            return rel_path.to_string();
        }
        let mut comps = rel_path.split(['/', '\\']).filter(|s| !s.is_empty());
        let Some(first) = comps.next() else {
            return rel_path.to_string();
        };
        if first != orig_root {
            return rel_path.to_string();
        }
        let rest: Vec<&str> = comps.collect();
        if rest.is_empty() {
            new_root.to_string()
        } else {
            format!("{}/{}", new_root, rest.join("/"))
        }
    }

    fn effective_roots(ann: &LazyAnnouncement) -> Result<Vec<String>> {
        if ann.roots.is_empty() {
            let single = safe_root_entry_name(&ann.root_name);
            validate_single_path_component(&single)?;
            return Ok(vec![single]);
        }
        if ann.roots.len() > MAX_ROOTS {
            anyhow::bail!(
                "Announcement roots count {} exceeds cap {}",
                ann.roots.len(),
                MAX_ROOTS
            );
        }
        let mut seen = std::collections::HashSet::with_capacity(ann.roots.len());
        let mut out = Vec::with_capacity(ann.roots.len());
        for raw in &ann.roots {
            validate_single_path_component(raw)?;
            if !seen.insert(raw.clone()) {
                anyhow::bail!("Duplicate top-level entry '{}' in announcement roots", raw);
            }
            out.push(raw.clone());
        }
        Ok(out)
    }

    async fn record_verified_cache(&self, entry: VerifiedCacheEntry) {
        let mut cache = self.verified_cache.write().await;
        if let Some(pos) = cache
            .iter()
            .position(|e| e.session_id == entry.session_id && e.manifest_hash == entry.manifest_hash)
        {
            cache.remove(pos);
        }
        while cache.len() >= MAX_VERIFIED_CACHE_ENTRIES {
            if let Some(evicted) = cache.pop_front() {
                if evicted.session_dir != entry.session_dir {
                    let dir = evicted.session_dir;
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = std::fs::remove_dir_all(dir);
                    })
                    .await;
                }
            }
        }
        cache.push_back(entry);
    }

    async fn lookup_verified_cache(&self, session_id: &str) -> Option<VerifiedCacheEntry> {
        let cache = self.verified_cache.read().await;
        cache
            .iter()
            .rev()
            .find(|e| e.session_id == session_id)
            .cloned()
    }

    async fn stream_to_cache_from(
        &self,
        ann: LazyAnnouncement,
        source_ip: Option<IpAddr>,
    ) -> Result<()> {
        if !is_valid_hex_session_id(&ann.session_id) {
            anyhow::bail!("Rejected invalid session_id in lazy announcement");
        }
        let roots = Self::effective_roots(&ann)?;
        let peer_ip = self.resolve_stream_peer_ip(source_ip).await?;
        let cache_dir = self.file_helper.get_cache_dir().to_path_buf();

        let stage_dir = cache_dir.join(format!(
            ".staging_{}_{}",
            &ann.session_id[..ann.session_id.len().min(16)],
            trust::generate_random_token_hex(6)
        ));
        if let Ok(meta) = std::fs::symlink_metadata(&stage_dir) {
            if meta.file_type().is_symlink() {
                anyhow::bail!("Refusing symlinked staging directory");
            }
            let _ = std::fs::remove_dir_all(&stage_dir);
        }
        ensure_dir_no_symlinks(&cache_dir, &stage_dir)?;

        info!(
            "📥 Streaming announced item '{}' ({} root(s), {:.1} MB) from {} into isolated staging cache...",
            ann.root_name,
            roots.len(),
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

        let (transferred_bytes, start_time, manifest_sha256) = match stream_res {
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

        let manifest_hex = to_hex_string(&manifest_sha256);
        let session_cache_dir = cache_dir.join(format!(
            "s_{}_{}",
            &ann.session_id[..ann.session_id.len().min(16)],
            &manifest_hex[..16]
        ));
        if let Ok(meta) = std::fs::symlink_metadata(&session_cache_dir) {
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_dir_all(&stage_dir);
                anyhow::bail!("Refusing symlinked verified cache directory");
            }
            let _ = std::fs::remove_dir_all(&session_cache_dir);
        }
        ensure_dir_no_symlinks(&cache_dir, &session_cache_dir)?;

        let mut cached_roots = Vec::with_capacity(roots.len());
        for root in &roots {
            let staged_item = ensure_safe_contained_path(&stage_dir, root)?;
            let meta = std::fs::symlink_metadata(&staged_item).with_context(|| {
                format!("Staged root entry '{}' missing after verified stream", root)
            })?;
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_dir_all(&stage_dir);
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                anyhow::bail!("Security violation: staged item '{}' is a symlink", root);
            }
            let dest_item = ensure_safe_contained_path(&session_cache_dir, root)?;
            if let Err(e) = move_staged_entry(&staged_item, &dest_item) {
                let _ = std::fs::remove_dir_all(&stage_dir);
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                return Err(e);
            }
            cached_roots.push(dest_item);
        }
        let _ = std::fs::remove_dir_all(&stage_dir);

        if cached_roots.is_empty() {
            let _ = std::fs::remove_dir_all(&session_cache_dir);
            anyhow::bail!("Verified clipboard cache commit produced zero root items");
        }

        // Only replace the native OS clipboard AFTER all staged items pass SHA-256 verification.
        let helper = Arc::clone(&self.file_helper);
        let roots_for_cb = cached_roots.clone();
        let new_seq = tokio::task::spawn_blocking(move || -> Result<i64> {
            helper.write_copied_files(&roots_for_cb)?;
            Ok(os_seq::get_clipboard_sequence())
        })
        .await
        .context("Clipboard writer task panicked")??;
        if new_seq >= 0 {
            let mut seq_lock = self.last_seq.write().await;
            *seq_lock = new_seq;
        }

        self.record_verified_cache(VerifiedCacheEntry {
            session_id: ann.session_id.clone(),
            manifest_hash: manifest_sha256,
            session_dir: session_cache_dir,
            roots,
        })
        .await;

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
    /// multi-item support, and non-destructive collision naming.
    pub async fn paste_remote(&self, custom_target: Option<PathBuf>) -> Result<String> {
        if self
            .is_pasting
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            warn!("Remote paste is already in progress, ignoring duplicate trigger");
            return Ok("Paste already in progress".to_string());
        }

        struct PasteGuard<'a> {
            service: &'a ClipboardService,
            clear_pending_on_exit: bool,
        }
        impl<'a> Drop for PasteGuard<'a> {
            fn drop(&mut self) {
                self.service
                    .is_pasting
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                #[cfg(target_os = "macos")]
                unsafe {
                    if self.clear_pending_on_exit {
                        set_has_pending_remote_file(false);
                    }
                    reset_touchbar_paste_progress();
                }
            }
        }
        let mut guard = PasteGuard {
            service: self,
            clear_pending_on_exit: false,
        };

        let ann = {
            let lock = self.pending_remote.read().await;
            lock.clone()
        }
        .context("No remote file announcement pending to paste")?;

        if !is_valid_hex_session_id(&ann.session_id) {
            anyhow::bail!("Rejected invalid session_id on pending paste");
        }
        let roots = Self::effective_roots(&ann)?;

        let target_dir = match custom_target {
            Some(dir) => dir,
            None => tokio::task::spawn_blocking(Self::resolve_active_destination_folder)
                .await
                .unwrap_or_else(|_| crate::system_info::user_desktop_or_downloads_dir()),
        };
        if let Ok(meta) = std::fs::symlink_metadata(&target_dir) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                anyhow::bail!(
                    "Refusing to paste into non-directory or symlinked target: {}",
                    target_dir.display()
                );
            }
        } else {
            anyhow::bail!(
                "Destination directory does not exist: {}",
                target_dir.display()
            );
        }

        let cache_dir = self.file_helper.get_cache_dir().to_path_buf();

        // Cache hit only if exact (session_id, manifest_hash) entry is verified and intact.
        if let Some(cached) = self.lookup_verified_cache(&ann.session_id).await {
            let all_present = target_dir != cache_dir
                && !cached.roots.is_empty()
                && cached.roots.iter().all(|r| {
                    let p = cached.session_dir.join(r);
                    std::fs::symlink_metadata(&p)
                        .map(|m| !m.file_type().is_symlink())
                        .unwrap_or(false)
                });
            if all_present {
                info!(
                    "📋 Item '{}' already present in verified cache ({}). Copying {} item(s) to {:?}...",
                    ann.root_name,
                    to_hex_string(&cached.manifest_hash[..4]),
                    cached.roots.len(),
                    target_dir
                );
                let mut pasted_paths = Vec::with_capacity(cached.roots.len());
                for root in &cached.roots {
                    let src = ensure_safe_contained_path(&cached.session_dir, root)?;
                    let dest = resolve_non_colliding_dest(&target_dir, root);
                    let src_c = src.clone();
                    let dest_c = dest.clone();
                    tokio::task::spawn_blocking(move || Self::copy_entry_all(&src_c, &dest_c))
                        .await
                        .context("Cache copy task panicked")??;
                    pasted_paths.push(dest);
                }

                {
                    let mut lock = self.pending_remote.write().await;
                    *lock = None;
                }
                {
                    let mut ip_lock = self.last_remote_ip.write().await;
                    *ip_lock = None;
                }
                guard.clear_pending_on_exit = true;

                if let Some(first_dest) = pasted_paths.first() {
                    Self::reveal_in_file_manager(first_dest);
                }
                let final_summary = if pasted_paths.len() == 1 {
                    pasted_paths[0]
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&ann.root_name)
                        .to_string()
                } else {
                    ann.root_name.clone()
                };
                return Ok(format!(
                    "✅ Pasted '{}' into {:?}",
                    final_summary, target_dir
                ));
            }
        }

        let last_ip = *self.last_remote_ip.read().await;
        let peer_ip = self.resolve_stream_peer_ip(last_ip).await?;

        // Stage inside an isolated hidden directory in `target_dir` so partial/corrupted files
        // never appear in the user's destination folder unless SHA-256 verification succeeds.
        let stage_dir = target_dir.join(format!(
            ".integrator_staging_{}",
            trust::generate_random_token_hex(8)
        ));
        if let Ok(meta) = std::fs::symlink_metadata(&stage_dir) {
            if meta.file_type().is_symlink() {
                anyhow::bail!("Refusing symlinked target staging folder");
            }
            let _ = std::fs::remove_dir_all(&stage_dir);
        }
        ensure_dir_no_symlinks(&target_dir, &stage_dir)?;

        info!(
            "📥 Initiating on-demand stream of '{}' ({} root(s)) from {} via isolated staging into {:?}",
            ann.root_name, roots.len(), peer_ip, target_dir
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

        let (transferred_bytes, start_time, _manifest_sha256) = match stream_res {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        let mut committed_paths = Vec::with_capacity(roots.len());
        for root in &roots {
            let staged_item = ensure_safe_contained_path(&stage_dir, root)?;
            if !staged_item.exists() {
                let _ = std::fs::remove_dir_all(&stage_dir);
                anyhow::bail!(
                    "Expected root entry '{}' missing from verified staging folder",
                    root
                );
            }
            let dest_item = resolve_non_colliding_dest(&target_dir, root);
            if let Err(e) = move_staged_entry(&staged_item, &dest_item) {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
            committed_paths.push(dest_item);
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
        guard.clear_pending_on_exit = true;

        if let Some(first_dest) = committed_paths.first() {
            Self::reveal_in_file_manager(first_dest);
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let avg_mb_s = (transferred_bytes as f64 / (1024.0 * 1024.0)) / elapsed.max(0.001);
        let display_label = if committed_paths.len() == 1 {
            committed_paths[0]
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&ann.root_name)
                .to_string()
        } else {
            ann.root_name.clone()
        };
        let msg = format!(
            "✅ Successfully pasted '{}' ({:.1} MB at {:.0} MB/s) into {:?}",
            display_label,
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
    use crate::clipboard::protocol::MAX_IMAGE_DIMENSION;
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

    #[test]
    fn remap_rel_root_never_collapses_unrelated_top_level_files() {
        assert_eq!(
            ClipboardService::remap_rel_root("alpha/file.txt", Some(("alpha", "alpha (2)"))),
            "alpha (2)/file.txt"
        );
        assert_eq!(
            ClipboardService::remap_rel_root("alpha", Some(("alpha", "alpha (2)"))),
            "alpha (2)"
        );
        assert_eq!(
            ClipboardService::remap_rel_root("other.txt", Some(("alpha", "alpha (2)"))),
            "other.txt"
        );
        assert_eq!(
            ClipboardService::remap_rel_root("beta/nested.txt", Some(("alpha", "alpha (2)"))),
            "beta/nested.txt"
        );
    }

    #[test]
    fn collect_local_entries_preserves_multi_item_roots_and_disambiguates_duplicates() {
        let base = std::env::temp_dir().join(format!(
            "integrator_multi_collect_{}",
            trust::generate_random_token_hex(6)
        ));
        let d1 = base.join("dir_one");
        let d2 = base.join("dir_two");
        let folder = base.join("folder");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::create_dir_all(&folder).unwrap();

        let f1 = d1.join("dup.txt");
        let f2 = d2.join("dup.txt");
        let f3 = folder.join("inside.bin");
        std::fs::write(&f1, b"first").unwrap();
        std::fs::write(&f2, b"second").unwrap();
        std::fs::write(&f3, b"third").unwrap();

        let copy = ClipboardService::collect_local_entries(&[f1, f2, folder]).unwrap();
        assert_eq!(copy.total_files, 3);
        assert_eq!(
            copy.top_entries,
            vec![
                "dup.txt".to_string(),
                "dup (2).txt".to_string(),
                "folder".to_string()
            ]
        );
        assert_eq!(copy.root_name, "dup.txt (+2 items)");

        let _ = std::fs::remove_dir_all(&base);
    }

    async fn setup_paired_clipboard_sessions(
        base: &Path,
        tag: &str,
    ) -> (
        TransportSessionV2<tokio::io::DuplexStream>,
        TransportSessionV2<tokio::io::DuplexStream>,
    ) {
        let ks_dir_c = base.join(format!("ks_c_{}", tag));
        let ks_dir_s = base.join(format!("ks_s_{}", tag));
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
        (c_res.unwrap(), s_res.unwrap())
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
        let f1_bytes = b"Integrator v1.0 authenticated file stream test";
        let f2_bytes = vec![0x3Cu8; 300_000];
        std::fs::write(&f1_path, f1_bytes).unwrap();
        std::fs::write(&f2_path, &f2_bytes).unwrap();

        // 1. Valid multi-file stream with per-file and manifest SHA-256 verification
        let (mut client_sess, mut server_sess) =
            setup_paired_clipboard_sessions(&src_dir, "valid").await;
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
        let (rx_bytes, _, _manifest) =
            recv_res.expect("receiver stream and SHA-256 checks must succeed");
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
        let (mut client_sess2, mut server_sess2) =
            setup_paired_clipboard_sessions(&src_dir, "corrupt").await;
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

        // 3. Premature TCP/session EOF (truncation abort) mid-file must fail cleanly
        let (mut client_sess3, mut server_sess3) =
            setup_paired_clipboard_sessions(&src_dir, "trunc").await;
        let dst_trunc = src_dir.join("dst_trunc");
        std::fs::create_dir_all(&dst_trunc).unwrap();

        let trunc_sender = async move {
            let rel = b"partial.bin";
            let mut hdr = Vec::new();
            hdr.push(FRAME_FILE);
            hdr.extend_from_slice(&(rel.len() as u16).to_be_bytes());
            hdr.extend_from_slice(rel);
            hdr.extend_from_slice(&(1024u64).to_be_bytes());
            server_sess3.send_message(&hdr).await.unwrap();

            let mut data = vec![FRAME_FILE_DATA];
            data.extend_from_slice(&[0x42u8; 100]);
            server_sess3.send_message(&data).await.unwrap();
            drop(server_sess3);
        };
        let (_, trunc_rx_res) = tokio::join!(
            trunc_sender,
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess3,
                &dst_trunc,
                1024,
                1,
                None
            )
        );
        assert!(trunc_rx_res.is_err(), "truncated stream must abort cleanly");

        // 4. Excessive FRAME_DIR count beyond MAX_TRANSFER_FILES must be rejected
        let (mut client_sess4, mut server_sess4) =
            setup_paired_clipboard_sessions(&src_dir, "dir_flood").await;
        let dst_flood = src_dir.join("dst_flood");
        std::fs::create_dir_all(&dst_flood).unwrap();

        let flood_sender = async move {
            for idx in 0..=(MAX_TRANSFER_FILES + 1) {
                let rel = format!("d{}", idx);
                let mut dir_rec = Vec::with_capacity(3 + rel.len());
                dir_rec.push(FRAME_DIR);
                dir_rec.extend_from_slice(&(rel.len() as u16).to_be_bytes());
                dir_rec.extend_from_slice(rel.as_bytes());
                if server_sess4.send_message(&dir_rec).await.is_err() {
                    break;
                }
            }
        };
        let (_, flood_rx_res) = tokio::join!(
            flood_sender,
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess4,
                &dst_flood,
                0,
                1,
                None
            )
        );
        assert!(
            flood_rx_res.is_err(),
            "FRAME_DIR count exceeding MAX_TRANSFER_FILES must be rejected"
        );

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }
}
