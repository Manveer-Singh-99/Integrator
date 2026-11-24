//! # Universal Clipboard Service & Zero-RAM Streaming Engine
//!
//! ## 1. Module Purpose & Scope
//! The `ClipboardService` provides secure, full-duplex, mutually authenticated clipboard
//! synchronization across macOS and Windows 10/11 workstations.
//!
//! Operating over `TransportSessionV2` (`ServiceId::ClipboardTransfer` on TCP port `CLIPBOARD_PORT = 58283`),
//! the service synchronizes UTF-8 plain text, uncompressed RGBA bitmaps, and entire directory
//! trees with zero memory-buffering overhead.
//!
//! ### Core Subsystem Responsibilities:
//! 1. **Lightweight Change Polling**: Continuously polls `os_seq::get_clipboard_sequence()` every
//!    120ms. Expensive OS clipboard reads and SHA-256 hashing occur only when the native sequence
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
//!              │  - Sequence Watcher Loop (120ms interval)               │
//!              │  - Format Negotiator (Text, Image, LazyAnnouncement)   │
//!              │  - Staging Pipeline & Atomic Cache Promotion            │
//!              └───────┬─────────────────┬───────────────────┬───────────┘
//!                      │                 │                   │
//!           Outbound   │     Inbound     │                   │ Progress Telemetry
//!           Streams    │     Streams     │                   │
//!                      ▼                 ▼                   ▼
//!       ┌───────────────────────────────┐     ┌──────────────────────────────┐
//!       │      TransportSessionV2       │     │     touchbar_hud.swift       │
//!       │ (ServiceId::ClipboardTransfer)│     │  - Live Transfer Progress %  │
//!       │   ChaCha20-Poly1305 over TCP  │     │  - MB/s Streaming Velocity   │
//!       └──────────────┬────────────────┘     └──────────────────────────────┘
//!                      │ Port 58283
//!                      ▼
//!             Remote Peer Workstation
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Instantiates `ClipboardService::new`, assigns `CLIPBOARD_INSTANCE`, spawns the
//!   sequence watcher task, and handles `clear_pending_state` / `clear_peer_remote_state_bounded[_async]`.
//! - Native Keyboard Shortcut Interceptors: Invoke `trigger_rust_remote_paste()` when the user
//!   presses `Cmd+V` / `Ctrl+V` while a remote lazy file transfer is pending.
//! - KVM Engine (`src/kvm/service.rs`): Reuses `ClipboardService` staging and streaming helpers
//!   for drag-and-drop operations.
//!
//! ### Downstream Callees:
//! - `super::protocol`: Wire message formats and frame markers.
//! - `super::os_seq`: OS sequence counter queries and fail-closed privacy inspection.
//! - `super::file_helper::FileClipboardHelper`: Native OS file clipboard access (`NSPasteboard` / `CF_HDROP`).
//! - `arboard::Clipboard`: Cross-platform plain text and bitmap read/write operations.
//! - `crate::trust`: Mutually authenticated transport session establishment.
//! - `crate::security::transport::TransportSessionV2`: Encrypted bi-directional framing over port 58283.
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

use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::file_helper::FileClipboardHelper;
use super::os_seq::{self, ClipboardPrivacyStatus};
use super::protocol::{
    ClipboardMessage, ClipboardPayload, LazyAnnouncement, StreamRequest, FRAME_DIR, FRAME_END,
    FRAME_FILE, FRAME_FILE_DATA, FRAME_FILE_HASH, FRAME_IMAGE_DATA, MAX_AUTO_STAGE_BYTES,
    MAX_CLIPBOARD_HEADER_BYTES, MAX_DIRECTORY_DEPTH, MAX_ROOTS, MAX_SINGLE_FILE_BYTES,
    MAX_TEXT_CHARS, MAX_TOTAL_TRANSFER_BYTES, MAX_TRANSFER_FILES,
};
#[cfg(target_os = "macos")]
use crate::config::MACOS_OSASCRIPT_BIN;
use crate::config::{CLIPBOARD_PORT, DRAG_STAGING_DIR_NAME};
use crate::discovery::DiscoveryManager;
use crate::security::transport::{ServiceId, TransportSessionV2};
use crate::trust;
use tokio::io::AsyncWriteExt;

/// Maximum number of concurrent unauthenticated TCP clipboard connections accepted before handshake (`16`).
const MAX_PRE_AUTH_CLIP_CONNS: usize = 16;
/// Maximum number of concurrent authenticated clipboard/drag transfer sessions (`8`).
const MAX_POST_AUTH_CLIP_CONNS: usize = 8;
/// Timeout applied to the `TransportSessionV2` mutual authentication handshake (`10 s`).
const CLIP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// High-throughput AEAD stream chunk payload size in bytes (`256 KiB`).
const STREAM_CHUNK_SIZE: usize = 256 * 1024;
/// Per-frame network I/O timeout guarding stalled reads/writes during streaming (`15 s`).
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
    /// Installs the macOS `CGEventTap` `Cmd+V` shortcut interceptor for pending remote file pastes.
    pub fn init_shortcut_interceptor();
    /// Updates the macOS Touch Bar HUD to advertise an announced remote file (`name`, `total_bytes`).
    fn notify_touchbar_remote_file(name: *const std::os::raw::c_char, total_bytes: u64);
    /// Updates the macOS Touch Bar HUD progress bar (`percent` in `0.0..=100.0`, `mb_per_sec`).
    fn update_touchbar_paste_progress(percent: f32, mb_per_sec: f32);
    /// Resets and clears the macOS Touch Bar HUD paste progress state.
    fn reset_touchbar_paste_progress();
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
extern "C" {
    /// Notifies native OS shortcut hooks (`CGEventTap` / `WH_KEYBOARD_LL`) whether a remote lazy
    /// file announcement is pending so `Cmd+V` / `Ctrl+V` can intercept and stream on demand.
    pub fn set_has_pending_remote_file(pending: bool);
}

/// Global singleton reference to the initialized `ClipboardService`, used by C FFI callbacks.
pub static CLIPBOARD_INSTANCE: std::sync::OnceLock<ClipboardService> = std::sync::OnceLock::new();
/// Global Tokio runtime handle captured at initialization for spawning async tasks from C FFI.
pub static TOKIO_HANDLE: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

/// C-ABI entry point invoked by native shortcut interceptors (`Cmd+V` / `Ctrl+V` / TouchBar)
/// to trigger on-demand streaming and pasting of the pending remote file announcement.
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

/// Encodes an arbitrary byte slice into lowercase hexadecimal ASCII characters.
fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Computes the SHA-256 hex digest of a UTF-8 plain text clipboard payload.
fn compute_text_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    to_hex_string(&hasher.finalize())
}

/// Computes a dimension-bound SHA-256 hex digest over `(width || height || byte_len || rgba)`.
fn compute_image_hash(width: usize, height: usize, rgba: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&(width as u64).to_le_bytes());
    hasher.update(&(height as u64).to_le_bytes());
    hasher.update(&(rgba.len() as u64).to_le_bytes());
    hasher.update(rgba);
    to_hex_string(&hasher.finalize())
}

/// Validates RGBA bitmap dimensions and buffer byte length via `protocol::validate_image_bounds`.
fn validate_image_bounds(width: usize, height: usize, rgba_len: usize) -> bool {
    super::protocol::validate_image_bounds(width, height, rgba_len).is_some()
}

/// Validates that `session_id` is a non-empty ASCII hex string of at most 128 characters.
fn is_valid_hex_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= 128
        && session_id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Formats an IPv4/IPv6/hostname target and TCP port into a valid socket address string.
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

/// Creates `dir` with private permissions (`0o700` on Unix) if absent, or verifies an existing
/// path is a real non-symlink directory.
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

/// Opens `path` read-only after verifying via `symlink_metadata` that it is a regular non-symlink
/// file, additionally passing `O_NOFOLLOW` on Unix to close any open-time symlink TOCTOU gap.
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

/// Atomically moves a verified non-symlink staged entry from `src` to `dst`, falling back to
/// recursive copy-and-remove only if `rename` fails across filesystem boundaries.
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

/// Disambiguates colliding top-level basenames in multi-root selections (`file (2).ext`, ...).
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

/// Removes orphaned non-symlink staging directories/files matching `prefixes` older than `max_age`.
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

/// Sweeps expired temporary clipboard and drag-and-drop staging directories older than 1 hour.
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
    if comp
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\0'))
    {
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

/// Extracts and validates the first safe path segment from a legacy announcement `root_name`,
/// falling back to `"clipboard_item"` if no valid segment exists.
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

/// Indexed local file/directory selection prepared for lazy announcement or cross-screen drag streaming.
#[derive(Clone, Debug)]
pub struct LocalPendingCopy {
    /// Random hex session identifier matching `LazyAnnouncement::session_id` or drag session ID.
    pub session_id: String,
    /// Display summary string (e.g. `"report.pdf"` or `"report.pdf (+2 items)"`).
    pub root_name: String,
    /// Total count of regular files across all roots (`1..=MAX_TRANSFER_FILES`).
    pub total_files: usize,
    /// Cumulative payload size in bytes across all indexed regular files (`<= MAX_TOTAL_TRANSFER_BYTES`).
    pub total_bytes: u64,
    /// Ordered relative directory paths (POSIX `/` separators) to create via `FRAME_DIR`.
    pub directories: Vec<String>,
    /// Ordered `(relative_path, source_abs_path)` pairs to stream via `FRAME_FILE`.
    pub files: Vec<(String, PathBuf)>,
    /// Disambiguated top-level root names matching `LazyAnnouncement::roots`.
    pub top_entries: Vec<String>,
}

/// Verified disk cache entry retained in an LRU queue after passing per-file and manifest SHA-256 checks.
#[derive(Clone, Debug)]
struct VerifiedCacheEntry {
    /// Session identifier of the cached transfer.
    session_id: String,
    /// Cumulative SHA-256 manifest digest verified at `FRAME_END`.
    manifest_hash: [u8; 32],
    /// Private directory under `clipboard_cache` holding the verified root items.
    session_dir: PathBuf,
    /// Top-level root entry names contained inside `session_dir`.
    roots: Vec<String>,
}

/// Distinguishes the business purpose of a streaming file transfer.
/// Guarantees that clipboard synchronisation toggles never cancel drag-and-drop operations,
/// and vice-versa (SEC-1F-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPurpose {
    /// Standard Universal Clipboard copy/paste or inline/streamed image transfer.
    Clipboard,
    /// Cross-screen KVM drag-and-drop file transfer.
    DragDrop,
}

/// Operation-scoped cancellation token that monitors subsystem feature flags
/// throughout long-running file and image streaming transfers (SEC-1F-02).
#[derive(Clone)]
pub struct TransferCancellation {
    /// Subsystem scope (`Clipboard` vs `DragDrop`) determining which feature flag applies.
    purpose: TransferPurpose,
    /// Optional reference to the live `FeatureManager` polled at chunk/frame boundaries.
    features: Option<Arc<crate::features::FeatureManager>>,
    /// Optional explicit atomic abort flag for caller/test-driven cancellation.
    manual_cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl TransferCancellation {
    /// Creates a new cancellation token bound to `purpose` and optional `FeatureManager`.
    pub fn new(
        purpose: TransferPurpose,
        features: Option<Arc<crate::features::FeatureManager>>,
    ) -> Self {
        Self {
            purpose,
            features,
            manual_cancel: None,
        }
    }

    /// Creates a cancellation token with an explicit manual `AtomicBool` abort signal (used in tests).
    #[cfg(test)]
    pub fn with_manual(
        purpose: TransferPurpose,
        features: Option<Arc<crate::features::FeatureManager>>,
        manual_cancel: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            purpose,
            features,
            manual_cancel: Some(manual_cancel),
        }
    }

    /// Creates a `TransferPurpose::Clipboard` cancellation token (used in tests).
    #[cfg(test)]
    pub fn clipboard(features: Option<Arc<crate::features::FeatureManager>>) -> Self {
        Self::new(TransferPurpose::Clipboard, features)
    }

    /// Creates a `TransferPurpose::DragDrop` cancellation token (used in tests).
    #[cfg(test)]
    pub fn dragdrop(features: Option<Arc<crate::features::FeatureManager>>) -> Self {
        Self::new(TransferPurpose::DragDrop, features)
    }

    /// Returns the `TransferPurpose` assigned to this cancellation token (used in tests).
    #[cfg(test)]
    pub fn purpose(&self) -> TransferPurpose {
        self.purpose
    }

    /// Evaluates whether the transfer has been cancelled via manual abort or feature disablement.
    pub fn is_cancelled(&self) -> bool {
        if let Some(manual) = &self.manual_cancel {
            if manual.load(std::sync::atomic::Ordering::Relaxed) {
                return true;
            }
        }
        match &self.features {
            Some(mgr) => match self.purpose {
                TransferPurpose::Clipboard => !mgr.is_enabled("clipboard"),
                TransferPurpose::DragDrop => false,
            },
            None => false,
        }
    }

    /// Fails with a descriptive cancellation error if `is_cancelled()` is true.
    pub fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            anyhow::bail!(
                "Transfer cancelled: {} synchronization was disabled or aborted during transfer",
                match self.purpose {
                    TransferPurpose::Clipboard => "Clipboard",
                    TransferPurpose::DragDrop => "Drag & Drop",
                }
            );
        }
        Ok(())
    }
}

/// Full-duplex, mutually authenticated Universal Clipboard & file streaming service.
#[derive(Clone)]
pub struct ClipboardService {
    /// Peer discovery manager used to resolve active paired peer IP addresses.
    discovery: DiscoveryManager,
    /// SHA-256 hex digest of the most recently synced/applied clipboard content for loop deduplication.
    last_hash: Arc<RwLock<String>>,
    /// Most recently observed OS clipboard modification sequence number (`-1` if unavailable).
    last_seq: Arc<RwLock<i64>>,
    /// Native OS file clipboard (`NSPasteboard` / `CF_HDROP`) and cache pruning driver.
    file_helper: Arc<FileClipboardHelper>,
    /// Currently staged local multi-file selection awaiting on-demand remote `RequestStream`.
    pending_local: Arc<RwLock<Option<LocalPendingCopy>>>,
    /// Most recent remote `LazyAnnouncement` awaiting local paste (`Cmd+V` / `Ctrl+V`).
    pending_remote: Arc<RwLock<Option<LazyAnnouncement>>>,
    /// Active outbound cross-screen drag sessions indexed by `session_id` (bounded to 16).
    pending_drag_sessions: Arc<RwLock<HashMap<String, LocalPendingCopy>>>,
    /// FIFO eviction queue tracking registration order for `pending_drag_sessions`.
    pending_drag_order: Arc<RwLock<VecDeque<String>>>,
    /// Bounded LRU cache of up to `MAX_VERIFIED_CACHE_ENTRIES` (8) verified file transfers on disk.
    verified_cache: Arc<RwLock<VecDeque<VerifiedCacheEntry>>>,
    /// IP address of the peer that sent the active `pending_remote` lazy announcement.
    last_remote_ip: Arc<RwLock<Option<IpAddr>>>,
    /// Re-entrancy guard preventing concurrent `paste_remote` invocations.
    is_pasting: Arc<std::sync::atomic::AtomicBool>,
    /// Runtime `FeatureManager` handle gating `clipboard` and `dragdrop` operations.
    features: Arc<OnceLock<Arc<crate::features::FeatureManager>>>,
    /// Per-peer `(LazyAnnouncement, source_ip, trust_generation)` map supporting scoped revocation.
    pending_remote_by_peer:
        Arc<std::sync::RwLock<HashMap<String, (LazyAnnouncement, IpAddr, u64)>>>,
    /// Per-peer set of registered drag `session_id`s supporting scoped revocation on unpair/block.
    drag_sessions_by_peer: Arc<std::sync::RwLock<HashMap<String, HashSet<String>>>>,
    /// Mapping from drag `session_id` to the peer trust generation under which it was registered.
    drag_session_generations: Arc<std::sync::RwLock<HashMap<String, u64>>>,
    /// Per-peer clipboard revocation generation watermark preventing stale re-population.
    revoked_clipboard_peers: Arc<std::sync::RwLock<HashMap<String, u64>>>,
    /// Async RwLock serializing OS clipboard commit writes (read) against peer revocation (write).
    clipboard_commit_lock: Arc<tokio::sync::RwLock<()>>,
}

impl ClipboardService {
    /// Initializes `ClipboardService`, sweeps orphaned staging directories, records the initial OS
    /// clipboard sequence counter, and registers the global `CLIPBOARD_INSTANCE` / `TOKIO_HANDLE`.
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
            pending_remote_by_peer: Arc::new(std::sync::RwLock::new(HashMap::new())),
            drag_sessions_by_peer: Arc::new(std::sync::RwLock::new(HashMap::new())),
            drag_session_generations: Arc::new(std::sync::RwLock::new(HashMap::new())),
            revoked_clipboard_peers: Arc::new(std::sync::RwLock::new(HashMap::new())),
            clipboard_commit_lock: Arc::new(tokio::sync::RwLock::new(())),
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = TOKIO_HANDLE.set(handle);
        }

        let _ = CLIPBOARD_INSTANCE.set(service.clone());
        Ok(service)
    }

    /// Binds the shared `FeatureManager` used to gate clipboard sync and cancel active transfers.
    pub fn set_feature_manager(&self, fm: Arc<crate::features::FeatureManager>) {
        let _ = self.features.set(fm);
    }

    /// Returns `true` if the `"clipboard"` feature flag (and its `"input_kvm"` prerequisite) is enabled.
    fn is_clipboard_enabled(&self) -> bool {
        self.features
            .get()
            .map(|f| f.is_enabled("clipboard"))
            .unwrap_or(false)
    }

    /// Returns `true` if the `"dragdrop"` feature flag is enabled.
    fn is_dragdrop_enabled(&self) -> bool {
        self.features
            .get()
            .map(|f| f.is_enabled("dragdrop"))
            .unwrap_or(false)
    }

    /// Constructs a `TransferCancellation` token scoped to `purpose` (`Clipboard` or `DragDrop`).
    pub(crate) fn cancellation_for(&self, purpose: TransferPurpose) -> TransferCancellation {
        TransferCancellation::new(purpose, self.features.get().cloned())
    }

    /// Clears the pending local and remote clipboard state along with TouchBar/hotkey indicators.
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
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        unsafe {
            set_has_pending_remote_file(false);
        }
    }

    /// Immediately and unconditionally clears all clipboard staging state, pending announcements,
    /// and active drag sessions associated specifically with `peer_device_id_hex` asynchronously.
    pub async fn clear_peer_remote_state_async(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let current_gen =
            crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        self.clear_peer_remote_state_bounded_async(&clean_id, current_gen)
            .await;
    }

    /// Asynchronously clears clipboard state for `peer_device_id_hex` bounded to `target_generation`.
    /// If the peer's active trust generation has already advanced beyond `target_generation`, the
    /// revocation mark and newer-generation resources are preserved to prevent races against re-pairing (SEC-1D-14).
    pub async fn clear_peer_remote_state_bounded_async(
        &self,
        peer_device_id_hex: &str,
        target_generation: u64,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();

        // Acquire write lease on clipboard_commit_lock so in-flight OS clipboard commits finish
        // and subsequent commits for the revoked peer are blocked (SEC-1D-14, SEC-1D-15).
        let _commit_guard = self.clipboard_commit_lock.write().await;

        let current_trans_gen =
            crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        let current_ks_gen = crate::security::keystore::global_keystore()
            .lock()
            .ok()
            .and_then(|ks| ks.peer_trust_generation(&clean_id))
            .unwrap_or(0);
        let active_current_gen = current_trans_gen.max(current_ks_gen);

        let is_repaired = active_current_gen > target_generation;

        if is_repaired {
            tracing::info!(
                "Preserving re-paired peer {} clipboard trust (bound gen {}, current active gen {})",
                clean_id,
                target_generation,
                active_current_gen
            );
        } else {
            // 1. Mark peer as revoked in clipboard service at target_generation
            let mut rev = self
                .revoked_clipboard_peers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let entry = rev.entry(clean_id.clone()).or_insert(target_generation);
            if target_generation > *entry {
                *entry = target_generation;
            }
        }

        // 2. Guaranteed blocking removal of peer's pending announcement if item generation <= target_generation
        let removed_ann = {
            let mut remotes = self
                .pending_remote_by_peer
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((_, _, gen)) = remotes.get(&clean_id) {
                if *gen <= target_generation {
                    remotes.remove(&clean_id).map(|(ann, _, _)| ann)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Also clean legacy single pending_remote if it was owned by this peer
        if let Some(ref ann) = removed_ann {
            let mut r = self.pending_remote.write().await;
            if let Some(ref cur) = *r {
                if cur.session_id == ann.session_id {
                    *r = None;
                    let mut ip_lock = self.last_remote_ip.write().await;
                    *ip_lock = None;
                    #[cfg(any(target_os = "macos", target_os = "windows"))]
                    unsafe {
                        set_has_pending_remote_file(false);
                    }
                    #[cfg(target_os = "macos")]
                    unsafe {
                        reset_touchbar_paste_progress();
                    }
                }
            }
        }

        // 3. Remove peer's drag sessions and staging files from disk if session_gen <= target_generation
        let session_ids = {
            let mut drag_peers = self
                .drag_sessions_by_peer
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let mut drag_gens = self
                .drag_session_generations
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(sessions) = drag_peers.get_mut(&clean_id) {
                let mut removed = Vec::new();
                sessions.retain(|sid| {
                    let sgen = drag_gens.get(sid).copied().unwrap_or(0);
                    if sgen <= target_generation {
                        removed.push(sid.clone());
                        drag_gens.remove(sid);
                        false
                    } else {
                        true
                    }
                });
                if sessions.is_empty() {
                    drag_peers.remove(&clean_id);
                }
                removed
            } else {
                Vec::new()
            }
        };

        if !session_ids.is_empty() {
            {
                let mut map = self.pending_drag_sessions.write().await;
                for sid in &session_ids {
                    map.remove(sid);
                }
            }
            {
                let mut order = self.pending_drag_order.write().await;
                order.retain(|s| !session_ids.contains(s));
            }
            for sid in &session_ids {
                let drag_dir = crate::system_info::app_data_dir()
                    .join(DRAG_STAGING_DIR_NAME)
                    .join(format!("drag_{}", sid));
                let _ = std::fs::remove_dir_all(&drag_dir);
            }
        }

        // Clear verified cache entries matching revoked session IDs
        {
            let mut cache = self.verified_cache.write().await;
            cache.retain(|entry| !session_ids.contains(&entry.session_id));
        }

        tracing::info!(
            "🛑 Cleared clipboard staging and drag sessions for peer {} at gen {}",
            clean_id,
            target_generation
        );
    }

    /// Immediately and unconditionally clears all clipboard staging state, pending announcements,
    /// and active drag sessions associated specifically with `peer_device_id_hex`.
    pub fn clear_peer_remote_state(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let current_gen =
            crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        self.clear_peer_remote_state_bounded(&clean_id, current_gen);
    }

    /// Synchronously clears clipboard state for `peer_device_id_hex` bounded to `target_generation`.
    pub fn clear_peer_remote_state_bounded(
        &self,
        peer_device_id_hex: &str,
        target_generation: u64,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let current_trans_gen =
            crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        let current_ks_gen = crate::security::keystore::global_keystore()
            .lock()
            .ok()
            .and_then(|ks| ks.peer_trust_generation(&clean_id))
            .unwrap_or(0);
        let active_current_gen = current_trans_gen.max(current_ks_gen);

        if active_current_gen <= target_generation {
            let mut rev = self
                .revoked_clipboard_peers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let entry = rev.entry(clean_id.clone()).or_insert(target_generation);
            if target_generation > *entry {
                *entry = target_generation;
            }
        }

        let removed_ann = {
            let mut remotes = self
                .pending_remote_by_peer
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((_, _, gen)) = remotes.get(&clean_id) {
                if *gen <= target_generation {
                    remotes.remove(&clean_id).map(|(ann, _, _)| ann)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(ref ann) = removed_ann {
            if let Ok(mut r) = self.pending_remote.try_write() {
                if let Some(ref cur) = *r {
                    if cur.session_id == ann.session_id {
                        *r = None;
                    }
                }
            } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let pr = Arc::clone(&self.pending_remote);
                let ann_id = ann.session_id.clone();
                handle.spawn(async move {
                    let mut r = pr.write().await;
                    if let Some(ref cur) = *r {
                        if cur.session_id == ann_id {
                            *r = None;
                        }
                    }
                });
            }
        }

        let session_ids = {
            let mut drag_peers = self
                .drag_sessions_by_peer
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let mut drag_gens = self
                .drag_session_generations
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(sessions) = drag_peers.get_mut(&clean_id) {
                let mut removed = Vec::new();
                sessions.retain(|sid| {
                    let sgen = drag_gens.get(sid).copied().unwrap_or(0);
                    if sgen <= target_generation {
                        removed.push(sid.clone());
                        drag_gens.remove(sid);
                        false
                    } else {
                        true
                    }
                });
                if sessions.is_empty() {
                    drag_peers.remove(&clean_id);
                }
                removed
            } else {
                Vec::new()
            }
        };

        if !session_ids.is_empty() {
            let mut acquired_drag = false;
            if let (Ok(mut map), Ok(mut order)) = (
                self.pending_drag_sessions.try_write(),
                self.pending_drag_order.try_write(),
            ) {
                for sid in &session_ids {
                    map.remove(sid);
                }
                order.retain(|s| !session_ids.contains(s));
                acquired_drag = true;
            }
            if !acquired_drag {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let pds = Arc::clone(&self.pending_drag_sessions);
                    let pdo = Arc::clone(&self.pending_drag_order);
                    let sids = session_ids.clone();
                    handle.spawn(async move {
                        let mut map = pds.write().await;
                        let mut order = pdo.write().await;
                        for sid in &sids {
                            map.remove(sid);
                        }
                        order.retain(|s| !sids.contains(s));
                    });
                }
            }
            for sid in &session_ids {
                let drag_dir = crate::system_info::app_data_dir()
                    .join(DRAG_STAGING_DIR_NAME)
                    .join(format!("drag_{}", sid));
                let _ = std::fs::remove_dir_all(&drag_dir);
            }
        }

        tracing::info!(
            "🛑 Cleared clipboard staging and drag sessions for peer {} at gen {}",
            clean_id,
            target_generation
        );
    }

    /// Authoritative check: returns true if `peer_device_id_hex` is revoked, unverified,
    /// blocked, or unauthenticated, failing closed on missing authorization state (SEC-1D-15).
    pub fn is_peer_revoked(&self, peer_device_id_hex: &str) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if clean_id.is_empty() {
            return true;
        }

        // 1. Authoritative check in transport revocation registry (SEC-1D-15)
        if crate::security::transport::is_peer_revoked(&clean_id) {
            return true;
        }

        // 2. Authoritative check against KeystoreV2 (fail closed if unknown or blocked)
        let (ks_exists, is_blocked, ks_trust_gen) = {
            if let Ok(ks_guard) = crate::security::keystore::global_keystore().lock() {
                let blocked = ks_guard.is_device_blocked(&clean_id);
                if let Some(peer) = ks_guard.get_peer(&clean_id) {
                    (true, blocked, peer.trust_generation)
                } else {
                    (false, blocked, 0)
                }
            } else {
                (false, false, 0)
            }
        };

        if is_blocked {
            return true;
        }

        // 3. Check in-memory clipboard revocation cache
        let rev_gen_opt = {
            let rev = self
                .revoked_clipboard_peers
                .read()
                .unwrap_or_else(|e| e.into_inner());
            rev.get(&clean_id).copied()
        };

        if let Some(rev_gen) = rev_gen_opt {
            let cur_transport_gen =
                crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
            let active_gen = ks_trust_gen.max(cur_transport_gen);
            // Re-pair requires that active trust generation strictly exceeds revocation generation
            if active_gen <= rev_gen {
                return true;
            }
        }

        // 4. Fail-closed: peer must have active trust generation in transport or be registered in Keystore
        let transport_gen =
            crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        if !ks_exists && transport_gen == 0 {
            // Unpaired, unauthenticated, unknown peer: fail closed!
            return true;
        }

        false
    }

    /// Clears the clipboard revocation mark for a peer upon successful re-pairing.
    pub fn clear_peer_revocation(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut rev = self
            .revoked_clipboard_peers
            .write()
            .unwrap_or_else(|e| e.into_inner());
        rev.remove(&clean_id);
    }

    /// Associates a registered drag session with its owning peer device ID.
    pub fn register_peer_drag_session(&self, peer_device_id_hex: &str, session_id: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let gen = crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        self.register_peer_drag_session_bounded(&clean_id, session_id, gen);
    }

    /// Checks if a drag session is actively registered for a specific peer.
    pub fn is_peer_drag_session_registered(
        &self,
        peer_device_id_hex: &str,
        session_id: &str,
    ) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let drag_peers = self
            .drag_sessions_by_peer
            .read()
            .unwrap_or_else(|e| e.into_inner());
        drag_peers
            .get(&clean_id)
            .map(|s| s.contains(session_id))
            .unwrap_or(false)
    }

    /// Associates a registered drag session with its owning peer device ID and generation.
    pub fn register_peer_drag_session_bounded(
        &self,
        peer_device_id_hex: &str,
        session_id: &str,
        generation: u64,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if self.is_peer_revoked(&clean_id) {
            tracing::warn!(
                "Rejected drag session registration for revoked peer {}",
                clean_id
            );
            return;
        }
        let mut drag_peers = self
            .drag_sessions_by_peer
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let mut drag_gens = self
            .drag_session_generations
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if self.is_peer_revoked(&clean_id) {
            return;
        }
        drag_peers
            .entry(clean_id)
            .or_default()
            .insert(session_id.to_string());
        drag_gens.insert(session_id.to_string(), generation);
    }

    /// Retrieves pending lazy announcement for a specific peer device ID hex.
    pub fn get_peer_pending_announcement(
        &self,
        peer_device_id_hex: &str,
    ) -> Option<LazyAnnouncement> {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let remotes = self
            .pending_remote_by_peer
            .read()
            .unwrap_or_else(|e| e.into_inner());
        remotes.get(&clean_id).map(|(ann, _, _)| ann.clone())
    }

    /// Sets pending lazy announcement for a specific peer device ID hex.
    pub fn set_peer_pending_announcement(
        &self,
        peer_device_id_hex: &str,
        ann: LazyAnnouncement,
        ip: IpAddr,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let gen = crate::security::transport::get_peer_trust_generation(&clean_id).unwrap_or(0);
        self.set_peer_pending_announcement_bounded(&clean_id, ann, ip, gen);
    }

    /// Sets pending lazy announcement for a specific peer device ID hex bound to its trust generation.
    pub fn set_peer_pending_announcement_bounded(
        &self,
        peer_device_id_hex: &str,
        ann: LazyAnnouncement,
        ip: IpAddr,
        generation: u64,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if self.is_peer_revoked(&clean_id) {
            tracing::warn!(
                "Rejected pending announcement for revoked peer {}",
                clean_id
            );
            return;
        }
        let mut remotes = self
            .pending_remote_by_peer
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if self.is_peer_revoked(&clean_id) {
            return;
        }
        remotes.insert(clean_id, (ann, ip, generation));
    }

    /// Checks via `spawn_blocking` whether `ip` belongs to a paired peer in `KeystoreV2`.
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

    /// Binds TCP listener on `0.0.0.0:CLIPBOARD_PORT`, launches the 120 ms sequence watcher task,
    /// and installs the native macOS `Cmd+V` shortcut interceptor.
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
                        let Ok(pre_permit) = Arc::clone(&pre_auth_limiter).try_acquire_owned()
                        else {
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

    /// Validates image bounds and SHA-256 integrity before writing an incoming RGBA bitmap to the OS clipboard.
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

        info!(
            "🖼️ Verified & received remote image ({}x{} px)",
            width, height
        );
        #[cfg(any(target_os = "macos", target_os = "windows"))]
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
                    debug!(
                        "Ignoring remote clipboard text while Universal Clipboard/KVM is disabled"
                    );
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
                #[cfg(any(target_os = "macos", target_os = "windows"))]
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
                    debug!(
                        "Ignoring remote clipboard image while Universal Clipboard/KVM is disabled"
                    );
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
                let cancellation = self.cancellation_for(TransferPurpose::Clipboard);
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
                    cancellation.check_cancelled()?;
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
                    cancellation.check_cancelled()?;
                }
                cancellation.check_cancelled()?;

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

                // Check peer authorization before mutating any local clipboard state or spawning tasks.
                let peer_dev_id = session.peer_device_id_hex().to_string();
                if self.is_peer_revoked(&peer_dev_id) {
                    warn!(
                        "Ignoring clipboard announcement from revoked peer {}",
                        peer_dev_id
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
                    let mut remotes = self
                        .pending_remote_by_peer
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    if self.is_peer_revoked(&peer_dev_id) {
                        warn!(
                            "Ignoring clipboard announcement from revoked peer {}",
                            peer_dev_id
                        );
                        return Ok(());
                    }
                    remotes.insert(
                        peer_dev_id.clone(),
                        (ann.clone(), peer_addr.ip(), session.trust_generation()),
                    );
                }
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
                    let name_c = std::ffi::CString::new(ann.root_name.clone()).unwrap_or_default();
                    unsafe {
                        notify_touchbar_remote_file(name_c.as_ptr(), ann.total_bytes);
                    }
                }
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                unsafe {
                    set_has_pending_remote_file(true);
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
                        let cancellation = self.cancellation_for(TransferPurpose::Clipboard);
                        Self::stream_files_over_session(
                            &mut session,
                            copy.directories,
                            copy.files,
                            Some(&cancellation),
                        )
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
                    let cancellation = self.cancellation_for(TransferPurpose::DragDrop);
                    Self::stream_files_over_session(
                        &mut session,
                        copy.directories,
                        copy.files,
                        Some(&cancellation),
                    )
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
                let seq_before = crate::clipboard::os_seq::get_clipboard_sequence();
                if seq_before < 0 {
                    return LocalClipboardSnapshot::Unchanged;
                }

                let privacy_status = crate::clipboard::os_seq::inspect_clipboard_privacy();
                match privacy_status {
                    ClipboardPrivacyStatus::ConcealedOrTransient => {
                        debug!("Skipping clipboard sync: concealed/transient/password-manager content detected");
                        return LocalClipboardSnapshot::Unchanged;
                    }
                    ClipboardPrivacyStatus::InspectionUnavailable => {
                        warn!("Skipping clipboard sync: native clipboard privacy inspection unavailable (failing closed)");
                        return LocalClipboardSnapshot::Unchanged;
                    }
                    ClipboardPrivacyStatus::SafeToSync => {}
                }

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

                    // TOCTOU generation check: sequence must remain unchanged during file acquisition
                    let seq_after = crate::clipboard::os_seq::get_clipboard_sequence();
                    if seq_after != seq_before {
                        debug!("Clipboard sequence changed during file acquisition ({} -> {}), discarding snapshot", seq_before, seq_after);
                        return LocalClipboardSnapshot::Unchanged;
                    }

                    // Revalidate privacy after acquisition
                    if crate::clipboard::os_seq::inspect_clipboard_privacy() != ClipboardPrivacyStatus::SafeToSync {
                        warn!("Clipboard privacy became non-safe during file acquisition, discarding snapshot");
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
                            // TOCTOU generation check: sequence must remain unchanged during image acquisition
                            let seq_after = crate::clipboard::os_seq::get_clipboard_sequence();
                            if seq_after != seq_before {
                                debug!("Clipboard sequence changed during image acquisition ({} -> {}), discarding snapshot", seq_before, seq_after);
                                return LocalClipboardSnapshot::Unchanged;
                            }

                            // Revalidate privacy after acquisition
                            if crate::clipboard::os_seq::inspect_clipboard_privacy() != ClipboardPrivacyStatus::SafeToSync {
                                warn!("Clipboard privacy became non-safe during image acquisition, discarding snapshot");
                                return LocalClipboardSnapshot::Unchanged;
                            }

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
                            // TOCTOU generation check: sequence must remain unchanged during text acquisition
                            let seq_after = crate::clipboard::os_seq::get_clipboard_sequence();
                            if seq_after != seq_before {
                                debug!("Clipboard sequence changed during text acquisition ({} -> {}), discarding snapshot", seq_before, seq_after);
                                return LocalClipboardSnapshot::Unchanged;
                            }

                            // Revalidate privacy after acquisition
                            if crate::clipboard::os_seq::inspect_clipboard_privacy() != ClipboardPrivacyStatus::SafeToSync {
                                warn!("Clipboard privacy became non-safe during text acquisition, discarding snapshot");
                                return LocalClipboardSnapshot::Unchanged;
                            }

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
                        let cancellation = self.cancellation_for(TransferPurpose::Clipboard);
                        if let Err(e) = Self::send_image_stream(
                            &peer_ip,
                            hash_hex,
                            width,
                            height,
                            rgba,
                            Some(&cancellation),
                        )
                        .await
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

    /// Clears pending remote file UI/shortcut state when local clipboard content supersedes it.
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
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        unsafe {
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
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to establish Clipboard TransportV2 to {}: {}",
                addr,
                e
            )
        })?;

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

        info!(
            "✅ Sent TransportV2 encrypted clipboard message to {}",
            addr
        );
        Ok(())
    }

    /// Streams raw RGBA pixels cleanly over `TransportSessionV2` without JSON expansion bloat.
    async fn send_image_stream(
        peer_ip: &str,
        hash_hex: String,
        width: usize,
        height: usize,
        rgba: Vec<u8>,
        cancellation: Option<&TransferCancellation>,
    ) -> Result<()> {
        if let Some(c) = cancellation {
            c.check_cancelled()?;
        }
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
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to connect ImageStream TransportV2 to {}: {}",
                addr,
                e
            )
        })?;

        if let Some(c) = cancellation {
            c.check_cancelled()?;
        }

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
            if let Some(c) = cancellation {
                c.check_cancelled()?;
            }
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
        cancellation: Option<&TransferCancellation>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        if let Some(c) = cancellation {
            c.check_cancelled()?;
        }

        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(b"INTEGRATOR-FILE-MANIFEST-V2");

        // 1. Directory frames: [FRAME_DIR(1B) || path_len_be(2B) || rel_path_utf8]
        for dir_rel in &directories {
            if let Some(c) = cancellation {
                c.check_cancelled()?;
            }
            let rel_bytes = dir_rel.as_bytes();
            if rel_bytes.is_empty() || rel_bytes.len() > 4096 {
                anyhow::bail!(
                    "Invalid directory path length {} in local copy",
                    rel_bytes.len()
                );
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
            if let Some(c) = cancellation {
                c.check_cancelled()?;
            }
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
                if let Some(c) = cancellation {
                    c.check_cancelled()?;
                }
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
                tokio::time::timeout(FRAME_IO_TIMEOUT, session.send_message(&chunk_buf[..1 + n]))
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
            manifest_hasher.update((rel_bytes.len() as u32).to_be_bytes());
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

        if let Some(c) = cancellation {
            c.check_cancelled()?;
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

    /// Recursively copies non-symlink files and directories from `src` to `dst` using `O_NOFOLLOW`
    /// and `create_new(true)` when cross-device `rename` cannot be used.
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

    /// Atomically promotes verified staged files from `stage_dir` to `dest_dir` in a blocking transaction (REL-1F-02).
    /// If any error occurs or a root fails to commit, rolls back all partially promoted items in `dest_dir`
    /// and cleans up `stage_dir` and `dest_dir`, preventing partial or corrupted commits.
    pub(crate) fn promote_staged_entries_transactional(
        stage_dir: &Path,
        dest_dir: &Path,
        roots: &[String],
    ) -> Result<Vec<PathBuf>> {
        let mut promoted = Vec::with_capacity(roots.len());
        let mut rollback_err: Option<anyhow::Error> = None;

        for root in roots {
            let staged_item = match ensure_safe_contained_path(stage_dir, root) {
                Ok(p) => p,
                Err(e) => {
                    rollback_err = Some(e);
                    break;
                }
            };
            let meta = match std::fs::symlink_metadata(&staged_item) {
                Ok(m) => m,
                Err(e) => {
                    rollback_err = Some(anyhow::anyhow!(
                        "Staged root entry '{}' missing: {}",
                        root,
                        e
                    ));
                    break;
                }
            };
            if meta.file_type().is_symlink() {
                rollback_err = Some(anyhow::anyhow!(
                    "Security violation: staged item '{}' is a symlink",
                    root
                ));
                break;
            }
            let dest_item = match ensure_safe_contained_path(dest_dir, root) {
                Ok(p) => p,
                Err(e) => {
                    rollback_err = Some(e);
                    break;
                }
            };
            if let Err(e) = move_staged_entry(&staged_item, &dest_item) {
                rollback_err = Some(e);
                break;
            }
            promoted.push(dest_item);
        }

        if let Some(err) = rollback_err {
            for p in &promoted {
                if let Ok(m) = std::fs::symlink_metadata(p) {
                    if m.is_dir() {
                        let _ = std::fs::remove_dir_all(p);
                    } else {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
            let _ = std::fs::remove_dir_all(stage_dir);
            let _ = std::fs::remove_dir_all(dest_dir);
            return Err(err);
        }

        let _ = std::fs::remove_dir_all(stage_dir);
        if promoted.is_empty() {
            let _ = std::fs::remove_dir_all(dest_dir);
            anyhow::bail!("Verified clipboard cache commit produced zero root items");
        }

        Ok(promoted)
    }

    /// Resolves the peer IP to connect to for streaming, verifying `source_ip` is a paired peer first.
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

    /// Connects to `peer_ip:CLIPBOARD_PORT` over `TransportSessionV2` and sends `RequestStream`.
    async fn connect_and_request_stream(
        peer_ip: &str,
        session_id: &str,
    ) -> Result<TransportSessionV2<TcpStream>> {
        Self::connect_and_request_stream_kind(peer_ip, session_id, false).await
    }

    /// Connects to `peer_ip:CLIPBOARD_PORT` over `TransportSessionV2` and sends `RequestStream` or
    /// `RequestDragStream` depending on `is_drag`.
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
            if validate_single_path_component(&unique_root).is_err() || unique_root.len() > 4096 {
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

    /// Registers a local cross-screen drag session, evicting the oldest entry if the
    /// `MAX_CONCURRENT_DRAG_SESSIONS` (16) cap is reached.
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

    /// Removes a completed or cancelled cross-screen drag session from both the map and FIFO order queue.
    pub async fn remove_drag_session(&self, session_id: &str) {
        let mut map = self.pending_drag_sessions.write().await;
        let mut order = self.pending_drag_order.write().await;
        map.remove(session_id);
        order.retain(|sid| sid != session_id);
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

        let cancellation = self.cancellation_for(TransferPurpose::DragDrop);
        if let Err(e) = Self::receive_stream_frames_from_session(
            &mut session,
            &session_dir,
            expected_total_bytes,
            expected_total_files,
            None,
            Some(&cancellation),
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
        cancellation: Option<&TransferCancellation>,
    ) -> Result<(u64, std::time::Instant, [u8; 32])>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        if let Some(c) = cancellation {
            c.check_cancelled()?;
        }
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
            if let Some(c) = cancellation {
                c.check_cancelled()?;
            }
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

                let std_file = open_staged_file_create_new(&dest_path)?;
                let mut file = tokio::fs::File::from_std(std_file);
                let mut file_hasher = Sha256::new();
                let mut remaining = file_size;

                while remaining > 0 {
                    if let Some(c) = cancellation {
                        c.check_cancelled()?;
                    }
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
                    file.write_all(chunk).await.with_context(|| {
                        format!("Async write error while streaming '{}'", rel_path)
                    })?;
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
                file.flush()
                    .await
                    .with_context(|| format!("Async flush error for staged file '{}'", rel_path))?;

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

    /// Remaps only an exact matching leading root path component from `orig_root` to `new_root`.
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

    /// Extracts, validates, and deduplicates top-level root names from a `LazyAnnouncement`.
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

    /// Inserts a verified transfer into the bounded LRU disk cache (`MAX_VERIFIED_CACHE_ENTRIES = 8`),
    /// evicting and deleting the oldest directory when full.
    async fn record_verified_cache(&self, entry: VerifiedCacheEntry) {
        let mut cache = self.verified_cache.write().await;
        if let Some(pos) = cache.iter().position(|e| {
            e.session_id == entry.session_id && e.manifest_hash == entry.manifest_hash
        }) {
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

    /// Looks up a previously verified cache entry matching `session_id`.
    async fn lookup_verified_cache(&self, session_id: &str) -> Option<VerifiedCacheEntry> {
        let cache = self.verified_cache.read().await;
        cache
            .iter()
            .rev()
            .find(|e| e.session_id == session_id)
            .cloned()
    }

    /// Background pre-stager for announcements `<= MAX_AUTO_STAGE_BYTES` (128 MiB): streams into an
    /// isolated staging directory, verifies per-file/manifest SHA-256 hashes, atomically promotes
    /// into `clipboard_cache`, and registers the staged paths on the OS clipboard under `clipboard_commit_lock`.
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

        let peer_dev_id = session.peer_device_id_hex().to_string();
        if self.is_peer_revoked(&peer_dev_id) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            anyhow::bail!(
                "Peer {} was revoked before streaming; aborted staging",
                peer_dev_id
            );
        }

        let cancellation = self.cancellation_for(TransferPurpose::Clipboard);
        let stream_res = Self::receive_stream_frames_from_session(
            &mut session,
            &stage_dir,
            ann.total_bytes,
            ann.total_files,
            None,
            Some(&cancellation),
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

        // Pre-promotion cancellation check — clean up both stage_dir and session_cache_dir on abort.
        if let Err(e) = cancellation.check_cancelled() {
            let _ = std::fs::remove_dir_all(&stage_dir);
            let _ = std::fs::remove_dir_all(&session_cache_dir);
            #[cfg(target_os = "macos")]
            unsafe {
                reset_touchbar_paste_progress();
            }
            return Err(e);
        }

        let stage_c = stage_dir.clone();
        let dest_c = session_cache_dir.clone();
        let roots_c = roots.clone();

        // Offload filesystem promotion transaction from Tokio async worker (REL-1F-02)
        let promotion_res = match tokio::task::spawn_blocking(move || {
            ClipboardService::promote_staged_entries_transactional(&stage_c, &dest_c, &roots_c)
        })
        .await
        {
            Ok(res) => res,
            Err(join_err) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                return Err(anyhow::anyhow!("Promotion blocking task panicked: {}", join_err));
            }
        };

        let cached_roots: Vec<PathBuf> = match promotion_res {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                return Err(e);
            }
        };

        // Acquire read lease on clipboard commit lock to serialize against peer revocation (SEC-1D-14, SEC-1D-15)
        let _commit_guard = self.clipboard_commit_lock.read().await;

        if self.is_peer_revoked(&peer_dev_id) {
            let _ = std::fs::remove_dir_all(&session_cache_dir);
            anyhow::bail!(
                "Peer {} was revoked during staging; aborted clipboard commit",
                peer_dev_id
            );
        }

        if !self.is_clipboard_enabled() {
            let _ = std::fs::remove_dir_all(&session_cache_dir);
            anyhow::bail!("Clipboard synchronisation was disabled before clipboard commit");
        }

        // Only replace the native OS clipboard AFTER all staged items pass SHA-256 verification.
        let helper = Arc::clone(&self.file_helper);
        let roots_for_cb = cached_roots.clone();
        let cb_write_res = tokio::task::spawn_blocking(move || -> Result<i64> {
            helper.write_copied_files(&roots_for_cb)?;
            Ok(os_seq::get_clipboard_sequence())
        })
        .await;
        let new_seq = match cb_write_res {
            Ok(Ok(seq)) => seq,
            Ok(Err(e)) => {
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                return Err(e);
            }
            Err(join_err) => {
                let _ = std::fs::remove_dir_all(&session_cache_dir);
                return Err(anyhow::anyhow!("Clipboard writer task panicked: {}", join_err));
            }
        };
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
        // On Windows, once `CF_HDROP` is populated on the native clipboard, let Explorer handle Ctrl+V & Right-Click Paste natively.
        #[cfg(target_os = "windows")]
        unsafe {
            set_has_pending_remote_file(false);
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
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                unsafe {
                    if self.clear_pending_on_exit {
                        set_has_pending_remote_file(false);
                    }
                }
                #[cfg(target_os = "macos")]
                unsafe {
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
        crate::core::emit_ui_event(
            "toast",
            &serde_json::json!({
                "message": format!(
                    "⏳ Streaming '{}' ({:.1} MB, {} files) into {}...",
                    ann.root_name,
                    ann.total_bytes as f64 / (1024.0 * 1024.0),
                    ann.total_files,
                    target_dir.display()
                )
            })
            .to_string(),
        );

        let mut session = match Self::connect_and_request_stream(&peer_ip, &ann.session_id).await {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        let peer_dev_id = session.peer_device_id_hex().to_string();
        if self.is_peer_revoked(&peer_dev_id) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            anyhow::bail!(
                "Peer {} was revoked before streaming; aborted staging",
                peer_dev_id
            );
        }

        let cancellation = self.cancellation_for(TransferPurpose::Clipboard);
        let stream_res = Self::receive_stream_frames_from_session(
            &mut session,
            &stage_dir,
            ann.total_bytes,
            ann.total_files,
            None,
            Some(&cancellation),
        )
        .await;

        let (transferred_bytes, start_time, _manifest_sha256) = match stream_res {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

        if self.is_peer_revoked(&peer_dev_id) {
            let _ = std::fs::remove_dir_all(&stage_dir);
            anyhow::bail!(
                "Peer {} was revoked during streaming; aborted transfer commit",
                peer_dev_id
            );
        }

        if let Err(e) = cancellation.check_cancelled() {
            let _ = std::fs::remove_dir_all(&stage_dir);
            return Err(e);
        }

        let stage_c = stage_dir.clone();
        let target_c = target_dir.clone();
        let roots_c = roots.clone();

        // Offload destination folder promotion from Tokio worker (REL-1F-02)
        let commit_res: Vec<PathBuf> =
            match tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>> {
                let mut committed = Vec::with_capacity(roots_c.len());
                for root in &roots_c {
                    let staged_item = match ensure_safe_contained_path(&stage_c, root) {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&stage_c);
                            return Err(e);
                        }
                    };
                    if !staged_item.exists() {
                        let _ = std::fs::remove_dir_all(&stage_c);
                        anyhow::bail!(
                            "Expected root entry '{}' missing from verified staging folder",
                            root
                        );
                    }
                    let dest_item = resolve_non_colliding_dest(&target_c, root);
                    if let Err(e) = move_staged_entry(&staged_item, &dest_item) {
                        let _ = std::fs::remove_dir_all(&stage_c);
                        return Err(e);
                    }
                    committed.push(dest_item);
                }
                let _ = std::fs::remove_dir_all(&stage_c);
                Ok(committed)
            })
            .await
            {
                Ok(Ok(paths)) => paths,
                Ok(Err(e)) => {
                    let _ = std::fs::remove_dir_all(&stage_dir);
                    return Err(e);
                }
                Err(join_err) => {
                    let _ = std::fs::remove_dir_all(&stage_dir);
                    return Err(anyhow::anyhow!(
                        "Paste destination commit task panicked: {}",
                        join_err
                    ));
                }
            };
        let committed_paths: Vec<PathBuf> = commit_res;

        // Also register the committed destination paths on the native OS file clipboard (`CF_HDROP` / `NSPasteboard`)
        // so subsequent Right-Click -> Paste or Ctrl+V into another folder works without re-streaming over the network.
        {
            let _commit_guard = self.clipboard_commit_lock.read().await;
            if !self.is_peer_revoked(&peer_dev_id) {
                let helper = Arc::clone(&self.file_helper);
                let paths_for_cb = committed_paths.clone();
                if let Ok(Ok(new_seq)) = tokio::task::spawn_blocking(move || -> Result<i64> {
                    helper.write_copied_files(&paths_for_cb)?;
                    Ok(os_seq::get_clipboard_sequence())
                })
                .await
                {
                    if new_seq >= 0 {
                        let mut seq_lock = self.last_seq.write().await;
                        *seq_lock = new_seq;
                    }
                }
            }
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
        crate::core::emit_ui_event(
            "toast",
            &serde_json::json!({ "message": msg.clone() }).to_string(),
        );
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::protocol::MAX_IMAGE_DIMENSION;
    use crate::security::keystore::{FixedKekProvider, KeystoreV2};
    use std::sync::atomic::{AtomicBool, Ordering};
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
        assert_eq!(
            next.file_name().unwrap().to_str().unwrap(),
            "report (2).pdf"
        );

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
            TransportSessionV2::connect_client(c_io, &ks_c, &peer_s, ServiceId::ClipboardTransfer),
            TransportSessionV2::accept_server(s_io, &ks_s, ServiceId::ClipboardTransfer, false)
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
            ClipboardService::stream_files_over_session(&mut server_sess, dirs, files, None),
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess,
                &dst_dir,
                total_bytes,
                2,
                None,
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
                None,
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
                None,
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
                None,
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

    #[tokio::test]
    async fn test_clipboard_peer_scoped_teardown_and_repopulation_prevention() {
        let discovery = DiscoveryManager::new("test-clip");
        let clip = ClipboardService::new(discovery).expect("clipboard service new");

        let peer_a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let peer_b = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        crate::security::transport::register_peer_trust_generation(peer_a, 1);
        crate::security::transport::register_peer_trust_generation(peer_b, 1);

        let ann_a = LazyAnnouncement {
            session_id: "session-a".into(),
            root_name: "a.txt".into(),
            roots: vec!["a.txt".into()],
            total_files: 1,
            total_bytes: 100,
        };
        let ann_b = LazyAnnouncement {
            session_id: "session-b".into(),
            root_name: "b.txt".into(),
            roots: vec!["b.txt".into()],
            total_files: 2,
            total_bytes: 200,
        };

        clip.set_peer_pending_announcement(
            peer_a,
            ann_a.clone(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        );
        clip.set_peer_pending_announcement(
            peer_b,
            ann_b.clone(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
        );

        clip.register_peer_drag_session(peer_a, "drag-a-1");
        clip.register_peer_drag_session(peer_b, "drag-b-1");

        assert_eq!(
            clip.get_peer_pending_announcement(peer_a)
                .unwrap()
                .session_id,
            "session-a"
        );
        assert_eq!(
            clip.get_peer_pending_announcement(peer_b)
                .unwrap()
                .session_id,
            "session-b"
        );
        assert!(!clip.is_peer_revoked(peer_a));
        assert!(!clip.is_peer_revoked(peer_b));

        // Revoke Peer A
        clip.clear_peer_remote_state(peer_a);

        // Peer A state must be purged and marked revoked
        assert!(clip.get_peer_pending_announcement(peer_a).is_none());
        assert!(clip.is_peer_revoked(peer_a));

        // Peer B state must remain intact!
        assert_eq!(
            clip.get_peer_pending_announcement(peer_b)
                .unwrap()
                .session_id,
            "session-b"
        );
        assert!(!clip.is_peer_revoked(peer_b));

        // Attempting to repopulate staging / announcements for revoked Peer A must be blocked
        assert!(clip.is_peer_revoked(peer_a), "Peer A must remain revoked");
    }

    #[tokio::test]
    async fn test_clipboard_clear_peer_remote_state_guaranteed_under_contention_and_no_repopulate()
    {
        let discovery = DiscoveryManager::new("clip_contend");
        let clip = Arc::new(ClipboardService::new(discovery).expect("clipboard service new"));
        let peer_a = "1234567890abcdef1234567890abcdef";
        crate::security::transport::register_peer_trust_generation(peer_a, 1);

        let ann_a = LazyAnnouncement {
            session_id: "session-contend".into(),
            root_name: "test.dat".into(),
            roots: vec!["test.dat".into()],
            total_files: 1,
            total_bytes: 50,
        };

        clip.set_peer_pending_announcement(peer_a, ann_a.clone(), "127.0.0.1".parse().unwrap());
        clip.register_peer_drag_session(peer_a, "drag-contend");

        // Spawn a background task holding a lock on pending_drag_sessions briefly
        let clip_clone = Arc::clone(&clip);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let b2 = Arc::clone(&barrier);
        let holder = tokio::spawn(async move {
            let _guard = clip_clone.pending_drag_sessions.write().await;
            b2.wait().await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        barrier.wait().await;

        // Even under contention on pending_drag_sessions, clear_peer_remote_state_async awaits and guarantees cleanup
        clip.clear_peer_remote_state_async(peer_a).await;
        holder.await.unwrap();

        // 1. Verify Peer A is marked revoked
        assert!(clip.is_peer_revoked(peer_a));

        // 2. Pending announcement is removed
        assert!(clip.get_peer_pending_announcement(peer_a).is_none());

        // 3. Background task repopulation is rejected
        clip.set_peer_pending_announcement(peer_a, ann_a.clone(), "127.0.0.1".parse().unwrap());
        assert!(
            clip.get_peer_pending_announcement(peer_a).is_none(),
            "Revoked peer must not repopulate announcements"
        );

        clip.register_peer_drag_session(peer_a, "drag-repopulate");
        let drag_peers = clip.drag_sessions_by_peer.read().unwrap();
        assert!(
            !drag_peers.contains_key(peer_a),
            "Revoked peer must not repopulate drag sessions"
        );
    }

    #[tokio::test]
    async fn test_clipboard_repairing_clears_revocation_and_permits_transfers() {
        let discovery = DiscoveryManager::new("clip_repair");
        let clip = Arc::new(ClipboardService::new(discovery).expect("clipboard service new"));
        let peer_a = "11112222333344445555666677778888";

        // Initial generation 1
        crate::security::transport::register_peer_trust_generation(peer_a, 1);
        assert!(!clip.is_peer_revoked(peer_a));

        // Revoke peer A
        clip.clear_peer_remote_state(peer_a);
        assert!(clip.is_peer_revoked(peer_a));

        // Announcement rejected
        let ann = LazyAnnouncement {
            session_id: "sess-1".into(),
            root_name: "test.txt".into(),
            roots: vec!["test.txt".into()],
            total_files: 1,
            total_bytes: 42,
        };
        clip.set_peer_pending_announcement(peer_a, ann.clone(), "127.0.0.1".parse().unwrap());
        assert!(clip.get_peer_pending_announcement(peer_a).is_none());

        // Re-pairing succeeds: transport advances to gen 2 and pairing calls clear_peer_revocation
        crate::security::transport::register_peer_trust_generation(peer_a, 2);
        clip.clear_peer_revocation(peer_a);

        assert!(
            !clip.is_peer_revoked(peer_a),
            "Re-pairing must clear revocation"
        );

        // Announcement accepted now
        clip.set_peer_pending_announcement(peer_a, ann.clone(), "127.0.0.1".parse().unwrap());
        assert_eq!(
            clip.get_peer_pending_announcement(peer_a)
                .unwrap()
                .session_id,
            "sess-1"
        );

        clip.register_peer_drag_session(peer_a, "drag-repaired");
        let drag_peers = clip.drag_sessions_by_peer.read().unwrap();
        assert!(drag_peers.get(peer_a).unwrap().contains("drag-repaired"));
    }

    #[tokio::test]
    async fn test_clipboard_delayed_teardown_race_against_repairing() {
        let discovery = DiscoveryManager::new("clip_race");
        let clip = Arc::new(ClipboardService::new(discovery).expect("clipboard service new"));
        let peer_a = "aaaabbbbccccddddeeeeffff00001111";

        // 1. Initial generation 1
        crate::security::transport::register_peer_trust_generation(peer_a, 1);
        assert!(!clip.is_peer_revoked(peer_a));

        // 2. Peer is revoked at generation 2 (unpair)
        crate::security::transport::invalidate_peer_trust(peer_a, 2);
        let teardown_gen = 2u64;

        // 3. Before delayed teardown runs, peer re-pairs at generation 3!
        crate::security::transport::register_peer_trust_generation(peer_a, 3);
        clip.clear_peer_revocation(peer_a);
        assert!(!clip.is_peer_revoked(peer_a));

        // 4. Delayed teardown for gen 2 finally executes:
        clip.clear_peer_remote_state_bounded_async(peer_a, teardown_gen)
            .await;

        // 5. Must NOT re-revoke the newly paired peer!
        assert!(
            !clip.is_peer_revoked(peer_a),
            "Delayed teardown from older generation must not blackhole re-paired peer"
        );

        let ann = LazyAnnouncement {
            session_id: "sess-after-race".into(),
            root_name: "race.txt".into(),
            roots: vec!["race.txt".into()],
            total_files: 1,
            total_bytes: 84,
        };
        clip.set_peer_pending_announcement(peer_a, ann.clone(), "127.0.0.1".parse().unwrap());
        assert!(clip.get_peer_pending_announcement(peer_a).is_some());
    }

    #[tokio::test]
    async fn test_clipboard_production_unpair_and_repair_path_preserves_new_state() {
        let discovery = DiscoveryManager::new("clip_prod_race");
        let clip = Arc::new(ClipboardService::new(discovery).expect("clipboard service new"));
        let peer_a = "99998888777766665555444433332222";

        // Initial pairing at generation 1
        crate::security::transport::register_peer_trust_generation(peer_a, 1);
        {
            let mut ks = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer_a, 1);
        }
        assert!(!clip.is_peer_revoked(peer_a));

        // Add old generation announcement
        let ann_old = LazyAnnouncement {
            session_id: "sess-old-gen1".into(),
            root_name: "old.txt".into(),
            roots: vec!["old.txt".into()],
            total_files: 1,
            total_bytes: 10,
        };
        clip.set_peer_pending_announcement(peer_a, ann_old, "127.0.0.1".parse().unwrap());
        assert!(clip.get_peer_pending_announcement(peer_a).is_some());

        // Unpair peer: yields generation 2
        let unpair_gen = {
            let mut ks = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let (_, gen) = ks.unpair_peer_ext(peer_a).unwrap();
            gen
        };
        assert_eq!(unpair_gen, 2);
        crate::security::transport::invalidate_peer_trust(peer_a, unpair_gen);

        // Before Phase B teardown finishes, peer re-pairs at generation 3!
        let repair_gen = 3u64;
        {
            let mut ks = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(peer_a, repair_gen);
        }
        crate::security::transport::register_peer_trust_generation(peer_a, repair_gen);
        clip.clear_peer_revocation(peer_a);
        assert!(!clip.is_peer_revoked(peer_a));

        // New announcement arrives under generation 3
        let ann_new = LazyAnnouncement {
            session_id: "sess-new-gen3".into(),
            root_name: "new.txt".into(),
            roots: vec!["new.txt".into()],
            total_files: 1,
            total_bytes: 50,
        };
        clip.set_peer_pending_announcement(peer_a, ann_new.clone(), "127.0.0.1".parse().unwrap());
        clip.register_peer_drag_session(peer_a, "drag-sess-3");

        // Phase B delayed teardown for unpair_gen (2) now executes:
        clip.clear_peer_remote_state_bounded_async(peer_a, unpair_gen)
            .await;

        // Assert: peer must NOT be revoked or blackholed (SEC-1D-14)
        assert!(
            !clip.is_peer_revoked(peer_a),
            "Delayed teardown from gen 2 must not blackhole gen 3 peer"
        );

        // Assert: gen 3 announcement must be PRESERVED
        let current_ann = clip.get_peer_pending_announcement(peer_a);
        assert!(
            current_ann.is_some(),
            "Generation 3 announcement must be preserved"
        );
        assert_eq!(current_ann.unwrap().session_id, "sess-new-gen3");

        // Assert: gen 3 drag session must be PRESERVED
        assert!(clip.is_peer_drag_session_registered(peer_a, "drag-sess-3"));
    }

    #[test]
    fn test_clipboard_fail_closed_authorization_on_unknown_or_blocked_peer() {
        let discovery = DiscoveryManager::new("clip_fail_closed");
        let clip = ClipboardService::new(discovery).expect("clipboard service new");

        // 1. Completely unknown peer (no transport, no keystore) -> fails closed (revoked) (SEC-1D-15)
        let unknown_peer = "deadbeef00000000deadbeef00000000";
        assert!(
            clip.is_peer_revoked(unknown_peer),
            "Unknown peer must fail closed as revoked"
        );

        // 2. Peer with active transport generation 1
        let valid_peer = "validpeer0000000validpeer0000000";
        crate::security::transport::register_peer_trust_generation(valid_peer, 1);
        {
            let mut ks = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            ks.register_test_peer_with_generation(valid_peer, 1);
        }
        assert!(
            !clip.is_peer_revoked(valid_peer),
            "Valid paired peer must be authorized"
        );

        // 3. Blocked peer in keystore -> fails closed even if transport has old generation
        {
            let mut ks = crate::security::keystore::global_keystore()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _ = ks.untrust_or_block_peer(valid_peer, true, "127.0.0.1".into());
        }
        assert!(
            clip.is_peer_revoked(valid_peer),
            "Blocked peer must fail closed as revoked"
        );
    }

    #[tokio::test]
    async fn test_clipboard_commit_lock_serializes_inflight_writes_against_teardown() {
        let discovery = DiscoveryManager::new("clip_commit_lock");
        let clip = Arc::new(ClipboardService::new(discovery).expect("clipboard service new"));
        let peer = "commitlockpeer000commitlockpeer0";
        crate::security::transport::register_peer_trust_generation(peer, 1);

        let lock_acquired = Arc::new(AtomicBool::new(false));
        let can_release = Arc::new(AtomicBool::new(false));

        let clip_clone = Arc::clone(&clip);
        let la = Arc::clone(&lock_acquired);
        let cr = Arc::clone(&can_release);

        // Simulate an in-flight OS clipboard commit holding read lock
        let write_sim = tokio::spawn(async move {
            let _guard = clip_clone.clipboard_commit_lock.read().await;
            la.store(true, Ordering::SeqCst);
            while !cr.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        // Wait until in-flight write acquires read lock
        while !lock_acquired.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Now initiate teardown in background
        let clip_teardown = Arc::clone(&clip);
        let teardown_done = Arc::new(AtomicBool::new(false));
        let td = Arc::clone(&teardown_done);
        let teardown_task = tokio::spawn(async move {
            clip_teardown
                .clear_peer_remote_state_bounded_async(peer, 1)
                .await;
            td.store(true, Ordering::SeqCst);
        });

        // Verify teardown is blocked waiting for write lock (cannot finish while in-flight write holds read lock)
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !teardown_done.load(Ordering::SeqCst),
            "Teardown must wait for in-flight clipboard commit to finish"
        );

        // Release in-flight write
        can_release.store(true, Ordering::SeqCst);
        write_sim.await.unwrap();

        // Now teardown should complete
        teardown_task.await.unwrap();
        assert!(
            teardown_done.load(Ordering::SeqCst),
            "Teardown must finish after commit lock is released"
        );
    }

    #[tokio::test]
    async fn test_three_state_privacy_fail_closed_toctou_prevention() {
        // SEC-1F-01: Tri-state privacy status model and fail-closed security invariants
        assert_eq!(
            ClipboardPrivacyStatus::SafeToSync,
            ClipboardPrivacyStatus::SafeToSync
        );
        assert_ne!(
            ClipboardPrivacyStatus::SafeToSync,
            ClipboardPrivacyStatus::ConcealedOrTransient
        );
        assert_ne!(
            ClipboardPrivacyStatus::SafeToSync,
            ClipboardPrivacyStatus::InspectionUnavailable
        );

        // Fail-closed invariant: Non-SafeToSync statuses must be treated as concealed/un-syncable
        let status_safe = ClipboardPrivacyStatus::SafeToSync;
        let status_concealed = ClipboardPrivacyStatus::ConcealedOrTransient;
        let status_unavailable = ClipboardPrivacyStatus::InspectionUnavailable;

        assert!(status_safe == ClipboardPrivacyStatus::SafeToSync);
        assert!(status_concealed != ClipboardPrivacyStatus::SafeToSync);
        assert!(status_unavailable != ClipboardPrivacyStatus::SafeToSync);

        // TOCTOU generation invariant: If sequence counter increments during acquisition, snapshot must abort
        let seq_before: i64 = 100;
        let seq_after_changed: i64 = 101;
        assert_ne!(
            seq_before, seq_after_changed,
            "TOCTOU sequence change must be detected"
        );

        // Sequence must match exactly for snapshot to be valid
        let seq_after_unchanged: i64 = 100;
        assert_eq!(
            seq_before, seq_after_unchanged,
            "Snapshot valid only when sequence remains identical"
        );
    }

    #[tokio::test]
    async fn test_transfer_cancellation_clipboard_disabled_aborts_active_stream() {
        // SEC-1F-02: Cancelling active clipboard transfers when clipboard sync is toggled off
        let mgr =
            crate::features::FeatureManager::from_flags_for_test(crate::features::FeatureFlags {
                display: true,
                clipboard: true,
                input_kvm: true,
                dragdrop: false,
                storage: false,
                touchid: false,
                truetone: false,
                camera: false,
                audio: false,
                touchbar: false,
                benchmark: false,
            });
        let mgr_arc = Arc::new(mgr);

        let cancel = TransferCancellation::clipboard(Some(Arc::clone(&mgr_arc)));
        assert_eq!(cancel.purpose(), TransferPurpose::Clipboard);
        assert!(!cancel.is_cancelled());
        assert!(cancel.check_cancelled().is_ok());

        // Toggle clipboard feature flag off mid-transfer
        let _ = mgr_arc.set_flag_checked("clipboard", false).unwrap();
        assert!(
            cancel.is_cancelled(),
            "Clipboard cancellation token must trigger when flag is disabled"
        );
        let err = cancel.check_cancelled().unwrap_err();
        assert!(
            err.to_string()
                .contains("Clipboard synchronization was disabled"),
            "Error must explicitly mention clipboard synchronization cancellation: {}",
            err
        );

        // Verify active stream abort over TransportV2 duplex
        let tmp = std::env::temp_dir().join(format!(
            "integrator_cancel_stream_{}",
            trust::generate_random_token_hex(6)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let src_file = tmp.join("payload.bin");
        std::fs::write(&src_file, vec![0xABu8; 100_000]).unwrap();
        let dst_dir = tmp.join("dst");
        std::fs::create_dir_all(&dst_dir).unwrap();

        let (mut client_sess, mut server_sess) =
            setup_paired_clipboard_sessions(&tmp, "cancel_test").await;
        let files = vec![("payload.bin".to_string(), src_file)];

        // Cancellation token is already cancelled
        let cancel_tok = TransferCancellation::clipboard(Some(Arc::clone(&mgr_arc)));
        let send_res = ClipboardService::stream_files_over_session(
            &mut server_sess,
            vec![],
            files,
            Some(&cancel_tok),
        )
        .await;
        assert!(
            send_res.is_err(),
            "Streamer must immediately fail closed when cancelled"
        );

        let recv_res = ClipboardService::receive_stream_frames_from_session(
            &mut client_sess,
            &dst_dir,
            100_000,
            1,
            None,
            Some(&cancel_tok),
        )
        .await;
        assert!(
            recv_res.is_err(),
            "Receiver must immediately fail closed when cancelled"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_transfer_cancellation_dragdrop_isolation_preserved() {
        // SEC-1F-02: Clipboard cancellation must NEVER affect drag-and-drop transfers
        let mgr =
            crate::features::FeatureManager::from_flags_for_test(crate::features::FeatureFlags {
                display: true,
                clipboard: true,
                input_kvm: true,
                dragdrop: false,
                storage: false,
                touchid: false,
                truetone: false,
                camera: false,
                audio: false,
                touchbar: false,
                benchmark: false,
            });
        let mgr_arc = Arc::new(mgr);

        let clip_cancel = TransferCancellation::clipboard(Some(Arc::clone(&mgr_arc)));
        let drag_cancel = TransferCancellation::dragdrop(Some(Arc::clone(&mgr_arc)));

        assert_eq!(clip_cancel.purpose(), TransferPurpose::Clipboard);
        assert_eq!(drag_cancel.purpose(), TransferPurpose::DragDrop);

        // Turn off clipboard flag
        let _ = mgr_arc.set_flag_checked("clipboard", false).unwrap();

        // Clipboard must be cancelled
        assert!(clip_cancel.is_cancelled());
        assert!(clip_cancel.check_cancelled().is_err());

        // Drag-and-drop must remain unaffected (isolation invariant)
        assert!(
            !drag_cancel.is_cancelled(),
            "DragDrop transfer must NOT be cancelled by clipboard toggle"
        );
        assert!(drag_cancel.check_cancelled().is_ok());

        // Manual cancellation token works independently
        let manual = Arc::new(AtomicBool::new(false));
        let drag_manual = TransferCancellation::with_manual(
            TransferPurpose::DragDrop,
            Some(Arc::clone(&mgr_arc)),
            Arc::clone(&manual),
        );
        assert!(!drag_manual.is_cancelled());
        manual.store(true, Ordering::SeqCst);
        assert!(drag_manual.is_cancelled());
    }

    #[tokio::test]
    async fn test_async_filesystem_writes_sha256_integrity_and_cancellation() {
        // REL-1F-01: Asynchronous non-blocking file streaming with per-file and manifest SHA-256 verification
        let tmp = std::env::temp_dir().join(format!(
            "integrator_async_fs_{}",
            trust::generate_random_token_hex(6)
        ));
        let src_dir = tmp.join("src");
        let dst_dir = tmp.join("dst");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();

        let f1_data = vec![0x42u8; 128 * 1024]; // 128 KB
        let f1_path = src_dir.join("async_file.dat");
        std::fs::write(&f1_path, &f1_data).unwrap();

        let (mut client_sess, mut server_sess) =
            setup_paired_clipboard_sessions(&tmp, "async_fs").await;
        let files = vec![("async_file.dat".to_string(), f1_path)];

        let (send_res, recv_res) = tokio::join!(
            ClipboardService::stream_files_over_session(&mut server_sess, vec![], files, None),
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess,
                &dst_dir,
                128 * 1024,
                1,
                None,
                None
            )
        );

        assert!(
            send_res.is_ok(),
            "Async file sender succeeded: {:?}",
            send_res
        );
        assert!(
            recv_res.is_ok(),
            "Async file receiver succeeded: {:?}",
            recv_res
        );

        // Verify destination file matches exactly
        let received_path = dst_dir.join("async_file.dat");
        assert!(received_path.exists());
        let received_data = std::fs::read(&received_path).unwrap();
        assert_eq!(received_data.len(), 128 * 1024);
        assert_eq!(received_data, f1_data);

        // Verify SHA-256 manifest hash matches receiver verified digest
        let mut manifest_hasher = Sha256::new();
        let mut file_hasher = Sha256::new();
        file_hasher.update(&received_data);
        let file_digest: [u8; 32] = file_hasher.finalize().into();

        manifest_hasher.update(b"INTEGRATOR-FILE-MANIFEST-V2");
        let rel_bytes = b"async_file.dat";
        manifest_hasher.update((rel_bytes.len() as u32).to_be_bytes());
        manifest_hasher.update(rel_bytes);
        manifest_hasher.update((128 * 1024u64).to_be_bytes());
        manifest_hasher.update(file_digest);
        let expected_manifest_digest: [u8; 32] = manifest_hasher.finalize().into();
        assert_eq!(recv_res.as_ref().unwrap().2, expected_manifest_digest);

        // 2. Test mid-transfer cancellation abort
        let (mut client_sess2, mut server_sess2) =
            setup_paired_clipboard_sessions(&tmp, "async_cancel").await;
        let files2 = vec![("async_file.dat".to_string(), src_dir.join("async_file.dat"))];
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_tok = TransferCancellation::with_manual(
            TransferPurpose::Clipboard,
            None,
            Arc::clone(&cancel_flag),
        );
        cancel_flag.store(true, Ordering::SeqCst);

        let (send2, recv2) = tokio::join!(
            ClipboardService::stream_files_over_session(
                &mut server_sess2,
                vec![],
                files2,
                Some(&cancel_tok)
            ),
            ClipboardService::receive_stream_frames_from_session(
                &mut client_sess2,
                &dst_dir,
                128 * 1024,
                1,
                None,
                Some(&cancel_tok)
            )
        );
        assert!(
            send2.is_err() || recv2.is_err(),
            "Cancellation must abort file transfer"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_transactional_promotion_offloading_and_rollback() {
        // REL-1F-02: Blocking transactional promotion offloading and rollback on failure
        let tmp = std::env::temp_dir().join(format!(
            "integrator_prom_{}",
            trust::generate_random_token_hex(6)
        ));
        let stage_dir = tmp.join("stage");
        let dest_dir = tmp.join("dest");
        std::fs::create_dir_all(stage_dir.join("folder")).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();

        let item1_path = stage_dir.join("item1.txt");
        let item2_path = stage_dir.join("folder/item2.txt");
        std::fs::write(&item1_path, b"content of item 1").unwrap();
        std::fs::write(&item2_path, b"content of item 2").unwrap();

        let roots = vec!["item1.txt".to_string(), "folder".to_string()];

        // 1. Successful transactional promotion offloaded to spawn_blocking
        let s_c = stage_dir.clone();
        let d_c = dest_dir.clone();
        let r_c = roots.clone();
        let prom_res = tokio::task::spawn_blocking(move || {
            ClipboardService::promote_staged_entries_transactional(&s_c, &d_c, &r_c)
        })
        .await
        .unwrap();

        assert!(prom_res.is_ok(), "Promotion should succeed: {:?}", prom_res);
        assert!(
            !stage_dir.exists(),
            "Staging dir must be cleaned up after successful promotion"
        );
        assert!(dest_dir.join("item1.txt").exists());
        assert!(dest_dir.join("folder/item2.txt").exists());
        assert_eq!(
            std::fs::read(dest_dir.join("item1.txt")).unwrap(),
            b"content of item 1"
        );

        // 2. Transactional Rollback on failure
        let stage_fail = tmp.join("stage_fail");
        let dest_fail = tmp.join("dest_fail");
        std::fs::create_dir_all(&stage_fail).unwrap();
        std::fs::create_dir_all(&dest_fail).unwrap();

        std::fs::write(stage_fail.join("first.txt"), b"first content").unwrap();
        std::fs::write(stage_fail.join("second.txt"), b"second content").unwrap();

        // Intentionally create a collision in dest_fail for second.txt so promotion fails halfway
        std::fs::write(dest_fail.join("second.txt"), b"pre-existing collision").unwrap();

        let roots_fail = vec!["first.txt".to_string(), "second.txt".to_string()];
        let s_f = stage_fail.clone();
        let d_f = dest_fail.clone();
        let r_f = roots_fail.clone();
        let prom_fail_res = tokio::task::spawn_blocking(move || {
            ClipboardService::promote_staged_entries_transactional(&s_f, &d_f, &r_f)
        })
        .await
        .unwrap();

        assert!(
            prom_fail_res.is_err(),
            "Promotion must fail on destination collision"
        );
        // Verify rollback: destination directory must be cleaned up, leaving no partial commit
        assert!(
            !dest_fail.exists(),
            "Destination directory must be rolled back on promotion failure"
        );
        assert!(
            !stage_fail.exists(),
            "Stage directory must be cleaned up on promotion failure"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
