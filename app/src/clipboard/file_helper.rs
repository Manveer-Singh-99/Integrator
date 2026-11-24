//! # Cross-Platform Native OS File Clipboard Driver
//!
//! ## 1. Module Purpose & Scope
//! This module provides the native OS clipboard integration for file and directory copying on
//! macOS and Windows 10/11.
//!
//! ### Core Subsystem Responsibilities:
//! - **macOS File Clipboard (`NSPasteboard`)**: Reads and writes file URL lists using linked Swift
//!   FFI bindings (`read_pasteboard_files_in_app` / `write_pasteboard_files_in_app`) operating over
//!   `\0`-delimited UTF-8 byte streams. Falls back to the isolated helper binary `macos_clip_files --nul`
//!   if in-process AppKit calls fail or encounter sandbox boundaries.
//! - **Windows File Clipboard (`CF_HDROP` / `DROPFILES`)**: Directly manages native Win32 clipboard
//!   APIs (`OpenClipboard`, `EmptyClipboard`, `SetClipboardData`) using a message-only `HWND_MESSAGE`
//!   owner window to ensure clipboard ownership is retained without locking desktop foreground threads.
//!   Encodes wide character strings (`DROPFILES` struct with `fWide = TRUE`). Falls back to
//!   `win_clip_files.exe --nul` if COM STA isolation is required.
//! - **Cache Directory Lifecycle & Pruning**: Enforces private directory permissions (`0o700`),
//!   strictly forbids symlink traversals, and performs periodic depth-first pruning (`PRUNE_INTERVAL = 300s`)
//!   to clean up expired clipboard files older than 24 hours.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                         Native File Clipboard Integration                              │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                      ┌────────────────────────────────────────┐
//!                      │       ClipboardService (service.rs)    │
//!                      └──────────────────┬─────────────────────┘
//!                                         │
//!                     read_files()        │ write_files(paths)
//!                                         ▼
//!                      ┌────────────────────────────────────────┐
//!                      │    FileClipboardHelper (file_helper.rs)│
//!                      └──────────┬──────────────────┬──────────┘
//!                                 │                  │
//!               macOS Compilation │                  │ Windows Compilation
//!                                 ▼                  ▼
//!              ┌─────────────────────────┐    ┌─────────────────────────┐
//!              │  Swift AppKit FFI       │    │  Win32 User32 / Shell32 │
//!              │  (NSPasteboard fileURLs)│    │  (CF_HDROP / DROPFILES) │
//!              └────────────┬────────────┘    └────────────┬────────────┘
//!                           │                              │
//!                   Fallback│                      Fallback│
//!                           ▼                              ▼
//!              ┌─────────────────────────┐    ┌─────────────────────────┐
//!              │  macos_clip_files --nul │    │ win_clip_files.exe --nul│
//!              └─────────────────────────┘    └─────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/clipboard/service.rs`: Calls `read_files` when the OS sequence changes to detect newly
//!   copied files, and calls `write_files` upon successfully streaming incoming files to register
//!   them in the local OS clipboard.
//!
//! ### Downstream Callees:
//! - macOS Swift FFI: `read_pasteboard_files_in_app`, `write_pasteboard_files_in_app`.
//! - Windows Win32 APIs: `user32.dll`, `shell32.dll`.
//! - Local Filesystem: Private cache directory management under `app_data_dir() / "clipboard_cache"`.
//!
//! ## 3. Threading & Concurrency Model
//! - Designed for execution inside `tokio::task::spawn_blocking` pools since Win32 clipboard calls
//!   and disk walks perform synchronous blocking I/O.
//! - `last_prune` is guarded by an internal `Mutex<Instant>` to ensure background pruning is throttled
//!   to at most once every 5 minutes regardless of clipboard read frequency.
//!
//! ## 4. Security & Safety Invariants
//! - **Symlink Rejection**: Both the base application data directory and the `clipboard_cache`
//!   directory are checked via `symlink_metadata`. If any component is a symlink, execution bails immediately.
//! - **NUL-Delimited Path Parsing**: Paths are exchanged using `\0`-delimiters without `.trim()` mangling,
//!   preserving valid whitespace in filenames while rejecting interior NUL characters.
//! - **Subprocess Hardening**: When spawning fallback binaries, Windows applies `CREATE_NO_WINDOW = 0x08000000`,
//!   preventing flashing command prompt windows on the user's screen.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

#[cfg(target_os = "macos")]
extern "C" {
    /// Swift AppKit FFI: copies `\0`-delimited UTF-8 file paths from `NSPasteboard.generalPasteboard`
    /// into `out_buf` (up to `cap` bytes). Returns byte count (`> 0`), `0` if no files are present,
    /// or `< 0` if `cap` was insufficient.
    fn read_pasteboard_files_in_app(out_buf: *mut u8, cap: usize) -> isize;
    /// Swift AppKit FFI: writes `\0`-delimited UTF-8 file paths (`paths_ptr`, `len` bytes) as
    /// `NSURL` file objects onto `NSPasteboard.generalPasteboard`.
    fn write_pasteboard_files_in_app(paths_ptr: *const u8, len: usize) -> bool;
}

/// Minimum interval between automatic background disk cache pruning passes (300 seconds / 5 minutes).
const PRUNE_INTERVAL: Duration = Duration::from_secs(300);
/// Maximum directory recursion depth when computing cached item byte sizes (64 levels).
const MAX_CACHE_WALK_DEPTH: usize = 64;
/// Initial stack/heap buffer capacity in bytes for in-process macOS `NSPasteboard` file path reads (64 KiB).
#[cfg(target_os = "macos")]
const MACOS_INITIAL_READ_CAP: usize = 64 * 1024;
/// Retry buffer capacity in bytes when a multi-file macOS `NSPasteboard` selection exceeds 64 KiB (2 MiB).
#[cfg(target_os = "macos")]
const MACOS_RETRY_READ_CAP: usize = 2 * 1024 * 1024;
/// Default maximum retention age in days for cached clipboard files (3 days).
const DEFAULT_CACHE_MAX_AGE_DAYS: u64 = 3;
/// Default maximum cumulative disk budget in bytes for cached clipboard files (10 GiB).
const DEFAULT_CACHE_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Fallback macOS file-clipboard helper binary name.
#[cfg(target_os = "macos")]
const MACOS_CLIP_HELPER_BIN: &str = "macos_clip_files";
/// Fallback Windows file-clipboard helper binary name.
#[cfg(target_os = "windows")]
const WIN_CLIP_HELPER_BIN: &str = "win_clip_files.exe";
/// Win32 process creation flag suppressing console window creation (`0x08000000`).
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Cross-platform helper managing native file clipboard interactions and disk cache lifecycle.
pub struct FileClipboardHelper {
    /// Isolated filesystem directory where staged clipboard files are written.
    cache_dir: PathBuf,
    /// Timestamp of the most recent disk cache cleanup walk.
    last_prune: Mutex<Instant>,
}

/// Ensures `cache_dir` exists as a private real directory (never following a symlink).
fn ensure_private_cache_dir(base_dir: &Path) -> Result<PathBuf> {
    if let Ok(meta) = std::fs::symlink_metadata(base_dir) {
        if meta.file_type().is_symlink() {
            bail!(
                "Refusing symlinked clipboard base directory: {}",
                base_dir.display()
            );
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut db = std::fs::DirBuilder::new();
            db.recursive(true).mode(0o700);
            db.create(base_dir)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(base_dir)?;
        }
    }

    let cache_dir = base_dir.join(crate::config::CLIPBOARD_CACHE_DIR_NAME);
    match std::fs::symlink_metadata(&cache_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                bail!(
                    "Refusing non-directory or symlinked clipboard cache path: {}",
                    cache_dir.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &cache_dir,
                    std::fs::Permissions::from_mode(0o700),
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let create_res = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut db = std::fs::DirBuilder::new();
                    db.mode(0o700);
                    db.create(&cache_dir)
                }
                #[cfg(not(unix))]
                {
                    std::fs::create_dir(&cache_dir)
                }
            };
            match create_res {
                Ok(()) => {}
                Err(ce) if ce.kind() == std::io::ErrorKind::AlreadyExists => {
                    let meta = std::fs::symlink_metadata(&cache_dir)?;
                    if meta.file_type().is_symlink() || !meta.is_dir() {
                        bail!(
                            "Refusing non-directory or symlinked clipboard cache path: {}",
                            cache_dir.display()
                        );
                    }
                }
                Err(ce) => return Err(ce.into()),
            }
        }
        Err(e) => return Err(e.into()),
    }

    Ok(cache_dir)
}

/// Splits a `\0`-delimited UTF-8 byte stream into ordered unique `PathBuf`s without `.trim()` mangling.
pub(crate) fn parse_nul_paths(bytes: &[u8]) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for segment in bytes.split(|&b| b == 0) {
        if segment.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(segment) {
            if !s.is_empty() {
                let pb = PathBuf::from(s);
                if seen.insert(pb.clone()) {
                    out.push(pb);
                }
            }
        }
    }
    out
}

/// Serializes paths as `\0`-delimited UTF-8 bytes while rejecting empty or interior-NUL paths.
pub(crate) fn serialize_nul_paths(files: &[PathBuf]) -> Result<Vec<u8>> {
    if files.is_empty() {
        bail!("No file paths provided for clipboard write");
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in files {
        let s = path
            .to_str()
            .context("Clipboard file path contains non-UTF-8 sequences")?;
        if s.is_empty() || s.as_bytes().contains(&0) {
            bail!("Invalid clipboard file path (empty or interior NUL)");
        }
        if seen.insert(s.to_owned()) {
            if !out.is_empty() {
                out.push(0);
            }
            out.extend_from_slice(s.as_bytes());
        }
    }
    if out.is_empty() {
        bail!("No valid file paths provided for clipboard write");
    }
    Ok(out)
}

impl FileClipboardHelper {
    /// Initializes the file clipboard helper using the default private `clipboard_cache` directory
    /// under `app_data_dir()` and performs an initial cache prune pass.
    pub fn new() -> Result<Self> {
        let base_dir = crate::system_info::app_data_dir();
        let cache_dir = ensure_private_cache_dir(&base_dir)?;
        Self::new_in_dir(cache_dir)
    }

    /// Initializes a `FileClipboardHelper` rooted at a specific `cache_dir` (used by `new()` and tests).
    pub(crate) fn new_in_dir(cache_dir: PathBuf) -> Result<Self> {
        let helper = Self {
            cache_dir,
            last_prune: Mutex::new(Instant::now()),
        };
        helper.prune_cache(DEFAULT_CACHE_MAX_AGE_DAYS, DEFAULT_CACHE_MAX_BYTES);
        Ok(helper)
    }

    /// Returns the filesystem path to the isolated clipboard cache directory.
    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Triggers a cache pruning sweep if at least `PRUNE_INTERVAL` (5 minutes) has elapsed
    /// since the previous sweep.
    pub(crate) fn maybe_prune_cache(&self) {
        let should_prune = {
            if let Ok(mut guard) = self.last_prune.lock() {
                if guard.elapsed() >= PRUNE_INTERVAL {
                    *guard = Instant::now();
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if should_prune {
            self.prune_cache(DEFAULT_CACHE_MAX_AGE_DAYS, DEFAULT_CACHE_MAX_BYTES);
        }
    }

    /// Persistent security, configuration, identity, and state files stored alongside app data
    /// that must never be evicted by cache pruning.
    pub(crate) fn is_persistent_state_file(path: &Path) -> bool {
        let Some(name_os) = path.file_name() else {
            return false;
        };
        let name = name_os.to_string_lossy().to_ascii_lowercase();
        const EXACT_PROTECTED: &[&str] = &[
            "security",
            crate::config::CLIPBOARD_CACHE_DIR_NAME,
            "trusted_peers.json",
            "trusted_peers_v2.json",
            "trust_config.json",
            "peer_history.json",
            "features.json",
            crate::config::APP_CONFIG_FILENAME,
            crate::config::KVM_LAYOUT_FILE,
            "active_mount.json",
            ".master_kek_v2.seed",
        ];
        if EXACT_PROTECTED.contains(&name.as_str()) {
            return true;
        }
        const PREFIX_PROTECTED: &[&str] = &[
            "trusted_peers",
            "trust_config",
            "peer_history",
            "features.json.",
            "app_config.json.",
            "kvm_layout.json.",
            "active_mount.json.",
            ".master_kek",
            crate::config::SUNSHINE_ADAPTER_OVERRIDE_PREFIX,
        ];
        PREFIX_PROTECTED.iter().any(|p| name.starts_with(p))
    }

    /// Removes expired staging directories/files and enforces the `max_bytes` cache budget.
    pub fn prune_cache(&self, max_age_days: u64, max_bytes: u64) {
        let Ok(entries) = std::fs::read_dir(&self.cache_dir) else {
            return;
        };

        let now = SystemTime::now();
        let max_age = Duration::from_secs(max_age_days.saturating_mul(24 * 60 * 60));
        let mut items: Vec<(PathBuf, bool, bool, SystemTime, u64)> = Vec::new();
        let mut total_size: u64 = 0;

        for entry in entries.flatten() {
            let p = entry.path();
            if Self::is_persistent_state_file(&p) {
                continue;
            }
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                let is_symlink = meta.file_type().is_symlink();
                let is_dir = !is_symlink && meta.is_dir();
                // Missing/unreadable mtime falls back to UNIX_EPOCH so orphaned corrupt items are evicted first.
                let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
                let size = if is_symlink {
                    meta.len()
                } else if is_dir {
                    Self::calculate_dir_size_depth(&p, 0)
                } else {
                    meta.len()
                };

                let age = now.duration_since(mtime).unwrap_or_default();
                if age > max_age {
                    let removed = if is_dir {
                        std::fs::remove_dir_all(&p).is_ok()
                    } else {
                        std::fs::remove_file(&p).is_ok()
                    };
                    if removed {
                        continue;
                    }
                }

                total_size = total_size.saturating_add(size);
                items.push((p, is_dir, is_symlink, mtime, size));
            }
        }

        if total_size > max_bytes {
            items.sort_by_key(|item| item.3);
            for (p, is_dir, _is_symlink, _, size) in items {
                if total_size <= max_bytes {
                    break;
                }
                let removed = if is_dir {
                    std::fs::remove_dir_all(&p).is_ok()
                } else {
                    std::fs::remove_file(&p).is_ok()
                };
                if removed {
                    total_size = total_size.saturating_sub(size);
                }
            }
        }
    }

    /// Recursively computes the cumulative byte size of a directory tree up to `MAX_CACHE_WALK_DEPTH`,
    /// ignoring symlinks to prevent directory cycle loops.
    fn calculate_dir_size_depth(path: &Path, depth: usize) -> u64 {
        if depth >= MAX_CACHE_WALK_DEPTH {
            return 0;
        }
        let mut total: u64 = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Ok(meta) = std::fs::symlink_metadata(&p) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if meta.is_dir() {
                        total = total.saturating_add(Self::calculate_dir_size_depth(&p, depth + 1));
                    } else {
                        total = total.saturating_add(meta.len());
                    }
                }
            }
        }
        total
    }

    /// Resolves an application helper binary by name via `system_info::find_app_helper`.
    fn find_helper(name: &str) -> Option<PathBuf> {
        crate::system_info::find_app_helper(name)
    }

    /// Reads currently copied file paths from the OS clipboard.
    pub fn read_copied_files(&self) -> Vec<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; MACOS_INITIAL_READ_CAP];
            let n = unsafe { read_pasteboard_files_in_app(buf.as_mut_ptr(), buf.len()) };
            if n == 0 {
                return Vec::new();
            }
            if n > 0 && (n as usize) <= buf.len() {
                return parse_nul_paths(&buf[..n as usize]);
            }
            if n < 0 {
                let mut big_buf = vec![0u8; MACOS_RETRY_READ_CAP];
                let n2 = unsafe {
                    read_pasteboard_files_in_app(big_buf.as_mut_ptr(), big_buf.len())
                };
                if n2 == 0 {
                    return Vec::new();
                }
                if n2 > 0 && (n2 as usize) <= big_buf.len() {
                    return parse_nul_paths(&big_buf[..n2 as usize]);
                }
            }

            if let Some(helper) = Self::find_helper(MACOS_CLIP_HELPER_BIN) {
                match Command::new(&helper).args(["read", "--nul"]).output() {
                    Ok(output) if output.status.success() => {
                        return parse_nul_paths(&output.stdout);
                    }
                    Ok(output) => {
                        warn!(
                            "macos_clip_files read failed ({:?}): {}",
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to spawn macos_clip_files fallback: {}", e);
                    }
                }
            }
            Vec::new()
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;

            match win32::read_cf_hdrop_files() {
                Ok(Some(paths)) => return paths,
                Ok(None) => return Vec::new(),
                Err(e) => {
                    warn!(
                        "Native Win32 CF_HDROP read failed ({}); trying win_clip_files.exe fallback",
                        e
                    );
                }
            }

            if let Some(helper) = Self::find_helper(WIN_CLIP_HELPER_BIN) {
                let mut cmd = Command::new(&helper);
                cmd.args(["read", "--nul"]).creation_flags(CREATE_NO_WINDOW);
                match cmd.output() {
                    Ok(output) if output.status.success() => {
                        return parse_nul_paths(&output.stdout);
                    }
                    Ok(output) => {
                        warn!(
                            "win_clip_files.exe read failed ({:?}): {}",
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to spawn win_clip_files.exe fallback: {}", e);
                    }
                }
            }
            Vec::new()
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Vec::new()
        }
    }

    /// Writes local staged file paths onto the OS clipboard so native Cmd+V / Ctrl+V works.
    pub fn write_copied_files(&self, files: &[PathBuf]) -> Result<()> {
        let nul_bytes = serialize_nul_paths(files)?;

        #[cfg(target_os = "macos")]
        {
            if unsafe { write_pasteboard_files_in_app(nul_bytes.as_ptr(), nul_bytes.len()) } {
                return Ok(());
            }

            let helper = Self::find_helper(MACOS_CLIP_HELPER_BIN).context(
                "macos_clip_files helper not found and in-process NSPasteboard write failed",
            )?;
            let mut child = Command::new(helper)
                .args(["write", "--nul"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to execute macos_clip_files")?;
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(&nul_bytes) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e).context("Failed to write paths to macos_clip_files stdin");
                }
            }
            let output = child
                .wait_with_output()
                .context("Failed waiting for macos_clip_files")?;
            if !output.status.success() {
                bail!(
                    "macos_clip_files write failed ({:?}): {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;

            if let Err(err) = win32::write_cf_hdrop_files(files) {
                warn!("Native Win32 CF_HDROP write error: {}, trying fallback...", err);
                let helper = Self::find_helper(WIN_CLIP_HELPER_BIN).context(
                    "Win32 CF_HDROP clipboard write failed and win_clip_files.exe fallback not found",
                )?;
                let mut child = Command::new(helper)
                    .args(["write", "--nul"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("Failed to execute win_clip_files.exe")?;
                if let Some(mut stdin) = child.stdin.take() {
                    if let Err(e) = stdin.write_all(&nul_bytes) {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(e).context("Failed to write paths to win_clip_files.exe stdin");
                    }
                }
                let output = child
                    .wait_with_output()
                    .context("Failed waiting for win_clip_files.exe")?;
                if !output.status.success() {
                    bail!(
                        "win_clip_files.exe write failed ({:?}): {}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
            }
            return Ok(());
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = nul_bytes;
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
mod win32 {
    use anyhow::{bail, Context, Result};
    use std::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use crate::clipboard::protocol::MAX_TRANSFER_FILES;

    /// Standard Win32 clipboard format identifier for file drop lists (`CF_HDROP = 15`).
    const CF_HDROP: u32 = 15;
    /// `GlobalAlloc` flag allocating movable memory handle required by `SetClipboardData` (`0x0002`).
    const GMEM_MOVEABLE: u32 = 0x0002;
    /// `GlobalAlloc` flag zero-initializing allocated memory (`0x0040`).
    const GMEM_ZEROINIT: u32 = 0x0040;
    /// Win32 pseudo-parent handle for creating message-only windows (`HWND_MESSAGE = -3`).
    const HWND_MESSAGE: *mut c_void = (-3isize) as *mut c_void;
    /// Upper bound on `DragQueryFileW` index inspection to prevent unbounded loops on malformed handles.
    const MAX_DROP_ITEMS_INSPECT: usize = MAX_TRANSFER_FILES * 4;
    /// Maximum UTF-16 code units allowed per Win32 extended file path (`32,768` chars).
    const MAX_EXTENDED_PATH_CHARS: u32 = 32_768;
    /// Maximum retry attempts when acquiring the Win32 clipboard lock via `OpenClipboard`.
    const OPEN_CLIPBOARD_RETRIES: usize = 8;
    /// Backoff sleep between consecutive failed `OpenClipboard` attempts (20 ms).
    const OPEN_CLIPBOARD_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

    /// Win32 `DROPFILES` header structure preceding the double-NUL-terminated file path list in `CF_HDROP`.
    #[repr(C)]
    struct DropFiles {
        /// Byte offset from the start of this structure to the beginning of the file path array (`20` bytes).
        p_files: u32,
        /// Drop-point X coordinate in client/screen coordinates (`0` for clipboard operations).
        pt_x: i32,
        /// Drop-point Y coordinate in client/screen coordinates (`0` for clipboard operations).
        pt_y: i32,
        /// Non-client area flag (`0` for clipboard operations).
        f_nc: i32,
        /// Wide-character encoding flag (`1` / `TRUE` for UTF-16LE paths, `0` for ANSI).
        f_wide: i32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(h_wnd_new_owner: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn GetClipboardData(u_format: u32) -> *mut c_void;
        fn SetClipboardData(u_format: u32, h_mem: *mut c_void) -> *mut c_void;
        fn CreateWindowExW(
            dw_ex_style: u32,
            lp_class_name: *const u16,
            lp_window_name: *const u16,
            dw_style: u32,
            x: i32,
            y: i32,
            n_width: i32,
            n_height: i32,
            h_wnd_parent: *mut c_void,
            h_menu: *mut c_void,
            h_instance: *mut c_void,
            lp_param: *mut c_void,
        ) -> *mut c_void;
        fn DestroyWindow(h_wnd: *mut c_void) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn DragQueryFileW(
            h_drop: *mut c_void,
            i_file: u32,
            lpsz_file: *mut u16,
            cch: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut c_void;
        fn GlobalLock(h_mem: *mut c_void) -> *mut u8;
        fn GlobalUnlock(h_mem: *mut c_void) -> i32;
        fn GlobalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    /// RAII wrapper for a temporary Win32 `HWND_MESSAGE` owner window used during `EmptyClipboard()`.
    struct OwnerWindow(*mut c_void);

    impl OwnerWindow {
        /// Creates a lightweight message-only window (`HWND_MESSAGE`) using the built-in `"Static"` class.
        fn create_message_only() -> Result<Self> {
            // System predefined "Static" class needs no RegisterClassW.
            let static_class: [u16; 7] = [b'S' as u16, b't' as u16, b'a' as u16, b't' as u16, b'i' as u16, b'c' as u16, 0];
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    static_class.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if hwnd.is_null() {
                return Err(std::io::Error::last_os_error())
                    .context("Failed to create hidden HWND_MESSAGE clipboard owner window");
            }
            Ok(Self(hwnd))
        }

        /// Returns the raw `HWND` pointer.
        fn as_ptr(&self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for OwnerWindow {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    DestroyWindow(self.0);
                }
            }
        }
    }

    /// RAII guard ensuring `CloseClipboard()` is called when the guard leaves scope.
    struct ClipboardGuard;

    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }

    /// Acquires the Win32 clipboard lock via `OpenClipboard`, retrying up to `OPEN_CLIPBOARD_RETRIES` times.
    fn open_clipboard_with_retry(hwnd: *mut c_void) -> Result<ClipboardGuard> {
        for _ in 0..OPEN_CLIPBOARD_RETRIES {
            if unsafe { OpenClipboard(hwnd) } != 0 {
                return Ok(ClipboardGuard);
            }
            std::thread::sleep(OPEN_CLIPBOARD_RETRY_INTERVAL);
        }
        Err(std::io::Error::last_os_error()).context("OpenClipboard failed after retries")
    }

    /// Reads the list of file paths from the Win32 `CF_HDROP` clipboard format via `DragQueryFileW`.
    pub fn read_cf_hdrop_files() -> Result<Option<Vec<PathBuf>>> {
        unsafe {
            if IsClipboardFormatAvailable(CF_HDROP) == 0 {
                return Ok(None);
            }
            let _guard = open_clipboard_with_retry(std::ptr::null_mut())?;
            if IsClipboardFormatAvailable(CF_HDROP) == 0 {
                return Ok(None);
            }
            let h_drop = GetClipboardData(CF_HDROP);
            if h_drop.is_null() {
                return Ok(None);
            }
            // Passing 0xFFFF_FFFF queries the total number of files in the HDROP structure.
            let raw_count = DragQueryFileW(h_drop, 0xFFFF_FFFF, std::ptr::null_mut(), 0);
            if raw_count == 0 {
                return Ok(None);
            }
            let count = (raw_count as usize).min(MAX_DROP_ITEMS_INSPECT);
            let mut paths = Vec::with_capacity(count.min(MAX_TRANSFER_FILES));
            for i in 0..count {
                if paths.len() >= MAX_TRANSFER_FILES {
                    break;
                }
                let len = DragQueryFileW(h_drop, i as u32, std::ptr::null_mut(), 0);
                if len == 0 || len > MAX_EXTENDED_PATH_CHARS {
                    continue;
                }
                let mut buf = vec![0u16; (len + 1) as usize];
                let copied = DragQueryFileW(h_drop, i as u32, buf.as_mut_ptr(), len + 1);
                if copied > 0 {
                    buf.truncate(copied as usize);
                    let os_str = std::ffi::OsString::from_wide(&buf);
                    paths.push(PathBuf::from(os_str));
                }
            }
            Ok(Some(paths))
        }
    }

    /// Writes a slice of local file paths into the Win32 clipboard as a UTF-16 `CF_HDROP` (`DROPFILES`) block.
    pub fn write_cf_hdrop_files(files: &[PathBuf]) -> Result<()> {
        if files.is_empty() {
            bail!("No files provided");
        }
        if files.len() > MAX_TRANSFER_FILES {
            bail!(
                "Refusing to write {} files to CF_HDROP (max {})",
                files.len(),
                MAX_TRANSFER_FILES
            );
        }

        let mut wide_chars: Vec<u16> = Vec::new();
        for f in files {
            let start_len = wide_chars.len();
            for code in f.as_os_str().encode_wide() {
                if code == 0 {
                    bail!("Interior NUL in clipboard file path: {}", f.display());
                }
                wide_chars.push(code);
            }
            if wide_chars.len() == start_len {
                bail!("Empty clipboard file path rejected");
            }
            wide_chars.push(0);
        }
        wide_chars.push(0); // Double null terminator

        let struct_size = std::mem::size_of::<DropFiles>();
        let wide_bytes = wide_chars
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .context("CF_HDROP byte size overflow")?;
        let byte_len = struct_size
            .checked_add(wide_bytes)
            .context("CF_HDROP allocation size overflow")?;

        let owner = OwnerWindow::create_message_only()?;

        unsafe {
            let h_mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, byte_len);
            if h_mem.is_null() {
                return Err(std::io::Error::last_os_error()).context("GlobalAlloc failed");
            }

            let ptr = GlobalLock(h_mem);
            if ptr.is_null() {
                let err = std::io::Error::last_os_error();
                GlobalFree(h_mem);
                return Err(err).context("GlobalLock failed");
            }

            let drop_files = DropFiles {
                p_files: struct_size as u32,
                pt_x: 0,
                pt_y: 0,
                f_nc: 0,
                f_wide: 1,
            };
            std::ptr::copy_nonoverlapping(
                &drop_files as *const DropFiles as *const u8,
                ptr,
                struct_size,
            );
            std::ptr::copy_nonoverlapping(
                wide_chars.as_ptr() as *const u8,
                ptr.add(struct_size),
                wide_bytes,
            );
            GlobalUnlock(h_mem);

            let _guard = match open_clipboard_with_retry(owner.as_ptr()) {
                Ok(g) => g,
                Err(e) => {
                    GlobalFree(h_mem);
                    return Err(e);
                }
            };
            if EmptyClipboard() == 0 {
                let err = std::io::Error::last_os_error();
                GlobalFree(h_mem);
                return Err(err).context("EmptyClipboard failed");
            }
            let set_res = SetClipboardData(CF_HDROP, h_mem);
            if set_res.is_null() {
                let err = std::io::Error::last_os_error();
                GlobalFree(h_mem);
                return Err(err).context("SetClipboardData(CF_HDROP) failed");
            }
            // Clipboard owns h_mem after SetClipboardData succeeds.
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_test_dir(tag: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "integrator_fh_test_{}_{}_{}",
            tag,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn nul_path_round_trip_preserves_spaces_newlines_and_dedups() {
        let paths = vec![
            PathBuf::from("/tmp/ leading space.txt"),
            PathBuf::from("/tmp/with\nnewline.txt"),
            PathBuf::from("/tmp/ leading space.txt"),
            PathBuf::from("/tmp/trailing "),
        ];
        let encoded = serialize_nul_paths(&paths).expect("serialize paths");
        let decoded = parse_nul_paths(&encoded);
        assert_eq!(
            decoded,
            vec![
                PathBuf::from("/tmp/ leading space.txt"),
                PathBuf::from("/tmp/with\nnewline.txt"),
                PathBuf::from("/tmp/trailing "),
            ]
        );
        assert!(serialize_nul_paths(&[PathBuf::from("/tmp/bad\0path")]).is_err());
    }

    #[test]
    fn persistent_state_files_are_protected_by_prune_cache() {
        let dir = temp_test_dir("persistent");
        for name in [
            "trusted_peers_v2.json",
            "trusted_peers_v2.json.tmp",
            ".master_kek_v2.seed",
            "features.json",
            "active_mount.json",
            "kvm_layout.json",
            "transient.bin",
        ] {
            std::fs::write(dir.join(name), vec![b'x'; 32]).unwrap();
        }
        let helper = FileClipboardHelper::new_in_dir(dir.clone()).unwrap();
        // Force size budget below everything to verify persistent files remain untouched.
        helper.prune_cache(3, 1);
        assert!(dir.join("trusted_peers_v2.json").exists());
        assert!(dir.join("trusted_peers_v2.json.tmp").exists());
        assert!(dir.join(".master_kek_v2.seed").exists());
        assert!(dir.join("features.json").exists());
        assert!(dir.join("active_mount.json").exists());
        assert!(dir.join("kvm_layout.json").exists());
        assert!(!dir.join("transient.bin").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_private_cache_dir_rejects_symlink_and_isolates_subfolder() {
        let base = temp_test_dir("isolated");
        let cache = ensure_private_cache_dir(&base).unwrap();
        assert_eq!(cache, base.join("clipboard_cache"));
        assert!(cache.is_dir());

        #[cfg(unix)]
        {
            let target = temp_test_dir("symlink_target");
            let sym_base = temp_test_dir("sym_parent");
            let sym = sym_base.join("clipboard_cache");
            std::os::unix::fs::symlink(&target, &sym).unwrap();
            assert!(ensure_private_cache_dir(&sym_base).is_err());
            let _ = std::fs::remove_dir_all(&target);
            let _ = std::fs::remove_dir_all(&sym_base);
        }

        let _ = std::fs::remove_dir_all(&base);
    }
}
