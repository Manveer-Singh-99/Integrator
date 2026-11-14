//! Native OS file clipboard readers and writers.
//!
//! Uses in-process native OS APIs on both platforms:
//! - macOS: `NSPasteboard` file URLs via linked Swift FFI (`read_pasteboard_files_in_app` /
//!   `write_pasteboard_files_in_app`), with `macos_clip_files` CLI as fallback.
//! - Windows: Win32 `CF_HDROP` (`OpenClipboard`, `DragQueryFileW`, `SetClipboardData`)
//!   using UTF-16 `fWide = TRUE` and retry backoff on clipboard contention, with
//!   `win_clip_files.exe` as fallback.

use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Context, Result};
use tracing::{info, warn};

#[cfg(target_os = "macos")]
extern "C" {
    fn read_pasteboard_files_in_app(out_buf: *mut u8, cap: usize) -> isize;
    fn write_pasteboard_files_in_app(paths_ptr: *const std::os::raw::c_char) -> bool;
    #[allow(dead_code)]
    fn clear_pasteboard_in_app();
}

pub struct FileClipboardHelper {
    cache_dir: PathBuf,
}

impl FileClipboardHelper {
    pub fn new() -> Result<Self> {
        let cache_dir = crate::system_info::app_data_dir();
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir)?;
        }

        let helper = Self { cache_dir };
        // Prune cache entries older than 3 days or if total cache exceeds 10 GB
        helper.prune_cache(3, 10 * 1024 * 1024 * 1024);

        Ok(helper)
    }

    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    fn is_persistent_state_file(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        matches!(
            name,
            "app_config.json"
                | "device_id"
                | "trusted_peers.json"
                | "peer_history.json"
                | "active_mount.json"
                | "features.json"
                | "spatial_test_chime.wav"
        ) || name.starts_with("trusted_peers.json.")
            || name.starts_with("features.json.")
    }

    /// Prunes stale entries in the cache directory to prevent disk bloat.
    pub fn prune_cache(&self, max_age_days: u64, max_bytes: u64) {
        if !self.cache_dir.exists() {
            return;
        }

        let now = std::time::SystemTime::now();
        let max_age = std::time::Duration::from_secs(max_age_days.saturating_mul(86400));

        let mut entries = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(&self.cache_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if Self::is_persistent_state_file(&path) {
                    continue;
                }
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    let mtime = meta.modified().unwrap_or(now);
                    let size = if meta.is_dir() {
                        Self::calculate_dir_size(&path)
                    } else {
                        meta.len()
                    };
                    entries.push((path, mtime, size));
                }
            }
        }

        entries.sort_by_key(|e| e.1);
        let mut total_size: u64 = entries.iter().map(|e| e.2).sum();

        for (path, mtime, size) in entries {
            let is_stale = now
                .duration_since(mtime)
                .map(|d| d > max_age)
                .unwrap_or(false);
            if is_stale || total_size > max_bytes {
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
                total_size = total_size.saturating_sub(size);
            }
        }
    }

    fn calculate_dir_size(path: &Path) -> u64 {
        let mut total = 0;
        if let Ok(read_dir) = std::fs::read_dir(path) {
            for entry in read_dir.flatten() {
                let p = entry.path();
                if let Ok(meta) = std::fs::symlink_metadata(&p) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if meta.is_dir() {
                        total += Self::calculate_dir_size(&p);
                    } else {
                        total += meta.len();
                    }
                }
            }
        }
        total
    }

    fn find_helper(name: &str) -> Option<PathBuf> {
        crate::system_info::find_app_helper(name)
    }

    /// Reads currently copied file paths from the OS clipboard.
    pub fn read_copied_files(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();

        #[cfg(target_os = "macos")]
        {
            let mut buf = vec![0u8; 256 * 1024];
            let n = unsafe { read_pasteboard_files_in_app(buf.as_mut_ptr(), buf.len()) };
            if n > 0 && (n as usize) < buf.len() {
                let text = String::from_utf8_lossy(&buf[..n as usize]);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let p = PathBuf::from(trimmed);
                        if p.exists() {
                            results.push(p);
                        }
                    }
                }
                return results;
            }

            if let Some(helper) = Self::find_helper("macos_clip_files") {
                if let Ok(output) = Command::new(&helper).arg("read").output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                let p = PathBuf::from(trimmed);
                                if p.exists() {
                                    results.push(p);
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(files) = win32_clip_files::read_cf_hdrop_files() {
                for p in files {
                    if p.exists() {
                        results.push(p);
                    }
                }
                return results;
            }

            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            if let Some(helper) = Self::find_helper("win_clip_files.exe") {
                let mut cmd = Command::new(&helper);
                cmd.arg("read").creation_flags(CREATE_NO_WINDOW);
                if let Ok(output) = cmd.output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                let p = PathBuf::from(trimmed);
                                if p.exists() {
                                    results.push(p);
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Sets the OS clipboard so that the user can immediately paste the file(s) into Finder or Explorer.
    pub fn write_copied_files(&self, files: &[PathBuf]) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let joined: String = files
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("\n");
            if let Ok(c_str) = std::ffi::CString::new(joined) {
                let ok = unsafe { write_pasteboard_files_in_app(c_str.as_ptr()) };
                if ok {
                    info!(
                        "Registered {} file(s) onto macOS NSPasteboard in-process",
                        files.len()
                    );
                    return Ok(());
                }
            }

            let helper = Self::find_helper("macos_clip_files")
                .context("macos_clip_files helper not found and in-process NSPasteboard write failed")?;
            let mut cmd = Command::new(helper);
            cmd.arg("write");
            for f in files {
                cmd.arg(f);
            }
            let status = cmd.status().context("Failed to execute macos_clip_files")?;
            if !status.success() {
                warn!("macos_clip_files write returned non-zero status");
            }
        }

        #[cfg(target_os = "windows")]
        {
            if win32_clip_files::write_cf_hdrop_files(files).is_ok() {
                info!(
                    "Registered {} file(s) onto Windows CF_HDROP clipboard in-process",
                    files.len()
                );
                return Ok(());
            }

            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let helper = Self::find_helper("win_clip_files.exe")
                .context("Win32 CF_HDROP clipboard write failed and win_clip_files.exe fallback not found")?;
            let mut cmd = Command::new(helper);
            cmd.arg("write").creation_flags(CREATE_NO_WINDOW);
            for f in files {
                cmd.arg(f);
            }
            let status = cmd.status().context("Failed to execute win_clip_files.exe")?;
            if !status.success() {
                warn!("win_clip_files.exe write returned non-zero status");
            }
        }

        info!(
            "Registered {} file(s) onto native OS clipboard for pasting",
            files.len()
        );
        Ok(())
    }

    /// Clears the native OS clipboard.
    #[allow(dead_code)]
    pub fn clear_clipboard(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            unsafe {
                clear_pasteboard_in_app();
            }
        }

        #[cfg(target_os = "windows")]
        {
            let _ = win32_clip_files::clear_win32_clipboard();
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod win32_clip_files {
    use anyhow::Result;
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;
    use std::time::Duration;

    const CF_HDROP: u32 = 15;
    const GMEM_MOVEABLE: u32 = 0x0002;
    const GMEM_ZEROINIT: u32 = 0x0040;

    #[repr(C)]
    struct DropFiles {
        p_files: u32,
        pt_x: i32,
        pt_y: i32,
        f_nc: i32,
        f_wide: i32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(h_wnd_new_owner: *mut std::ffi::c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn GetClipboardData(u_format: u32) -> *mut std::ffi::c_void;
        fn SetClipboardData(u_format: u32, h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn DragQueryFileW(
            h_drop: *mut std::ffi::c_void,
            i_file: u32,
            lpsz_file: *mut u16,
            cch: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut std::ffi::c_void;
        fn GlobalLock(h_mem: *mut std::ffi::c_void) -> *mut u8;
        fn GlobalUnlock(h_mem: *mut std::ffi::c_void) -> i32;
        fn GlobalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    fn open_clipboard_with_retry() -> bool {
        for _ in 0..6 {
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        false
    }

    pub fn read_cf_hdrop_files() -> Option<Vec<PathBuf>> {
        if unsafe { IsClipboardFormatAvailable(CF_HDROP) } == 0 {
            return Some(Vec::new());
        }
        if !open_clipboard_with_retry() {
            return None;
        }
        let mut out = Vec::new();
        unsafe {
            let h_drop = GetClipboardData(CF_HDROP);
            if !h_drop.is_null() {
                let count = DragQueryFileW(h_drop, 0xFFFF_FFFF, std::ptr::null_mut(), 0);
                for idx in 0..count {
                    let chars = DragQueryFileW(h_drop, idx, std::ptr::null_mut(), 0);
                    if chars > 0 && chars < 32_768 {
                        let mut buf = vec![0u16; (chars + 1) as usize];
                        let copied = DragQueryFileW(h_drop, idx, buf.as_mut_ptr(), chars + 1);
                        if copied > 0 {
                            let os_str = OsString::from_wide(&buf[..copied as usize]);
                            out.push(PathBuf::from(os_str));
                        }
                    }
                }
            }
            let _ = CloseClipboard();
        }
        Some(out)
    }

    pub fn write_cf_hdrop_files(files: &[PathBuf]) -> Result<()> {
        let mut wide_list: Vec<u16> = Vec::new();
        for f in files {
            wide_list.extend(f.as_os_str().encode_wide());
            wide_list.push(0);
        }
        wide_list.push(0); // Double-NUL terminator required by DROPFILES

        let header_bytes = std::mem::size_of::<DropFiles>();
        let total_bytes = header_bytes + wide_list.len() * std::mem::size_of::<u16>();

        if !open_clipboard_with_retry() {
            anyhow::bail!("Could not open Windows clipboard after retries");
        }

        unsafe {
            let _ = EmptyClipboard();
            let h_mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, total_bytes);
            if h_mem.is_null() {
                let _ = CloseClipboard();
                anyhow::bail!("GlobalAlloc failed for CF_HDROP");
            }
            let ptr = GlobalLock(h_mem);
            if ptr.is_null() {
                let _ = GlobalFree(h_mem);
                let _ = CloseClipboard();
                anyhow::bail!("GlobalLock failed for CF_HDROP");
            }

            let df = DropFiles {
                p_files: header_bytes as u32,
                pt_x: 0,
                pt_y: 0,
                f_nc: 0,
                f_wide: 1,
            };
            std::ptr::write_unaligned(ptr as *mut DropFiles, df);
            let dest_wide = ptr.add(header_bytes) as *mut u16;
            std::ptr::copy_nonoverlapping(wide_list.as_ptr(), dest_wide, wide_list.len());
            let _ = GlobalUnlock(h_mem);

            if SetClipboardData(CF_HDROP, h_mem).is_null() {
                let _ = GlobalFree(h_mem);
                let _ = CloseClipboard();
                anyhow::bail!("SetClipboardData(CF_HDROP) failed");
            }
            let _ = CloseClipboard();
        }
        Ok(())
    }

    pub fn clear_win32_clipboard() -> Result<()> {
        if !open_clipboard_with_retry() {
            anyhow::bail!("Could not open Windows clipboard to clear");
        }
        unsafe {
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
        Ok(())
    }
}
