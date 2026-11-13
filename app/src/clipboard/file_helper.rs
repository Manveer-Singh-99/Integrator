//! Native OS file clipboard readers and writers.

use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, Context};
use tracing::{info, warn};

pub struct FileClipboardHelper {
    cache_dir: PathBuf,
}

impl FileClipboardHelper {
    pub fn new() -> Result<Self> {
        let home = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").map(PathBuf::from)?
        } else {
            std::env::var("HOME").map(PathBuf::from)?
        };

        let cache_dir = home.join(".usbc_clipboard_cache");
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

    /// Prunes stale entries in the cache directory to prevent disk bloat.
    /// Keeps total cache size under max_bytes (default 10 GB) and removes entries older than max_age_days.
    pub fn prune_cache(&self, max_age_days: u64, max_bytes: u64) {
        if !self.cache_dir.exists() {
            return;
        }

        let now = std::time::SystemTime::now();
        let max_age = std::time::Duration::from_secs(max_age_days * 86400);

        let mut entries = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(&self.cache_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if let Ok(meta) = entry.metadata() {
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

        // Sort oldest first
        entries.sort_by_key(|e| e.1);

        let mut total_size: u64 = entries.iter().map(|e| e.2).sum();

        for (path, mtime, size) in entries {
            let is_stale = now.duration_since(mtime).map(|d| d > max_age).unwrap_or(false);
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
                if let Ok(meta) = entry.metadata() {
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
        let candidates = [
            PathBuf::from(name),
            PathBuf::from(format!("app/{}", name)),
            if cfg!(target_os = "windows") {
                PathBuf::from(r"C:\Users\Manveer Singh\mac-windows-usbc-bridge\app").join(name)
            } else {
                PathBuf::from("/Users/manveersingh/mac-windows-usbc-bridge/app").join(name)
            },
        ];
        for c in &candidates {
            if c.exists() {
                if let Ok(abs) = c.canonicalize() {
                    return Some(abs);
                }
                return Some(c.clone());
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let c1 = parent.join(name);
                if c1.exists() { return Some(c1); }
                let c2 = parent.join("../../").join(name);
                if c2.exists() { return Some(c2); }
                let c3 = parent.join("../../app").join(name);
                if c3.exists() { return Some(c3); }
            }
        }
        None
    }

    /// Reads currently copied file paths from the OS clipboard.
    pub fn read_copied_files(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if let Some(helper) = Self::find_helper("macos_clip_files") {
                match Command::new(&helper).arg("read").output() {
                    Ok(output) => {
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
                        } else {
                            warn!("macos_clip_files read returned error: {:?}", output.status);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to execute macos_clip_files at {:?}: {}", helper, e);
                    }
                }
            } else {
                warn!("macos_clip_files helper binary not found");
            }
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            if let Some(helper) = Self::find_helper("win_clip_files.exe") {
                let mut cmd = Command::new(&helper);
                cmd.arg("read").creation_flags(CREATE_NO_WINDOW);
                match cmd.output() {
                    Ok(output) => {
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
                        } else {
                            warn!("win_clip_files.exe read returned error: {:?}", output.status);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to execute win_clip_files.exe at {:?}: {}", helper, e);
                    }
                }
            } else {
                warn!("win_clip_files.exe helper binary not found");
            }
        }

        results
    }

    /// Sets the OS clipboard so that the user can immediately paste the file(s) into Finder or Explorer.
    #[allow(dead_code)]
    pub fn write_copied_files(&self, files: &[PathBuf]) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let helper = Self::find_helper("macos_clip_files")
                .context("macos_clip_files helper not found")?;

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
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let helper = Self::find_helper("win_clip_files.exe")
                .context("win_clip_files.exe helper not found")?;

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

        info!("Registered {} file(s) onto native OS clipboard for pasting", files.len());
        Ok(())
    }

    /// Clears the native OS clipboard so stale text/files are removed immediately.
    #[allow(dead_code)]
    pub fn clear_clipboard(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            if let Some(helper) = Self::find_helper("macos_clip_files") {
                let _ = Command::new(helper).arg("clear").status();
            }
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            if let Some(helper) = Self::find_helper("win_clip_files.exe") {
                let mut cmd = Command::new(helper);
                cmd.arg("clear").creation_flags(CREATE_NO_WINDOW);
                let _ = cmd.status();
            }
        }

        Ok(())
    }
}
