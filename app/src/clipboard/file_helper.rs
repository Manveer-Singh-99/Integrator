//! Native OS file clipboard readers and writers.

use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, Context};
use tracing::{info, warn, debug};

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

        Ok(Self { cache_dir })
    }

    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
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
            if let Some(helper) = Self::find_helper("win_clip_files.exe") {
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
            let helper = Self::find_helper("win_clip_files.exe")
                .context("win_clip_files.exe helper not found")?;

            let mut cmd = Command::new(helper);
            cmd.arg("write");
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
}
