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

        Ok(Self { cache_dir })
    }

    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Reads currently copied file paths from the OS clipboard.
    pub fn read_copied_files(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();

        #[cfg(target_os = "macos")]
        {
            let helper_path = Path::new("macos_clip_files");
            let helper = if helper_path.exists() {
                helper_path.to_path_buf()
            } else {
                Path::new("app/macos_clip_files").to_path_buf()
            };

            if let Ok(output) = Command::new(helper).arg("read").output() {
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

        #[cfg(target_os = "windows")]
        {
            let helper_path = Path::new("win_clip_files.exe");
            let helper = if helper_path.exists() {
                helper_path.to_path_buf()
            } else {
                Path::new("app/win_clip_files.exe").to_path_buf()
            };

            if let Ok(output) = Command::new(helper).arg("read").output() {
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

        results
    }

    /// Sets the OS clipboard so that the user can immediately paste the file(s) into Finder or Explorer.
    pub fn write_copied_files(&self, files: &[PathBuf]) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let helper_path = Path::new("macos_clip_files");
            let helper = if helper_path.exists() {
                helper_path.to_path_buf()
            } else {
                Path::new("app/macos_clip_files").to_path_buf()
            };

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
            let helper_path = Path::new("win_clip_files.exe");
            let helper = if helper_path.exists() {
                helper_path.to_path_buf()
            } else {
                Path::new("app/win_clip_files.exe").to_path_buf()
            };

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
