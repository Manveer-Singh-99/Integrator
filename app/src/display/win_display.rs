//! Windows Native Display Controller.
//! Manages Virtual Display Driver (ROOT\\DISPLAY\\0001), Sunshine services,
//! registry configuration, and Moonlight client execution.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use anyhow::{Result, Context};
#[allow(unused_imports)]
use tracing::{info, warn};

pub struct WinDisplayManager;

impl WinDisplayManager {
    /// Finds the Moonlight executable on Windows.
    pub fn find_moonlight_exe() -> Option<PathBuf> {
        let candidates = [
            PathBuf::from(r"C:\Program Files\Moonlight Game Streaming\Moonlight.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Moonlight Game Streaming\Moonlight.exe"),
        ];
        for c in &candidates {
            if c.exists() {
                return Some(c.clone());
            }
        }
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(local_appdata).join(r"Programs\Moonlight Game Streaming\Moonlight.exe");
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// Updates Moonlight host registry entry (host 2) with the active Mac IP.
    #[allow(unused_variables)]
    pub fn update_moonlight_host_registry(mac_ip: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let reg_key = r"HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts\2";
            let _ = Command::new("reg")
                .args(["add", reg_key, "/v", "localaddress", "/t", "REG_SZ", "/d", mac_ip, "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = Command::new("reg")
                .args(["add", reg_key, "/v", "manualaddress", "/t", "REG_SZ", "/d", mac_ip, "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            info!("Updated Moonlight registry host 2 address to {}", mac_ip);
        }
        Ok(())
    }

    /// Launches Moonlight.exe on Windows.
    pub fn start_moonlight_client(
        mac_ip: &str,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        audio_on_host: bool,
    ) -> Result<()> {
        let exe = Self::find_moonlight_exe()
            .context("Moonlight.exe not found on Windows")?;

        // 1. Update registry
        let _ = Self::update_moonlight_host_registry(mac_ip);

        // 2. Kill existing Moonlight cleanly
        let _ = Self::stop_moonlight_client();
        std::thread::sleep(Duration::from_millis(300));

        // 3. Build arguments
        let res_arg = format!("{}x{}", width, height);
        let mut args = vec![
            "stream".to_string(),
            mac_ip.to_string(),
            "Desktop".to_string(),
            "--resolution".to_string(),
            res_arg,
            "--fps".to_string(),
            fps.to_string(),
            "--bitrate".to_string(),
            bitrate_kbps.to_string(),
            "--display-mode".to_string(),
            "fullscreen".to_string(),
        ];
        if audio_on_host {
            args.push("--audio-on-host".to_string());
        }

        let mut cmd = Command::new(exe);
        cmd.args(&args);

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        cmd.spawn().context("Failed to spawn Moonlight.exe on Windows")?;
        info!("Launched Moonlight on Windows ({}x{} @ {}Hz streaming from {})", width, height, fps, mac_ip);
        Ok(())
    }

    /// Stops Moonlight.exe on Windows.
    pub fn stop_moonlight_client() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill")
                .args(["/F", "/IM", "Moonlight.exe"])
                .creation_flags(0x08000000)
                .status();
        }
        info!("Terminated Moonlight.exe on Windows");
        Ok(())
    }

    /// Enables the Virtual Display Driver (ROOT\DISPLAY\0001).
    pub fn enable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let status = Command::new("pnputil.exe")
                .args(["/enable-device", r"ROOT\DISPLAY\0001"])
                .creation_flags(0x08000000)
                .status()?;
            if !status.success() {
                warn!("pnputil /enable-device returned non-zero status");
            }
        }
        info!("Enabled Virtual Display Driver device (ROOT\\DISPLAY\\0001)");
        Ok(())
    }

    /// Disables the Virtual Display Driver (ROOT\DISPLAY\0001).
    pub fn disable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let status = Command::new("pnputil.exe")
                .args(["/disable-device", r"ROOT\DISPLAY\0001"])
                .creation_flags(0x08000000)
                .status()?;
            if !status.success() {
                warn!("pnputil /disable-device returned non-zero status");
            }
        }
        info!("Disabled Virtual Display Driver device (ROOT\\DISPLAY\\0001)");
        Ok(())
    }

    /// Checks if ROOT\DISPLAY\0001 is active.
    pub fn is_vdd_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            if let Ok(output) = Command::new("pnputil.exe")
                .args(["/enum-devices", "/instanceid", r"ROOT\DISPLAY\0001"])
                .creation_flags(0x08000000)
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                return text.contains("Started") || text.contains("OK");
            }
        }
        false
    }
}
