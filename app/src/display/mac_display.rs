//! macOS display control: in-process CGVirtualDisplay management,
//! dynamic Sunshine configuration, and non-destructive Moonlight launching.

use crate::system_info;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::info;

const INTEGRATOR_VD_VENDOR: u32 = 0x494E; // 'IN'
const INTEGRATOR_VD_PRODUCT: u32 = 0x0165;

#[cfg(target_os = "macos")]
extern "C" {
    fn start_virtual_display_in_app(width: u32, height: u32, fps: u32, hi_dpi: bool) -> u32;
    fn stop_virtual_display_in_app();
    fn get_virtual_display_id_in_app() -> u32;
    fn is_virtual_display_active_in_app() -> bool;

    fn CGGetOnlineDisplayList(
        max_displays: u32,
        online_displays: *mut u32,
        display_count: *mut u32,
    ) -> i32;
    fn CGDisplayVendorNumber(display: u32) -> u32;
    fn CGDisplayModelNumber(display: u32) -> u32;
}

pub struct MacDisplayManager;

impl MacDisplayManager {
    /// Locate Integrator's own virtual display using our custom Vendor/Product ID
    /// (never misidentifying a physical external monitor).
    #[cfg(target_os = "macos")]
    pub fn get_active_virtual_display() -> Option<u32> {
        let in_app_id = unsafe { get_virtual_display_id_in_app() };
        if in_app_id != 0 {
            return Some(in_app_id);
        }

        let mut displays = [0u32; 16];
        let mut count: u32 = 0;
        let err = unsafe { CGGetOnlineDisplayList(16, displays.as_mut_ptr(), &mut count) };
        if err != 0 {
            return None;
        }
        for i in 0..count as usize {
            let id = displays[i];
            unsafe {
                if CGDisplayVendorNumber(id) == INTEGRATOR_VD_VENDOR
                    && CGDisplayModelNumber(id) == INTEGRATOR_VD_PRODUCT
                {
                    return Some(id);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "macos"))]
    pub fn get_active_virtual_display() -> Option<u32> {
        None
    }

    /// Updates discovered `sunshine.conf` `output_name = <display_id>`.
    pub fn configure_sunshine_output(display_id: u32) -> Result<()> {
        let conf_path = system_info::find_sunshine_conf().unwrap_or_else(|| {
            system_info::user_home_dir().join(".config/sunshine/sunshine.conf")
        });

        if let Some(parent) = conf_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = if conf_path.exists() {
            std::fs::read_to_string(&conf_path)?
        } else {
            String::new()
        };

        let mut new_lines = Vec::new();
        let mut found = false;
        for line in content.lines() {
            if line.trim().starts_with("output_name") {
                new_lines.push(format!("output_name = {}", display_id));
                found = true;
            } else {
                new_lines.push(line.to_string());
            }
        }
        if !found {
            new_lines.push(format!("output_name = {}", display_id));
        }

        std::fs::write(&conf_path, new_lines.join("\n") + "\n")?;
        info!(
            "Configured Sunshine {} output_name = {}",
            conf_path.display(),
            display_id
        );
        Ok(())
    }

    /// Creates or reuses an in-process CGVirtualDisplay on macOS.
    pub fn start_virtual_display(width: u32, height: u32, fps: u32) -> Result<u32> {
        #[cfg(target_os = "macos")]
        {
            let w = width.clamp(800, 7680);
            let h = height.clamp(600, 4320);
            let f = fps.clamp(30, 240);
            let id = unsafe { start_virtual_display_in_app(w, h, f, false) };
            if id == 0 {
                anyhow::bail!(
                    "Failed to create in-process CGVirtualDisplay ({}x{} @ {}Hz)",
                    w,
                    h,
                    f
                );
            }
            info!(
                "Created in-process virtual display ID={} ({}x{} @ {}Hz)",
                id, w, h, f
            );
            Ok(id)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (width, height, fps);
            anyhow::bail!("macOS virtual display only supported on macOS")
        }
    }

    /// Tears down the in-process virtual display cleanly.
    pub fn stop_virtual_display() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            unsafe {
                stop_virtual_display_in_app();
            }
            info!("Stopped in-process virtual display");
        }
        Ok(())
    }

    pub fn is_virtual_display_active() -> bool {
        #[cfg(target_os = "macos")]
        {
            let active = unsafe { is_virtual_display_active_in_app() };
            active || Self::get_active_virtual_display().is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Launches Sunshine daemon using dynamic binary discovery.
    pub fn start_sunshine() -> Result<()> {
        let _ = Self::stop_sunshine();
        std::thread::sleep(Duration::from_millis(250));

        let sunshine_bin = system_info::find_sunshine_binary().context(
            "Sunshine binary not found. Install Sunshine.app or add `sunshine` to PATH.",
        )?;

        let log_dir = system_info::user_home_dir().join("Library/Logs");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_file = std::fs::File::create(log_dir.join("sunshine.log"))?;

        Command::new(&sunshine_bin)
            .stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file))
            .spawn()
            .with_context(|| format!("Failed to launch {}", sunshine_bin.display()))?;

        info!("Launched Sunshine server ({})", sunshine_bin.display());
        Ok(())
    }

    pub fn stop_sunshine() -> Result<()> {
        let _ = Command::new("killall").arg("sunshine").status();
        info!("Stopped Sunshine server on macOS");
        Ok(())
    }

    /// Waits until Sunshine binds its configured local port.
    pub async fn wait_for_sunshine_ready(timeout_dur: Duration) -> bool {
        let (_, port, _) = system_info::read_sunshine_config_info();
        let addr = format!("127.0.0.1:{}", port);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout_dur {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }

    pub async fn wait_for_port(ip: &str, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", ip, port);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }

    /// Launches Moonlight CLI on macOS without clobbering unrelated hosts or user global settings.
    pub fn start_moonlight_client(
        pc_ip: &str,
        port: u16,
        host_name: &str,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        audio_on_host: bool,
    ) -> Result<()> {
        let _ = Command::new("killall").arg("Moonlight").status();
        std::thread::sleep(Duration::from_millis(250));

        let moonlight_bin = system_info::find_moonlight_binary().context(
            "Moonlight.app not found. Install Moonlight in /Applications or ~/Applications.",
        )?;

        let host_target = resolve_or_refresh_mac_moonlight_slot(pc_ip, port, host_name)
            .unwrap_or_else(|| pc_ip.to_string());

        let res_arg = format!("{}x{}", width.max(800), height.max(600));
        let fps_arg = fps.clamp(30, 240).to_string();
        let bitrate_arg = bitrate_kbps.clamp(5000, 500000).to_string();

        let mut cmd = Command::new(&moonlight_bin);
        cmd.args([
            "stream",
            &host_target,
            "Desktop",
            "--resolution",
            &res_arg,
            "--fps",
            &fps_arg,
            "--bitrate",
            &bitrate_arg,
            "--display-mode",
            "fullscreen",
            "--no-vsync",
            "--no-frame-pacing",
            "--quit-after",
        ]);
        if audio_on_host {
            cmd.arg("--audio-on-host");
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn()
            .with_context(|| format!("Failed to spawn {}", moonlight_bin.display()))?;

        info!(
            "Launched Moonlight on macOS -> '{}' ({}:{}) at {} @ {}Hz",
            host_target, pc_ip, port, res_arg, fps_arg
        );
        Ok(())
    }

    pub fn stop_moonlight_client() -> Result<()> {
        let _ = Command::new("killall").arg("Moonlight").status();
        info!("Stopped Moonlight on macOS");
        Ok(())
    }

    pub fn show_notification(title: &str, message: &str) {
        let t = title.replace('"', "\\\"");
        let m = message.replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"{}\"", m, t);
        let _ = Command::new("osascript").args(["-e", &script]).spawn();
    }
}

/// Inspect existing paired Moonlight hosts in `com.moonlight-stream.Moonlight` and refresh ONLY
/// a slot that genuinely matches `host_name` / `pc_ip` & `port`, never touching unrelated hosts.
fn resolve_or_refresh_mac_moonlight_slot(
    pc_ip: &str,
    port: u16,
    host_name: &str,
) -> Option<String> {
    let out = Command::new("defaults")
        .args(["read", "com.moonlight-stream.Moonlight"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut size: usize = 0;
    let mut props: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_matches('"').to_string();
            let val = v.trim().trim_matches('"').to_string();
            if key == "hosts.size" {
                size = val.parse().unwrap_or(0);
            } else if key.starts_with("hosts.") {
                props.insert(key, val);
            }
        }
    }

    if size == 0 {
        return None;
    }

    let wanted_port = port.to_string();
    let mut best_slot: Option<usize> = None;

    for idx in 1..=size {
        let h_name = props
            .get(&format!("hosts.{}.hostname", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_local_ip = props
            .get(&format!("hosts.{}.localaddress", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_manual_ip = props
            .get(&format!("hosts.{}.manualaddress", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_local_port = props
            .get(&format!("hosts.{}.localport", idx))
            .map(String::as_str)
            .unwrap_or("47989");

        let ip_match = h_local_ip == pc_ip || h_manual_ip == pc_ip;
        let name_match =
            !host_name.is_empty() && h_name.eq_ignore_ascii_case(host_name);
        let port_match = h_local_port == wanted_port;

        if name_match && port_match {
            best_slot = Some(idx);
            break;
        }
        if ip_match && port_match && best_slot.is_none() {
            best_slot = Some(idx);
        }
        if name_match && best_slot.is_none() {
            best_slot = Some(idx);
        }
    }

    let idx = best_slot?;
    // Update the matched slot's active direct route IP so USB-C/Wi-Fi switching works seamlessly
    for field in ["localaddress", "manualaddress"] {
        let key = format!("hosts.{}.{}", idx, field);
        let _ = Command::new("defaults")
            .args(["write", "com.moonlight-stream.Moonlight", &key, "-string", pc_ip])
            .status();
    }

    // Prefer UUID if stored so Moonlight binds deterministically when multiple entries exist
    if let Some(uuid) = props.get(&format!("hosts.{}.uuid", idx)) {
        if !uuid.is_empty() {
            return Some(uuid.clone());
        }
    }
    props
        .get(&format!("hosts.{}.hostname", idx))
        .cloned()
        .or_else(|| Some(pc_ip.to_string()))
}

#[allow(dead_code)]
fn _unused_pathbuf_marker(_p: PathBuf) {}
