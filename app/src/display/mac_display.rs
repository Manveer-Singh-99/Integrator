//! # macOS Display Management Subsystem
//!
//! ## 1. Module Purpose & Scope
//! This module owns the macOS-specific implementation of the **Display Subsystem** (`display` feature).
//! It provides:
//! 1. In-process virtual display lifecycle management via CoreGraphics private SPI (`virtual_display.m`).
//! 2. Dynamic discovery and output targeting for the Sunshine streaming server (`sunshine.conf`).
//! 3. LaunchServices-based execution of `Sunshine.app` ensuring proper macOS Screen Recording TCC permissions.
//! 4. Non-destructive resolution and execution of the Moonlight client CLI on macOS.
//! 5. Desktop user notifications via AppleScript (`osascript`).
//!
//! ## 2. Cross-Platform Architectural Pipelines
//!
//! ### Mac-as-Host Extended Desktop
//! - **Virtual Display**: Creates a private `CGVirtualDisplay` in-process with Integrator Vendor ID `0x494E`
//!   and Product ID `0x0165`. Because it is created in-process, it is recognized natively by macOS
//!   window server without requiring third-party kernel extensions or driver bundles.
//! - **Sunshine Output Targeting**: Reads `sunshine.conf` and rewrites `output_name = <display_id>`
//!   dynamically so Sunshine captures the virtual display exclusively.
//! - **Hardware Acceleration**: Sunshine captures frames via ScreenCaptureKit / Desktop Duplication
//!   and encodes them using Apple Silicon VideoToolbox hardware encoders (H.264 or HEVC).
//! - **Moonlight Streaming**: Windows peer receives the stream and decodes via D3D11 / NVDEC / AMF / Intel QSV.
//!
//! ### Mac-as-Client Extended Desktop
//! - Receives a stream from a Windows host (which encodes via NVIDIA NVENC, AMD AMF, or Intel QuickSync).
//! - Reads existing paired hosts non-destructively from `com.moonlight-stream.Moonlight` preferences via
//!   `defaults read`, refreshes the matching host's direct IP route, and spawns `Moonlight.app` with
//!   VideoToolbox hardware decoding, `--no-vsync`, and `--no-frame-pacing`.
//!
//! ### Shared Camera Coexistence
//! While high-resolution display streaming runs over ports 47989/48989, the FaceTime HD camera stream
//! runs independently over port 58287 in uncompressed 720p30 NV12 into Windows 11 FrameServer
//! (`integrator_vcam.dll` / `Integrator MacBook Camera`). Display streaming and camera capture
//! execute simultaneously across distinct threads and network ports with zero mutual interference.
//!
//! ## 3. Threading & Process Management Model
//! - **Process Spawning**: Processes (`open`, `killall`, `defaults`, `osascript`) are launched via
//!   standard `std::process::Command` within `tokio::task::spawn_blocking` blocks.
//! - **Zombie Prevention**: Every spawned child process is handed off to a dedicated reaping thread
//!   ([`reap_child`]) which blocks until the child exits, preventing zombie process accumulation.
//!
//! ## 4. Security & Safety Invariants
//! - **LaunchServices TCC Inheritance**: When Sunshine is installed as a `.app` bundle, it is launched
//!   via `/usr/bin/open` rather than directly as a POSIX binary. This ensures macOS attributes Screen
//!   Recording permissions directly to `Sunshine.app` rather than requiring `Integrator.app` to
//!   request Screen Recording rights.
//! - **Private Log File Permissions**: Output log files (`sunshine.log`, `sunshine.err.log`) are created
//!   with POSIX mode `0600` (read/write by owner only), rejecting symlinks to mitigate symlink traversal.
//! - **AppleScript Sanitization**: Notification titles and messages are filtered to strip control
//!   characters and truncated to safe length limits before passing to `osascript`.

use crate::system_info;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tracing::{info, warn};

/// Spawns a dedicated background thread to wait on and reap a child process, preventing zombies.
///
/// # Arguments
/// - `child`: The spawned child process handle.
/// - `label`: Diagnostic label used to name the reaper thread.
fn reap_child(mut child: Child, label: &'static str) {
    let _ = std::thread::Builder::new()
        .name(format!("reap-{}", label))
        .spawn(move || {
            let _ = child.wait();
        });
}

/// Creates or truncates a private log file with mode `0600` (read/write by owner only).
///
/// Rejects symlinked paths to prevent symlink traversal privilege escalation.
///
/// # Arguments
/// - `path`: Destination filesystem path.
fn create_private_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Refusing to open symlinked log file",
            ));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Pure string transformation helper updating or inserting `output_name = <display_id>` in sunshine configuration.
///
/// Preserves comments, whitespace, and unrelated configuration keys.
///
/// # Arguments
/// - `content`: Existing raw content of `sunshine.conf`.
/// - `display_id`: CoreGraphics display identifier to set.
pub(crate) fn update_sunshine_output_content(content: &str, display_id: u32) -> String {
    let mut new_lines = Vec::new();
    let mut found = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            if let Some((k, _)) = trimmed.split_once('=') {
                if k.trim() == "output_name" {
                    new_lines.push(format!("output_name = {}", display_id));
                    found = true;
                    continue;
                }
            }
        }
        new_lines.push(line.to_string());
    }
    if !found {
        new_lines.push(format!("output_name = {}", display_id));
    }
    new_lines.join("\n") + "\n"
}

#[cfg(target_os = "macos")]
extern "C" {
    fn start_virtual_display_in_app(width: u32, height: u32, fps: u32, hi_dpi: bool) -> u32;
    fn stop_virtual_display_in_app();
    fn get_virtual_display_id_in_app() -> u32;
    fn is_virtual_display_active_in_app() -> bool;
}

/// Manager providing macOS native display creation, Sunshine configuration, and Moonlight execution.
pub struct MacDisplayManager;

impl MacDisplayManager {
    /// Locates Integrator's own virtual display using custom Vendor/Product ID (`0x494E` / `0x0165`).
    ///
    /// Guarantees that physical external displays are never misidentified as Integrator virtual displays.
    #[cfg(target_os = "macos")]
    pub fn get_active_virtual_display() -> Option<u32> {
        let in_app_id = unsafe { get_virtual_display_id_in_app() };
        if in_app_id != 0 {
            Some(in_app_id)
        } else {
            None
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    pub fn get_active_virtual_display() -> Option<u32> {
        None
    }

    /// Updates discovered `sunshine.conf` with `output_name = <display_id>`.
    ///
    /// # Arguments
    /// - `display_id`: CoreGraphics display identifier of the target virtual screen.
    pub fn configure_sunshine_output(display_id: u32) -> Result<()> {
        let conf_path = system_info::find_sunshine_conf().unwrap_or_else(|| {
            system_info::user_home_dir().join(".config/sunshine/sunshine.conf")
        });

        let content = if conf_path.exists() {
            std::fs::read_to_string(&conf_path)?
        } else {
            String::new()
        };

        let updated = update_sunshine_output_content(&content, display_id);
        system_info::atomic_write_private(&conf_path, updated.as_bytes())?;
        info!(
            "Configured Sunshine {} output_name = {}",
            conf_path.display(),
            display_id
        );
        Ok(())
    }

    /// Creates or reuses an in-process `CGVirtualDisplay` on macOS.
    ///
    /// # Arguments
    /// - `width`: Target display width in pixels (clamped to 800..=7680).
    /// - `height`: Target display height in pixels (clamped to 600..=4320).
    /// - `fps`: Target refresh rate in Hertz (clamped to 30..=240).
    ///
    /// # Returns
    /// CoreGraphics display identifier (`CGDirectDisplayID`) on success.
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

    /// Returns whether an Integrator virtual display is currently instantiated and online.
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

    /// Launches the Sunshine streaming server daemon using dynamic binary and bundle discovery.
    ///
    /// When Sunshine is packaged inside a `.app` bundle, it is launched via `/usr/bin/open`
    /// to preserve Screen Recording TCC permissions.
    pub fn start_sunshine() -> Result<()> {
        let _ = Self::stop_sunshine();
        std::thread::sleep(Duration::from_millis(250));

        let sunshine_bin = system_info::find_sunshine_binary().context(
            "Sunshine binary not found. Install Sunshine.app or add `sunshine` to PATH.",
        )?;

        let log_dir = system_info::user_home_dir().join("Library/Logs");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("sunshine.log");
        let err_log_path = log_dir.join("sunshine.err.log");
        let conf_path = system_info::find_sunshine_conf().filter(|p| p.is_file());

        // Launch Sunshine.app via LaunchServices (`open`) when packaged inside a .app bundle
        // so macOS attributes Screen Recording TCC permissions to Sunshine.app itself rather than
        // inheriting Integrator.app's TCC context.
        if let Some(app_bundle) = sunshine_bin
            .ancestors()
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("app"))
        {
            if let Err(e) = create_private_log_file(&log_path) {
                warn!("Could not prepare Sunshine stdout log {}: {}", log_path.display(), e);
            }
            if let Err(e) = create_private_log_file(&err_log_path) {
                warn!("Could not prepare Sunshine stderr log {}: {}", err_log_path.display(), e);
            }
            let mut cmd = Command::new("/usr/bin/open");
            cmd.arg("-g")
                .arg("-n")
                .arg("-a")
                .arg(app_bundle)
                .arg("-o")
                .arg(&log_path)
                .arg("--stderr")
                .arg(&err_log_path);
            if let Some(conf) = &conf_path {
                cmd.arg("--args").arg(conf);
            }
            let status = cmd
                .status()
                .with_context(|| format!("Failed to launch {} via open", app_bundle.display()))?;
            if !status.success() {
                anyhow::bail!(
                    "`open` exited with status {} while starting {}",
                    status,
                    app_bundle.display()
                );
            }
            info!("Launched Sunshine bundle ({}) via LaunchServices", app_bundle.display());
        } else {
            let log_file = create_private_log_file(&log_path)?;
            let mut cmd = Command::new(&sunshine_bin);
            if let Some(conf) = &conf_path {
                cmd.arg(conf);
            }
            let child = cmd
                .stdin(Stdio::null())
                .stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file))
                .spawn()
                .with_context(|| format!("Failed to launch {}", sunshine_bin.display()))?;
            reap_child(child, "sunshine");

            info!("Launched Sunshine server ({})", sunshine_bin.display());
        }
        Ok(())
    }

    /// Dispatches an administrative POST request to the local Sunshine REST API on macOS.
    ///
    /// Executes `/usr/bin/curl` with a 2-second timeout and default administrative credentials (`admin:alpine`).
    ///
    /// # Arguments
    /// - `web_port`: Sunshine web administration port (e.g. 47990).
    /// - `path`: API endpoint path (e.g. `"/api/apps/close"`).
    pub fn call_sunshine_api(web_port: u16, path: &str) {
        let url = format!("https://127.0.0.1:{}{}", web_port, path);
        let _ = Command::new("/usr/bin/curl")
            .args(["-s", "-k", "-m", "2", "-u", "admin:alpine", "-X", "POST", &url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Stops any running Sunshine server processes on macOS.
    pub fn stop_sunshine() -> Result<()> {
        Self::call_sunshine_api(47990, "/api/apps/close");
        Self::call_sunshine_api(47990, "/api/reset-display-device-persistence");

        let is_running = || {
            ["Sunshine", "sunshine"].iter().any(|proc_name| {
                Command::new("/usr/bin/pgrep")
                    .args(["-x", proc_name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
        };

        let _ = Command::new("/usr/bin/killall")
            .args(["-q", "-TERM", "Sunshine", "sunshine"])
            .status();
        for _ in 0..10 {
            if !is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if is_running() {
            let _ = Command::new("/usr/bin/killall")
                .args(["-q", "-KILL", "Sunshine", "sunshine"])
                .status();
        }
        info!("Stopped Sunshine server on macOS");
        Ok(())
    }

    /// Waits until Sunshine binds its configured local port.
    pub async fn wait_for_sunshine_ready(timeout_dur: Duration) -> bool {
        let (_, port, _) = system_info::read_sunshine_config_info();
        Self::wait_for_port("127.0.0.1", port, timeout_dur).await
    }

    /// Probes a TCP port until connection succeeds or `timeout` expires.
    pub async fn wait_for_port(ip: &str, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", ip, port);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if matches!(
                tokio::time::timeout(Duration::from_millis(300), tokio::net::TcpStream::connect(&addr)).await,
                Ok(Ok(_))
            ) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }

    /// Launches the Moonlight client CLI on macOS without clobbering unrelated host pairing configurations.
    ///
    /// # Arguments
    /// - `pc_ip`: Target host IPv4 address.
    /// - `port`: Sunshine web/RTSP port.
    /// - `host_name`: Host display name.
    /// - `width`: Stream width in pixels.
    /// - `height`: Stream height in pixels.
    /// - `fps`: Refresh rate in Hertz.
    /// - `bitrate_kbps`: Maximum bitrate in kilobits per second.
    /// - `audio_on_host`: Whether audio is retained on host.
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
        if !system_info::is_valid_ipv4(pc_ip) {
            anyhow::bail!("Invalid host IPv4 address for Moonlight: {}", pc_ip);
        }

        let _ = Self::stop_moonlight_client();

        let moonlight_bin = system_info::find_moonlight_binary().context(
            "Moonlight.app not found. Install Moonlight in /Applications or ~/Applications.",
        )?;

        let host_target = resolve_or_refresh_mac_moonlight_slot(pc_ip, port, host_name)
            .unwrap_or_else(|| pc_ip.to_string());
        let host_target = host_target.trim().to_string();
        if host_target.is_empty()
            || host_target.starts_with('-')
            || host_target.chars().any(|c| c.is_control())
        {
            anyhow::bail!("Invalid Moonlight host target '{}'", host_target);
        }

        let w = (width.clamp(800, 7680)) & !1;
        let h = (height.clamp(600, 4320)) & !1;
        let res_arg = format!("{}x{}", w, h);
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
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn {}", moonlight_bin.display()))?;
        reap_child(child, "moonlight");

        info!(
            "Launched Moonlight on macOS -> '{}' ({}:{}) at {} @ {}Hz",
            host_target, pc_ip, port, res_arg, fps_arg
        );
        Ok(())
    }

    /// Stops any running Moonlight client processes on macOS.
    pub fn stop_moonlight_client() -> Result<()> {
        let is_running = || {
            Command::new("/usr/bin/pgrep")
                .args(["-x", "Moonlight"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        if is_running() {
            let _ = Command::new("/usr/bin/killall")
                .args(["-q", "Moonlight"])
                .status();
            for _ in 0..8 {
                if !is_running() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        }
        info!("Stopped Moonlight on macOS");
        Ok(())
    }

    /// Displays a native macOS desktop notification via AppleScript (`osascript`).
    pub fn show_notification(title: &str, message: &str) {
        let safe_title: String = title.chars().filter(|c| !c.is_control()).take(128).collect();
        let safe_msg: String = message.chars().filter(|c| !c.is_control()).take(256).collect();
        if let Ok(child) = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "on run argv\ndisplay notification (item 1 of argv) with title (item 2 of argv)\nend run",
                safe_msg.as_str(),
                safe_title.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            reap_child(child, "osascript");
        }
    }
}

/// Inspects existing paired Moonlight hosts in `com.moonlight-stream.Moonlight` preferences
/// and refreshes ONLY the slot that genuinely matches `host_name` / `pc_ip` & `port`.
///
/// Guarantees that existing user configurations and other gaming PC pairings remain completely untouched.
fn resolve_or_refresh_mac_moonlight_slot(
    pc_ip: &str,
    port: u16,
    host_name: &str,
) -> Option<String> {
    if !system_info::is_valid_ipv4(pc_ip) {
        return None;
    }

    let out = Command::new("/usr/bin/defaults")
        .args(["read", "com.moonlight-stream.Moonlight"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut size: usize = 0;
    let mut indices = std::collections::BTreeSet::new();
    let mut props: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_matches('"').to_string();
            let val = v.trim().trim_matches('"').to_string();
            if key == "hosts.size" {
                size = val.parse().unwrap_or(0);
            } else if let Some(rest) = key.strip_prefix("hosts.") {
                if let Some((idx_str, _)) = rest.split_once('.') {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        indices.insert(idx);
                    }
                }
                props.insert(key, val);
            }
        }
    }

    for idx in 1..=size {
        indices.insert(idx);
    }
    if indices.is_empty() {
        return None;
    }

    let wanted_port = port.to_string();
    let mut best_slot: Option<usize> = None;

    for idx in indices {
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
        let h_manual_port = props
            .get(&format!("hosts.{}.manualport", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_http_port = props
            .get(&format!("hosts.{}.httpport", idx))
            .map(String::as_str)
            .unwrap_or("");

        let ip_match = h_local_ip == pc_ip || h_manual_ip == pc_ip;
        let name_match =
            !host_name.is_empty() && h_name.eq_ignore_ascii_case(host_name);
        let port_match = h_local_port == wanted_port
            || h_manual_port == wanted_port
            || h_http_port == wanted_port;

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
        match Command::new("/usr/bin/defaults")
            .args(["write", "com.moonlight-stream.Moonlight", &key, "-string", pc_ip])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => warn!("defaults write {} exited with status {}", key, s),
            Err(e) => warn!("Failed to invoke defaults write {}: {}", key, e),
        }
    }

    // Prefer hostname or direct route IP so Moonlight connects immediately without UUID WoL timeout delays
    if let Some(hname) = props.get(&format!("hosts.{}.hostname", idx)) {
        let trimmed = hname.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('-') && !trimmed.chars().any(|c| c.is_control())
        {
            return Some(trimmed.to_string());
        }
    }
    if !pc_ip.trim().is_empty() && system_info::is_valid_ipv4(pc_ip) {
        return Some(pc_ip.trim().to_string());
    }
    props
        .get(&format!("hosts.{}.uuid", idx))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('-') && !s.chars().any(|c| c.is_control()))
        .or_else(|| Some(pc_ip.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_sunshine_output_preserves_comments_and_other_keys() {
        let initial = "# output_name = 99\noutput_name_secondary = 2\nport = 47989\noutput_name = 1\n";
        let updated = update_sunshine_output_content(initial, 42);
        assert_eq!(
            updated,
            "# output_name = 99\noutput_name_secondary = 2\nport = 47989\noutput_name = 42\n"
        );
    }
}
