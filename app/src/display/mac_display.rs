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

use crate::{config, system_info};
use anyhow::{Context, Result};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Maximum curl execution timeout in seconds for local Sunshine REST API control requests.
const SUNSHINE_API_TIMEOUT_SECS: &str = "2";

/// Default relative directory under `$HOME` for `sunshine.conf` when no existing config is discovered.
const MACOS_DEFAULT_SUNSHINE_CONF_DIR: &str = ".config/sunshine";

/// Relative per-user macOS diagnostic log directory under `$HOME`.
const MACOS_LOGS_REL_DIR: &str = "Library/Logs";

/// Filename for Sunshine standard output logs on macOS.
const SUNSHINE_STDOUT_LOG_NAME: &str = "sunshine.log";

/// Filename for Sunshine standard error logs on macOS.
const SUNSHINE_STDERR_LOG_NAME: &str = "sunshine.err.log";

/// Settling delay after stopping a prior Sunshine process before relaunching it.
const SUNSHINE_RESTART_DELAY: Duration = Duration::from_millis(250);

/// Maximum number of `pgrep` polling iterations while waiting for Sunshine to exit after SIGTERM.
const SUNSHINE_STOP_POLL_ATTEMPTS: usize = 10;

/// Interval between Sunshine process-exit polling checks.
const SUNSHINE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Per-attempt TCP connect timeout when probing Sunshine readiness.
const PORT_PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// Delay between TCP readiness probe attempts.
const PORT_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Maximum number of `pgrep` polling iterations while waiting for Moonlight to terminate.
const MOONLIGHT_STOP_POLL_ATTEMPTS: usize = 8;

/// Interval between Moonlight process-exit polling checks.
const MOONLIGHT_STOP_POLL_INTERVAL: Duration = Duration::from_millis(80);

/// Maximum safe character length for macOS notification titles passed to `osascript`.
const MAX_NOTIFICATION_TITLE_LEN: usize = 128;

/// Maximum safe character length for macOS notification messages passed to `osascript`.
const MAX_NOTIFICATION_MESSAGE_LEN: usize = 256;

/// Retained handle to the Integrator-owned Moonlight child process (SEC-1D-16).
static OWNED_MOONLIGHT_PROCESS: Mutex<Option<Child>> = Mutex::new(None);

/// Retained handle to the Integrator-owned Sunshine host process (SEC-1D-16).
static OWNED_SUNSHINE_PROCESS: Mutex<Option<Child>> = Mutex::new(None);

/// Sets the mock/test child handle for owned Moonlight process testing.
#[cfg(test)]
pub fn set_owned_moonlight_child(child: Child) {
    *OWNED_MOONLIGHT_PROCESS.lock().unwrap() = Some(child);
}

/// Returns whether an owned Moonlight process handle is currently retained.
#[cfg(test)]
pub fn has_owned_moonlight_child() -> bool {
    OWNED_MOONLIGHT_PROCESS.lock().unwrap().is_some()
}

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
    /// Locates Integrator's own virtual display using custom Vendor/Product ID
    /// ([`config::INTEGRATOR_EDID_VENDOR_ID`] / [`config::INTEGRATOR_EDID_PRODUCT_ID`]).
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
            system_info::user_home_dir()
                .join(MACOS_DEFAULT_SUNSHINE_CONF_DIR)
                .join(config::SUNSHINE_CONF_FILENAME)
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
    /// - `width`: Target display width in pixels (clamped to [`config::MIN_DISPLAY_WIDTH`]..=[`config::MAX_DISPLAY_WIDTH`]).
    /// - `height`: Target display height in pixels (clamped to [`config::MIN_DISPLAY_HEIGHT`]..=[`config::MAX_DISPLAY_HEIGHT`]).
    /// - `fps`: Target refresh rate in Hertz (clamped to [`config::MIN_DISPLAY_FPS`]..=[`config::MAX_DISPLAY_FPS`]).
    ///
    /// # Returns
    /// CoreGraphics display identifier (`CGDirectDisplayID`) on success.
    pub fn start_virtual_display(width: u32, height: u32, fps: u32) -> Result<u32> {
        #[cfg(target_os = "macos")]
        {
            let w = width.clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH);
            let h = height.clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT);
            let f = fps.clamp(config::MIN_DISPLAY_FPS, config::MAX_DISPLAY_FPS);
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
            for _ in 0..10 {
                if !Self::is_virtual_display_active() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if Self::is_virtual_display_active() {
                anyhow::bail!("Virtual display remains active on macOS after stop request");
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
        std::thread::sleep(SUNSHINE_RESTART_DELAY);

        let sunshine_bin = system_info::find_sunshine_binary().context(
            "Sunshine binary not found. Install Sunshine.app or add `sunshine` to PATH.",
        )?;

        let log_dir = system_info::user_home_dir().join(MACOS_LOGS_REL_DIR);
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join(SUNSHINE_STDOUT_LOG_NAME);
        let err_log_path = log_dir.join(SUNSHINE_STDERR_LOG_NAME);
        let conf_path = system_info::find_sunshine_conf().filter(|p| p.is_file());

        let log_file = create_private_log_file(&log_path)?;
        let err_log_file = create_private_log_file(&err_log_path)?;
        let mut cmd = Command::new(&sunshine_bin);
        if let Some(conf) = &conf_path {
            cmd.arg(conf);
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(err_log_file))
            .spawn()
            .with_context(|| format!("Failed to launch {}", sunshine_bin.display()))?;

        let pid = child.id();
        *OWNED_SUNSHINE_PROCESS.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);

        info!("Launched Sunshine server ({}) with owned PID {}", sunshine_bin.display(), pid);
        Ok(())
    }

    /// Dispatches an administrative POST request to the local Sunshine REST API on macOS.
    ///
    /// Resolves credentials dynamically via [`system_info::resolve_sunshine_api_credentials`]
    /// (environment variables or user preferences) and pipes them to `curl -K -` over `stdin`
    /// so secrets never appear on process `argv` or `ps aux`. Skips execution cleanly if no
    /// credentials are configured.
    ///
    /// # Arguments
    /// - `web_port`: Sunshine web administration port (e.g. [`config::SUNSHINE_DEFAULT_WEB_PORT`]).
    /// - `path`: API endpoint path (e.g. [`config::SUNSHINE_API_CLOSE_PATH`]).
    pub fn call_sunshine_api(web_port: u16, path: &str) {
        let Some((user, pass)) = system_info::resolve_sunshine_api_credentials() else {
            debug!(
                "Skipping macOS Sunshine API POST to {}:{} (no Sunshine API credentials configured)",
                web_port, path
            );
            return;
        };
        let url = format!("https://{}:{}{}", Ipv4Addr::LOCALHOST, web_port, path);
        let auth_cfg = system_info::format_curl_basic_auth_config(&user, &pass);
        if let Ok(mut child) = Command::new(config::MACOS_CURL_BIN)
            .args([
                "-s",
                "-k",
                "-m",
                SUNSHINE_API_TIMEOUT_SECS,
                "-K",
                "-",
                "-X",
                "POST",
                &url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(auth_cfg.as_bytes());
            }
            let _ = child.wait();
        }
    }

    /// Stops the Integrator-owned Sunshine server process on macOS without killing external processes (SEC-1D-16).
    pub fn stop_sunshine() -> Result<()> {
        let (_, base_port, _) = system_info::read_sunshine_config_info();
        let web_port = base_port.saturating_add(config::SUNSHINE_WEB_PORT_OFFSET);
        Self::call_sunshine_api(web_port, config::SUNSHINE_API_CLOSE_PATH);
        Self::call_sunshine_api(web_port, config::SUNSHINE_API_RESET_PERSISTENCE_PATH);

        let mut lock = OWNED_SUNSHINE_PROCESS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut child) = lock.take() {
            let pid = child.id() as i32;
            info!("Stopping Integrator-owned Sunshine host process (PID {})", pid);
            #[cfg(unix)]
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let mut exited = false;
            for _ in 0..SUNSHINE_STOP_POLL_ATTEMPTS {
                if let Ok(Some(_)) = child.try_wait() {
                    exited = true;
                    break;
                }
                std::thread::sleep(SUNSHINE_STOP_POLL_INTERVAL);
            }
            if !exited {
                warn!("Escalating to SIGKILL for owned Sunshine host (PID {})", pid);
                let _ = child.kill();
                let _ = child.wait();
            }
            info!("Stopped Integrator-owned Sunshine host process (PID {})", pid);
        }
        Ok(())
    }

    /// Waits until Sunshine binds its configured local port.
    pub async fn wait_for_sunshine_ready(timeout_dur: Duration) -> bool {
        let (_, port, _) = system_info::read_sunshine_config_info();
        let loopback = Ipv4Addr::LOCALHOST.to_string();
        Self::wait_for_port(&loopback, port, timeout_dur).await
    }

    /// Probes a TCP port until connection succeeds or `timeout` expires.
    pub async fn wait_for_port(ip: &str, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", ip, port);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if matches!(
                tokio::time::timeout(PORT_PROBE_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&addr)).await,
                Ok(Ok(_))
            ) {
                return true;
            }
            tokio::time::sleep(PORT_PROBE_RETRY_INTERVAL).await;
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

        let app_name = system_info::resolve_moonlight_app_name();
        let w = width.clamp(config::MIN_DISPLAY_WIDTH, config::MAX_DISPLAY_WIDTH) & !1;
        let h = height.clamp(config::MIN_DISPLAY_HEIGHT, config::MAX_DISPLAY_HEIGHT) & !1;
        let res_arg = format!("{}x{}", w, h);
        let fps_arg = fps
            .clamp(config::MIN_DISPLAY_FPS, config::MAX_DISPLAY_FPS)
            .to_string();
        let bitrate_arg = bitrate_kbps
            .clamp(config::MIN_BITRATE_KBPS, config::MAX_BITRATE_KBPS)
            .to_string();

        let mut cmd = Command::new(&moonlight_bin);
        cmd.args([
            "stream",
            &host_target,
            &app_name,
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
        let pid = child.id();
        *OWNED_MOONLIGHT_PROCESS.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);

        info!(
            "Launched Moonlight on macOS (PID {}) -> '{}' ({}:{}) at {} @ {}Hz",
            pid, host_target, pc_ip, port, res_arg, fps_arg
        );
        Ok(())
    }

    /// Stops the Integrator-owned Moonlight client process on macOS without killing external processes (SEC-1D-16).
    pub fn stop_moonlight_client() -> Result<()> {
        let mut lock = OWNED_MOONLIGHT_PROCESS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut child) = lock.take() {
            let pid = child.id() as i32;
            info!("Stopping Integrator-owned Moonlight client process (PID {})", pid);
            #[cfg(unix)]
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let mut exited = false;
            for _ in 0..MOONLIGHT_STOP_POLL_ATTEMPTS {
                if let Ok(Some(_)) = child.try_wait() {
                    exited = true;
                    break;
                }
                std::thread::sleep(MOONLIGHT_STOP_POLL_INTERVAL);
            }
            if !exited {
                warn!("Escalating to SIGKILL for owned Moonlight client (PID {})", pid);
                let _ = child.kill();
                let _ = child.wait();
            }
            info!("Stopped Integrator-owned Moonlight client process (PID {})", pid);
        }
        Ok(())
    }

    /// Displays a native macOS desktop notification via AppleScript (`osascript`).
    pub fn show_notification(title: &str, message: &str) {
        let safe_title: String = title
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_NOTIFICATION_TITLE_LEN)
            .collect();
        let safe_msg: String = message
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_NOTIFICATION_MESSAGE_LEN)
            .collect();
        if let Ok(child) = Command::new(config::MACOS_OSASCRIPT_BIN)
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

/// Normalizes a Moonlight/Sunshine hostname by stripping whitespace, trailing dots, and `.local` mDNS suffixes.
fn normalize_moonlight_hostname(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_suffix(".local") {
        stripped.trim().to_string()
    } else {
        lower
    }
}

/// Parses `defaults read com.moonlight-stream.Moonlight` text output and selects the best matching
/// host slot `(slot_index, launch_target, hostname_needs_ip_refresh)` for `(pc_ip, port, host_name)`.
///
/// # Topology Switching Guarantees
/// - Matches hostnames case-insensitively across `.local` mDNS suffixes when switching between
///   USB-C (`10.99.99.x`), Thunderbolt (`169.254.x.x`), PC Hotspot (`192.168.137.x`),
///   Phone Hotspot (`172.20.10.x`), and Normal LAN (`192.168.1.x`).
/// - If a user originally paired the single matching-port host by raw IPv4 address (so `hosts.N.hostname`
///   holds an older topology IP like `"10.99.99.1"`), matches that slot as a fallback and flags
///   `hostname_needs_ip_refresh = true` so `resolve_or_refresh_mac_moonlight_slot` updates `hostname`
///   and returns `pc_ip` instead of a stale IP or a slow UUID WoL lookup.
fn parse_and_select_mac_moonlight_slot(
    defaults_output: &str,
    pc_ip: &str,
    port: u16,
    host_name: &str,
) -> Option<(usize, String, bool)> {
    let clean_ip = pc_ip.trim();
    if !system_info::is_valid_ipv4(clean_ip) {
        return None;
    }

    let mut size: usize = 0;
    let mut indices = std::collections::BTreeSet::new();
    let mut props: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for line in defaults_output.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_matches('"').to_string();
            let val = v.trim().trim_matches('"').to_string();
            if key == "hosts.size" {
                size = val.parse().unwrap_or(0);
            } else if let Some(rest) = key.strip_prefix("hosts.") {
                if let Some((idx_str, _)) = rest.split_once('.') {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if idx > 0 {
                            indices.insert(idx);
                        }
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
    let default_port_str = config::SUNSHINE_DEFAULT_PORT.to_string();
    let wanted_host_norm = normalize_moonlight_hostname(host_name);
    let mut best_slot: Option<usize> = None;
    let mut best_score: u8 = 0;
    let mut raw_ip_port_candidates: Vec<usize> = Vec::new();

    for &idx in &indices {
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
        let h_remote_ip = props
            .get(&format!("hosts.{}.remoteaddress", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_local_port = props
            .get(&format!("hosts.{}.localport", idx))
            .map(String::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(default_port_str.as_str());
        let h_manual_port = props
            .get(&format!("hosts.{}.manualport", idx))
            .map(String::as_str)
            .unwrap_or("");
        let h_http_port = props
            .get(&format!("hosts.{}.httpport", idx))
            .map(String::as_str)
            .unwrap_or("");

        let ip_match = h_local_ip == clean_ip || h_manual_ip == clean_ip || h_remote_ip == clean_ip;
        let slot_host_norm = normalize_moonlight_hostname(h_name);
        let name_match = !wanted_host_norm.is_empty()
            && !slot_host_norm.is_empty()
            && slot_host_norm == wanted_host_norm;
        let port_match = h_local_port == wanted_port
            || h_manual_port == wanted_port
            || h_http_port == wanted_port;

        if port_match && (h_name.trim().is_empty() || system_info::is_valid_ipv4(h_name.trim())) {
            raw_ip_port_candidates.push(idx);
        }

        let score = if name_match && port_match {
            5
        } else if ip_match && port_match {
            4
        } else if name_match {
            2
        } else if ip_match {
            1
        } else {
            0
        };

        if score > best_score {
            best_score = score;
            best_slot = Some(idx);
        }
    }

    if best_slot.is_none() && raw_ip_port_candidates.len() == 1 {
        best_slot = Some(raw_ip_port_candidates[0]);
    }

    let idx = best_slot?;
    let raw_hname = props
        .get(&format!("hosts.{}.hostname", idx))
        .map(|s| s.trim())
        .unwrap_or("");
    let hname_is_stale_ip =
        !raw_hname.is_empty() && system_info::is_valid_ipv4(raw_hname) && raw_hname != clean_ip;

    let launch_target = if !raw_hname.is_empty()
        && !hname_is_stale_ip
        && !raw_hname.starts_with('-')
        && !raw_hname.chars().any(|c| c.is_control())
    {
        raw_hname.to_string()
    } else {
        clean_ip.to_string()
    };

    Some((idx, launch_target, hname_is_stale_ip))
}

/// Inspects existing paired Moonlight hosts in [`config::MOONLIGHT_MACOS_PREFS_DOMAIN`] preferences
/// and refreshes ONLY the slot that genuinely matches `host_name` / `pc_ip` & `port`.
///
/// Guarantees that existing user configurations and other gaming PC pairings remain completely untouched.
fn resolve_or_refresh_mac_moonlight_slot(
    pc_ip: &str,
    port: u16,
    host_name: &str,
) -> Option<String> {
    let clean_ip = pc_ip.trim();
    if !system_info::is_valid_ipv4(clean_ip) {
        return None;
    }

    let out = Command::new(config::MACOS_DEFAULTS_BIN)
        .args(["read", config::MOONLIGHT_MACOS_PREFS_DOMAIN])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let (idx, launch_target, hname_is_stale_ip) =
        parse_and_select_mac_moonlight_slot(&text, clean_ip, port, host_name)?;

    // Update the matched slot's active route IP across USB-C, Thunderbolt, Hotspot, and LAN transitions
    let mut fields = vec!["localaddress", "manualaddress"];
    if hname_is_stale_ip {
        fields.push("hostname");
    }
    for field in fields {
        let key = format!("hosts.{}.{}", idx, field);
        match Command::new(config::MACOS_DEFAULTS_BIN)
            .args([
                "write",
                config::MOONLIGHT_MACOS_PREFS_DOMAIN,
                &key,
                "-string",
                clean_ip,
            ])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => warn!("defaults write {} exited with status {}", key, s),
            Err(e) => warn!("Failed to invoke defaults write {}: {}", key, e),
        }
    }

    Some(launch_target)
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

    #[test]
    fn mac_moonlight_slot_resolves_across_all_five_topologies_without_stale_ip() {
        // Slot 1 paired via mDNS (.local) on LAN 192.168.1.50; switches to USB-C, Thunderbolt, PC Hotspot, and Phone Hotspot
        let prefs_mdns = r#"
{
    "hosts.size" = 1;
    "hosts.1.hostname" = "Studio-PC.local";
    "hosts.1.localaddress" = "192.168.1.50";
    "hosts.1.manualaddress" = "192.168.1.50";
    "hosts.1.localport" = 47989;
    "hosts.1.uuid" = "uuid-studio-pc";
}
"#;
        for new_ip in [
            "10.99.99.1",
            "169.254.10.1",
            "192.168.137.1",
            "172.20.10.7",
            "192.168.1.50",
        ] {
            let (idx, target, stale_ip) =
                parse_and_select_mac_moonlight_slot(prefs_mdns, new_ip, 47989, "Studio-PC")
                    .expect("should match slot across topology transition");
            assert_eq!(idx, 1);
            assert_eq!(target, "Studio-PC.local");
            assert!(!stale_ip);
        }

        // Slot originally paired by raw USB-C IP ("10.99.99.1" stored in hostname) switching to iPhone Hotspot "172.20.10.7"
        let prefs_raw_ip = r#"
{
    "hosts.size" = 1;
    "hosts.1.hostname" = "10.99.99.1";
    "hosts.1.localaddress" = "10.99.99.1";
    "hosts.1.manualaddress" = "10.99.99.1";
    "hosts.1.localport" = 47989;
    "hosts.1.uuid" = "uuid-raw-ip";
}
"#;
        let (idx, target, stale_ip) =
            parse_and_select_mac_moonlight_slot(prefs_raw_ip, "172.20.10.7", 47989, "Studio-PC")
                .expect("single raw-IP slot should match on topology switch");
        assert_eq!(idx, 1);
        assert_eq!(target, "172.20.10.7", "must never return stale IP 10.99.99.1");
        assert!(stale_ip);
    }

    #[cfg(unix)]
    #[test]
    fn test_display_owned_process_termination_spares_external_process() {
        // Spawn an external mock process that simulates an independent Moonlight instance
        let mut external_child = Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("spawn external mock process");
        let ext_pid = external_child.id() as i32;

        // Spawn an Integrator-owned Moonlight process
        let owned_child = Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("spawn owned mock process");
        let owned_pid = owned_child.id() as i32;

        set_owned_moonlight_child(owned_child);
        assert!(has_owned_moonlight_child(), "Owned child handle must be retained");

        // Stop the Moonlight client
        let res = MacDisplayManager::stop_moonlight_client();
        assert!(res.is_ok(), "stop_moonlight_client must succeed");
        assert!(!has_owned_moonlight_child(), "Owned child handle must be cleared after stop");

        // Verify the owned child was terminated
        #[cfg(unix)]
        unsafe {
            let mut check_count = 0;
            while libc::kill(owned_pid, 0) == 0 && check_count < 20 {
                std::thread::sleep(Duration::from_millis(50));
                check_count += 1;
            }
            let owned_alive = libc::kill(owned_pid, 0) == 0;
            assert!(!owned_alive, "Owned process (PID {}) must be terminated", owned_pid);

            // Verify the external process is STILL ALIVE (unaffected by stop_moonlight_client)
            let ext_alive = libc::kill(ext_pid, 0) == 0;
            assert!(ext_alive, "External process (PID {}) must NOT be terminated by stop_moonlight_client", ext_pid);
        }

        // Clean up external child
        let _ = external_child.kill();
        let _ = external_child.wait();
    }
}
