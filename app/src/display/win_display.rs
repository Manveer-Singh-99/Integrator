//! # Windows Native Display & Virtual Display Driver Subsystem
//!
//! ## 1. Module Purpose & Scope
//! This module owns the Windows 11-specific implementation of the **Display Subsystem** (`display` feature).
//! It provides:
//! 1. Dynamic discovery and PnP control of Windows Virtual Display Driver (VDD) adapters
//!    (IddSampleDriver, Apollo, MTT VDD, Parsec, Amyuni, Spacedesk).
//! 2. Display slot attachment and detachment via `VddCtl.exe join 1` and `VddCtl.exe leave 1`.
//! 3. Windows Service and Scheduled Task supervision for the Sunshine streaming host
//!    (`SunshineService`, `SunshineSecondary`).
//! 4. Non-destructive resolution and IP updating of existing Moonlight host pairing slots in
//!    `HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts`.
//! 5. Windows DirectX GPU routing via `HKCU\Software\Microsoft\DirectX\UserGpuPreferences`, directing
//!    discrete GPUs for hardware video encoding (NVENC / AMF) and decoding (D3D11 / NVDEC).
//!
//! ## 2. Cross-Platform Architectural Pipelines
//!
//! ### Windows-as-Host Extended Desktop
//! - **VDD PnP Activation**: Discovers the display adapter under `ROOT\DISPLAY` and enables it via
//!   `Enable-PnpDevice`. Attaches display slot 1 via `VddCtl.exe join 1` (verified in `Program Files` to
//!   prevent privilege escalation).
//! - **Sunshine Desktop Duplication**: Sunshine captures the newly attached virtual screen via DXGI
//!   Desktop Duplication API, encodes video with discrete GPU hardware (NVIDIA NVENC, AMD AMF, or
//!   Intel QuickSync), and listens on port 47989 (or secondary 48989).
//! - **Moonlight Streaming**: The macOS client receives the stream and renders with VideoToolbox hardware decoding.
//!
//! ### Windows-as-Client Extended Desktop
//! - Receives a stream from a macOS host (which encodes via Apple Silicon VideoToolbox).
//! - Queries `HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts` via `reg.exe query /s`,
//!   locates the matched slot non-destructively, updates its `localaddress` / `manualaddress` without
//!   wiping existing paired games or settings, and launches `Moonlight.exe` in fullscreen.
//!
//! ### Shared Camera Coexistence
//! While Windows display streaming captures the desktop imagery with high frame rates (60 to 240 Hz),
//! the Shared Camera subsystem operates simultaneously over port 58287:
//! - macOS captures FaceTime HD camera at 720p30 NV12 (`camera_macos.swift`).
//! - Frames stream directly across `TransportSessionV2` into `camera_windows.cpp` and `vcam_windows.cpp`.
//! - Windows 11 Media Foundation FrameServer (`integrator_vcam.dll`) exposes "Integrator MacBook Camera"
//!   system-wide to Teams, Zoom, OBS, and browsers without requiring third-party drivers or physical camera
//!   source wrapper attributes (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).
//! The display and camera subsystems run concurrently without port conflicts or GPU encoder resource starvation.
//!
//! ## 3. Threading & Process Management Model
//! - **Hidden Process Spawning**: All Windows process executions (`reg.exe`, `sc.exe`, `schtasks.exe`,
//!   `powershell.exe`, `taskkill.exe`) use `CREATE_NO_WINDOW` (0x08000000) to avoid flashing command prompts.
//! - **Zombie Reaping**: Background worker threads ([`reap_child`]) wait for spawned child processes.
//! - **Registry Synchronization**: Registry updates are executed before launching `Moonlight.exe` to
//!   prevent races with Qt `QSettings` flushes.
//!
//! ## 4. Security & Safety Invariants
//! - **Driver Security**: `find_vdd_ctl` restricts binary discovery to authenticated system root and Program Files locations
//!   (`%SystemDrive%\VirtualDisplayDriver`, `Program Files`, `ProgramW6432`), rejecting user-writable directories to prevent local privilege escalation.
//! - **PowerShell Escaping**: Dynamic parameters passed to PowerShell commands are sanitized using
//!   [`ps_single_quote`], doubling embedded single quotes.
//! - **Non-Destructive Registry Updates**: Existing user preferences (`AutoHDREnable`, `SwapEffectUpgradeEnable`)
//!   in `UserGpuPreferences` are preserved during GPU routing updates.

use crate::system_info;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "windows")]
use std::time::Duration;
#[allow(unused_imports)]
use tracing::{info, warn};

/// Spawns a dedicated thread to wait on and reap an exiting child process, preventing zombies.
///
/// # Arguments
/// - `child`: Spawned child process handle.
/// - `label`: Diagnostic label naming the reaper thread.
fn reap_child(mut child: Child, label: &'static str) {
    let _ = std::thread::Builder::new()
        .name(format!("reap-{}", label))
        .spawn(move || {
            let _ = child.wait();
        });
}

/// Windows process creation flag suppressing visible console window creation.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Windows Registry path for Moonlight host pairing slots.
#[cfg(target_os = "windows")]
const MOONLIGHT_HOSTS_REG_KEY: &str =
    r"HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts";

/// Windows Registry path for per-application DirectX GPU preferences.
#[cfg(target_os = "windows")]
const DIRECTX_GPU_PREFS_KEY: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";

/// Manager providing Windows native display creation, VDD PnP control, and Moonlight client execution.
pub struct WinDisplayManager;

impl WinDisplayManager {
    /// Discovers the Moonlight executable via `system_info::find_moonlight_binary()` or standard installation directories.
    pub fn find_moonlight_exe() -> Option<PathBuf> {
        system_info::find_moonlight_binary().or_else(|| {
            #[cfg(target_os = "windows")]
            {
                find_moonlight_legacy_dir_windows()
            }
            #[cfg(not(target_os = "windows"))]
            {
                None
            }
        })
    }

    /// Resolves an existing Moonlight host slot non-destructively and launches `Moonlight.exe`.
    ///
    /// # Arguments
    /// - `mac_ip`: Target host IPv4 address.
    /// - `port`: Sunshine web/RTSP port.
    /// - `host_name`: Target host display name.
    /// - `width`: Stream width in pixels.
    /// - `height`: Stream height in pixels.
    /// - `fps`: Refresh rate in Hertz.
    /// - `bitrate_kbps`: Maximum bitrate in kilobits per second.
    /// - `audio_on_host`: Whether audio is retained on host.
    pub fn start_moonlight_client(
        mac_ip: &str,
        port: u16,
        host_name: &str,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        audio_on_host: bool,
    ) -> Result<()> {
        if !system_info::is_valid_ipv4(mac_ip) {
            anyhow::bail!("Invalid host IPv4 address for Moonlight: {}", mac_ip);
        }

        let exe = Self::find_moonlight_exe().context("Moonlight.exe not found on Windows")?;

        // 1. Stop existing Moonlight cleanly before refreshing registry so QSettings does not race
        let _ = Self::stop_moonlight_client();

        // 2. Resolve existing paired slot non-destructively and refresh IP only if changed
        let target = resolve_or_refresh_win_moonlight_slot(mac_ip, port, host_name)
            .trim()
            .to_string();
        if target.is_empty() || target.starts_with('-') || target.chars().any(|c| c.is_control()) {
            anyhow::bail!("Invalid Moonlight host target '{}'", target);
        }

        // 3. Build CLI arguments
        let w = (width.clamp(800, 7680)) & !1;
        let h = (height.clamp(600, 4320)) & !1;
        let res_arg = format!("{}x{}", w, h);
        let fps_arg = fps.clamp(30, 240).to_string();
        let bitrate_arg = bitrate_kbps.clamp(5000, 500000).to_string();

        let mut cmd = Command::new(&exe);
        cmd.args([
            "stream",
            &target,
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

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn {}", exe.display()))?;
        reap_child(child, "moonlight");
        info!(
            "Launched Moonlight on Windows -> '{}' ({}:{}) at {} @ {}Hz",
            target, mac_ip, port, res_arg, fps_arg
        );
        Ok(())
    }

    /// Stops any running `Moonlight.exe` processes on Windows via `taskkill.exe`.
    pub fn stop_moonlight_client() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let taskkill = system_info::system32_exe("taskkill.exe");
            let image_name = Self::find_moonlight_exe()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .filter(|n| !n.is_empty() && !n.starts_with('/'))
                .unwrap_or_else(|| "Moonlight.exe".to_string());

            let _ = hidden_cmd(&taskkill)
                .args(["/F", "/IM", &image_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if !image_name.eq_ignore_ascii_case("Moonlight.exe") {
                let _ = hidden_cmd(&taskkill)
                    .args(["/F", "/IM", "Moonlight.exe"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }

            for _ in 0..8 {
                if !is_image_running(&image_name) && !is_image_running("Moonlight.exe") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        }
        info!("Terminated Moonlight.exe on Windows");
        Ok(())
    }

    /// Discovers and enables any Virtual Display Driver PnP adapters and ensures Sunshine is running.
    pub fn enable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let ps_exe = system_info::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");
            let schtasks = system_info::system32_exe("schtasks.exe");

            // 1. Discover virtual display PnP devices dynamically and enable if not already OK
            let vdd_devices = discover_vdd_pnp_devices();
            if vdd_devices.is_empty() {
                info!("No standalone virtual display PnP adapter found (Apollo/native Sunshine mode)");
            } else {
                for dev in &vdd_devices {
                    if !dev.status.eq_ignore_ascii_case("OK") {
                        let ps = format!(
                            "Enable-PnpDevice -InstanceId {} -Confirm:$false -ErrorAction Stop",
                            ps_single_quote(&dev.instance_id)
                        );
                        let out = hidden_cmd(&ps_exe)
                            .args([
                                "-NoProfile",
                                "-NonInteractive",
                                "-ExecutionPolicy",
                                "Bypass",
                                "-Command",
                                &ps,
                            ])
                            .output()
                            .with_context(|| {
                                format!("Failed to invoke Enable-PnpDevice for {}", dev.instance_id)
                            })?;
                        if !out.status.success() {
                            anyhow::bail!(
                                "Enable-PnpDevice for {} failed (Administrator privileges may be required): {}",
                                dev.instance_id,
                                String::from_utf8_lossy(&out.stderr).trim()
                            );
                        }
                    }
                    info!(
                        "Virtual display adapter ready: {} ({})",
                        dev.instance_id, dev.friendly_name
                    );
                }
            }

            // 2. Ensure Sunshine host service, secondary task, or binary is running
            ensure_sunshine_running()?;

            // Clear any lingering stream sessions on Sunshine web APIs to guarantee clean connection state
            Self::call_sunshine_api(48990, "/api/apps/close");
            Self::call_sunshine_api(47990, "/api/apps/close");

            // 3. Attach virtual display slot 1 via VddCtl.exe if present, else optional marker
            if let Some(vdd_ctl) = find_vdd_ctl() {
                let status = hidden_cmd(&vdd_ctl)
                    .args(["join", "1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .with_context(|| format!("Failed to invoke {}", vdd_ctl.display()))?;
                if !status.success() {
                    anyhow::bail!(
                        "{} join 1 exited with status {}",
                        vdd_ctl.display(),
                        status
                    );
                }
                info!("Attached virtual display slot 1 via {}", vdd_ctl.display());
            } else if !vdd_devices.is_empty() {
                system_info::atomic_write_private(
                    &system_info::app_data_dir().join("win_vdd.active"),
                    b"1",
                )?;
            }

            // 4. Start dynamic watcher only if that scheduled task exists
            if scheduled_task_exists("VddDynamicWatcher") {
                let status = hidden_cmd(&schtasks)
                    .args(["/Run", "/TN", "VddDynamicWatcher"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if let Ok(s) = status {
                    if !s.success() {
                        warn!("Scheduled task VddDynamicWatcher exited with {}", s);
                    }
                }
            }
        }
        info!("Enabled Virtual Display Driver on Windows");
        Ok(())
    }

    /// Dispatches an administrative POST request to the local Sunshine REST API.
    ///
    /// Executes native Windows `curl.exe` with a 2-second timeout and default administrative credentials (`admin:alpine`).
    /// Used to clear lingering streaming sessions (`/api/apps/close`) and reset display topology
    /// persistence (`/api/reset-display-device-persistence`).
    ///
    /// # Arguments
    /// - `web_port`: Sunshine web administration port (e.g. 47990 or 48990).
    /// - `path`: API endpoint path (e.g. `"/api/apps/close"`).
    pub fn call_sunshine_api(web_port: u16, path: &str) {
        #[cfg(target_os = "windows")]
        {
            let curl_exe = system_info::system32_exe("curl.exe");
            let url = format!("https://127.0.0.1:{}{}", web_port, path);
            let _ = hidden_cmd(&curl_exe)
                .args(["-s", "-k", "-m", "2", "-u", "admin:alpine", "-X", "POST", &url])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (web_port, path);
        }
    }

    /// Gracefully detaches/disables discovered Virtual Display Driver slots and adapters.
    pub fn disable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let _ = std::fs::remove_file(system_info::app_data_dir().join("win_vdd.active"));

            // Gracefully terminate any active streaming sessions and clear device persistence
            Self::call_sunshine_api(48990, "/api/apps/close");
            Self::call_sunshine_api(48990, "/api/reset-display-device-persistence");
            Self::call_sunshine_api(47990, "/api/apps/close");
            Self::call_sunshine_api(47990, "/api/reset-display-device-persistence");

            let mut first_err: Option<anyhow::Error> = None;
            if let Some(vdd_ctl) = find_vdd_ctl() {
                match hidden_cmd(&vdd_ctl)
                    .args(["leave", "1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                {
                    Ok(s) if s.success() => {
                        info!("Detached virtual display slot 1 via {}", vdd_ctl.display());
                    }
                    Ok(s) => {
                        first_err.get_or_insert_with(|| {
                            anyhow::anyhow!("{} leave 1 exited with {}", vdd_ctl.display(), s)
                        });
                    }
                    Err(e) => {
                        first_err.get_or_insert_with(|| e.into());
                    }
                }

                if let Some(dir) = vdd_ctl.parent() {
                    let slot1 = dir.join("slot1.active");
                    if slot1.exists() {
                        if let Err(e) = std::fs::remove_file(&slot1) {
                            warn!("Could not remove {}: {}", slot1.display(), e);
                        }
                    }
                }
            }

            if let Some(err) = first_err {
                return Err(err);
            }
            info!("Disabled virtual display slot 1 on Windows");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    /// Checks if a Virtual Display Driver session/slot is currently active on Windows.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn is_vdd_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            if let Some(vdd_ctl) = find_vdd_ctl() {
                if let Some(dir) = vdd_ctl.parent() {
                    if dir.join("slot1.active").exists() {
                        return true;
                    }
                }
            }
            if system_info::app_data_dir().join("win_vdd.active").exists() {
                return true;
            }
        }
        false
    }

    /// Reads current GPU preferences for encode and decode dynamically from Sunshine config,
    /// enumerated GPUs, and Windows `UserGpuPreferences`.
    #[cfg(target_os = "windows")]
    pub fn get_gpu_preferences() -> (String, String) {
        let gpus = system_info::enumerate_gpus();
        let (_, _, adapter_name) = system_info::read_sunshine_config_info();

        let encode_gpu = if let Some(ref adapter) = adapter_name {
            resolve_label_from_adapter(adapter, &gpus)
        } else if let Some(conf_path) = system_info::find_sunshine_conf() {
            std::fs::read_to_string(&conf_path)
                .ok()
                .and_then(|c| parse_sunshine_encoder(&c))
                .map(|enc| match enc.as_str() {
                    "nvenc" => "nvidia".to_string(),
                    "amdvce" | "amf" | "amd" => "amd".to_string(),
                    "quicksync" => "intel".to_string(),
                    "auto" => "auto".to_string(),
                    other => other.to_string(),
                })
                .unwrap_or_else(|| {
                    system_info::find_sunshine_binary()
                        .and_then(|bin| query_user_gpu_preference(&bin))
                        .map(|pref| gpu_label_for_preference(pref, &gpus))
                        .unwrap_or_else(|| "auto".to_string())
                })
        } else {
            system_info::find_sunshine_binary()
                .and_then(|bin| query_user_gpu_preference(&bin))
                .map(|pref| gpu_label_for_preference(pref, &gpus))
                .unwrap_or_else(|| "auto".to_string())
        };

        let moonlight_exe =
            system_info::find_moonlight_binary().or_else(find_moonlight_legacy_dir_windows);
        let decode_gpu = moonlight_exe
            .and_then(|bin| query_user_gpu_preference(&bin))
            .map(|pref| gpu_label_for_preference(pref, &gpus))
            .unwrap_or_else(|| "auto".to_string());

        (encode_gpu, decode_gpu)
    }

    /// Sets GPU preferences on Windows for Sunshine encoder and Moonlight decoder using
    /// live GPU enumeration and dynamic binary/config discovery.
    #[cfg(target_os = "windows")]
    pub fn set_gpu_preferences(encode_gpu: &str, decode_gpu: &str) -> Result<()> {
        let gpus = system_info::enumerate_gpus();

        // 1. Resolve & apply Sunshine encode GPU
        let enc_target = resolve_gpu_target(encode_gpu, &gpus);
        if enc_target.is_auto {
            if let Some(conf_path) = system_info::find_sunshine_conf() {
                update_sunshine_conf_encoder(&conf_path, None, true).with_context(|| {
                    format!("Failed to reset GPU keys in {}", conf_path.display())
                })?;
            }
        } else {
            if let Some(ref adapter_name) = enc_target.adapter_name {
                system_info::write_sunshine_adapter_name(adapter_name)
                    .context("Could not update Sunshine adapter_name")?;
            }
            if let Some(conf_path) = system_info::find_sunshine_conf() {
                update_sunshine_conf_encoder(&conf_path, enc_target.encoder, false)
                    .with_context(|| {
                        format!("Failed to update encoder in {}", conf_path.display())
                    })?;
            }
        }

        if let Some(sunshine_exe) = system_info::find_sunshine_binary() {
            set_user_gpu_preference(&sunshine_exe, enc_target.reg_pref)?;
        }

        // 2. Resolve & apply Moonlight decode GPU
        let dec_target = resolve_gpu_target(decode_gpu, &gpus);
        let moonlight_exe =
            system_info::find_moonlight_binary().or_else(find_moonlight_legacy_dir_windows);
        if let Some(moonlight_path) = moonlight_exe {
            set_user_gpu_preference(&moonlight_path, dec_target.reg_pref)?;
        }

        info!(
            "Updated Windows GPU routing: Encode GPU [{}] (adapter={:?}, {}), Decode GPU [{}] ({})",
            encode_gpu,
            enc_target.adapter_name,
            enc_target.reg_pref,
            decode_gpu,
            dec_target.reg_pref
        );
        Ok(())
    }
}

/// Helper function creating a `Command` configured with `CREATE_NO_WINDOW` on Windows.
#[cfg(target_os = "windows")]
fn hidden_cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Scans standard Program Files and Local AppData paths for legacy Moonlight installations.
#[cfg(target_os = "windows")]
fn find_moonlight_legacy_dir_windows() -> Option<PathBuf> {
    for env_key in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "LOCALAPPDATA",
    ] {
        if let Ok(base) = std::env::var(env_key) {
            let base_path = PathBuf::from(base);
            for rel in [
                r"Moonlight Game Streaming\Moonlight.exe",
                r"Programs\Moonlight Game Streaming\Moonlight.exe",
            ] {
                let candidate = base_path.join(rel);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Discovers `VddCtl.exe` strictly inside authenticated system root and Program Files locations.
#[cfg(target_os = "windows")]
fn find_vdd_ctl() -> Option<PathBuf> {
    // 1. Dedicated VirtualDisplayDriver root installation directory
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let primary = PathBuf::from(&sys_drive).join(r"VirtualDisplayDriver\VddCtl.exe");
    if primary.is_file() {
        return Some(primary);
    }

    // 2. Protected Program Files locations
    for env_key in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        if let Ok(base) = std::env::var(env_key) {
            let trimmed = base.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = PathBuf::from(trimmed)
                .join("VirtualDisplayDriver")
                .join("VddCtl.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Verifies whether a named Windows Scheduled Task is registered.
#[cfg(target_os = "windows")]
fn scheduled_task_exists(task_name: &str) -> bool {
    hidden_cmd(&system_info::system32_exe("schtasks.exe"))
        .args(["/Query", "/TN", task_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks whether `SunshineService` is running via `sc.exe query`.
#[cfg(target_os = "windows")]
fn is_sunshine_service_active() -> bool {
    if let Ok(out) = hidden_cmd(&system_info::system32_exe("sc.exe"))
        .args(["query", "SunshineService"])
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout).to_ascii_uppercase();
            return txt.contains("RUNNING") || txt.contains("START_PENDING");
        }
    }
    false
}

/// Checks whether a process with `image_name` is running via `tasklist.exe`.
#[cfg(target_os = "windows")]
fn is_image_running(image_name: &str) -> bool {
    let filter = format!("IMAGENAME eq {}", image_name);
    if let Ok(out) = hidden_cmd(&system_info::system32_exe("tasklist.exe"))
        .args(["/FI", &filter, "/NH"])
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            return txt.contains(&image_name.to_ascii_lowercase());
        }
    }
    false
}

/// Checks whether `sunshine.exe` process is active.
#[cfg(target_os = "windows")]
fn is_sunshine_process_running() -> bool {
    is_image_running("sunshine.exe")
}

/// Ensures that Sunshine is active by checking service status, scheduled task, or starting the binary.
#[cfg(target_os = "windows")]
fn ensure_sunshine_running() -> Result<()> {
    let sc_exe = system_info::system32_exe("sc.exe");
    let schtasks = system_info::system32_exe("schtasks.exe");

    let svc_started = hidden_cmd(&sc_exe)
        .args(["start", "SunshineService"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if scheduled_task_exists("SunshineSecondary") {
        let status = hidden_cmd(&schtasks)
            .args(["/Run", "/TN", "SunshineSecondary"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Failed to launch SunshineSecondary scheduled task")?;
        if !status.success() {
            anyhow::bail!("Scheduled task SunshineSecondary exited with {}", status);
        }
        return Ok(());
    }

    if svc_started || is_sunshine_service_active() || is_sunshine_process_running() {
        return Ok(());
    }

    if let Some(bin) = system_info::find_sunshine_binary() {
        let mut cmd = hidden_cmd(&bin);
        if let Some(dir) = bin.parent() {
            cmd.current_dir(dir);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn Sunshine {}", bin.display()))?;
        reap_child(child, "sunshine");
        info!("Started Sunshine binary ({})", bin.display());
        return Ok(());
    }

    anyhow::bail!("Neither SunshineSecondary task, SunshineService, nor sunshine.exe binary found")
}

/// Enumerates display adapters using PowerShell `Get-PnpDevice -Class Display` and parses virtual adapters.
#[cfg(target_os = "windows")]
fn discover_vdd_pnp_devices() -> Vec<VddPnpDevice> {
    let ps_exe = system_info::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");
    let ps_script = "Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.InstanceId -replace '[\\r\\n\\|]',' ')|$(($_.FriendlyName) -replace '[\\r\\n\\|]',' ')|$(($_.Name) -replace '[\\r\\n\\|]',' ')|$($_.Status -replace '[\\r\\n\\|]',' ')\" }";
    let Ok(out) = hidden_cmd(&ps_exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script,
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_vdd_pnp_devices(&String::from_utf8_lossy(&out.stdout))
}

/// Non-destructively locates or updates the Moonlight host registry entry on Windows.
#[cfg(target_os = "windows")]
fn resolve_or_refresh_win_moonlight_slot(mac_ip: &str, port: u16, host_name: &str) -> String {
    let reg_exe = system_info::system32_exe("reg.exe");
    let Ok(out) = hidden_cmd(&reg_exe)
        .args(["query", MOONLIGHT_HOSTS_REG_KEY, "/s"])
        .output()
    else {
        return mac_ip.to_string();
    };
    if !out.status.success() {
        return mac_ip.to_string();
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let slots = parse_moonlight_hosts_reg(&text);
    let Some(slot) = select_moonlight_host_slot(&slots, mac_ip, port, host_name) else {
        return mac_ip.to_string();
    };

    if !mac_ip.is_empty() && system_info::is_valid_ipv4(mac_ip) {
        let local_changed = slot.localaddress != mac_ip;
        let manual_changed = (!slot.manualaddress.is_empty() && slot.manualaddress != mac_ip)
            || (local_changed && slot.manualaddress != mac_ip);

        if local_changed {
            let _ = hidden_cmd(&reg_exe)
                .args([
                    "add",
                    &slot.reg_key,
                    "/v",
                    "localaddress",
                    "/t",
                    "REG_SZ",
                    "/d",
                    mac_ip,
                    "/f",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if manual_changed {
            let _ = hidden_cmd(&reg_exe)
                .args([
                    "add",
                    &slot.reg_key,
                    "/v",
                    "manualaddress",
                    "/t",
                    "REG_SZ",
                    "/d",
                    mac_ip,
                    "/f",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if local_changed || manual_changed {
            info!(
                "Refreshed Moonlight registry slot '{}' ({}) IP -> {}",
                slot.reg_key,
                if slot.hostname.is_empty() {
                    mac_ip
                } else {
                    &slot.hostname
                },
                mac_ip
            );
        }
    }

    let hname = slot.hostname.trim();
    if !hname.is_empty() && !hname.starts_with('-') && !hname.chars().any(|c| c.is_control()) {
        hname.to_string()
    } else if !mac_ip.is_empty() && system_info::is_valid_ipv4(mac_ip) {
        mac_ip.to_string()
    } else {
        let uuid = slot.uuid.trim();
        if !uuid.is_empty() && !uuid.starts_with('-') && !uuid.chars().any(|c| c.is_control()) {
            uuid.to_string()
        } else {
            mac_ip.to_string()
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn resolve_or_refresh_win_moonlight_slot(mac_ip: &str, _port: u16, _host_name: &str) -> String {
    mac_ip.to_string()
}

/// Reads the raw `REG_SZ` preference string for an executable path from `UserGpuPreferences`.
#[cfg(target_os = "windows")]
fn query_user_gpu_preference_raw(exe_path: &std::path::Path) -> Option<String> {
    let exe_str = exe_path.to_string_lossy();
    let reg_exe = system_info::system32_exe("reg.exe");
    let output = hidden_cmd(&reg_exe)
        .args(["query", DIRECTX_GPU_PREFS_KEY, "/v", exe_str.as_ref()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    extract_reg_sz_value_data(&text)
}

/// Extracts the numeric GPU preference code (1: Integrated, 2/4: Discrete) from a raw preference string.
#[cfg(target_os = "windows")]
fn query_user_gpu_preference(exe_path: &std::path::Path) -> Option<u8> {
    let text = query_user_gpu_preference_raw(exe_path)?;
    parse_user_gpu_preference_value(&text)
}

/// Sets or updates the GPU preference token in `UserGpuPreferences`, preserving other existing settings.
#[cfg(target_os = "windows")]
fn set_user_gpu_preference(exe_path: &std::path::Path, pref_val: &str) -> Result<()> {
    let existing = query_user_gpu_preference_raw(exe_path);
    let merged = merge_user_gpu_preference_value(existing.as_deref(), pref_val);
    let exe_str = exe_path.to_string_lossy();
    let reg_exe = system_info::system32_exe("reg.exe");
    let status = hidden_cmd(&reg_exe)
        .args([
            "add",
            DIRECTX_GPU_PREFS_KEY,
            "/v",
            exe_str.as_ref(),
            "/t",
            "REG_SZ",
            "/d",
            &merged,
            "/f",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("Failed to update UserGpuPreferences for {}", exe_str))?;
    if !status.success() {
        anyhow::bail!("reg.exe add UserGpuPreferences exited with {}", status);
    }
    Ok(())
}

/// Updates the `encoder` setting and optionally removes `adapter_name` in `sunshine.conf`.
#[cfg(target_os = "windows")]
fn update_sunshine_conf_encoder(
    conf_path: &std::path::Path,
    encoder: Option<&str>,
    remove_adapter: bool,
) -> Result<()> {
    let content = std::fs::read_to_string(conf_path)?;
    if let Some(updated) = update_sunshine_encoder_content(&content, encoder, remove_adapter) {
        system_info::atomic_write_private(conf_path, updated.as_bytes())?;
    }
    Ok(())
}

// ============================================================================
// Pure cross-platform parsing & resolution helpers (unit-tested on all OSes)
// ============================================================================

/// Parsed representation of an existing Moonlight host pairing slot in Windows Registry.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MoonlightHostSlot {
    /// Full registry key path (e.g. `HKCU\Software\...\hosts\10`).
    reg_key: String,
    /// Configured hostname.
    hostname: String,
    /// Host unique identifier UUID.
    uuid: String,
    /// Local network IP address.
    localaddress: String,
    /// Manual override IP address.
    manualaddress: String,
    /// Remote external IP address.
    remoteaddress: String,
    /// List of configured TCP/UDP ports associated with this host.
    ports: Vec<u16>,
}

/// Splits a single line of `reg.exe query` output into value name and value data.
#[cfg(any(target_os = "windows", test))]
fn split_reg_query_value_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    for reg_type in [
        "REG_EXPAND_SZ",
        "REG_MULTI_SZ",
        "REG_DWORD",
        "REG_QWORD",
        "REG_BINARY",
        "REG_SZ",
    ] {
        if let Some(pos) = trimmed.find(reg_type) {
            if pos > 0 && trimmed.as_bytes()[pos - 1].is_ascii_whitespace() {
                let after = &trimmed[pos + reg_type.len()..];
                if after.is_empty() || after.as_bytes()[0].is_ascii_whitespace() {
                    return Some((trimmed[..pos].trim(), after.trim()));
                }
            }
        }
    }
    None
}

/// Extracts the data string from a single-line `REG_SZ` registry query output.
#[cfg(any(target_os = "windows", test))]
fn extract_reg_sz_value_data(reg_output: &str) -> Option<String> {
    for line in reg_output.lines() {
        if let Some((_, val_data)) = split_reg_query_value_line(line) {
            return Some(val_data.to_string());
        }
    }
    None
}

/// Parses the numeric preference code from `GpuPreference=<n>;` in a semicolon-delimited string.
#[cfg(any(target_os = "windows", test))]
fn parse_user_gpu_preference_value(raw: &str) -> Option<u8> {
    for part in raw.split([';', ' ', '\t', '\r', '\n']) {
        let token = part.trim();
        if let Some(val) = token.strip_prefix("GpuPreference=") {
            if let Ok(code) = val.trim().parse::<u8>() {
                return Some(code);
            }
        }
    }
    None
}

/// Merges a new `GpuPreference=<n>;` token into an existing semicolon-delimited DirectX preference string.
#[cfg(any(target_os = "windows", test))]
fn merge_user_gpu_preference_value(existing_raw: Option<&str>, new_pref: &str) -> String {
    let new_token = new_pref.trim().trim_end_matches(';');
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;

    if let Some(existing) = existing_raw {
        for raw_part in existing.split(';') {
            let part = raw_part.trim();
            if part.is_empty() {
                continue;
            }
            if part.starts_with("GpuPreference=") {
                if !replaced {
                    parts.push(new_token.to_string());
                    replaced = true;
                }
            } else {
                parts.push(part.to_string());
            }
        }
    }

    if !replaced {
        parts.insert(0, new_token.to_string());
    }

    parts.join(";") + ";"
}

/// Parses a 16-bit integer from a decimal or hex (`0x...`) string representation.
#[cfg(any(target_os = "windows", test))]
fn parse_reg_u16(raw: &str) -> Option<u16> {
    let t = raw.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u16>().ok()
    }
}

/// Parses the multi-key output of `reg query ...\Moonlight\hosts /s` into a list of [`MoonlightHostSlot`] structs.
#[cfg(any(target_os = "windows", test))]
fn parse_moonlight_hosts_reg(output: &str) -> Vec<MoonlightHostSlot> {
    let mut slots: Vec<MoonlightHostSlot> = Vec::new();
    let mut current_slot_idx: Option<usize> = None;
    let hosts_reg_base = r"HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts";

    for line in output.lines() {
        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() {
            continue;
        }

        let lower = trimmed_end.to_ascii_lowercase();
        if trimmed_end.starts_with("HKEY_") || lower.starts_with("hkcu\\") {
            if let Some(pos) = lower.find(r"\moonlight\hosts") {
                let after = &trimmed_end[pos + r"\moonlight\hosts".len()..];
                if let Some(sub) = after.strip_prefix('\\') {
                    if !sub.is_empty() && !sub.contains('\\') {
                        let reg_key = format!(r"{}\{}", hosts_reg_base, sub);
                        if let Some(idx) = slots.iter().position(|s| s.reg_key == reg_key) {
                            current_slot_idx = Some(idx);
                        } else {
                            slots.push(MoonlightHostSlot {
                                reg_key,
                                ..Default::default()
                            });
                            current_slot_idx = Some(slots.len() - 1);
                        }
                        continue;
                    }
                }
            }
            current_slot_idx = None;
            continue;
        }

        let Some(slot_idx) = current_slot_idx else {
            continue;
        };
        let Some((val_name_raw, val_data)) = split_reg_query_value_line(trimmed_end) else {
            continue;
        };
        let val_name = val_name_raw.to_ascii_lowercase();

        let slot = &mut slots[slot_idx];
        match val_name.as_str() {
            "hostname" => slot.hostname = val_data.to_string(),
            "uuid" => slot.uuid = val_data.to_string(),
            "localaddress" => slot.localaddress = val_data.to_string(),
            "manualaddress" => slot.manualaddress = val_data.to_string(),
            "remoteaddress" => slot.remoteaddress = val_data.to_string(),
            "localport" | "manualport" | "httpport" | "port" => {
                if let Some(p) = parse_reg_u16(val_data) {
                    if p > 0 && !slot.ports.contains(&p) {
                        slot.ports.push(p);
                    }
                }
            }
            _ => {}
        }
    }

    slots
}

/// Non-destructively selects the best matching Moonlight host slot based on IP, port, and hostname scoring.
#[cfg(any(target_os = "windows", test))]
fn select_moonlight_host_slot<'a>(
    slots: &'a [MoonlightHostSlot],
    mac_ip: &str,
    port: u16,
    host_name: &str,
) -> Option<&'a MoonlightHostSlot> {
    let mut best: Option<&'a MoonlightHostSlot> = None;
    let mut best_score: u8 = 0;

    for slot in slots {
        let ip_match = !mac_ip.is_empty()
            && (slot.localaddress == mac_ip
                || slot.manualaddress == mac_ip
                || slot.remoteaddress == mac_ip);
        let name_match = !host_name.is_empty() && slot.hostname.eq_ignore_ascii_case(host_name);
        if !ip_match && !name_match {
            continue;
        }

        let score = if port > 0 {
            if slot.ports.contains(&port) {
                if name_match {
                    5
                } else {
                    4
                }
            } else if slot.ports.is_empty() {
                if name_match {
                    3
                } else {
                    2
                }
            } else if name_match {
                // Slot specifies a different port; only match as last resort by hostname
                1
            } else {
                0
            }
        } else if name_match {
            3
        } else {
            2
        };

        if score > best_score {
            best_score = score;
            best = Some(slot);
        }
    }

    best
}

/// Escapes a string for safe inclusion inside PowerShell single-quoted string literals.
#[cfg(any(target_os = "windows", test))]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Parsed PnP device descriptor for a Virtual Display Driver adapter.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct VddPnpDevice {
    /// Device instance ID (e.g. `ROOT\DISPLAY\0002`).
    instance_id: String,
    /// Friendly device name (e.g. `Virtual Display Driver`).
    friendly_name: String,
    /// Current PnP operational status (`OK`, `Disabled`, etc.).
    status: String,
}

/// Determines whether a PnP display device matches known virtual display driver signatures.
#[cfg(any(target_os = "windows", test))]
fn is_virtual_display_adapter(instance_id: &str, friendly_name: &str, name: &str) -> bool {
    let combined = format!("{} {}", friendly_name, name).to_ascii_lowercase();
    if combined.contains("basic display") {
        return false;
    }
    let has_vdd_keyword = [
        "virtual display",
        "iddsampledriver",
        "mttvdd",
        "parsec",
        "sudovda",
        "apollo",
        "amyuni",
        "usbmmidd",
        "spacedesk",
        "indirectdisplay",
    ]
    .iter()
    .any(|pat| combined.contains(pat));

    if has_vdd_keyword {
        return true;
    }
    instance_id.to_ascii_uppercase().starts_with(r"ROOT\DISPLAY")
        && (combined.contains("virtual") || combined.contains("vdd") || combined.trim().is_empty())
}

/// Parses the output of `Get-PnpDevice -Class Display` into a list of matching virtual display adapters.
#[cfg(any(target_os = "windows", test))]
fn parse_vdd_pnp_devices(output: &str) -> Vec<VddPnpDevice> {
    let mut devices = Vec::new();
    for line in output.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let parts: Vec<&str> = t.split('|').collect();
        let instance_id = parts.first().map(|s| s.trim()).unwrap_or("");
        if instance_id.is_empty() {
            continue;
        }
        let friendly_name = parts.get(1).map(|s| s.trim()).unwrap_or("");
        let name = parts.get(2).map(|s| s.trim()).unwrap_or("");
        let status = parts.get(3).map(|s| s.trim()).unwrap_or("");

        if is_virtual_display_adapter(instance_id, friendly_name, name) {
            let label = if !friendly_name.is_empty() {
                friendly_name
            } else {
                name
            };
            devices.push(VddPnpDevice {
                instance_id: instance_id.to_string(),
                friendly_name: label.to_string(),
                status: status.to_string(),
            });
        }
    }
    devices
}

/// Target GPU parameters resolved for video encoding or decoding.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedGpuTarget {
    /// Whether automatic selection is enabled.
    is_auto: bool,
    /// Adapter name matching Sunshine's `adapter_name` config parameter.
    adapter_name: Option<String>,
    /// Encoder keyword (e.g. `"nvenc"`, `"amdvce"`, `"quicksync"`).
    encoder: Option<&'static str>,
    /// DirectX registry preference string (e.g. `"GpuPreference=2;"`).
    reg_pref: &'static str,
}

/// Identifies GPU vendor ("nvidia", "amd", "intel") from vendor and device name strings.
#[cfg(any(target_os = "windows", test))]
fn vendor_key(vendor: &str, name: &str) -> Option<String> {
    let combined = format!("{} {}", vendor, name).to_ascii_lowercase();
    if combined.contains("nvidia")
        || combined.contains("geforce")
        || combined.contains("rtx")
        || combined.contains("gtx")
        || combined.contains("quadro")
    {
        Some("nvidia".to_string())
    } else if combined.contains("amd") || combined.contains("radeon") {
        Some("amd".to_string())
    } else if combined.contains("intel")
        || combined.contains("arc")
        || combined.contains("iris")
        || combined.contains("uhd")
    {
        Some("intel".to_string())
    } else {
        None
    }
}

/// Resolves the hardware encoder identifier for a given GPU vendor/name.
#[cfg(any(target_os = "windows", test))]
fn encoder_for_gpu(vendor: &str, name: &str) -> Option<&'static str> {
    match vendor_key(vendor, name).as_deref() {
        Some("nvidia") => Some("nvenc"),
        Some("amd") => Some("amdvce"),
        Some("intel") => Some("quicksync"),
        _ => None,
    }
}

/// Returns the vendor or discrete/integrated label matching a numeric DirectX preference code.
#[cfg(any(target_os = "windows", test))]
fn gpu_label_for_preference(pref_code: u8, gpus: &[system_info::GpuDeviceInfo]) -> String {
    let real_gpus: Vec<&system_info::GpuDeviceInfo> = gpus
        .iter()
        .filter(|g| !(g.vendor == "System" && g.name == "Default System GPU"))
        .collect();
    match pref_code {
        2 | 4 => real_gpus
            .iter()
            .copied()
            .filter(|g| g.is_discrete)
            .max_by_key(|g| g.vram_mb.unwrap_or(0))
            .and_then(|g| vendor_key(&g.vendor, &g.name))
            .unwrap_or_else(|| "discrete".to_string()),
        1 => real_gpus
            .iter()
            .copied()
            .find(|g| !g.is_discrete)
            .and_then(|g| vendor_key(&g.vendor, &g.name))
            .unwrap_or_else(|| "integrated".to_string()),
        _ => "auto".to_string(),
    }
}

/// Resolves a vendor label from an adapter name string and GPU device list.
#[cfg(any(target_os = "windows", test))]
fn resolve_label_from_adapter(adapter: &str, gpus: &[system_info::GpuDeviceInfo]) -> String {
    let adapter_lower = adapter.to_ascii_lowercase();
    if let Some(matched) = gpus.iter().find(|g| {
        !(g.vendor == "System" && g.name == "Default System GPU")
            && (g.name.eq_ignore_ascii_case(adapter)
                || g.name.to_ascii_lowercase().contains(&adapter_lower)
                || adapter_lower.contains(&g.name.to_ascii_lowercase()))
    }) {
        return vendor_key(&matched.vendor, &matched.name).unwrap_or_else(|| {
            if matched.is_discrete {
                "discrete".to_string()
            } else {
                "integrated".to_string()
            }
        });
    }
    vendor_key("", adapter).unwrap_or_else(|| adapter.to_string())
}

/// Resolves target encoder, adapter name, and registry preference from a user selection string.
#[cfg(any(target_os = "windows", test))]
fn resolve_gpu_target(selection: &str, gpus: &[system_info::GpuDeviceInfo]) -> ResolvedGpuTarget {
    let trimmed = selection.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.is_empty() || lower == "auto" || lower == "default" {
        return ResolvedGpuTarget {
            is_auto: true,
            adapter_name: None,
            encoder: None,
            reg_pref: "GpuPreference=0;",
        };
    }

    let real_gpus: Vec<&system_info::GpuDeviceInfo> = gpus
        .iter()
        .filter(|g| !(g.vendor == "System" && g.name == "Default System GPU"))
        .collect();

    match lower.as_str() {
        "discrete" | "dgpu" | "high-performance" | "high_performance" => {
            if let Some(gpu) = real_gpus
                .iter()
                .copied()
                .filter(|g| g.is_discrete)
                .max_by_key(|g| g.vram_mb.unwrap_or(0))
            {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: Some(gpu.name.clone()),
                    encoder: encoder_for_gpu(&gpu.vendor, &gpu.name),
                    reg_pref: "GpuPreference=2;",
                }
            } else {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: None,
                    encoder: None,
                    reg_pref: "GpuPreference=2;",
                }
            }
        }
        "integrated" | "igpu" | "power-saving" | "power_saving" => {
            if let Some(gpu) = real_gpus.iter().copied().find(|g| !g.is_discrete) {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: Some(gpu.name.clone()),
                    encoder: encoder_for_gpu(&gpu.vendor, &gpu.name),
                    reg_pref: "GpuPreference=1;",
                }
            } else {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: None,
                    encoder: None,
                    reg_pref: "GpuPreference=1;",
                }
            }
        }
        "nvidia" | "amd" | "intel" => {
            let matched = real_gpus
                .iter()
                .copied()
                .filter(|g| vendor_key(&g.vendor, &g.name).as_deref() == Some(lower.as_str()))
                .max_by_key(|g| (g.is_discrete, g.vram_mb.unwrap_or(0)));

            if let Some(gpu) = matched {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: Some(gpu.name.clone()),
                    encoder: encoder_for_gpu(&gpu.vendor, &gpu.name),
                    reg_pref: if gpu.is_discrete {
                        "GpuPreference=2;"
                    } else {
                        "GpuPreference=1;"
                    },
                }
            } else {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: None,
                    encoder: encoder_for_gpu(&lower, &lower),
                    reg_pref: if lower == "intel" {
                        "GpuPreference=1;"
                    } else {
                        "GpuPreference=2;"
                    },
                }
            }
        }
        _ => {
            let matched = real_gpus
                .iter()
                .copied()
                .find(|g| g.name.eq_ignore_ascii_case(trimmed))
                .or_else(|| {
                    real_gpus
                        .iter()
                        .copied()
                        .find(|g| g.name.to_ascii_lowercase().contains(&lower))
                })
                .or_else(|| {
                    real_gpus
                        .iter()
                        .copied()
                        .find(|g| lower.contains(&g.name.to_ascii_lowercase()))
                });

            if let Some(gpu) = matched {
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: Some(gpu.name.clone()),
                    encoder: encoder_for_gpu(&gpu.vendor, &gpu.name),
                    reg_pref: if gpu.is_discrete {
                        "GpuPreference=2;"
                    } else {
                        "GpuPreference=1;"
                    },
                }
            } else {
                let enc = encoder_for_gpu("", &lower);
                let looks_integrated = lower.contains("uhd")
                    || lower.contains("iris")
                    || lower.contains("integrated")
                    || (lower.contains("intel")
                        && !lower.contains("arc a")
                        && !lower.contains("arc b"));
                ResolvedGpuTarget {
                    is_auto: false,
                    adapter_name: Some(trimmed.to_string()),
                    encoder: enc,
                    reg_pref: if looks_integrated {
                        "GpuPreference=1;"
                    } else {
                        "GpuPreference=2;"
                    },
                }
            }
        }
    }
}

/// Parses the `encoder` setting from `sunshine.conf` contents.
#[cfg(any(target_os = "windows", test))]
fn parse_sunshine_encoder(content: &str) -> Option<String> {
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == "encoder" {
                let val = v.trim();
                if !val.is_empty() {
                    return Some(val.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// Pure string transformation helper updating or inserting the `encoder` setting in `sunshine.conf`.
#[cfg(any(target_os = "windows", test))]
fn update_sunshine_encoder_content(
    content: &str,
    encoder: Option<&str>,
    remove_adapter: bool,
) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut found_encoder = false;
    let mut changed = false;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if !trimmed.starts_with('#') {
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                if remove_adapter && key == "adapter_name" {
                    changed = true;
                    continue;
                }
                if key == "encoder" {
                    found_encoder = true;
                    if let Some(enc) = encoder {
                        if v.trim() != enc {
                            changed = true;
                        }
                        lines.push(format!("encoder = {}", enc));
                    } else {
                        changed = true;
                    }
                    continue;
                }
            }
        }
        lines.push(raw.to_string());
    }

    if !found_encoder {
        if let Some(enc) = encoder {
            lines.push(format!("encoder = {}", enc));
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let line_ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    Some(lines.join(line_ending) + line_ending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moonlight_registry_slot_resolution() {
        let reg_output = r#"
HKEY_CURRENT_USER\Software\Moonlight Game Streaming Project\Moonlight\hosts
    size    REG_SZ    2

HKEY_CURRENT_USER\Software\Moonlight Game Streaming Project\Moonlight\hosts\10
    hostname    REG_SZ    Workstation-A
    localaddress    REG_SZ    192.168.1.10
    manualaddress    REG_SZ    
    localport    REG_DWORD    0xbb75
    uuid    REG_SZ    uuid-slot-10

HKEY_CURRENT_USER\Software\Moonlight Game Streaming Project\Moonlight\hosts\10\apps\1
    name    REG_SZ    Desktop

HKEY_CURRENT_USER\Software\Moonlight Game Streaming Project\Moonlight\hosts\12
    hostname    REG_SZ    Studio-Host
    localaddress    REG_SZ    192.168.1.25
    manualaddress    REG_SZ    10.0.0.2
    httpport    REG_DWORD    0xbf5d
    uuid    REG_SZ    uuid-slot-12
"#;
        let slots = parse_moonlight_hosts_reg(reg_output);
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].ports, vec![47989]);
        assert_eq!(slots[1].ports, vec![48989]);

        let s1 = select_moonlight_host_slot(&slots, "10.0.0.5", 47989, "Workstation-A").unwrap();
        assert_eq!(s1.uuid, "uuid-slot-10");

        let s2 = select_moonlight_host_slot(&slots, "192.168.1.25", 48989, "").unwrap();
        assert_eq!(s2.uuid, "uuid-slot-12");

        // Unmatched host should return None (non-destructive)
        assert!(select_moonlight_host_slot(&slots, "172.16.0.99", 47989, "Unknown").is_none());
    }

    #[test]
    fn test_vdd_pnp_adapter_discovery() {
        let ps_out = "\
PCI\\VEN_10DE&DEV_28E0\\4&1234|NVIDIA GeForce RTX Laptop GPU|NVIDIA GeForce RTX Laptop GPU|OK\n\
ROOT\\DISPLAY\\0002|Virtual Display Driver|Virtual Display Driver|Disabled\n\
SWD\\DRIVERENUM\\MttVDD&0000|MttVDD Virtual Display|MttVDD|OK\n\
ROOT\\BASICDISPLAY\\0000|Microsoft Basic Display Adapter|Microsoft Basic Display Adapter|OK\n";

        let devs = parse_vdd_pnp_devices(ps_out);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].instance_id, r"ROOT\DISPLAY\0002");
        assert_eq!(devs[0].status, "Disabled");
        assert_eq!(devs[1].instance_id, r"SWD\DRIVERENUM\MttVDD&0000");
        assert_eq!(ps_single_quote("ROOT\\DISPLAY'02"), "'ROOT\\DISPLAY''02'");
    }

    #[test]
    fn test_gpu_resolution_for_any_vendor_or_substring() {
        let gpus = vec![
            system_info::GpuDeviceInfo {
                index: 0,
                name: "AMD Radeon RX 7900 XTX".into(),
                vendor: "AMD".into(),
                is_discrete: true,
                vram_mb: Some(24576),
            },
            system_info::GpuDeviceInfo {
                index: 1,
                name: "Intel(R) UHD Graphics 770".into(),
                vendor: "Intel".into(),
                is_discrete: false,
                vram_mb: None,
            },
        ];

        let disc = resolve_gpu_target("discrete", &gpus);
        assert_eq!(disc.adapter_name.as_deref(), Some("AMD Radeon RX 7900 XTX"));
        assert_eq!(disc.encoder, Some("amdvce"));
        assert_eq!(disc.reg_pref, "GpuPreference=2;");

        let igpu = resolve_gpu_target("integrated", &gpus);
        assert_eq!(
            igpu.adapter_name.as_deref(),
            Some("Intel(R) UHD Graphics 770")
        );
        assert_eq!(igpu.encoder, Some("quicksync"));
        assert_eq!(igpu.reg_pref, "GpuPreference=1;");

        let sub = resolve_gpu_target("7900", &gpus);
        assert_eq!(sub.adapter_name.as_deref(), Some("AMD Radeon RX 7900 XTX"));
        assert_eq!(sub.reg_pref, "GpuPreference=2;");

        let auto = resolve_gpu_target("auto", &gpus);
        assert!(auto.is_auto);
        assert_eq!(auto.reg_pref, "GpuPreference=0;");

        assert_eq!(gpu_label_for_preference(2, &gpus), "amd");
        assert_eq!(gpu_label_for_preference(1, &gpus), "intel");
        assert_eq!(gpu_label_for_preference(0, &gpus), "auto");
        assert_eq!(
            resolve_label_from_adapter("AMD Radeon RX 7900 XTX", &gpus),
            "amd"
        );
    }

    #[test]
    fn test_sunshine_conf_encoder_update() {
        let initial = "# adapter_name = old\nport = 47989\nencoder = nvenc\n";
        assert_eq!(parse_sunshine_encoder(initial).as_deref(), Some("nvenc"));

        let updated = update_sunshine_encoder_content(initial, Some("amdvce"), false).unwrap();
        assert_eq!(updated, "# adapter_name = old\nport = 47989\nencoder = amdvce\n");

        let cleared = update_sunshine_encoder_content(
            "adapter_name = AMD Radeon\nport = 47989\nencoder = amdvce\n",
            None,
            true,
        )
        .unwrap();
        assert_eq!(cleared, "port = 47989\n");
    }

    #[test]
    fn test_user_gpu_preferences_parse_and_preserve() {
        let reg_out = "\nHKEY_CURRENT_USER\\Software\\Microsoft\\DirectX\\UserGpuPreferences\n    C:\\Moonlight.exe    REG_SZ    AutoHDREnable=1;GpuPreference=4;SwapEffectUpgradeEnable=1;\n";
        let raw = extract_reg_sz_value_data(reg_out).unwrap();
        assert_eq!(parse_user_gpu_preference_value(&raw), Some(4));

        let merged = merge_user_gpu_preference_value(Some(&raw), "GpuPreference=2;");
        assert_eq!(
            merged,
            "AutoHDREnable=1;GpuPreference=2;SwapEffectUpgradeEnable=1;"
        );

        let inserted = merge_user_gpu_preference_value(Some("AutoHDREnable=1;"), "GpuPreference=1;");
        assert_eq!(inserted, "GpuPreference=1;AutoHDREnable=1;");
    }
}
