//! Windows Native Display Controller.
//! Manages dynamic Virtual Display Driver discovery/control, Sunshine services,
//! non-destructive Moonlight host resolution, GPU routing, and Moonlight client execution.

use crate::system_info;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
#[allow(unused_imports)]
use tracing::{info, warn};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(target_os = "windows")]
const MOONLIGHT_HOSTS_REG_KEY: &str =
    r"HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts";

#[cfg(target_os = "windows")]
const DIRECTX_GPU_PREFS_KEY: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";

pub struct WinDisplayManager;

impl WinDisplayManager {
    /// Finds the Moonlight executable via `system_info::find_moonlight_binary()`.
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
        let exe = Self::find_moonlight_exe().context("Moonlight.exe not found on Windows")?;

        // 1. Resolve existing paired slot non-destructively and refresh IP only if changed
        let target = resolve_or_refresh_win_moonlight_slot(mac_ip, port, host_name);

        // 2. Kill existing Moonlight cleanly
        let _ = Self::stop_moonlight_client();
        std::thread::sleep(Duration::from_millis(250));

        // 3. Build CLI arguments
        let res_arg = format!("{}x{}", width.max(800), height.max(600));
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
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd.spawn()
            .with_context(|| format!("Failed to spawn {}", exe.display()))?;
        info!(
            "Launched Moonlight on Windows -> '{}' ({}:{}) at {} @ {}Hz",
            target, mac_ip, port, res_arg, fps_arg
        );
        Ok(())
    }

    /// Stops Moonlight.exe on Windows.
    pub fn stop_moonlight_client() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let image_name = Self::find_moonlight_exe()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "Moonlight.exe".to_string());

            let _ = hidden_cmd("taskkill")
                .args(["/F", "/IM", &image_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if !image_name.eq_ignore_ascii_case("Moonlight.exe") {
                let _ = hidden_cmd("taskkill")
                    .args(["/F", "/IM", "Moonlight.exe"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        info!("Terminated Moonlight.exe on Windows");
        Ok(())
    }

    /// Discovers and enables any Virtual Display Driver PnP adapters and ensures Sunshine is running.
    pub fn enable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // 1. Discover virtual display PnP devices dynamically and enable if not already OK
            let vdd_devices = discover_vdd_pnp_devices();
            if vdd_devices.is_empty() {
                info!("No standalone virtual display PnP adapter found (Apollo/native Sunshine mode)");
            } else {
                for dev in &vdd_devices {
                    if !dev.status.eq_ignore_ascii_case("OK") {
                        let ps = format!(
                            "Enable-PnpDevice -InstanceId {} -Confirm:$false -ErrorAction SilentlyContinue",
                            ps_single_quote(&dev.instance_id)
                        );
                        let _ = hidden_cmd("powershell.exe")
                            .args([
                                "-NoProfile",
                                "-NonInteractive",
                                "-ExecutionPolicy",
                                "Bypass",
                                "-Command",
                                &ps,
                            ])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                    }
                    info!(
                        "Virtual display adapter ready: {} ({})",
                        dev.instance_id, dev.friendly_name
                    );
                }
            }

            // 2. Ensure Sunshine host service, secondary task, or binary is running
            ensure_sunshine_running();

            // 3. Attach virtual display slot 1 via VddCtl.exe if present, else optional task/marker
            if let Some(vdd_ctl) = find_vdd_ctl() {
                let _ = hidden_cmd(&vdd_ctl)
                    .args(["join", "1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                info!("Attached virtual display slot 1 via {}", vdd_ctl.display());
            } else if scheduled_task_exists("ToggleSecondScreen") {
                let _ = hidden_cmd("schtasks.exe")
                    .args(["/Run", "/TN", "ToggleSecondScreen"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            } else if !vdd_devices.is_empty() {
                let _ = std::fs::write(system_info::app_data_dir().join("win_vdd.active"), "1");
            }

            // 4. Start dynamic watcher only if that scheduled task exists
            if scheduled_task_exists("VddDynamicWatcher") {
                let _ = hidden_cmd("schtasks.exe")
                    .args(["/Run", "/TN", "VddDynamicWatcher"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        info!("Enabled Virtual Display Driver on Windows");
        Ok(())
    }

    /// Gracefully detaches/disables discovered Virtual Display Driver slots and adapters.
    pub fn disable_vdd_device() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let _ = std::fs::remove_file(system_info::app_data_dir().join("win_vdd.active"));

            let mut keep_pnp_for_other_slot = false;
            if let Some(vdd_ctl) = find_vdd_ctl() {
                let _ = hidden_cmd(&vdd_ctl)
                    .args(["leave", "1"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();

                if let Some(dir) = vdd_ctl.parent() {
                    let _ = std::fs::remove_file(dir.join("slot1.active"));
                    if dir.join("slot0.active").exists() {
                        keep_pnp_for_other_slot = true;
                    }
                }
            }

            if !keep_pnp_for_other_slot {
                for dev in discover_vdd_pnp_devices() {
                    if dev.status.eq_ignore_ascii_case("OK") {
                        let ps = format!(
                            "Disable-PnpDevice -InstanceId {} -Confirm:$false -ErrorAction SilentlyContinue",
                            ps_single_quote(&dev.instance_id)
                        );
                        let _ = hidden_cmd("powershell.exe")
                            .args([
                                "-NoProfile",
                                "-NonInteractive",
                                "-ExecutionPolicy",
                                "Bypass",
                                "-Command",
                                &ps,
                            ])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                        info!(
                            "Disabled virtual display adapter: {} ({})",
                            dev.instance_id, dev.friendly_name
                        );
                    }
                }
            }
        }
        info!("Disabled Virtual Display Driver on Windows");
        Ok(())
    }

    /// Checks if a Virtual Display Driver session/slot is currently active on Windows.
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
    pub fn get_gpu_preferences() -> (String, String) {
        #[cfg(target_os = "windows")]
        {
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
        #[cfg(not(target_os = "windows"))]
        {
            ("auto".to_string(), "auto".to_string())
        }
    }

    /// Sets GPU preferences on Windows for Sunshine encoder and Moonlight decoder using
    /// live GPU enumeration and dynamic binary/config discovery.
    #[allow(unused_variables)]
    pub fn set_gpu_preferences(encode_gpu: &str, decode_gpu: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let gpus = system_info::enumerate_gpus();

            // 1. Resolve & apply Sunshine encode GPU
            let enc_target = resolve_gpu_target(encode_gpu, &gpus);
            if enc_target.is_auto {
                if let Some(conf_path) = system_info::find_sunshine_conf() {
                    if let Err(e) = update_sunshine_conf_encoder(&conf_path, None, true) {
                        warn!(
                            "Failed to reset GPU keys in {}: {}",
                            conf_path.display(),
                            e
                        );
                    }
                }
            } else {
                if let Some(ref adapter_name) = enc_target.adapter_name {
                    if let Err(e) = system_info::write_sunshine_adapter_name(adapter_name) {
                        warn!("Could not update Sunshine adapter_name: {}", e);
                    }
                }
                if let Some(conf_path) = system_info::find_sunshine_conf() {
                    if let Err(e) =
                        update_sunshine_conf_encoder(&conf_path, enc_target.encoder, false)
                    {
                        warn!(
                            "Failed to update encoder in {}: {}",
                            conf_path.display(),
                            e
                        );
                    }
                }
            }

            if let Some(sunshine_exe) = system_info::find_sunshine_binary() {
                set_user_gpu_preference(&sunshine_exe, enc_target.reg_pref);
            }

            // 2. Resolve & apply Moonlight decode GPU
            let dec_target = resolve_gpu_target(decode_gpu, &gpus);
            let moonlight_exe =
                system_info::find_moonlight_binary().or_else(find_moonlight_legacy_dir_windows);
            if let Some(moonlight_path) = moonlight_exe {
                set_user_gpu_preference(&moonlight_path, dec_target.reg_pref);
            }

            info!(
                "Updated Windows GPU routing: Encode GPU [{}] (adapter={:?}, {}), Decode GPU [{}] ({})",
                encode_gpu,
                enc_target.adapter_name,
                enc_target.reg_pref,
                decode_gpu,
                dec_target.reg_pref
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn hidden_cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

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

#[cfg(target_os = "windows")]
fn find_vdd_ctl() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("VDDCTL_PATH") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
            let joined = p.join("VddCtl.exe");
            if joined.is_file() {
                return Some(joined);
            }
        }
    }

    let mut candidates = Vec::new();
    for env_key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Ok(base) = std::env::var(env_key) {
            candidates.push(
                PathBuf::from(base)
                    .join("VirtualDisplayDriver")
                    .join("VddCtl.exe"),
            );
        }
    }
    candidates.push(PathBuf::from(r"C:\VirtualDisplayDriver\VddCtl.exe"));
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local_app)
                .join("VirtualDisplayDriver")
                .join("VddCtl.exe"),
        );
    }

    if let Some(found) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(found);
    }

    system_info::find_app_helper("VddCtl.exe").or_else(|| system_info::find_in_path("VddCtl.exe"))
}

#[cfg(target_os = "windows")]
fn scheduled_task_exists(task_name: &str) -> bool {
    hidden_cmd("schtasks.exe")
        .args(["/Query", "/TN", task_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn is_sunshine_service_active() -> bool {
    if let Ok(out) = hidden_cmd("sc.exe")
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

#[cfg(target_os = "windows")]
fn is_sunshine_process_running() -> bool {
    if let Ok(out) = hidden_cmd("tasklist")
        .args(["/FI", "IMAGENAME eq sunshine.exe", "/NH"])
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            return txt.contains("sunshine.exe");
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn ensure_sunshine_running() {
    let svc_started = hidden_cmd("sc.exe")
        .args(["start", "SunshineService"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if scheduled_task_exists("SunshineSecondary") {
        let _ = hidden_cmd("schtasks.exe")
            .args(["/Run", "/TN", "SunshineSecondary"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return;
    }

    if svc_started || is_sunshine_service_active() || is_sunshine_process_running() {
        return;
    }

    if let Some(bin) = system_info::find_sunshine_binary() {
        let mut cmd = hidden_cmd(&bin);
        if let Some(dir) = bin.parent() {
            cmd.current_dir(dir);
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(_) => info!("Started Sunshine binary ({})", bin.display()),
            Err(e) => warn!("Failed to spawn Sunshine {}: {}", bin.display(), e),
        }
    } else {
        warn!("Neither SunshineSecondary task, SunshineService, nor sunshine.exe binary found");
    }
}

#[cfg(target_os = "windows")]
fn discover_vdd_pnp_devices() -> Vec<VddPnpDevice> {
    let ps_script = "Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.InstanceId)|$($_.FriendlyName)|$($_.Name)|$($_.Status)\" }";
    let Ok(out) = hidden_cmd("powershell.exe")
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

#[cfg(target_os = "windows")]
fn resolve_or_refresh_win_moonlight_slot(mac_ip: &str, port: u16, host_name: &str) -> String {
    let Ok(out) = hidden_cmd("reg")
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

    if !mac_ip.is_empty() {
        let local_changed = slot.localaddress != mac_ip;
        let manual_changed = (!slot.manualaddress.is_empty() && slot.manualaddress != mac_ip)
            || (local_changed && slot.manualaddress != mac_ip);

        if local_changed {
            let _ = hidden_cmd("reg")
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
            let _ = hidden_cmd("reg")
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

    if !slot.uuid.trim().is_empty() {
        slot.uuid.trim().to_string()
    } else if !slot.hostname.trim().is_empty() {
        slot.hostname.trim().to_string()
    } else {
        mac_ip.to_string()
    }
}

#[cfg(not(target_os = "windows"))]
fn resolve_or_refresh_win_moonlight_slot(mac_ip: &str, _port: u16, _host_name: &str) -> String {
    mac_ip.to_string()
}

#[cfg(target_os = "windows")]
fn query_user_gpu_preference(exe_path: &std::path::Path) -> Option<u8> {
    let exe_str = exe_path.to_string_lossy();
    let output = hidden_cmd("reg")
        .args(["query", DIRECTX_GPU_PREFS_KEY, "/v", exe_str.as_ref()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("GpuPreference=2") {
        Some(2)
    } else if text.contains("GpuPreference=1") {
        Some(1)
    } else if text.contains("GpuPreference=0") {
        Some(0)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn set_user_gpu_preference(exe_path: &std::path::Path, pref_val: &str) {
    let exe_str = exe_path.to_string_lossy();
    let _ = hidden_cmd("reg")
        .args([
            "add",
            DIRECTX_GPU_PREFS_KEY,
            "/v",
            exe_str.as_ref(),
            "/t",
            "REG_SZ",
            "/d",
            pref_val,
            "/f",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(target_os = "windows")]
fn update_sunshine_conf_encoder(
    conf_path: &std::path::Path,
    encoder: Option<&str>,
    remove_adapter: bool,
) -> Result<()> {
    let content = std::fs::read_to_string(conf_path)?;
    if let Some(updated) = update_sunshine_encoder_content(&content, encoder, remove_adapter) {
        std::fs::write(conf_path, updated)?;
    }
    Ok(())
}

// ============================================================================
// Pure cross-platform parsing & resolution helpers (unit-tested on all OSes)
// ============================================================================

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MoonlightHostSlot {
    reg_key: String,
    hostname: String,
    uuid: String,
    localaddress: String,
    manualaddress: String,
    remoteaddress: String,
    ports: Vec<u16>,
}

#[cfg(any(target_os = "windows", test))]
fn parse_reg_u16(raw: &str) -> Option<u16> {
    let t = raw.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u16>().ok()
    }
}

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
        let trimmed = trimmed_end.trim();
        let Some(reg_pos) = trimmed.find("REG_") else {
            continue;
        };
        if reg_pos == 0 || !trimmed.as_bytes()[reg_pos - 1].is_ascii_whitespace() {
            continue;
        }

        let val_name = trimmed[..reg_pos].trim().to_ascii_lowercase();
        let after_reg = &trimmed[reg_pos..];
        let val_data = match after_reg.find(char::is_whitespace) {
            Some(ws) => after_reg[ws..].trim(),
            None => "",
        };

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

#[cfg(any(target_os = "windows", test))]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct VddPnpDevice {
    instance_id: String,
    friendly_name: String,
    status: String,
}

#[cfg(any(target_os = "windows", test))]
fn is_virtual_display_adapter(instance_id: &str, friendly_name: &str, name: &str) -> bool {
    if instance_id.to_ascii_uppercase().starts_with(r"ROOT\DISPLAY") {
        return true;
    }
    let combined = format!("{} {}", friendly_name, name).to_ascii_lowercase();
    [
        "virtual display",
        "iddsampledriver",
        "mttvdd",
        "parsec",
        "sudovda",
        "apollo",
    ]
    .iter()
    .any(|pat| combined.contains(pat))
}

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

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedGpuTarget {
    is_auto: bool,
    adapter_name: Option<String>,
    encoder: Option<&'static str>,
    reg_pref: &'static str,
}

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

#[cfg(any(target_os = "windows", test))]
fn encoder_for_gpu(vendor: &str, name: &str) -> Option<&'static str> {
    match vendor_key(vendor, name).as_deref() {
        Some("nvidia") => Some("nvenc"),
        Some("amd") => Some("amdvce"),
        Some("intel") => Some("quicksync"),
        _ => None,
    }
}

#[cfg(any(target_os = "windows", test))]
fn gpu_label_for_preference(pref_code: u8, gpus: &[system_info::GpuDeviceInfo]) -> String {
    let real_gpus: Vec<&system_info::GpuDeviceInfo> = gpus
        .iter()
        .filter(|g| !(g.vendor == "System" && g.name == "Default System GPU"))
        .collect();
    match pref_code {
        2 => real_gpus
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
}
