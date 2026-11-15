//! Hardware-agnostic GPU Telemetry across NVIDIA, AMD, Intel, and Apple GPUs.
//!
//! Avoids assuming GPU index 0 or RTX/NVIDIA hardware; discovers all GPUs via
//! `nvidia-smi` (preferring Sunshine's configured adapter or highest-VRAM discrete GPU)
//! and falls back to OS GPU enumeration + performance counters for non-NVIDIA systems.

use crate::system_info;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::{Command, Stdio};
#[cfg(target_os = "windows")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
const NVIDIA_SMI_TIMEOUT: Duration = Duration::from_millis(1500);
#[cfg(target_os = "windows")]
const NVIDIA_CACHE_TTL: Duration = Duration::from_millis(1200);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuTelemetry {
    pub gpu_name: String,
    pub temperature_c: u32,
    pub power_usage_watts: f32,
    pub gpu_utilization_percent: u32,
    pub memory_utilization_percent: u32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub core_clock_mhz: u32,
}

impl Default for GpuTelemetry {
    fn default() -> Self {
        Self {
            gpu_name: "Detecting GPU...".to_string(),
            temperature_c: 0,
            power_usage_watts: 0.0,
            gpu_utilization_percent: 0,
            memory_utilization_percent: 0,
            memory_used_mb: 0,
            memory_total_mb: 0,
            core_clock_mhz: 0,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_optional_u32(raw: &str) -> u32 {
    let clean = raw.trim();
    clean
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| v.clamp(0.0, u32::MAX as f32).round() as u32)
        .unwrap_or(0)
}

#[cfg(any(target_os = "windows", test))]
fn parse_optional_u64(raw: &str) -> u64 {
    let clean = raw.trim();
    clean
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| v.clamp(0.0, (u64::MAX / 2) as f64).round() as u64)
        .unwrap_or(0)
}

#[cfg(any(target_os = "windows", test))]
fn parse_optional_f32(raw: &str) -> f32 {
    raw.trim()
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0)
}

#[cfg(any(target_os = "windows", test))]
fn parse_nvidia_smi_csv_line(line: &str) -> Option<GpuTelemetry> {
    let rev_parts: Vec<&str> = line.rsplitn(8, ',').map(|s| s.trim()).collect();
    if rev_parts.len() != 8 {
        return None;
    }
    let gpu_name = rev_parts[7];
    if gpu_name.is_empty() {
        return None;
    }
    Some(GpuTelemetry {
        gpu_name: gpu_name.to_string(),
        temperature_c: parse_optional_u32(rev_parts[6]),
        power_usage_watts: parse_optional_f32(rev_parts[5]),
        gpu_utilization_percent: parse_optional_u32(rev_parts[4]),
        memory_utilization_percent: parse_optional_u32(rev_parts[3]),
        memory_used_mb: parse_optional_u64(rev_parts[2]),
        memory_total_mb: parse_optional_u64(rev_parts[1]),
        core_clock_mhz: parse_optional_u32(rev_parts[0]),
    })
}

pub fn query_gpu_telemetry() -> Option<GpuTelemetry> {
    #[cfg(target_os = "windows")]
    {
        if let Some(nvidia) = query_nvidia_smi() {
            return Some(nvidia);
        }
        query_generic_windows_gpu()
    }
    #[cfg(not(target_os = "windows"))]
    {
        query_generic_unix_gpu()
    }
}

#[cfg(target_os = "windows")]
fn find_trusted_nvidia_smi() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        candidates.push(PathBuf::from(sys_root).join("System32").join("nvidia-smi.exe"));
    }
    candidates.push(PathBuf::from(r"C:\Windows\System32\nvidia-smi.exe"));
    if let Ok(pf) = std::env::var("ProgramFiles") {
        candidates.push(
            PathBuf::from(pf)
                .join("NVIDIA Corporation")
                .join("NVSMI")
                .join("nvidia-smi.exe"),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(target_os = "windows")]
fn run_nvidia_smi_with_timeout() -> Option<String> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let bin = find_trusted_nvidia_smi()?;
    let mut cmd = Command::new(bin);
    cmd.args([
        "--query-gpu=name,temperature.gpu,power.draw,utilization.gpu,utilization.memory,memory.used,memory.total,clocks.current.graphics",
        "--format=csv,noheader,nounits",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        if let Some(mut s) = stdout_pipe {
            let _ = s.read_to_string(&mut out);
        }
        out
    });

    let deadline = Instant::now() + NVIDIA_SMI_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let text = reader.join().unwrap_or_default();
                return status.success().then_some(text);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn query_nvidia_smi() -> Option<GpuTelemetry> {
    static NVIDIA_CACHE: OnceLock<Mutex<(Instant, Option<GpuTelemetry>)>> = OnceLock::new();
    let cache = NVIDIA_CACHE.get_or_init(|| {
        Mutex::new((Instant::now() - Duration::from_secs(60), None))
    });
    if let Ok(guard) = cache.lock() {
        if guard.0.elapsed() < NVIDIA_CACHE_TTL {
            return guard.1.clone();
        }
    }

    let stdout = match run_nvidia_smi_with_timeout() {
        Some(s) => s,
        None => {
            if let Ok(mut guard) = cache.lock() {
                *guard = (Instant::now(), None);
            }
            return None;
        }
    };

    let (_, _, preferred_adapter) = system_info::read_sunshine_config_info();
    let parsed_list: Vec<GpuTelemetry> = stdout
        .lines()
        .filter_map(parse_nvidia_smi_csv_line)
        .collect();

    if parsed_list.is_empty() {
        return None;
    }

    // Prefer GPU configured in Sunshine, otherwise pick the one with highest VRAM.
    let selected = if let Some(pref) = preferred_adapter {
        let pref_lower = pref.to_ascii_lowercase();
        parsed_list
            .iter()
            .find(|g| {
                g.gpu_name.to_ascii_lowercase().contains(&pref_lower)
                    || pref_lower.contains(&g.gpu_name.to_ascii_lowercase())
            })
            .cloned()
            .or_else(|| parsed_list.into_iter().max_by_key(|g| g.memory_total_mb))
    } else {
        parsed_list.into_iter().max_by_key(|g| g.memory_total_mb)
    };

    if let Ok(mut guard) = cache.lock() {
        *guard = (Instant::now(), selected.clone());
    }
    selected
}

#[cfg(target_os = "windows")]
fn query_generic_windows_gpu() -> Option<GpuTelemetry> {
    let gpus = system_info::enumerate_gpus();
    let preferred = system_info::read_sunshine_config_info().2;
    let chosen = preferred
        .as_ref()
        .and_then(|pref| {
            gpus.iter()
                .find(|g| g.name.to_ascii_lowercase().contains(&pref.to_ascii_lowercase()))
        })
        .or_else(|| gpus.iter().find(|g| g.is_discrete))
        .or_else(|| gpus.first())?;

    Some(GpuTelemetry {
        gpu_name: chosen.name.clone(),
        temperature_c: 0,
        power_usage_watts: 0.0,
        gpu_utilization_percent: 0,
        memory_utilization_percent: 0,
        memory_used_mb: 0,
        memory_total_mb: chosen.vram_mb.unwrap_or(0),
        core_clock_mhz: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_parsers_reject_nan_inf_and_handle_commas_in_names() {
        assert_eq!(parse_optional_f32("NaN"), 0.0);
        assert_eq!(parse_optional_f32("inf"), 0.0);
        assert_eq!(parse_optional_f32("-3.5"), 0.0);
        assert_eq!(parse_optional_u32("inf"), 0);
        assert_eq!(parse_optional_u64("[N/A]"), 0);

        let parsed = parse_nvidia_smi_csv_line(
            "NVIDIA GeForce RTX, Studio Edition, 54, inf, 12, 30, 1024, 24576, 2100",
        )
        .unwrap();
        assert_eq!(parsed.gpu_name, "NVIDIA GeForce RTX, Studio Edition");
        assert_eq!(parsed.temperature_c, 54);
        assert_eq!(parsed.power_usage_watts, 0.0);
        assert_eq!(parsed.memory_used_mb, 1024);
        assert_eq!(parsed.memory_total_mb, 24576);
        assert_eq!(parsed.core_clock_mhz, 2100);
    }
}

#[cfg(not(target_os = "windows"))]
fn query_generic_unix_gpu() -> Option<GpuTelemetry> {
    let gpus = system_info::enumerate_gpus();
    let chosen = gpus.iter().find(|g| g.is_discrete).or_else(|| gpus.first())?;
    Some(GpuTelemetry {
        gpu_name: chosen.name.clone(),
        temperature_c: 0,
        power_usage_watts: 0.0,
        gpu_utilization_percent: 0,
        memory_utilization_percent: 0,
        memory_used_mb: 0,
        memory_total_mb: chosen.vram_mb.unwrap_or(0),
        core_clock_mhz: 0,
    })
}
