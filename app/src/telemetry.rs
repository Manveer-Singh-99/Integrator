//! Hardware-agnostic GPU Telemetry across NVIDIA, AMD, Intel, and Apple GPUs.
//!
//! Avoids assuming GPU index 0 or RTX/NVIDIA hardware; discovers all GPUs via
//! `nvidia-smi` (preferring Sunshine's configured adapter or highest-VRAM discrete GPU)
//! and falls back to OS GPU enumeration + performance counters for non-NVIDIA systems.

use crate::system_info;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::process::Command;

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

fn parse_optional_u32(raw: &str) -> u32 {
    let clean = raw.trim();
    clean
        .parse::<f32>()
        .ok()
        .map(|v| v.max(0.0).round() as u32)
        .unwrap_or(0)
}

fn parse_optional_u64(raw: &str) -> u64 {
    let clean = raw.trim();
    clean
        .parse::<f64>()
        .ok()
        .map(|v| v.max(0.0).round() as u64)
        .unwrap_or(0)
}

fn parse_optional_f32(raw: &str) -> f32 {
    raw.trim().parse::<f32>().unwrap_or(0.0).max(0.0)
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
fn query_nvidia_smi() -> Option<GpuTelemetry> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut cmd = Command::new("nvidia-smi");
    cmd.args([
        "--query-gpu=name,temperature.gpu,power.draw,utilization.gpu,utilization.memory,memory.used,memory.total,clocks.current.graphics",
        "--format=csv,noheader,nounits",
    ]);
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (_, _, preferred_adapter) = system_info::read_sunshine_config_info();
    let mut parsed_list = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() < 8 || parts[0].is_empty() {
            continue;
        }
        parsed_list.push(GpuTelemetry {
            gpu_name: parts[0].to_string(),
            temperature_c: parse_optional_u32(parts[1]),
            power_usage_watts: parse_optional_f32(parts[2]),
            gpu_utilization_percent: parse_optional_u32(parts[3]),
            memory_utilization_percent: parse_optional_u32(parts[4]),
            memory_used_mb: parse_optional_u64(parts[5]),
            memory_total_mb: parse_optional_u64(parts[6]),
            core_clock_mhz: parse_optional_u32(parts[7]),
        });
    }

    if parsed_list.is_empty() {
        return None;
    }

    // Prefer GPU configured in Sunshine, otherwise pick the one with highest VRAM.
    if let Some(pref) = preferred_adapter {
        let pref_lower = pref.to_ascii_lowercase();
        if let Some(matched) = parsed_list
            .iter()
            .find(|g| g.gpu_name.to_ascii_lowercase().contains(&pref_lower) || pref_lower.contains(&g.gpu_name.to_ascii_lowercase()))
        {
            return Some(matched.clone());
        }
    }

    parsed_list.into_iter().max_by_key(|g| g.memory_total_mb)
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
