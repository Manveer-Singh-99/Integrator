//! Telemetry payloads for GPU monitoring and Touch Bar rendering.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(dead_code)]
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
            gpu_name: "NVIDIA GeForce RTX 5070".to_string(),
            temperature_c: 0,
            power_usage_watts: 0.0,
            gpu_utilization_percent: 0,
            memory_utilization_percent: 0,
            memory_used_mb: 0,
            memory_total_mb: 8192,
            core_clock_mhz: 0,
        }
    }
}

/// Queries live NVIDIA GPU telemetry via nvidia-smi with zero console window creation.
pub fn query_gpu_telemetry() -> Option<GpuTelemetry> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = std::process::Command::new("nvidia-smi");
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args(&[
            "--query-gpu=name,temperature.gpu,power.draw,clocks.current.graphics,memory.used,memory.total,utilization.gpu",
            "--format=csv,noheader,nounits"
        ]);
        let output = cmd.output().ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = text.trim().split(',').map(|s| s.trim()).collect();
        if parts.len() >= 7 {
            let gpu_name = parts[0].to_string();
            let temperature_c = parts[1].parse::<f32>().unwrap_or(0.0) as u32;
            let power_usage_watts = parts[2].parse::<f32>().unwrap_or(0.0);
            let core_clock_mhz = parts[3].parse::<u32>().unwrap_or(0);
            let memory_used_mb = parts[4].parse::<u64>().unwrap_or(0);
            let memory_total_mb = parts[5].parse::<u64>().unwrap_or(8151);
            let gpu_utilization_percent = parts[6].parse::<u32>().unwrap_or(0);
            let memory_utilization_percent = if memory_total_mb > 0 {
                ((memory_used_mb as f64 / memory_total_mb as f64) * 100.0) as u32
            } else {
                0
            };

            Some(GpuTelemetry {
                gpu_name,
                temperature_c,
                power_usage_watts,
                gpu_utilization_percent,
                memory_utilization_percent,
                memory_used_mb,
                memory_total_mb,
                core_clock_mhz,
            })
        } else {
            None
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}
