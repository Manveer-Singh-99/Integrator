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
