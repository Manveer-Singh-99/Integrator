//! # Cross-Platform Hardware GPU Telemetry Engine (`telemetry.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `telemetry.rs` implements hardware-agnostic GPU metrics collection across NVIDIA, AMD, Intel,
//! and Apple Silicon graphics architectures.
//!
//! Rather than hardcoding assumptions such as GPU index 0 or assuming an NVIDIA discrete card exists,
//! this module dynamically discovers all system graphics adapters. On Windows systems equipped with
//! NVIDIA hardware, it queries `nvidia-smi` via a sandboxed, timeout-bounded subprocess to capture
//! real-time core clock speeds, GPU/memory utilization percentages, power draw (in Watts), and core
//! thermals (in degrees Celsius). For non-NVIDIA or integrated systems (Intel Iris Xe, AMD Radeon,
//! Apple M1/M2/M3/M4 unified memory architectures), it falls back to operating system hardware
//! enumeration (`system_info::enumerate_gpus`) via DXGI or IOKit/Metal.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core.rs`: Periodically polls GPU telemetry and embeds the statistics into outbound peer telemetry
//!   datagrams (streamed over `TELEMETRY_PORT` 58285) or dispatches them to native UI views via FFI.
//! - UI Status Widgets: Consumed by macOS SwiftUI and Windows WinUI 3 overlays to display real-time
//!   encoder/decoder utilization and thermal health bars.
//!
//! ### Downstream Callees:
//! - `system_info::enumerate_gpus`: Provides baseline adapter model names and VRAM capacity via OS APIs.
//! - `system_info::read_sunshine_config_info`: Discovers whether an external streamer (Sunshine/Moonlight)
//!   has bound to a specific GPU adapter index, matching Integrator's telemetry to the active render device.
//! - `nvidia-smi.exe` (Windows): Queried from verified, trusted system directories using `std::process::Command`.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Remote machines exchange GPU telemetry so the encoding host knows if the decoding client is dropping
//! frames due to GPU saturation, and vice versa. Telemetry is serialized as JSON and transported over
//! encrypted ChaCha20-Poly1305 transport channels.
//!
//! ## 3. Threading & Concurrency Model
//! - **Subprocess Execution**: `run_nvidia_smi_with_timeout` executes on asynchronous blocking threads
//!   (`spawn_blocking`). A dedicated helper thread reads standard output while the parent thread polls
//!   the process handle against a 1500ms deadline.
//! - **Static Cache (`NVIDIA_CACHE`)**: Protected by `OnceLock<Mutex<(Instant, Option<GpuTelemetry>)>>`
//!   with a 1200ms Time-To-Live (TTL). Consecutive calls from multiple threads or UI timers hit the memory
//!   cache, eliminating subprocess fork storms.
//!
//! ## 4. Security & Safety Invariants
//! - **Executable Path Verification**: `find_trusted_nvidia_smi` only searches explicit, hardened system paths
//!   (`%SystemRoot%\System32` and `%ProgramFiles%\NVIDIA Corporation\NVSMI`). It never searches the working
//!   directory (`PATH`), mitigating DLL/binary hijacking risks.
//! - **Windowless Subprocess**: Processes are spawned with `CREATE_NO_WINDOW (0x08000000)` to prevent UI flashing.
//! - **Resilient Parsing**: CSV split handling uses reverse parsing (`rsplitn`) to safely handle commercial GPU
//!   names containing embedded commas (e.g., `"NVIDIA GeForce RTX, Studio Edition"`). Non-finite floats (`NaN`, `inf`)
//!   and negative numbers are rejected and sanitized to zero.

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

/// Maximum duration permitted for `nvidia-smi.exe` execution before hard termination.
#[cfg(target_os = "windows")]
const NVIDIA_SMI_TIMEOUT: Duration = Duration::from_millis(1500);

/// In-memory cache lifetime for GPU metrics. Prevents redundant process spawning within 1.2 seconds.
#[cfg(target_os = "windows")]
const NVIDIA_CACHE_TTL: Duration = Duration::from_millis(1200);

/// Snapshot of graphics processing unit performance, memory, and thermal state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuTelemetry {
    /// Human-readable brand and model name of the graphics adapter (e.g. `"NVIDIA GeForce RTX 4090"` or `"Apple M3 Max"`).
    pub gpu_name: String,
    /// Core die temperature in degrees Celsius (°C). Range: 0–120. (0 if unsupported by hardware/driver).
    pub temperature_c: u32,
    /// Real-time graphics card power draw in Watts (W). Range: 0.0–600.0.
    pub power_usage_watts: f32,
    /// Core compute engine load percentage. Range: 0–100%.
    pub gpu_utilization_percent: u32,
    /// Onboard VRAM memory controller load percentage. Range: 0–100%.
    pub memory_utilization_percent: u32,
    /// Currently allocated dedicated video memory in Megabytes (MB).
    pub memory_used_mb: u64,
    /// Total installed dedicated video memory in Megabytes (MB).
    pub memory_total_mb: u64,
    /// Current graphics core clock frequency in Megahertz (MHz). Range: 0–3500.
    pub core_clock_mhz: u32,
}

/// Parses an unsigned 32-bit integer from a raw string, handling floating-point strings and invalid values.
///
/// Rejects `NaN`, infinite values, and negative numbers, returning `0` on error or clamping to `u32::MAX`.
#[cfg(any(target_os = "windows", test))]
fn parse_optional_u32(raw: &str) -> u32 {
    parse_optional_f32(raw).clamp(0.0, u32::MAX as f32).round() as u32
}

/// Parses an unsigned 64-bit integer from a raw string, handling scientific notation and non-numeric placeholders.
///
/// Returns `0` if parsing fails, string represents `[N/A]`, or value is negative.
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

/// Parses a 32-bit floating point value from a raw string, verifying finite bounds and non-negativity.
///
/// Returns `0.0` if value is `NaN`, infinite, or negative.
#[cfg(any(target_os = "windows", test))]
fn parse_optional_f32(raw: &str) -> f32 {
    raw.trim()
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0)
}

/// Parses a single CSV line output by `nvidia-smi --format=csv,noheader,nounits`.
///
/// # Field Layout (Reverse Split)
/// Uses `rsplitn(8, ',')` to read columns from right-to-left. This allows the GPU product name
/// (which is the first column in the query) to contain internal commas without breaking column alignment.
///
/// # Arguments
/// * `line` - A single CSV string line from `nvidia-smi`.
///
/// # Return Value
/// Returns `Some(GpuTelemetry)` if line had at least 8 comma-separated fields, or `None` on format mismatch.
#[cfg(any(target_os = "windows", test))]
fn parse_nvidia_smi_csv_line(line: &str) -> Option<GpuTelemetry> {
    // Split into at most 8 slices starting from the end of the line
    let rev_parts: Vec<&str> = line.rsplitn(8, ',').map(|s| s.trim()).collect();
    if rev_parts.len() != 8 {
        return None;
    }

    // Because rsplitn was used, index 7 contains the remainder (the GPU name at the start of the line)
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

/// Public cross-platform entry point to query real-time GPU telemetry.
///
/// On Windows, probes `nvidia-smi` first; if unavailable or non-NVIDIA, falls back to DXGI enumeration.
/// On macOS / Unix, queries IOKit/Metal GPU topology via `system_info::enumerate_gpus`.
///
/// # Return Value
/// Returns `Some(GpuTelemetry)` with populated metrics, or `None` if no GPU was found.
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

/// Locates the `nvidia-smi.exe` binary in trusted system directories.
///
/// Explicitly avoids searching the current working directory or relative paths.
#[cfg(target_os = "windows")]
fn find_trusted_nvidia_smi() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    // Check %SystemRoot%\System32\nvidia-smi.exe
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        candidates.push(PathBuf::from(sys_root).join("System32").join("nvidia-smi.exe"));
    }
    // Check fallback C:\Windows\System32\nvidia-smi.exe
    candidates.push(PathBuf::from(r"C:\Windows\System32\nvidia-smi.exe"));

    // Check %ProgramFiles%\NVIDIA Corporation\NVSMI\nvidia-smi.exe
    if let Ok(pf) = std::env::var("ProgramFiles") {
        candidates.push(
            PathBuf::from(pf)
                .join("NVIDIA Corporation")
                .join("NVSMI")
                .join("nvidia-smi.exe"),
        );
    }

    // Return the first candidate that exists as a verified file on disk
    candidates.into_iter().find(|p| p.is_file())
}

/// Executes `nvidia-smi.exe` asynchronously with a strict 1500ms timeout guard.
///
/// Uses `CREATE_NO_WINDOW` to avoid flashing a command prompt window on the user's desktop.
/// Spawns a dedicated thread to drain standard output to prevent pipe buffer deadlocks.
#[cfg(target_os = "windows")]
fn run_nvidia_smi_with_timeout() -> Option<String> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let bin = find_trusted_nvidia_smi()?;
    let mut cmd = Command::new(bin);
    // Request raw CSV data without header rows and without unit suffix strings (e.g. "W", "MHz", "MiB")
    cmd.args([
        "--query-gpu=name,temperature.gpu,power.draw,utilization.gpu,utilization.memory,memory.used,memory.total,clocks.current.graphics",
        "--format=csv,noheader,nounits",
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();

    // Spawn background reader thread to drain stdout pipe without blocking child process
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
                // Process terminated before deadline; join stdout thread and return output
                let text = reader.join().unwrap_or_default();
                return status.success().then_some(text);
            }
            Ok(None) => {
                // Process still running: check timeout deadline
                if Instant::now() >= deadline {
                    // Deadline exceeded: forcibly kill the child process to release system resources
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                // Process wait error: kill child and exit
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Queries NVIDIA telemetry with caching and adapter selection preference.
///
/// Employs an in-memory cache with 1200ms TTL. If multiple GPUs exist, prioritizes the adapter
/// matching the Sunshine streaming configuration, falling back to the card with greatest VRAM.
#[cfg(target_os = "windows")]
fn query_nvidia_smi() -> Option<GpuTelemetry> {
    static NVIDIA_CACHE: OnceLock<Mutex<(Instant, Option<GpuTelemetry>)>> = OnceLock::new();
    let cache = NVIDIA_CACHE.get_or_init(|| {
        Mutex::new((Instant::now() - Duration::from_secs(60), None))
    });

    // Check if cached metrics are still fresh
    if let Ok(guard) = cache.lock() {
        if guard.0.elapsed() < NVIDIA_CACHE_TTL {
            return guard.1.clone();
        }
    }

    // Execute nvidia-smi with timeout
    let stdout = match run_nvidia_smi_with_timeout() {
        Some(s) => s,
        None => {
            // Update cache with negative result to throttle repeated failed executions
            if let Ok(mut guard) = cache.lock() {
                *guard = (Instant::now(), None);
            }
            return None;
        }
    };

    // Inspect Sunshine configuration to see if a preferred GPU adapter index/name was specified
    let (_, _, preferred_adapter) = system_info::read_sunshine_config_info();
    let parsed_list: Vec<GpuTelemetry> = stdout
        .lines()
        .filter_map(parse_nvidia_smi_csv_line)
        .collect();

    if parsed_list.is_empty() {
        return None;
    }

    // Prefer GPU configured in Sunshine, otherwise pick the one with highest VRAM
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

    // Store successful result in cache
    if let Ok(mut guard) = cache.lock() {
        *guard = (Instant::now(), selected.clone());
    }
    selected
}

/// Fallback telemetry collector for Windows machines running AMD, Intel, or virtual GPUs.
///
/// Enumerates DXGI adapters via `system_info::enumerate_gpus` and returns available VRAM and adapter name.
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

/// Fallback telemetry collector for macOS and non-Windows Unix systems.
///
/// Resolves Apple Silicon Metal devices or discrete GPUs via `system_info::enumerate_gpus`.
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
