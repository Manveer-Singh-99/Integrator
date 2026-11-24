//! # Cross-Screen TrueTone & Bradford Chromatic Adaptation Engine
//!
//! ## 1. Module Purpose & Scope
//! This module provides Apple-style continuous ambient color temperature synchronization and chromatic
//! adaptation between a macOS host equipped with an Apple Ambient Light Sensor (ALS) and a paired
//! Windows 10/11 workstation.
//!
//! Architectural split (PC performs **all** colour calculation and smooth transitions):
//! 1. **macOS Host (Thin Sensor Forwarder)**: Samples raw hardware ALS telemetry (`lux`, raw ADC
//!    channels `ch0..ch2`, and CIE XYZ tristimulus coordinates) every **2 seconds** via
//!    `ambient_light.swift` and forwards raw telemetry to Windows with zero color math on Mac.
//! 2. **Windows PC (Chromaticity Estimation, Partial Adaptation & Smooth 4s Animator)**:
//!    - Computes Correlated Color Temperature (CCT) from raw CIE XYZ (McCamy cubic) or raw ADC
//!      red/blue channel ratios (`3000 + (ch2/ch0) * 3500`).
//!    - Applies temporal EMA noise filtering and lux-weighted partial chromatic adaptation (Apple True
//!      Tone style, tapering adaptation strength in very dim rooms to prevent monitor-glare swings).
//!    - Solves the Bradford Chromatic Adaptation Transform (CAT) in cone response space to obtain
//!      per-channel linear sRGB multipliers `(k_r, k_g, k_b)`.
//!    - Drives a dedicated ~30 Hz background animator thread that interpolates across a **4-second
//!      $C^1$-continuous cubic Hermite curve** whenever 2-second ALS updates arrive, updating Win32
//!      `SetDeviceGammaRamp` smoothly with zero abrupt jumps or flicker.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                     TrueTone Raw ALS Forwarding & 4s Smooth PC Engine                  │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!        MacBook (Sensor Only, 2s cadence)              Windows 11 (Colour Math + 4s Ramp)
//!   ┌───────────────────────────────────────┐      ┌──────────────────────────────────────────┐
//!   │ Apple ALS (ambient_light.swift)       │      │ SyncTrueTone RPC -> apply_raw_als_sync() │
//!   │ read_mac_raw_ambient_sensor()         │      │ - McCamy CIE XYZ / ch2:ch0 CCT solver    │
//!   └──────────────────┬────────────────────┘      │ - EMA Filter + Lux-Weighted Adaptation   │
//!                      │ raw_als every 2s          │ - Bradford CAT -> (k_r, k_g, k_b)        │
//!                      └──────────────────────────►│ - 4s C1 Hermite Animator (30 Hz LUT)     │
//!                                                  └────────────────────┬─────────────────────┘
//!                                                                       ▼
//!                                                         Win32 SetDeviceGammaRamp (256-LUT)
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Spawns `run_continuous_truetone_sync`, handles manual calibration triggers
//!   (`apply_hardware_gamma_ramp`), exposes UI telemetry (`read_ambient_light`), and restores
//!   neutral LUTs on disable/shutdown (`reset_hardware_gamma_ramp`).
//! - `src/display/controller.rs`: Receives `DisplayRpcRequest::SyncTrueTone` on Windows, delegates raw
//!   ALS telemetry to `apply_raw_als_sync` (or manual overrides to `apply_hardware_gamma_ramp`), and
//!   returns PC-calculated `AmbientLightData` back to Mac for status pill display parity.
//!
//! ### Downstream Callees:
//! - `src/ambient_light.swift`: C-ABI FFI `read_mac_raw_ambient_sensor` (raw IOKit HID sensor only).
//! - Win32 `gdi32.dll` / `user32.dll`: `SetDeviceGammaRamp`, `GetDC`, `ReleaseDC` on Windows.
//!
//! ## 3. Threading & Concurrency Model
//! - **Lock-Free Status Atomics**: `USER_GAMMA_COMP_X100`, `LAST_SYNCED_CCT`, `LAST_SYNCED_LUX_X10`,
//!   and `LAST_SYNCED_EPOCH_SECS` store UI-visible state lock-free (`Release`/`Acquire`).
//! - **Dedicated PC Animator Thread**: `ANIMATOR_STATE` (`Mutex<TransitionState>` + `Condvar`) wakes
//!   the background `truetone-animator` thread only during active 4-second transitions (~33ms ticks)
//!   and releases the mutex before calling Win32 GDI `SetDeviceGammaRamp`.
//! - **Single-Flight Mac Dispatch Guard**: `SYNC_IN_FLIGHT` (`AtomicBool`) prevents overlapping 2s RPCs.
//!
//! ## 4. Security & Safety Invariants
//! - **Finite Number Guarantee**: Every raw channel, CIE coordinate, multiplier, and gamma input is
//!   verified finite (`is_finite()`), safely falling back to neutral D65 (`1.0`).
//! - **LUT Ramp Clamping**: CCT is clamped to `[MIN_CCT_KELVIN, MAX_CCT_KELVIN]` (`[2500, 9000] K`)
//!   and multipliers are clamped to `[0.4, 1.5]` so panels cannot black out or clip harshly.
//! - **GDI Handle Hygiene**: `apply_windows_gamma_ramp` unconditionally pairs `GetDC(NULL)` with
//!   `ReleaseDC(NULL, hdc)` before checking `SetDeviceGammaRamp` return status.

use crate::config::{
    D65_CCT_KELVIN, MAX_CCT_KELVIN, MAX_GAMMA_COMP_FACTOR, MIN_CCT_KELVIN, MIN_GAMMA_COMP_FACTOR,
};
use crate::discovery::DiscoveryManager;
#[cfg(target_os = "macos")]
use crate::display::controller::DisplayController;
#[cfg(target_os = "macos")]
use crate::display::protocol::DisplayRpcRequest;
use crate::features::FeatureManager;
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::sync::{Condvar, Mutex, OnceLock};
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(any(target_os = "windows", test))]
use std::time::Instant;
#[cfg(target_os = "windows")]
use std::time::Duration;

/// ALS-to-PC transition duration in seconds (4s smooth glide accommodates 2s ALS updates cleanly).
#[cfg(any(target_os = "windows", test))]
const ALS_TRANSITION_WINDOW_SECS: f32 = 4.0;

/// Snappier smooth transition duration in seconds for manual UI slider calibration triggers.
#[cfg(target_os = "windows")]
const MANUAL_TRANSITION_WINDOW_SECS: f32 = 0.65;

/// Frame cadence for the Windows GPU LUT transition animator (~30 Hz = 33 ms per step).
#[cfg(target_os = "windows")]
const ANIMATOR_FRAME_INTERVAL: Duration = Duration::from_millis(33);

/// Exponential moving average weight for incoming 2s raw ALS readings on PC (smooths ADC noise).
#[cfg(any(target_os = "windows", test))]
const PC_ALS_EMA_ALPHA: f32 = 0.30;

/// Maximum gap (seconds) before the PC ALS EMA filter snaps directly to a fresh room reading.
#[cfg(any(target_os = "windows", test))]
const PC_ALS_FILTER_RESET_GAP_SECS: f32 = 15.0;

/// Minimum RGB multiplier change required to retarget an ongoing or settled LUT transition.
#[cfg(any(target_os = "windows", test))]
const MULTIPLIER_RETARGET_EPSILON: f32 = 0.0015;

/// Scaled integer (`value * 100`) storing user-selected gamma compensation factor (default: `1.00x`).
static USER_GAMMA_COMP_X100: AtomicU32 = AtomicU32::new(100);

/// Most recent PC-calculated or synced correlated color temperature in Kelvin (`0` = none synced yet).
static LAST_SYNCED_CCT: AtomicU32 = AtomicU32::new(0);

/// Most recent ambient illuminance in lux stored as fixed-point `lux * 10` (`0.1 lx` resolution).
static LAST_SYNCED_LUX_X10: AtomicU32 = AtomicU32::new(0);

/// Unix epoch seconds when the last ambient telemetry was recorded (`0` = never).
static LAST_SYNCED_EPOCH_SECS: AtomicU64 = AtomicU64::new(0);

/// Single-flight guard preventing overlapping 2s ALS RPCs from macOS.
#[cfg(target_os = "macos")]
static SYNC_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Updates the user's preferred gamma compensation factor for True Tone sync.
pub fn set_user_gamma_comp(comp: f32) {
    if comp.is_finite() && comp > 0.0 {
        let val = (comp.clamp(MIN_GAMMA_COMP_FACTOR, MAX_GAMMA_COMP_FACTOR) * 100.0).round() as u32;
        USER_GAMMA_COMP_X100.store(val, Ordering::Release);
    }
}

/// Retrieves the user's preferred gamma compensation factor.
#[cfg(any(target_os = "macos", test))]
pub fn get_user_gamma_comp() -> f32 {
    let val = USER_GAMMA_COMP_X100.load(Ordering::Acquire);
    (val as f32) / 100.0
}

/// Records the latest ambient light sample (PC-calculated CCT + lux) for status reporting.
pub fn record_synced_ambient(lux: f32, cct_kelvin: u32) {
    let cct = cct_kelvin.clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN);
    let lux_x10 = if lux.is_finite() && lux >= 0.0 {
        (lux * 10.0).round() as u32
    } else {
        0
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    LAST_SYNCED_LUX_X10.store(lux_x10, Ordering::Relaxed);
    LAST_SYNCED_EPOCH_SECS.store(now, Ordering::Relaxed);
    LAST_SYNCED_CCT.store(cct, Ordering::Release);
}

/// Clears any synced ambient telemetry (e.g. when True Tone is disabled or reset to neutral).
pub fn clear_synced_ambient() {
    LAST_SYNCED_CCT.store(0, Ordering::Release);
    LAST_SYNCED_LUX_X10.store(0, Ordering::Relaxed);
    LAST_SYNCED_EPOCH_SECS.store(0, Ordering::Relaxed);
}

/// Returns `Some((lux, cct_kelvin, unix_epoch_secs))` for the most recent synced ambient telemetry.
pub fn get_last_synced_ambient() -> Option<(f32, u32, u64)> {
    let cct = LAST_SYNCED_CCT.load(Ordering::Acquire);
    if cct == 0 {
        return None;
    }
    let lux = LAST_SYNCED_LUX_X10.load(Ordering::Relaxed) as f32 / 10.0;
    let ts = LAST_SYNCED_EPOCH_SECS.load(Ordering::Relaxed);
    Some((lux, cct, ts))
}

/// Raw hardware ambient light sample captured on macOS without color calculation.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
struct RawAmbientSample {
    /// Illuminance in Lux (`>= 0.0`, finite).
    lux: f32,
    /// Raw ADC warm/red channel (`ch0`), if available.
    ch0: Option<f32>,
    /// Raw ADC green channel (`ch1`), if available.
    ch1: Option<f32>,
    /// Raw ADC cool/blue channel (`ch2`), if available.
    ch2: Option<f32>,
    /// Factory-calibrated CIE X tristimulus coordinate, if `ColorSpace == 1`.
    cie_x: Option<f32>,
    /// Factory-calibrated CIE Y tristimulus coordinate, if `ColorSpace == 1`.
    cie_y: Option<f32>,
    /// Factory-calibrated CIE Z tristimulus coordinate, if `ColorSpace == 1`.
    cie_z: Option<f32>,
    /// True when the local hardware ALS sensor yielded a valid sample.
    supported: bool,
}

#[cfg(target_os = "macos")]
extern "C" {
    /// Native Swift/IOKit FFI entry point (`ambient_light.swift`) sampling raw ALS channels only.
    fn read_mac_raw_ambient_sensor(
        out_lux: *mut f32,
        out_ch0: *mut f32,
        out_ch1: *mut f32,
        out_ch2: *mut f32,
        out_cie_x: *mut f32,
        out_cie_y: *mut f32,
        out_cie_z: *mut f32,
    ) -> bool;
}

/// Reads the macOS ALS hardware raw channels cleanly (no CCT/color math performed on macOS).
#[cfg(target_os = "macos")]
fn read_mac_raw_ambient_sample() -> RawAmbientSample {
    let mut lux: f32 = -1.0;
    let mut ch0: f32 = -1.0;
    let mut ch1: f32 = -1.0;
    let mut ch2: f32 = -1.0;
    let mut cie_x: f32 = -1.0;
    let mut cie_y: f32 = -1.0;
    let mut cie_z: f32 = -1.0;

    // SAFETY: Passes valid mutable pointers to stack-allocated `f32` locals.
    let ok = unsafe {
        read_mac_raw_ambient_sensor(
            &mut lux,
            &mut ch0,
            &mut ch1,
            &mut ch2,
            &mut cie_x,
            &mut cie_y,
            &mut cie_z,
        )
    };
    if !ok || !lux.is_finite() || lux < 0.0 {
        return RawAmbientSample::default();
    }

    let opt_pos = |v: f32| -> Option<f32> {
        if v.is_finite() && v > 0.0 {
            Some(v)
        } else {
            None
        }
    };
    let (cx, cy, cz) = if cie_x.is_finite()
        && cie_y.is_finite()
        && cie_z.is_finite()
        && cie_x > 0.0
        && cie_y > 0.0
        && cie_z >= 0.0
    {
        (Some(cie_x), Some(cie_y), Some(cie_z))
    } else {
        (None, None, None)
    };

    RawAmbientSample {
        lux,
        ch0: opt_pos(ch0),
        ch1: opt_pos(ch1),
        ch2: opt_pos(ch2),
        cie_x: cx,
        cie_y: cy,
        cie_z: cz,
        supported: true,
    }
}

/// Continuously polls raw Mac ALS sensor telemetry every 2 seconds and streams raw sensor channels
/// to the paired Windows PC, where the PC computes all chromaticity, adaptation, and smooth 4s LUT ramps.
pub async fn run_continuous_truetone_sync(
    discovery: DiscoveryManager,
    features: Arc<FeatureManager>,
) {
    #[cfg(target_os = "macos")]
    {
        tracing::info!("🎨 Continuous True Tone raw ALS forwarder started on macOS (2s cadence -> PC math)");

        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            if !features.is_enabled("truetone") {
                continue;
            }

            let peer_ip = match discovery.get_peer_ip().await {
                Some(ip) => ip,
                None => match discovery.get_best_peer().await {
                    Some(p) => p.addr.ip().to_string(),
                    None => continue,
                },
            };

            let sample = tokio::task::spawn_blocking(read_mac_raw_ambient_sample)
                .await
                .unwrap_or_default();

            if !sample.supported || !sample.lux.is_finite() || sample.lux < 0.0 {
                continue;
            }

            if SYNC_IN_FLIGHT
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                /// RAII guard ensuring `SYNC_IN_FLIGHT` is always released even if the task aborts.
                struct SyncInFlightGuard;
                impl Drop for SyncInFlightGuard {
                    fn drop(&mut self) {
                        SYNC_IN_FLIGHT.store(false, Ordering::Release);
                    }
                }

                let gamma_comp = get_user_gamma_comp();
                let rpc = DisplayRpcRequest::SyncTrueTone {
                    lux: sample.lux,
                    cct: 0,
                    gamma_comp,
                    raw_als: true,
                    als_ch0: sample.ch0,
                    als_ch1: sample.ch1,
                    als_ch2: sample.ch2,
                    cie_x: sample.cie_x,
                    cie_y: sample.cie_y,
                    cie_z: sample.cie_z,
                };
                let target_ip = peer_ip.clone();
                tokio::spawn(async move {
                    let _guard = SyncInFlightGuard;
                    match DisplayController::send_remote_rpc(&target_ip, &rpc).await {
                        Ok(resp) if resp.success => {
                            if let Some(als) = resp.ambient_light {
                                record_synced_ambient(als.lux, als.cct_kelvin);
                            }
                        }
                        Ok(resp) => {
                            tracing::debug!(
                                "True Tone raw ALS sync to {} rejected: {}",
                                target_ip,
                                resp.message
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                "True Tone raw ALS transport error to {}: {}",
                                target_ip,
                                e
                            );
                        }
                    }
                });
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (discovery, features);
    }
}

/// Ambient light snapshot exposed to the UI / RPC layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientLightData {
    /// Illuminance in lux (`>= 0`, finite).
    pub lux: f32,
    /// Correlated color temperature in Kelvin (`MIN_CCT_KELVIN..=MAX_CCT_KELVIN`, or D65 fallback).
    pub cct_kelvin: u32,
    /// `true` when a real sensor reading (macOS) or synced PC sample is available.
    pub supported: bool,
    /// Unix epoch seconds of the sample; `0` when unsupported.
    pub updated_at_secs: u64,
}

/// Reads current ambient telemetry without running any CCT/color computation on macOS
/// (macOS uses PC-calculated CCT from `record_synced_ambient` when available, else D65 neutral).
pub fn read_ambient_light() -> AmbientLightData {
    #[cfg(target_os = "macos")]
    {
        let raw = read_mac_raw_ambient_sample();
        if raw.supported {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let synced_cct = get_last_synced_ambient()
                .map(|(_, cct, _)| cct)
                .unwrap_or(D65_CCT_KELVIN);
            AmbientLightData {
                lux: raw.lux,
                cct_kelvin: synced_cct,
                supported: true,
                updated_at_secs: now,
            }
        } else {
            AmbientLightData {
                lux: 0.0,
                cct_kelvin: D65_CCT_KELVIN,
                supported: false,
                updated_at_secs: 0,
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some((lux, cct, ts)) = get_last_synced_ambient() {
            AmbientLightData {
                lux,
                cct_kelvin: cct,
                supported: true,
                updated_at_secs: ts,
            }
        } else {
            AmbientLightData {
                lux: 0.0,
                cct_kelvin: D65_CCT_KELVIN,
                supported: false,
                updated_at_secs: 0,
            }
        }
    }
}

/// Estimates raw Correlated Color Temperature in Kelvin on the PC from incoming Mac ALS sensor channels.
///
/// Prefers factory-calibrated CIE XYZ tristimulus coordinates (McCamy 1992 cubic approximation),
/// falling back to raw red/blue channel ratio (`3000 + (ch2/ch0) * 3500`) or D65 neutral (`6500 K`)
/// for monochrome hardware.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn estimate_cct_from_raw_als(
    als_ch0: Option<f32>,
    als_ch2: Option<f32>,
    cie_x: Option<f32>,
    cie_y: Option<f32>,
    cie_z: Option<f32>,
) -> f32 {
    if let (Some(cx), Some(cy), Some(cz)) = (cie_x, cie_y, cie_z) {
        if cx.is_finite() && cy.is_finite() && cz.is_finite() && cx > 0.0 && cy > 0.0 && cz >= 0.0 {
            let sum = cx + cy + cz;
            if sum > 0.001 {
                let x = cx / sum;
                let y = cy / sum;
                let denom = 0.1858 - y;
                if denom.abs() > 0.02 {
                    let n = (x - 0.3320) / denom;
                    let cct = 449.0 * n.powi(3) + 3525.0 * n.powi(2) + 6823.3 * n + 5520.33;
                    if cct.is_finite() && cct > 500.0 && cct < 25_000.0 {
                        return cct.clamp(MIN_CCT_KELVIN as f32, MAX_CCT_KELVIN as f32);
                    }
                }
            }
        }
    }

    if let (Some(ch0), Some(ch2)) = (als_ch0, als_ch2) {
        if ch0.is_finite() && ch2.is_finite() && ch0 > 0.0 && ch2 > 0.0 {
            let ratio = ch2 / ch0;
            if ratio.is_finite() {
                let cct = 3000.0 + (ratio * 3500.0);
                if cct.is_finite() {
                    return cct.clamp(MIN_CCT_KELVIN as f32, MAX_CCT_KELVIN as f32);
                }
            }
        }
    }

    D65_CCT_KELVIN as f32
}

/// Computes Apple-style partial chromatic adaptation factor `D` (`0.45..=0.85`) as a smooth
/// logarithmic function of ambient illuminance (lux).
///
/// Prevents dark-room display self-glare from driving full white-point saturation swings while
/// approaching full visual adaptation under typical indoor/daylight lighting.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn apple_adaptation_degree_from_lux(lux: f32) -> f32 {
    if !lux.is_finite() || lux <= 0.0 {
        return 0.45;
    }
    let norm = ((1.0 + lux).ln() / (1.0 + 300.0f32).ln()).clamp(0.0, 1.0);
    0.45 + 0.40 * norm
}

/// Persistent PC-side temporal exponential moving average filter state for incoming raw ALS telemetry.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default)]
struct PcAdaptationFilter {
    /// Smoothed CCT in Kelvin (`None` before first sample or after reset).
    ema_cct: Option<f32>,
    /// Smoothed illuminance in Lux (`None` before first sample or after reset).
    ema_lux: Option<f32>,
    /// Timestamp of the last processed raw ALS sample.
    last_sample_at: Option<Instant>,
}

#[cfg(any(target_os = "windows", test))]
impl PcAdaptationFilter {
    /// Updates the EMA filter with a fresh raw ALS `(lux, raw_cct)` sample and returns `(smoothed_lux, adapted_cct)`.
    fn ingest(&mut self, lux: f32, raw_cct: f32, now: Instant) -> (f32, u32) {
        let safe_lux = if lux.is_finite() && lux >= 0.0 { lux } else { 0.0 };
        let safe_cct = if raw_cct.is_finite() {
            raw_cct.clamp(MIN_CCT_KELVIN as f32, MAX_CCT_KELVIN as f32)
        } else {
            D65_CCT_KELVIN as f32
        };

        let stale = self
            .last_sample_at
            .map_or(true, |prev| now.saturating_duration_since(prev).as_secs_f32() > PC_ALS_FILTER_RESET_GAP_SECS);

        let (ema_lux, ema_cct) = if stale {
            (safe_lux, safe_cct)
        } else {
            let prev_lux = self.ema_lux.unwrap_or(safe_lux);
            let prev_cct = self.ema_cct.unwrap_or(safe_cct);
            (
                prev_lux + PC_ALS_EMA_ALPHA * (safe_lux - prev_lux),
                prev_cct + PC_ALS_EMA_ALPHA * (safe_cct - prev_cct),
            )
        };

        self.ema_lux = Some(ema_lux);
        self.ema_cct = Some(ema_cct);
        self.last_sample_at = Some(now);

        let degree = apple_adaptation_degree_from_lux(ema_lux);
        let blended = (D65_CCT_KELVIN as f32) + degree * (ema_cct - D65_CCT_KELVIN as f32);
        let adapted_cct = (blended.round() as u32).clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN);
        (ema_lux, adapted_cct)
    }

    /// Resets filter history so re-enabling True Tone starts fresh cleanly.
    #[cfg(target_os = "windows")]
    fn reset(&mut self) {
        self.ema_cct = None;
        self.ema_lux = None;
        self.last_sample_at = None;
    }
}

#[cfg(target_os = "windows")]
static PC_FILTER: OnceLock<Mutex<PcAdaptationFilter>> = OnceLock::new();

#[cfg(target_os = "windows")]
fn pc_filter() -> &'static Mutex<PcAdaptationFilter> {
    PC_FILTER.get_or_init(|| Mutex::new(PcAdaptationFilter::default()))
}

/// Calculates Bradford Chromatic Adaptation Transform linear sRGB scaling factors `(k_r, k_g, k_b)`
/// for a target ambient CCT (`cct_kelvin`) relative to the standard CIE D65 (`6500 K`) white point,
/// scaled by the user's `gamma_comp` intensity multiplier.
#[cfg(any(target_os = "windows", test))]
pub fn calculate_bradford_multipliers(cct_kelvin: u32, gamma_comp: f32) -> (f32, f32, f32) {
    let safe_gamma = if gamma_comp.is_finite() {
        gamma_comp.clamp(MIN_GAMMA_COMP_FACTOR, MAX_GAMMA_COMP_FACTOR)
    } else {
        1.0
    };
    let t = cct_kelvin.clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN) as f32;

    // CIE Daylight (D-illuminant) for >= 4000K so 6500K aligns with D65; Kang 2002 Planckian below 4000K.
    let inv_t = 1000.0 / t;
    let (x, y) = if t < 4000.0 {
        let x = -0.2661239 * inv_t.powi(3) - 0.2343580 * inv_t.powi(2)
            + 0.8776956 * inv_t
            + 0.179910;
        let y = if t <= 2222.0 {
            -1.1063814 * x.powi(3) - 1.34811020 * x.powi(2) + 2.18555832 * x - 0.20219683
        } else {
            -0.9549476 * x.powi(3) - 1.37418593 * x.powi(2) + 2.09137015 * x - 0.16748867
        };
        (x, y)
    } else {
        let x = if t <= 7000.0 {
            -4.6070 * inv_t.powi(3) + 2.9678 * inv_t.powi(2) + 0.09911 * inv_t + 0.244063
        } else {
            -2.0064 * inv_t.powi(3) + 1.9018 * inv_t.powi(2) + 0.24748 * inv_t + 0.237040
        };
        let y = -3.0 * x.powi(2) + 2.87 * x - 0.275;
        (x, y)
    };

    // CIE XYZ for destination white point (Y = 1.0)
    let y_safe = y.max(0.0001);
    let xd = x / y_safe;
    let yd = 1.0f32;
    let zd = ((1.0 - x - y) / y_safe).max(0.0);

    // Reference white point D65
    let xs = 0.95047f32;
    let ys = 1.00000f32;
    let zs = 1.08883f32;

    // Bradford cone response scaling adapted to XYZ -> linear sRGB
    let rho_s = 0.8951 * xs + 0.2664 * ys - 0.1614 * zs;
    let gam_s = -0.7502 * xs + 1.7135 * ys + 0.0367 * zs;
    let bet_s = 0.0389 * xs - 0.0685 * ys + 1.0296 * zs;

    let rho_d = 0.8951 * xd + 0.2664 * yd - 0.1614 * zd;
    let gam_d = -0.7502 * xd + 1.7135 * yd + 0.0367 * zd;
    let bet_d = 0.0389 * xd - 0.0685 * yd + 1.0296 * zd;

    let s_r = (rho_d / rho_s.max(0.0001)).clamp(0.4, 2.0);
    let s_g = (gam_d / gam_s.max(0.0001)).clamp(0.4, 2.0);
    let s_b = (bet_d / bet_s.max(0.0001)).clamp(0.4, 2.0);

    let a_rho = s_r * rho_s;
    let a_gam = s_g * gam_s;
    let a_bet = s_b * bet_s;

    let ax = 0.9869929 * a_rho - 0.1470543 * a_gam + 0.1599627 * a_bet;
    let ay = 0.4323053 * a_rho + 0.5183603 * a_gam + 0.0492912 * a_bet;
    let az = -0.0085287 * a_rho + 0.0400428 * a_gam + 0.9684867 * a_bet;

    let r_lin = 3.2404542 * ax - 1.5371385 * ay - 0.4985314 * az;
    let g_lin = -0.9692660 * ax + 1.8760108 * ay + 0.0415560 * az;
    let b_lin = 0.0556434 * ax - 0.2040259 * ay + 1.0572252 * az;

    let max_chan = r_lin.max(g_lin).max(b_lin).max(0.0001);
    let k_r = ((r_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);
    let k_g = ((g_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);
    let k_b = ((b_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);

    (
        if k_r.is_finite() { k_r } else { 1.0 },
        if k_g.is_finite() { k_g } else { 1.0 },
        if k_b.is_finite() { k_b } else { 1.0 },
    )
}

/// Evaluates a $C^1$-continuous cubic Hermite spline from `(start, start_vel)` to `(target, 0)`
/// at `elapsed_secs` inside `duration_secs`.
///
/// Returns `(position, velocity_per_sec, still_active)`. Preserving both position and velocity when
/// a new 2-second ALS target interrupts a 4-second transition eliminates start-stop pulsing and snaps.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn evaluate_hermite_at(
    start: [f32; 3],
    start_vel: [f32; 3],
    target: [f32; 3],
    duration_secs: f32,
    elapsed_secs: f32,
) -> ([f32; 3], [f32; 3], bool) {
    if !duration_secs.is_finite() || duration_secs <= 0.001 || elapsed_secs >= duration_secs {
        return (target, [0.0; 3], false);
    }
    let u = (elapsed_secs.max(0.0) / duration_secs).clamp(0.0, 1.0);
    let u2 = u * u;
    let u3 = u2 * u;

    let h00 = 2.0 * u3 - 3.0 * u2 + 1.0;
    let h10 = u3 - 2.0 * u2 + u;
    let h01 = -2.0 * u3 + 3.0 * u2;

    let dh00 = 6.0 * u2 - 6.0 * u;
    let dh10 = 3.0 * u2 - 4.0 * u + 1.0;
    let dh01 = -6.0 * u2 + 6.0 * u;

    let mut pos = [0.0f32; 3];
    let mut vel = [0.0f32; 3];
    for c in 0..3 {
        let p0 = start[c];
        let v0_scaled = start_vel[c] * duration_secs;
        let p1 = target[c];
        let p = h00 * p0 + h10 * v0_scaled + h01 * p1;
        let v = (dh00 * p0 + dh10 * v0_scaled + dh01 * p1) / duration_secs;
        pos[c] = if p.is_finite() { p.clamp(0.4, 1.5) } else { p1 };
        vel[c] = if v.is_finite() { v.clamp(-1.0, 1.0) } else { 0.0 };
    }
    (pos, vel, true)
}

/// Shared transition state for smooth PC gamma ramp animation across overlapping 2s ALS arrivals.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct TransitionState {
    /// Most recently applied RGB multipliers `[kr, kg, kb]`.
    current: [f32; 3],
    /// Current rate of change per second `[dkr/dt, dkg/dt, dkb/dt]`.
    velocity: [f32; 3],
    /// Start RGB multipliers for the active Hermite segment.
    start: [f32; 3],
    /// Start velocity per second for the active Hermite segment.
    start_vel: [f32; 3],
    /// Target destination RGB multipliers for the active Hermite segment.
    target: [f32; 3],
    /// Timestamp when the active Hermite segment began.
    started_at: Instant,
    /// Duration of the active Hermite segment in seconds (4.0s for ALS sync).
    duration_secs: f32,
    /// True while a transition is actively animating toward `target`.
    active: bool,
    /// True once the singleton animator thread has been spawned.
    #[cfg(target_os = "windows")]
    thread_spawned: bool,
}

#[cfg(any(target_os = "windows", test))]
impl TransitionState {
    fn neutral(now: Instant) -> Self {
        Self {
            current: [1.0, 1.0, 1.0],
            velocity: [0.0, 0.0, 0.0],
            start: [1.0, 1.0, 1.0],
            start_vel: [0.0, 0.0, 0.0],
            target: [1.0, 1.0, 1.0],
            started_at: now,
            duration_secs: ALS_TRANSITION_WINDOW_SECS,
            active: false,
            #[cfg(target_os = "windows")]
            thread_spawned: false,
        }
    }

    /// Samples current position and velocity at `now` without mutating active segment bounds.
    fn sample_at(&self, now: Instant) -> ([f32; 3], [f32; 3], bool) {
        if !self.active {
            return (self.current, [0.0; 3], false);
        }
        let elapsed = now.saturating_duration_since(self.started_at).as_secs_f32();
        evaluate_hermite_at(self.start, self.start_vel, self.target, self.duration_secs, elapsed)
    }

    /// Retargets the transition smoothly to `new_target` over `duration_secs` starting from the
    /// exact instantaneous `(pos, vel)` at `now`. Returns `true` if animation state changed.
    fn retarget_at(&mut self, new_target: [f32; 3], duration_secs: f32, now: Instant) -> bool {
        let safe_target = [
            if new_target[0].is_finite() { new_target[0].clamp(0.4, 1.5) } else { 1.0 },
            if new_target[1].is_finite() { new_target[1].clamp(0.4, 1.5) } else { 1.0 },
            if new_target[2].is_finite() { new_target[2].clamp(0.4, 1.5) } else { 1.0 },
        ];
        let (cur_pos, cur_vel, still_active) = self.sample_at(now);
        let max_target_delta = (safe_target[0] - self.target[0])
            .abs()
            .max((safe_target[1] - self.target[1]).abs())
            .max((safe_target[2] - self.target[2]).abs());
        let max_cur_delta = (safe_target[0] - cur_pos[0])
            .abs()
            .max((safe_target[1] - cur_pos[1]).abs())
            .max((safe_target[2] - cur_pos[2]).abs());

        if max_target_delta < MULTIPLIER_RETARGET_EPSILON && (still_active || max_cur_delta < MULTIPLIER_RETARGET_EPSILON) {
            return false;
        }

        self.current = cur_pos;
        self.velocity = if still_active { cur_vel } else { [0.0; 3] };
        self.start = cur_pos;
        self.start_vel = self.velocity;
        self.target = safe_target;
        self.started_at = now;
        self.duration_secs = duration_secs.max(0.05);
        self.active = true;
        true
    }
}

#[cfg(target_os = "windows")]
static ANIMATOR_SYNC: OnceLock<(Mutex<TransitionState>, Condvar)> = OnceLock::new();

#[cfg(target_os = "windows")]
fn animator_sync() -> &'static (Mutex<TransitionState>, Condvar) {
    ANIMATOR_SYNC.get_or_init(|| (Mutex::new(TransitionState::neutral(Instant::now())), Condvar::new()))
}

/// Win32 GDI `SetDeviceGammaRamp` 256-entry 16-bit per-channel hardware Lookup Table (LUT).
#[cfg(target_os = "windows")]
#[repr(C)]
struct DdkGammaRamp {
    red: [u16; 256],
    green: [u16; 256],
    blue: [u16; 256],
}

/// Acquires the primary screen device context (`GetDC(NULL)`), programs the 256-entry RGB gamma ramp
/// via Win32 `SetDeviceGammaRamp`, and unconditionally releases the DC (`ReleaseDC`).
#[cfg(target_os = "windows")]
fn apply_windows_gamma_ramp(ramp: &DdkGammaRamp) -> Result<()> {
    use std::ffi::c_void;

    #[link(name = "gdi32")]
    extern "system" {
        fn SetDeviceGammaRamp(h_dc: *mut c_void, lp_ramp: *const c_void) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn GetDC(h_wnd: *mut c_void) -> *mut c_void;
        fn ReleaseDC(h_wnd: *mut c_void, h_dc: *mut c_void) -> i32;
    }

    // SAFETY: `GetDC(NULL)` obtains the screen device context; `ramp` is a valid `#[repr(C)]`
    // struct of three 256-element `u16` arrays, and `ReleaseDC(NULL, hdc)` always executes before return.
    unsafe {
        let hdc = GetDC(std::ptr::null_mut());
        if hdc.is_null() {
            anyhow::bail!("Failed to acquire screen device context via GetDC(NULL)");
        }
        let res = SetDeviceGammaRamp(hdc, ramp as *const _ as *const c_void);
        ReleaseDC(std::ptr::null_mut(), hdc);
        if res == 0 {
            anyhow::bail!("SetDeviceGammaRamp failed on Windows host display");
        }
    }
    Ok(())
}

/// Programs a linear 256-entry Win32 gamma ramp scaled by `(kr, kg, kb)`.
#[cfg(target_os = "windows")]
fn apply_windows_multipliers(kr: f32, kg: f32, kb: f32) -> Result<()> {
    let mut ramp = DdkGammaRamp {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };
    for i in 0..256 {
        let base = (i as f32 / 255.0) * 65535.0;
        ramp.red[i] = (base * kr).clamp(0.0, 65535.0).round() as u16;
        ramp.green[i] = (base * kg).clamp(0.0, 65535.0).round() as u16;
        ramp.blue[i] = (base * kb).clamp(0.0, 65535.0).round() as u16;
    }
    apply_windows_gamma_ramp(&ramp)
}

/// Ensures the background ~30 Hz Windows smooth ramp animator thread is running and schedules a transition.
#[cfg(target_os = "windows")]
fn schedule_smooth_transition(target: [f32; 3], duration_secs: f32) -> Result<()> {
    let pair = animator_sync();
    let mut st = pair.0.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let changed = st.retarget_at(target, duration_secs, now);
    if !st.thread_spawned {
        st.thread_spawned = true;
        std::thread::Builder::new()
            .name("integrator-truetone-animator".into())
            .spawn(move || {
                let (lock, cvar) = animator_sync();
                let mut logged_gdi_err = false;
                loop {
                    let frame_mults = {
                        let mut guard = match lock.lock() {
                            Ok(g) => g,
                            Err(e) => e.into_inner(),
                        };
                        while !guard.active {
                            guard = match cvar.wait(guard) {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                        }
                        let (pos, vel, still_active) = guard.sample_at(Instant::now());
                        guard.current = pos;
                        guard.velocity = vel;
                        if !still_active {
                            guard.active = false;
                        }
                        pos
                    };

                    if let Err(e) = apply_windows_multipliers(frame_mults[0], frame_mults[1], frame_mults[2]) {
                        if !logged_gdi_err {
                            tracing::warn!("True Tone smooth LUT step failed: {}", e);
                            logged_gdi_err = true;
                        }
                    } else {
                        logged_gdi_err = false;
                    }

                    let guard = match lock.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    if guard.active {
                        let _ = cvar.wait_timeout(guard, ANIMATOR_FRAME_INTERVAL);
                    }
                }
            })?;
    }
    if changed {
        pair.1.notify_one();
    }
    Ok(())
}

/// PC-side entry point for incoming raw Mac ALS telemetry: computes CCT, applies Apple-like EMA +
/// lux-weighted partial adaptation + Bradford CAT multipliers on Windows, and starts/updates a smooth
/// 4-second $C^1$ Hermite LUT transition.
#[cfg(target_os = "windows")]
pub fn apply_raw_als_sync(
    lux: f32,
    als_ch0: Option<f32>,
    _als_ch1: Option<f32>,
    als_ch2: Option<f32>,
    cie_x: Option<f32>,
    cie_y: Option<f32>,
    cie_z: Option<f32>,
    gamma_comp: f32,
) -> Result<(f32, u32)> {
    let raw_cct = estimate_cct_from_raw_als(als_ch0, als_ch2, cie_x, cie_y, cie_z);
    let (filtered_lux, adapted_cct) = {
        let mut f = pc_filter().lock().unwrap_or_else(|e| e.into_inner());
        f.ingest(lux, raw_cct, Instant::now())
    };
    let (kr, kg, kb) = calculate_bradford_multipliers(adapted_cct, gamma_comp);
    schedule_smooth_transition([kr, kg, kb], ALS_TRANSITION_WINDOW_SECS)?;
    Ok((filtered_lux, adapted_cct))
}

/// Non-Windows fallback stub (Windows PC owns raw ALS calculation & LUT transition).
#[cfg(not(target_os = "windows"))]
pub fn apply_raw_als_sync(
    lux: f32,
    _als_ch0: Option<f32>,
    _als_ch1: Option<f32>,
    _als_ch2: Option<f32>,
    _cie_x: Option<f32>,
    _cie_y: Option<f32>,
    _cie_z: Option<f32>,
    _gamma_comp: f32,
) -> Result<(f32, u32)> {
    let safe_lux = if lux.is_finite() && lux >= 0.0 { lux } else { 0.0 };
    Ok((safe_lux, D65_CCT_KELVIN))
}

/// Applies manual CCT/gamma calibration via the smooth Windows GPU Gamma LUT animator.
#[cfg(target_os = "windows")]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    let (kr, kg, kb) = calculate_bradford_multipliers(cct_kelvin, gamma_comp);
    schedule_smooth_transition([kr, kg, kb], MANUAL_TRANSITION_WINDOW_SECS)?;
    tracing::info!(
        "🎨 Windows True Tone LUT target scheduled smoothly: CCT={}K, Comp={:.2}x",
        cct_kelvin,
        if gamma_comp.is_finite() { gamma_comp } else { 1.0 }
    );
    Ok(())
}

/// Logs simulated Bradford CAT gamma LUT update on non-Windows hosts.
#[cfg(not(target_os = "windows"))]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    let safe_gamma = if gamma_comp.is_finite() { gamma_comp } else { 1.0 };
    tracing::info!(
        "🎨 Simulated Gamma LUT Ramp on macOS/Unix: CCT={}K, Comp={:.2}x",
        cct_kelvin,
        safe_gamma
    );
    Ok(())
}

/// Cancels any active transition, clears PC adaptation/synced telemetry, and restores linear neutral LUT.
#[cfg(target_os = "windows")]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    clear_synced_ambient();
    {
        let mut f = pc_filter().lock().unwrap_or_else(|e| e.into_inner());
        f.reset();
    }
    {
        let (lock, cvar) = animator_sync();
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        let spawned = st.thread_spawned;
        *st = TransitionState::neutral(Instant::now());
        st.thread_spawned = spawned;
        cvar.notify_one();
    }

    apply_windows_multipliers(1.0, 1.0, 1.0)?;
    tracing::info!("🎨 Restored neutral identity gamma ramp on Windows host");
    Ok(())
}

/// Clears synced ambient telemetry on non-Windows platforms when True Tone is disabled or reset.
#[cfg(not(target_os = "windows"))]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    clear_synced_ambient();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bradford_handles_nan_inf_and_preserves_finite_bounds() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 0.0] {
            let (r, g, b) = calculate_bradford_multipliers(D65_CCT_KELVIN, bad);
            assert!(r.is_finite() && (0.4..=1.5).contains(&r));
            assert!(g.is_finite() && (0.4..=1.5).contains(&g));
            assert!(b.is_finite() && (0.4..=1.5).contains(&b));
        }
        let (r65, g65, b65) = calculate_bradford_multipliers(D65_CCT_KELVIN, 1.0);
        assert!((r65 - 1.0).abs() < 0.05 && (g65 - 1.0).abs() < 0.05 && (b65 - 1.0).abs() < 0.05);
    }

    #[test]
    fn synced_ambient_record_clear_roundtrip() {
        clear_synced_ambient();
        assert!(get_last_synced_ambient().is_none());
        record_synced_ambient(123.4, 100_000);
        let (lux, cct, ts) = get_last_synced_ambient().expect("synced");
        assert!((lux - 123.4).abs() < 0.11);
        assert_eq!(cct, MAX_CCT_KELVIN);
        assert!(ts > 0);
        record_synced_ambient(f32::NAN, 1);
        let (lux, cct, _) = get_last_synced_ambient().expect("synced");
        assert_eq!(lux, 0.0);
        assert_eq!(cct, MIN_CCT_KELVIN);
        clear_synced_ambient();
        assert!(get_last_synced_ambient().is_none());
    }

    #[test]
    fn test_user_gamma_comp_get_set_clamping() {
        set_user_gamma_comp(1.15);
        assert!((get_user_gamma_comp() - 1.15).abs() < 0.01);

        set_user_gamma_comp(0.1);
        assert!((get_user_gamma_comp() - MIN_GAMMA_COMP_FACTOR).abs() < 0.01);

        set_user_gamma_comp(5.0);
        assert!((get_user_gamma_comp() - MAX_GAMMA_COMP_FACTOR).abs() < 0.01);

        set_user_gamma_comp(1.0);
        assert!((get_user_gamma_comp() - 1.0).abs() < 0.01);
    }

    #[test]
    fn pc_cct_estimator_prefers_cie_xyz_and_falls_back_to_channels() {
        // D65 CIE 1931 chromaticity (x=0.3127, y=0.3290, z=0.3583) -> ~6500K
        let d65_cct = estimate_cct_from_raw_als(
            Some(50.0),
            Some(50.0),
            Some(0.3127),
            Some(0.3290),
            Some(0.3583),
        );
        assert!((d65_cct - 6505.0).abs() < 30.0, "got {}", d65_cct);

        // Warm 3000K CIE chromaticity (x=0.4369, y=0.4041) -> ~3000K
        let warm_cct = estimate_cct_from_raw_als(None, None, Some(0.4369), Some(0.4041), Some(0.1590));
        assert!((warm_cct - 3005.0).abs() < 30.0, "got {}", warm_cct);

        // Channel ratio fallback when CIE XYZ is unavailable
        let ch_cct = estimate_cct_from_raw_als(Some(100.0), Some(100.0), None, None, None);
        assert!((ch_cct - 6500.0).abs() < 1.0);

        // Monochrome sensor fallback -> D65
        let mono_cct = estimate_cct_from_raw_als(None, None, None, None, None);
        assert!((mono_cct - 6500.0).abs() < 0.1);
    }

    #[test]
    fn smooth_4s_hermite_preserves_c1_continuity_across_2s_als_retarget() {
        let t0 = Instant::now();
        let mut st = TransitionState::neutral(t0);

        // First ALS update arrives at t=0 -> target warmer display over 4s window.
        let target1 = [1.0, 0.92, 0.80];
        assert!(st.retarget_at(target1, ALS_TRANSITION_WINDOW_SECS, t0));
        assert!(st.active);

        // At t=2.0s (midpoint of 4s window), evaluate position & velocity before 2nd ALS sample arrives.
        let t2 = t0 + Duration::from_secs(2);
        let (pos_before, vel_before, active_at_2s) = st.sample_at(t2);
        assert!(active_at_2s);
        assert!((pos_before[2] - 0.90).abs() < 0.01);
        assert!(vel_before[2] < 0.0);

        // Second ALS update arrives at t=2.0s pushing target further warm.
        let target2 = [1.0, 0.88, 0.68];
        assert!(st.retarget_at(target2, ALS_TRANSITION_WINDOW_SECS, t2));

        // Immediately after retarget at t=2.0s: zero jump in position OR velocity (C1 smooth!).
        let (pos_after, vel_after, _) = st.sample_at(t2);
        for c in 0..3 {
            assert!((pos_after[c] - pos_before[c]).abs() < 1e-5);
            assert!((vel_after[c] - vel_before[c]).abs() < 1e-5);
        }

        // At t=6.0s (4s after the 2nd update), converges cleanly to exact target2 at rest.
        let t_end = t2 + Duration::from_secs(4);
        let (pos_end, vel_end, active_end) = st.sample_at(t_end);
        assert!(!active_end);
        assert_eq!(pos_end, target2);
        assert_eq!(vel_end, [0.0; 3]);
    }

    #[test]
    fn apple_lux_adaptation_and_ema_filter_dampens_glare_spikes() {
        let low = apple_adaptation_degree_from_lux(2.0);
        let high = apple_adaptation_degree_from_lux(300.0);
        assert!(low >= 0.45 && low < 0.55);
        assert!(high > 0.80 && high <= 0.85);

        let mut f = PcAdaptationFilter::default();
        let t0 = Instant::now();
        let (_lux0, cct0) = f.ingest(150.0, 6500.0, t0);
        assert_eq!(cct0, 6500);

        // Single-frame 2s spike to 2500K should be damped by EMA rather than snapping to 2500K.
        let (_lux1, cct1) = f.ingest(150.0, 2500.0, t0 + Duration::from_secs(2));
        assert!(cct1 > 5000 && cct1 < 6500, "expected damped transition, got {}", cct1);
    }
}
