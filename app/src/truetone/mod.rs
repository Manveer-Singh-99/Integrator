//! # Cross-Screen TrueTone & Bradford Chromatic Adaptation Engine
//!
//! ## 1. Module Purpose & Scope
//! This module provides real-time ambient color temperature synchronization and chromatic adaptation
//! between a macOS host equipped with an Apple Ambient Light Sensor (ALS) and a paired Windows 10/11
//! workstation.
//!
//! When a MacBook Pro is positioned alongside an external Windows monitor, differences in panel
//! native white points and room lighting can cause significant visual fatigue and jarring color
//! mismatch. This module:
//! 1. Telemeters ambient illumination (lux) and Correlated Color Temperature (CCT in Kelvin) from
//!    the Mac hardware sensor (`ambient_light.swift`).
//! 2. Solves the CIE daylight / Planckian locus chromaticity equations to derive destination XYZ
//!    tristimulus white points.
//! 3. Applies the Bradford Chromatic Adaptation Transform (CAT) in cone response space to calculate
//!    per-channel linear sRGB multipliers `(k_r, k_g, k_b)`.
//! 4. Injects calibrated 256-entry hardware gamma lookup tables (LUT) directly into the Windows GPU
//!    using the Win32 GDI `SetDeviceGammaRamp` API.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                          TrueTone & Chromatic Adaptation Flow                          │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                 MacBook (Host)                               Windows 11 (Client)
//!     ┌──────────────────────────────────┐             ┌──────────────────────────────────┐
//!     │ Apple Ambient Light Sensor (ALS) │             │ Windows Display Controller       │
//!     │ IOKit HID (ambient_light.swift)  │             │ (src/display/win_display.rs)     │
//!     └────────────────┬─────────────────┘             └────────────────▲─────────────────┘
//!                      │                                                │
//!                      │ lux, CCT (2500K..9000K)                        │ apply_hardware_
//!                      ▼                                                │ gamma_ramp()
//!     ┌──────────────────────────────────┐                              │
//!     │   read_ambient_light()           │                              │
//!     │   (src/truetone/mod.rs)          │                              │
//!     └────────────────┬─────────────────┘                              │
//!                      │ Telemetry Broadcast (UDP / RPC)                │
//!                      ├────────────────────────────────────────────────┘
//!                      │
//!                      ▼
//!     ┌──────────────────────────────────┐
//!     │ Bradford CAT Matrix Transform    │
//!     │ - CIE D-Illuminant / Planckian   │
//!     │ - Cone Response Scaling (M_BFD)  │
//!     │ - SetDeviceGammaRamp GDI API     │
//!     └──────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Periodically samples ambient light (`read_ambient_light`), spawns the continuous
//!   macOS ambient sync daemon (`run_continuous_truetone_sync`), applies manual or peer-synced color
//!   calibration (`apply_hardware_gamma_ramp`), and restores neutral LUTs on teardown (`reset_hardware_gamma_ramp`).
//! - `src/display/controller.rs`: Handles incoming `DisplayRpcRequest::SyncTrueTone` RPC payloads on
//!   Windows, recording the synced ambient telemetry (`record_synced_ambient`) and programming the GPU LUT.
//! - Native Settings UI (`ui-macos/`, `ui-windows/`): Toggles Cross-Screen TrueTone, adjusts gamma
//!   compensation (`set_user_gamma_comp`), and displays live active/synced lux and Kelvin status pills.
//!
//! ### Downstream Callees:
//! - `src/ambient_light.swift`: FFI bridge (`read_mac_ambient_sensor`) to Apple IOKit HID ambient light sensor.
//! - `src/display/controller.rs`: Dispatches encrypted `DisplayRpcRequest::SyncTrueTone` messages to the Windows peer.
//! - Win32 `gdi32.dll` / `user32.dll`: `SetDeviceGammaRamp`, `GetDC`, and `ReleaseDC` on Windows.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! 1. The macOS host reads hardware ALS telemetry `(lux, cct_kelvin)` every 2 seconds in `run_continuous_truetone_sync`.
//! 2. When ambient CCT shifts by `>= 40 K`, illuminance shifts by `>= 15 lux`, or the 45-second keepalive expires,
//!    macOS sends `DisplayRpcRequest::SyncTrueTone { lux, cct, gamma_comp }` over the authenticated transport channel.
//! 3. The Windows peer records `(lux, cct_kelvin, epoch_secs)` in lock-free atomics via `record_synced_ambient`
//!    (so `read_ambient_light()` on Windows reports `supported: true` with active synced metrics to the WinUI 3 frontend)
//!    and injects the Bradford-adapted 256-entry RGB LUT via `apply_hardware_gamma_ramp`.
//! 4. Disabling True Tone or shutting down invokes `reset_hardware_gamma_ramp`, which clears the synced ambient
//!    atomics (`clear_synced_ambient`) and restores a linear identity LUT.
//!
//! ## 3. Mathematical Foundations: Bradford CAT
//! - **Reference White Point**: Standard CIE D65 (`x = 0.3127, y = 0.3290`, `X = 0.95047, Y = 1.00000, Z = 1.08883`).
//! - **Target White Point**: Computed using CIE Daylight equations (for CCT >= 4000K) or the Kang 2002
//!   Planckian approximation (for CCT < 4000K).
//! - **Cone Transformation**: XYZ values are projected into Bradford cone response space via matrix $M_{BFD}$:
//!   $$\begin{bmatrix} \rho \\ \gamma \\ \beta \end{bmatrix} = \begin{bmatrix} 0.8951 & 0.2664 & -0.1614 \\ -0.7502 & 1.7135 & 0.0367 \\ 0.0389 & -0.0685 & 1.0296 \end{bmatrix} \begin{bmatrix} X \\ Y \\ Z \end{bmatrix}$$
//! - Scaling ratios $s_\rho = \rho_d / \rho_s$, $s_\gamma = \gamma_d / \gamma_s$, $s_\beta = \beta_d / \beta_s$
//!   are applied and mapped back through $M_{BFD}^{-1}$ into linear sRGB space.
//!
//! ## 4. Threading & Concurrency Model
//! - **Lock-Free Atomic State**: User gamma compensation (`USER_GAMMA_COMP_X100`) and peer-synced ambient
//!   telemetry (`LAST_SYNCED_CCT`, `LAST_SYNCED_LUX_X10`, `LAST_SYNCED_EPOCH_SECS`) are stored in global
//!   atomics (`AtomicU32` / `AtomicU64`) with `Release`/`Acquire` memory ordering so status snapshots never contend.
//! - **Single-Flight RPC Guard**: On macOS, `SYNC_IN_FLIGHT` (`AtomicBool` compare-and-swap) guarantees at most
//!   one in-flight network RPC dispatch at any time.
//! - **Blocking FFI & Win32 Isolation**: Hardware IOKit sensor reads and Win32 GDI `SetDeviceGammaRamp` calls are
//!   executed inside `tokio::task::spawn_blocking` so Tokio async workers are never stalled.
//!
//! ## 5. Security & Safety Invariants
//! - **Finite Number Guarantee**: All multipliers, lux readings, and gamma values are verified for finite validity
//!   (`is_finite()`). Any `NaN` or `Inf` value safely falls back to neutral `1.0` (or `0.0` lux).
//! - **LUT Ramp Clamping**: Color temperature is clamped to `[MIN_CCT_KELVIN, MAX_CCT_KELVIN]` (`[2500, 9000] K`)
//!   and channel multipliers are clamped to `[0.4, 1.5]`, preventing display blackout or extreme color distortion.
//! - **GDI Handle Hygiene**: `apply_windows_gamma_ramp` unconditionally pairs `GetDC(NULL)` with `ReleaseDC(NULL, hdc)`
//!   before inspecting the `SetDeviceGammaRamp` return code, preventing Win32 GDI device-context leaks.

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
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

/// Scaled integer (value * 100) storing user-selected gamma compensation factor (default: 1.00x).
static USER_GAMMA_COMP_X100: AtomicU32 = AtomicU32::new(100);

/// Most recent synced correlated color temperature in Kelvin (0 = nothing synced yet).
/// Written when the paired Mac pushes `SyncTrueTone` (or a manual calibration is applied)
/// and read by `read_ambient_light()` on non-macOS hosts so the UI can show an active status.
static LAST_SYNCED_CCT: AtomicU32 = AtomicU32::new(0);

/// Most recent synced illuminance in lux, stored as fixed-point `lux * 10` (0.1 lux resolution).
static LAST_SYNCED_LUX_X10: AtomicU32 = AtomicU32::new(0);

/// Unix epoch seconds at which the last synced ambient sample was recorded (0 = never).
static LAST_SYNCED_EPOCH_SECS: AtomicU64 = AtomicU64::new(0);

/// Reentrancy guard preventing overlapping asynchronous True Tone RPC sync dispatches
/// (only the macOS sender daemon dispatches RPCs).
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

/// Records the latest ambient light sample received from the paired Mac (or a manual
/// calibration) so the PC can report an active synced True Tone status.
///
/// * `lux` - illuminance in lux; stored at 0.1 lux resolution only when finite and `>= 0`
///   (invalid values are stored as 0.0 lux rather than rejected, so the CCT/timestamp stay fresh).
/// * `cct_kelvin` - clamped to `[MIN_CCT_KELVIN, MAX_CCT_KELVIN]` before storage, so a
///   recorded CCT is always strictly positive and marks the state as "synced".
///
/// Thread-safety: three independent atomics; a concurrent reader may briefly observe a
/// mix of old/new fields, which is harmless for a status display. The CCT is written last
/// with `Release` so that readers observing it with `Acquire` see the matching lux/timestamp.
#[allow(dead_code)] // Consumed by Windows SyncTrueTone RPC handler in display/controller.rs and tests.
pub fn record_synced_ambient(lux: f32, cct_kelvin: u32) {
    let cct = cct_kelvin.clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN);
    let lux_x10 = if lux.is_finite() && lux >= 0.0 {
        // `as u32` saturates for huge values, so no overflow is possible.
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

/// Forgets the last synced ambient sample (e.g. when the display ramp is reset to neutral).
/// After this call `get_last_synced_ambient()` returns `None`.
pub fn clear_synced_ambient() {
    LAST_SYNCED_CCT.store(0, Ordering::Release);
    LAST_SYNCED_LUX_X10.store(0, Ordering::Relaxed);
    LAST_SYNCED_EPOCH_SECS.store(0, Ordering::Relaxed);
}

/// Returns `Some((lux, cct_kelvin, unix_epoch_secs))` for the most recent synced ambient
/// sample, or `None` if nothing has been synced (or it was cleared).
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn get_last_synced_ambient() -> Option<(f32, u32, u64)> {
    let cct = LAST_SYNCED_CCT.load(Ordering::Acquire);
    if cct == 0 {
        return None;
    }
    let lux = LAST_SYNCED_LUX_X10.load(Ordering::Relaxed) as f32 / 10.0;
    let ts = LAST_SYNCED_EPOCH_SECS.load(Ordering::Relaxed);
    Some((lux, cct, ts))
}

/// Continuously monitors the ambient light sensor on macOS and synchronizes
/// chromatic calibration to the paired Windows PC whenever ambient light changes.
pub async fn run_continuous_truetone_sync(
    discovery: DiscoveryManager,
    features: Arc<FeatureManager>,
) {
    #[cfg(target_os = "macos")]
    {
        let mut last_synced_cct: Option<u32> = None;
        let mut last_synced_lux: Option<f32> = None;
        let mut last_sync_instant = Instant::now() - Duration::from_secs(60);

        tracing::info!("🎨 Continuous True Tone ambient sync daemon started on macOS");

        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            if !features.is_enabled("truetone") {
                continue;
            }

            let peer_ip = match discovery.get_peer_ip().await {
                Some(ip) => ip,
                None => match discovery.get_best_peer().await {
                    Some(p) => p.addr.ip().to_string(),
                    None => {
                        last_synced_cct = None;
                        last_synced_lux = None;
                        continue;
                    }
                },
            };

            let als = tokio::task::spawn_blocking(read_ambient_light)
                .await
                .unwrap_or(AmbientLightData {
                    lux: 0.0,
                    cct_kelvin: D65_CCT_KELVIN,
                    supported: false,
                    updated_at_secs: 0,
                });

            if !als.supported || !als.lux.is_finite() || als.lux < 0.0 {
                continue;
            }

            let cct = als.cct_kelvin;
            let lux = als.lux;

            let cct_delta = match last_synced_cct {
                Some(prev) => (cct as i64 - prev as i64).abs(),
                None => i64::MAX,
            };
            let lux_delta = match last_synced_lux {
                Some(prev) => (lux - prev).abs(),
                None => f32::MAX,
            };
            let time_elapsed = last_sync_instant.elapsed() >= Duration::from_secs(45);

            // Deadband filter: trigger when color temperature changes by >= 40K,
            // or illuminance changes by >= 15 Lux, or on periodic keepalive.
            if cct_delta >= 40 || lux_delta >= 15.0 || time_elapsed {
                if SYNC_IN_FLIGHT
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    /// RAII guard ensuring `SYNC_IN_FLIGHT` is cleared even if the RPC future panics or aborts.
                    struct SyncInFlightGuard;
                    impl Drop for SyncInFlightGuard {
                        fn drop(&mut self) {
                            SYNC_IN_FLIGHT.store(false, Ordering::Release);
                        }
                    }

                    let gamma_comp = get_user_gamma_comp();
                    let rpc = DisplayRpcRequest::SyncTrueTone {
                        lux,
                        cct,
                        gamma_comp,
                    };
                    let target_ip = peer_ip.clone();
                    tokio::spawn(async move {
                        let _guard = SyncInFlightGuard;
                        let res = DisplayController::send_remote_rpc(&target_ip, &rpc).await;
                        match res {
                            Ok(resp) if resp.success => {
                                tracing::debug!(
                                    "🎨 Auto-synced True Tone to {}: {}K ({:.1} lux)",
                                    target_ip,
                                    cct,
                                    lux
                                );
                            }
                            Ok(resp) => {
                                tracing::debug!(
                                    "True Tone sync to {} rejected: {}",
                                    target_ip,
                                    resp.message
                                );
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "True Tone sync transport error to {}: {}",
                                    target_ip,
                                    e
                                );
                            }
                        }
                    });

                    last_synced_cct = Some(cct);
                    last_synced_lux = Some(lux);
                    last_sync_instant = Instant::now();
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (discovery, features);
    }
}

/// Ambient light snapshot exposed to the UI / RPC layer (serialized as JSON/Bincode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientLightData {
    /// Illuminance in lux (`>= 0`, finite).
    pub lux: f32,
    /// Correlated color temperature in Kelvin (`MIN_CCT_KELVIN..=MAX_CCT_KELVIN`, or D65 fallback).
    pub cct_kelvin: u32,
    /// `true` when a real sensor reading (macOS) or a synced Mac sample (Windows) is available.
    pub supported: bool,
    /// Unix epoch seconds of the sample; 0 when unsupported.
    pub updated_at_secs: u64,
}

#[cfg(target_os = "macos")]
extern "C" {
    /// Native Swift/IOKit FFI entry point (`ambient_light.swift`) sampling Apple's HID Ambient Light Sensor.
    /// Returns `true` when valid finite lux and Kelvin chromaticity readings are written to `out_lux`/`out_cct`.
    fn read_mac_ambient_sensor(out_lux: *mut f32, out_cct: *mut u32) -> bool;
}

/// Reads the local ambient light sensor on macOS; on other platforms (no local Apple ALS) returns
/// the most recent sample synced from the paired Mac, or `supported: false` if none exists.
pub fn read_ambient_light() -> AmbientLightData {
    #[cfg(target_os = "macos")]
    {
        let mut lux: f32 = 0.0;
        let mut cct: u32 = 0;
        // SAFETY: Passes valid mutable pointers to stack-allocated `f32` and `u32` variables.
        let ok = unsafe { read_mac_ambient_sensor(&mut lux, &mut cct) };
        if ok && lux.is_finite() && lux >= 0.0 {
            // Normalize monochrome ALS fallback (cct == 0 -> D65) and clamp within safe CCT bounds.
            let safe_cct = if cct == 0 {
                D65_CCT_KELVIN
            } else {
                cct.clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN)
            };
            AmbientLightData {
                lux,
                cct_kelvin: safe_cct,
                supported: true,
                updated_at_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
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

/// Calculates Bradford Chromatic Adaptation Transform linear sRGB scaling factors `(k_r, k_g, k_b)`
/// for a target ambient CCT (`cct_kelvin`) relative to the standard CIE D65 (`6500 K`) white point,
/// scaled by the user's `gamma_comp` intensity multiplier.
///
/// # Arguments
/// * `cct_kelvin` - Target correlated color temperature in Kelvin (clamped to `MIN_CCT_KELVIN..=MAX_CCT_KELVIN`).
/// * `gamma_comp` - User brightness/gamma compensation factor (clamped to `MIN_GAMMA_COMP_FACTOR..=MAX_GAMMA_COMP_FACTOR`; falls back to `1.0` if non-finite).
///
/// # Return Value
/// Returns `(k_r, k_g, k_b)` channel multipliers, each guaranteed finite and clamped to `[0.4, 1.5]`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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

    // Per-cone scaling ratios clamped to [0.4, 2.0] to avoid chromaticity singularities at extreme CCTs.
    let s_r = (rho_d / rho_s.max(0.0001)).clamp(0.4, 2.0);
    let s_g = (gam_d / gam_s.max(0.0001)).clamp(0.4, 2.0);
    let s_b = (bet_d / bet_s.max(0.0001)).clamp(0.4, 2.0);

    // Adapted D65 white in Bradford cone space, mapped back via M_BFD^-1 to XYZ then linear sRGB.
    let a_rho = s_r * rho_s;
    let a_gam = s_g * gam_s;
    let a_bet = s_b * bet_s;

    // Exact inverse Bradford M_BFD^-1 transformation matrix.
    let ax = 0.9869929 * a_rho - 0.1470543 * a_gam + 0.1599627 * a_bet;
    let ay = 0.4323053 * a_rho + 0.5183603 * a_gam + 0.0492912 * a_bet;
    let az = -0.0085287 * a_rho + 0.0400428 * a_gam + 0.9684867 * a_bet;

    // Standard IEC 61966-2-1 CIE XYZ -> linear sRGB matrix (D65 white reference).
    let r_lin = 3.2404542 * ax - 1.5371385 * ay - 0.4985314 * az;
    let g_lin = -0.9692660 * ax + 1.8760108 * ay + 0.0415560 * az;
    let b_lin = 0.0556434 * ax - 0.2040259 * ay + 1.0572252 * az;

    // Normalize against peak channel to preserve overall display luminance, then apply user gamma compensation
    // and clamp final LUT factors to [0.4, 1.5] so panels cannot black out or clip heavily.
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

/// Win32 GDI `SetDeviceGammaRamp` 256-entry 16-bit per-channel hardware Lookup Table (LUT).
#[cfg(target_os = "windows")]
#[repr(C)]
struct DdkGammaRamp {
    /// Red channel 16-bit output word (`0..=65535`) for each 8-bit input index (`0..=255`).
    red: [u16; 256],
    /// Green channel 16-bit output word (`0..=65535`) for each 8-bit input index (`0..=255`).
    green: [u16; 256],
    /// Blue channel 16-bit output word (`0..=65535`) for each 8-bit input index (`0..=255`).
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

    // SAFETY: `GetDC(NULL)` obtains the entire screen's GDI device context; `ramp` is a valid
    // `#[repr(C)]` struct of three 256-element `u16` arrays (1536 bytes) matching Win32 `SetDeviceGammaRamp`,
    // and `ReleaseDC(NULL, hdc)` is called unconditionally before returning.
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

/// Injects Bradford CAT calibrated Gamma LUT directly into the Windows GPU hardware ramp.
#[cfg(target_os = "windows")]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    let (kr, kg, kb) = calculate_bradford_multipliers(cct_kelvin, gamma_comp);

    let mut ramp = DdkGammaRamp {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    // Construct 256-entry 16-bit LUT with subtle mid-tone contrast lift (exponent 1/1.05)
    // and per-channel Bradford white-point scaling clamped to 16-bit [0, 65535].
    for i in 0..256 {
        let base = (i as f32 / 255.0).powf(1.0 / 1.05) * 65535.0;
        ramp.red[i] = (base * kr).clamp(0.0, 65535.0).round() as u16;
        ramp.green[i] = (base * kg).clamp(0.0, 65535.0).round() as u16;
        ramp.blue[i] = (base * kb).clamp(0.0, 65535.0).round() as u16;
    }

    apply_windows_gamma_ramp(&ramp)?;

    tracing::info!(
        "🎨 Windows GPU Gamma LUT updated via Bradford CAT: CCT={}K, Comp={:.2}x",
        cct_kelvin,
        if gamma_comp.is_finite() { gamma_comp } else { 1.0 }
    );
    Ok(())
}

/// Logs simulated Bradford CAT gamma LUT update on non-Windows platforms where native True Tone manages the panel.
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

/// Clears any synced ambient telemetry and restores the neutral linear identity gamma ramp on the display.
#[cfg(target_os = "windows")]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    clear_synced_ambient();
    let mut ramp = DdkGammaRamp {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    for i in 0..256 {
        let val = ((i as f32 / 255.0) * 65535.0).round() as u16;
        ramp.red[i] = val;
        ramp.green[i] = val;
        ramp.blue[i] = val;
    }

    apply_windows_gamma_ramp(&ramp)?;
    tracing::info!("🎨 Restored neutral identity gamma ramp on Windows host");
    Ok(())
}

/// Clears any synced ambient telemetry on non-Windows platforms when True Tone is reset.
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

        set_user_gamma_comp(0.1); // below min 0.70
        assert!((get_user_gamma_comp() - MIN_GAMMA_COMP_FACTOR).abs() < 0.01);

        set_user_gamma_comp(5.0); // above max 1.30
        assert!((get_user_gamma_comp() - MAX_GAMMA_COMP_FACTOR).abs() < 0.01);

        set_user_gamma_comp(1.0); // reset
        assert!((get_user_gamma_comp() - 1.0).abs() < 0.01);
    }
}
